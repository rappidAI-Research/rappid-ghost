package broker

import (
	"context"
	"encoding/json"
	"net/http"
)

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	NumPredict *int `json:"num_predict,omitempty"`
	NumCtx     *int `json:"num_ctx,omitempty"`
}

type ollamaChat struct {
	Model     string          `json:"model"`
	Messages  []ollamaMessage `json:"messages"`
	Stream    bool            `json:"stream"`
	KeepAlive int             `json:"keep_alive"`
	Options   *ollamaOptions  `json:"options,omitempty"`
}

// Native Ollama is deliberately distinct from the OpenAI compatibility API.
// No model management, cloud discovery, tools, media or unlimited prediction.
func (s *Server) ollamaRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, data []byte) {
	const op = "/api/chat"
	if s.model == nil || s.cfg.Model.ProtocolName() != ProtocolOllama {
		s.deny(w, r, "model", "model_protocol_not_granted", 403)
		return
	}
	var call ollamaChat
	if decodeStrict(data, &call) != nil || call.Model != s.cfg.Model.Name || call.Stream || call.KeepAlive != 0 || len(call.Messages) < 1 || len(call.Messages) > 64 {
		s.deny(w, r, op, "invalid_ollama_request", 400)
		return
	}
	user := false
	for _, message := range call.Messages {
		if message.Content == "" || len(message.Content) > 64*1024 || (message.Role != "system" && message.Role != "user" && message.Role != "assistant") {
			s.deny(w, r, op, "invalid_ollama_message", 400)
			return
		}
		user = user || message.Role == "user"
	}
	if !user {
		s.deny(w, r, op, "invalid_ollama_message", 400)
		return
	}
	max := s.cfg.Model.MaxOutputTokens
	if max == 0 {
		max = 4096
	}
	predict, contextTokens := max, 2048
	if call.Options != nil {
		if n := call.Options.NumPredict; n != nil {
			if *n < 1 || *n > max {
				s.deny(w, r, op, "output_budget", 403)
				return
			}
			predict = *n
		}
		if n := call.Options.NumCtx; n != nil {
			if *n < 512 || *n > 4096 {
				s.deny(w, r, op, "context_budget", 403)
				return
			}
			contextTokens = *n
		}
	}
	// Always materialize finite limits; absent/null optional input cannot select
	// Ollama's unlimited defaults. keep_alive=0 is a service request, not a claim
	// that another process securely erases memory or cannot retain prompts.
	call.Options = &ollamaOptions{NumPredict: &predict, NumCtx: &contextTokens}
	data, _ = json.Marshal(call)
	if s.audit(ctx, "admission", op, "explicit_model_grant") != nil {
		http.Error(w, "broker audit unavailable", 503)
		return
	}
	response, err := s.forward(ctx, s.model, op, data)
	if err != nil {
		s.deny(w, r, op, "upstream_unavailable", 502)
		return
	}
	s.modelResponse(ctx, w, r, op, response, func(data []byte) error {
		return validateOllamaResponse(data, call.Model, predict)
	})
}

func validateOllamaResponse(data []byte, model string, max int) error {
	var response struct {
		Model     string `json:"model"`
		CreatedAt string `json:"created_at"`
		Message   struct {
			Role     string `json:"role"`
			Content  string `json:"content"`
			Thinking string `json:"thinking,omitempty"`
		} `json:"message"`
		Done               bool   `json:"done"`
		DoneReason         string `json:"done_reason"`
		TotalDuration      int64  `json:"total_duration"`
		LoadDuration       int64  `json:"load_duration"`
		PromptEvalCount    int64  `json:"prompt_eval_count"`
		PromptEvalDuration int64  `json:"prompt_eval_duration"`
		EvalCount          int    `json:"eval_count"`
		EvalDuration       int64  `json:"eval_duration"`
	}
	if decodeStrict(data, &response) != nil || response.Model != model || !response.Done || (response.DoneReason != "stop" && response.DoneReason != "length") || response.Message.Role != "assistant" || response.EvalCount < 0 || response.EvalCount > max || len(response.CreatedAt) > 64 || response.TotalDuration < 0 || response.LoadDuration < 0 || response.PromptEvalCount < 0 || response.PromptEvalDuration < 0 || response.EvalDuration < 0 {
		return errModelProtocol
	}
	return nil
}
