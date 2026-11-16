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

// NormalizeOllamaChat implements the bounded native text contract shared by
// the broker and the example TLS edge. It grants no endpoint, identity or tool.
func NormalizeOllamaChat(data []byte, model string, max int) ([]byte, int, error) {
	if len(data) > MaxRequestBytes || max < 0 || max > 8192 {
		return nil, 0, errModelProtocol
	}
	var call ollamaChat
	if decodeStrict(data, &call) != nil || call.Model != model || call.Stream || call.KeepAlive != 0 || len(call.Messages) < 1 || len(call.Messages) > 64 {
		return nil, 0, &protocolInputError{reason: "invalid_ollama_request", status: 400}
	}
	user := false
	for _, message := range call.Messages {
		if message.Content == "" || len(message.Content) > 64*1024 || (message.Role != "system" && message.Role != "user" && message.Role != "assistant") {
			return nil, 0, &protocolInputError{reason: "invalid_ollama_message", status: 400}
		}
		user = user || message.Role == "user"
	}
	if !user {
		return nil, 0, &protocolInputError{reason: "invalid_ollama_message", status: 400}
	}
	if max == 0 {
		max = 4096
	}
	predict, contextTokens := max, 2048
	if call.Options != nil {
		if n := call.Options.NumPredict; n != nil {
			if *n < 1 || *n > max {
				return nil, 0, &protocolInputError{reason: "output_budget", status: 403}
			}
			predict = *n
		}
		if n := call.Options.NumCtx; n != nil {
			if *n < 512 || *n > 4096 {
				return nil, 0, &protocolInputError{reason: "context_budget", status: 403}
			}
			contextTokens = *n
		}
	}
	// Always materialize finite limits; absent/null optional input cannot select
	// Ollama's unlimited defaults. keep_alive=0 is a service request, not a claim
	// that another process securely erases memory or cannot retain prompts.
	call.Options = &ollamaOptions{NumPredict: &predict, NumCtx: &contextTokens}
	normalized, err := json.Marshal(call)
	return normalized, predict, err
}

type protocolInputError struct {
	reason string
	status int
}

func (e *protocolInputError) Error() string { return e.reason }

// Native Ollama is deliberately distinct from the OpenAI compatibility API.
// No model management, cloud discovery, tools, media or unlimited prediction.
func (s *Server) ollamaRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, data []byte) {
	const op = "/api/chat"
	if s.model == nil || s.cfg.Model.ProtocolName() != ProtocolOllama {
		s.deny(w, r, "model", "model_protocol_not_granted", 403)
		return
	}
	data, predict, err := NormalizeOllamaChat(data, s.cfg.Model.Name, s.cfg.Model.MaxOutputTokens)
	if err != nil {
		reason, status := "invalid_ollama_request", 400
		if e, ok := err.(*protocolInputError); ok {
			reason, status = e.reason, e.status
		}
		s.deny(w, r, op, reason, status)
		return
	}
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
		return validateOllamaResponse(data, s.cfg.Model.Name, predict)
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
