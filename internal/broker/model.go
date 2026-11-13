package broker

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
)

func (s *Server) modelRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, data []byte) {
	op := r.URL.Path
	if s.model == nil {
		s.deny(w, r, "model", "model_not_configured", 403)
		return
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(data, &body) != nil {
		s.deny(w, r, op, "invalid_model_request", 400)
		return
	}
	allowed := strings.Fields("model input messages instructions tools tool_choice parallel_tool_calls store stream reasoning text include previous_response_id max_output_tokens max_tokens temperature top_p prompt_cache_key safety_identifier service_tier truncation stream_options client_metadata prompt_cache_options access_programs")
	for key := range body {
		known := false
		for _, v := range allowed {
			known = known || v == key
		}
		if !known {
			s.deny(w, r, op, "unsupported_model_field", 400)
			return
		}
	}
	// Do not let an ignored field from the other API select an alternate
	// input representation or bypass the text-only content validator.
	if op == "/v1/responses" && len(body["messages"]) > 0 || op == "/v1/chat/completions" && len(body["input"]) > 0 {
		s.deny(w, r, op, "ambiguous_model_input", 400)
		return
	}
	// Codex emits advisory client/cache metadata. It is neither authorization nor
	// necessary for stateless inference; do not share caller cache/session keys.
	delete(body, "client_metadata")
	delete(body, "prompt_cache_key")
	delete(body, "prompt_cache_options")
	if v := body["access_programs"]; len(v) > 0 && string(v) != "null" {
		s.deny(w, r, op, "unsupported_access_program", 403)
		return
	}
	delete(body, "access_programs")
	var model string
	if json.Unmarshal(body["model"], &model) != nil || model != s.cfg.Model.Name {
		s.deny(w, r, op, "model_not_granted", 403)
		return
	}
	if !localModelInput(body) || !textOnly(body["input"]) || !textOnly(body["messages"]) {
		s.deny(w, r, op, "remote_model_input_denied", 403)
		return
	}
	if !localToolDefinitions(body["tools"]) || !localToolChoice(body["tool_choice"]) {
		s.deny(w, r, op, "server_tools_denied", 403)
		return
	}
	if len(body["previous_response_id"]) > 0 {
		s.deny(w, r, op, "remote_history_denied", 403)
		return
	}
	{
		if v := body["store"]; len(v) > 0 && string(v) != "false" {
			s.deny(w, r, op, "remote_storage_denied", 403)
			return
		}
		body["store"] = json.RawMessage("false")
	}
	max := s.cfg.Model.MaxOutputTokens
	if max == 0 {
		max = 4096
	}
	field := "max_output_tokens"
	if op == "/v1/chat/completions" {
		field = "max_tokens"
	}
	other := "max_tokens"
	if field == "max_tokens" {
		other = "max_output_tokens"
	}
	if len(body[other]) > 0 {
		s.deny(w, r, op, "conflicting_output_budget", 400)
		return
	}
	if v := body[field]; len(v) > 0 {
		var n int
		if json.Unmarshal(v, &n) != nil || n < 1 || n > max {
			s.deny(w, r, op, "output_budget", 403)
			return
		}
	} else {
		body[field], _ = json.Marshal(max)
	}
	data, _ = json.Marshal(body)
	if s.audit(ctx, "admission", op, "explicit_model_grant") != nil {
		http.Error(w, "broker audit unavailable", 503)
		return
	}
	response, err := s.forward(ctx, s.model, op, data)
	if err != nil {
		s.deny(w, r, op, "upstream_unavailable", 502)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		s.deny(w, r, op, "upstream_rejected", 502)
		return
	}
	kind, _, mimeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mimeErr != nil || (kind != "application/json" && kind != "text/event-stream") {
		s.deny(w, r, op, "unsupported_response_type", 502)
		return
	}
	if s.check(ctx) != nil {
		s.deny(w, r, op, "inactive_or_contained", 403)
		return
	}
	if kind == "application/json" {
		data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
		if err != nil || len(data) > MaxResponseBytes || validJSON(data) != nil {
			s.deny(w, r, op, "invalid_model_response", 502)
			return
		}
		if s.check(ctx) != nil {
			s.deny(w, r, op, "inactive_or_contained", 403)
			return
		}
		if s.audit(ctx, "completion", op, "completed") != nil {
			http.Error(w, "broker audit unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", kind)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
		return
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Cache-Control", "no-store")
	// Bound streamed bytes and propagate backpressure/cancellation. Buffered
	// JSON tools use a separate path so no partial tool result is released.
	buffer := make([]byte, 16*1024)
	remaining := int64(MaxResponseBytes)
	for {
		if ctx.Err() != nil || s.check(ctx) != nil {
			return
		}
		n, readErr := response.Body.Read(buffer)
		if int64(n) > remaining {
			s.fail(errResponseLimit)
			return
		}
		remaining -= int64(n)
		if n > 0 {
			if _, err := w.Write(buffer[:n]); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if readErr == io.EOF {
			_ = s.audit(ctx, "completion", op, "completed")
			return
		}
		if readErr != nil {
			return
		}
	}
}

func textOnly(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			if typ, ok := x["type"].(string); ok {
				switch typ {
				case "input_image", "image_url", "input_file", "input_audio", "audio", "file_search", "web_search", "web_search_preview", "computer", "computer_use_preview", "mcp", "image_generation":
					return false
				}
			}
			for k, v := range x {
				if k == "image_url" || k == "file_url" || k == "audio_url" || k == "server_url" {
					return false
				}
				if !walk(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !walk(v) {
					return false
				}
			}
		}
		return true
	}
	return walk(value)
}

// Only client-executed function/custom definitions may be sent to the model.
// Native server tools (web, files, hosted MCP, future unknown types) are denied.
func localToolDefinitions(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var tools []map[string]json.RawMessage
	if json.Unmarshal(raw, &tools) != nil || len(tools) > 128 {
		return false
	}
	for _, tool := range tools {
		var typ string
		if json.Unmarshal(tool["type"], &typ) != nil {
			return false
		}
		switch typ {
		case "function", "custom":
		case "tool_search":
			var execution string
			if json.Unmarshal(tool["execution"], &execution) != nil || execution != "client" {
				return false
			}
		case "namespace":
			if !localToolDefinitions(tool["tools"]) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// No provider-side item references or unknown future remote-input types. Local
// function outputs are text, not an instruction for the broker to fetch a URL.
func localModelInput(body map[string]json.RawMessage) bool {
	if raw := body["input"]; len(raw) > 0 {
		var text string
		if string(raw) == "null" {
			return false
		}
		if json.Unmarshal(raw, &text) != nil {
			var items []map[string]json.RawMessage
			if json.Unmarshal(raw, &items) != nil {
				return false
			}
			for _, item := range items {
				var typ string
				_ = json.Unmarshal(item["type"], &typ)
				switch typ {
				case "", "message":
					if !textContent(item["content"], false) {
						return false
					}
				case "function_call", "custom_tool_call", "reasoning":
				case "tool_search_call", "tool_search_output":
					var execution string
					if json.Unmarshal(item["execution"], &execution) != nil || execution != "client" {
						return false
					}
				case "function_call_output", "custom_tool_call_output":
					if !textContent(item["output"], false) {
						return false
					}
				default:
					return false
				}
			}
		}
	}
	if raw := body["messages"]; len(raw) > 0 {
		var messages []map[string]json.RawMessage
		if json.Unmarshal(raw, &messages) != nil {
			return false
		}
		for _, message := range messages {
			if !textContent(message["content"], true) {
				return false
			}
		}
	}
	return true
}
func textContent(raw json.RawMessage, allowNull bool) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return allowNull
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return true
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) != nil {
		return false
	}
	for _, part := range parts {
		var typ string
		_ = json.Unmarshal(part["type"], &typ)
		switch typ {
		case "text", "input_text", "output_text", "refusal":
		default:
			return false
		}
	}
	return true
}

// Tool selection cannot request a hosted tool that is absent from the allowed
// local definitions. Unqualified selector variants fail closed.
func localToolChoice(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var choice string
	if json.Unmarshal(raw, &choice) == nil {
		return choice == "auto" || choice == "none" || choice == "required"
	}
	var selector struct {
		Type      string `json:"type"`
		Name      string `json:"name"`
		Namespace string `json:"namespace,omitempty"`
	}
	if decodeStrict(raw, &selector) != nil {
		return false
	}
	return (selector.Type == "function" || selector.Type == "custom") && len(selector.Name) > 0 && len(selector.Name) <= 128 && len(selector.Namespace) <= 128
}
