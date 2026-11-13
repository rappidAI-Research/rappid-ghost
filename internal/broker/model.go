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
	allowed := strings.Fields("model input messages instructions tools tool_choice parallel_tool_calls store stream reasoning text include previous_response_id max_output_tokens max_tokens temperature top_p prompt_cache_key safety_identifier service_tier truncation stream_options context_management")
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
	var model string
	if json.Unmarshal(body["model"], &model) != nil || model != s.cfg.Model.Name {
		s.deny(w, r, op, "model_not_granted", 403)
		return
	}
	if !textOnly(data) || !localToolDefinitions(body["tools"]) || len(body["previous_response_id"]) > 0 {
		s.deny(w, r, op, "remote_resources_or_server_tools_denied", 403)
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
