package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type toolCall struct {
	ID        string                     `json:"id"`
	Name      string                     `json:"name"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

var errResponseLimit = errors.New("broker response byte budget exhausted")

func (s *Server) callTool(ctx context.Context, call toolCall) (json.RawMessage, string, int) {
	if s.app == nil {
		return nil, "application_not_configured", 403
	}
	if !namePattern.MatchString(call.ID) {
		return nil, "invalid_request_id", 400
	}
	var found *Tool
	for i := range s.cfg.Tools {
		if s.cfg.Tools[i].Name == call.Name {
			found = &s.cfg.Tools[i]
			break
		}
	}
	if found == nil {
		return nil, "unregistered_tool", 403
	}
	if len(call.Arguments) != len(found.Parameters) {
		return nil, "invalid_tool_schema", 400
	}
	for key, typ := range found.Parameters {
		raw, ok := call.Arguments[key]
		if !ok {
			return nil, "invalid_tool_schema", 400
		}
		switch typ {
		case "string":
			var v string
			if json.Unmarshal(raw, &v) != nil || len(v) > 1024 {
				return nil, "invalid_tool_schema", 400
			}
		case "integer":
			var v int64
			if json.Unmarshal(raw, &v) != nil || v < -10000 || v > 10000 {
				return nil, "invalid_tool_schema", 400
			}
		case "boolean":
			var v bool
			if json.Unmarshal(raw, &v) != nil {
				return nil, "invalid_tool_schema", 400
			}
		}
	}
	var resource string
	_ = json.Unmarshal(call.Arguments[found.ResourceArgument], &resource)
	allowed := false
	for _, v := range found.Resources {
		allowed = allowed || v == resource
	}
	if !allowed {
		return nil, "resource_not_granted", 403
	}
	s.mu.Lock()
	seen := s.replay[call.ID]
	if !seen {
		s.replay[call.ID] = true
	}
	s.mu.Unlock()
	if seen {
		return nil, "replayed_request", 409
	}
	if s.check(ctx) != nil {
		return nil, "inactive_or_contained", 403
	}
	if s.audit(ctx, "admission", found.Name, "explicit_tool_resource_grant") != nil {
		return nil, "audit_unavailable", 503
	}
	// IDs forwarded to the trusted application are host-generated, not a tenant
	// identity or arbitrary caller metadata. The application authenticates its
	// credential and reauthorizes every resource operation itself.
	outbound := map[string]any{"id": newID(), "name": found.Name, "arguments": call.Arguments}
	data, _ := json.Marshal(outbound)
	response, err := s.forward(ctx, s.app, "/ghost/tools/call", data)
	if err != nil {
		return nil, "upstream_unavailable", 502
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return nil, "application_authorization_denied", 403
	}
	if response.StatusCode != 200 {
		return nil, "application_rejected", 502
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, MaxRequestBytes+1))
	if err != nil || len(data) > MaxRequestBytes || validJSON(data) != nil {
		return nil, "invalid_application_response", 502
	}
	if s.check(ctx) != nil {
		return nil, "inactive_or_contained", 403
	}
	if s.audit(ctx, "completion", found.Name, "completed") != nil {
		return nil, "audit_unavailable", 503
	}
	return data, "", 200
}
func (s *Server) toolRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, data []byte) {
	var call toolCall
	if decodeStrict(data, &call) != nil {
		s.deny(w, r, "tool", "invalid_tool_schema", 400)
		return
	}
	result, reason, status := s.callTool(ctx, call)
	if status != 200 {
		s.deny(w, r, "tool", reason, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(result)
}
