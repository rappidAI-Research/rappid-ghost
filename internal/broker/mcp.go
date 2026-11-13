package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type mcpIDKey struct{}

func validMCPID(id json.RawMessage) bool {
	var name string
	if json.Unmarshal(id, &name) == nil {
		return len(name) > 0 && len(name) <= 128
	}
	n, err := strconv.ParseUint(string(id), 10, 53)
	return err == nil && n <= 9007199254740991
}

const MCPVersion = "2026-07-28"

type mcpMeta struct {
	Protocol   string `json:"io.modelcontextprotocol/protocolVersion"`
	ClientInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"io.modelcontextprotocol/clientInfo"`
	Capabilities map[string]json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
}

func (s *Server) mcpRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, data []byte) {
	if r.Header.Get("MCP-Protocol-Version") != MCPVersion {
		s.deny(w, r, "mcp", "unsupported_mcp_version", 400)
		return
	}
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		s.deny(w, r, "mcp", "mcp_accept_required", 406)
		return
	}
	var wire struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if decodeStrict(data, &wire) != nil || wire.JSONRPC != "2.0" || !validMCPID(wire.ID) || r.Header.Get("Mcp-Method") != wire.Method || r.Header.Get("MCP-Protocol-Version") != MCPVersion {
		s.deny(w, r, "mcp", "unsupported_mcp_envelope", 400)
		return
	}
	// Deliberately restricted stateless MCP 2026 tools/discovery subset. Older
	// handshake sessions, notifications, writes, subscriptions and MRTR are not
	// silently accepted or forwarded to a privileged upstream server.
	var params struct {
		Name      string                     `json:"name,omitempty"`
		Arguments map[string]json.RawMessage `json:"arguments,omitempty"`
		Meta      mcpMeta                    `json:"_meta"`
	}
	if decodeStrict(wire.Params, &params) != nil || params.Meta.Protocol != MCPVersion || params.Meta.ClientInfo.Name == "" || params.Meta.ClientInfo.Version == "" || params.Meta.Capabilities == nil || r.Header.Get("Mcp-Name") != params.Name {
		s.deny(w, r, "mcp", "mcp_metadata_mismatch", 400)
		return
	}
	var result map[string]any
	switch wire.Method {
	case "server/discover":
		if params.Name != "" || len(params.Arguments) > 0 {
			s.deny(w, r, "mcp", "invalid_discovery", 400)
			return
		}
		result = map[string]any{"resultType": "complete", "supportedVersions": []string{MCPVersion}, "capabilities": map[string]any{"tools": map[string]bool{"listChanged": false}}}
	case "tools/list":
		if s.app == nil || params.Name != "" || len(params.Arguments) > 0 {
			s.deny(w, r, "mcp", "tools_unavailable", 403)
			return
		}
		tools := make([]any, 0, len(s.cfg.Tools))
		for _, t := range s.cfg.Tools {
			props := map[string]any{}
			required := make([]string, 0, len(t.Parameters))
			for k, typ := range t.Parameters {
				props[k] = map[string]string{"type": typ}
				required = append(required, k)
			}
			sort.Strings(required)
			tools = append(tools, map[string]any{"name": t.Name, "inputSchema": map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}})
		}
		result = map[string]any{"resultType": "complete", "tools": tools}
	case "tools/call":
		sum := sha256.Sum256(wire.ID)
		idString := "mcp_" + hex.EncodeToString(sum[:24])
		value, reason, status := s.callTool(ctx, toolCall{ID: idString, Name: params.Name, Arguments: params.Arguments})
		if status != 200 {
			s.deny(w, r, "mcp", reason, status)
			return
		}
		result = map[string]any{"resultType": "complete", "isError": false, "content": []any{map[string]string{"type": "text", "text": string(value)}}}
	default:
		s.deny(w, r, "mcp", "unsupported_mcp_method", 403)
		return
	}
	if wire.Method != "tools/call" && s.audit(ctx, "completion", wire.Method, "completed") != nil {
		http.Error(w, "broker audit unavailable", 503)
		return
	}
	result["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": map[string]string{"name": "ghost-read-tool-broker", "version": "0.5.0"}}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": wire.ID, "result": result})
}
