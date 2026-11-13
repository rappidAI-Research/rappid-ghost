package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Qualify the restricted transport against an independent, pinned official SDK,
// not against a Ghost client that could share the same protocol mistakes.
func TestOfficialMCPSDKDiscoveryListCallAndDeniedResource(t *testing.T) {
	f := setup(t, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = "ghost-broker"; f.s.ServeHTTP(w, r) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "ghost-qualification", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: MCPVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "documents.read" {
		t.Fatalf("SDK list tools=%+v error=%v", tools, err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "documents.read", Arguments: map[string]string{"record_id": "case_A"}})
	if err != nil || result.IsError || len(result.Content) != 1 {
		t.Fatalf("SDK call result=%+v error=%v", result, err)
	}
	if _, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "documents.read", Arguments: map[string]string{"record_id": "case_B"}}); err == nil {
		t.Fatal("SDK foreign resource accepted")
	}
	if f.calls.Load() != 1 {
		t.Fatal("denied MCP request reached app")
	}
}
func mcpBody(id, method, name, args string) string {
	params := map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": MCPVersion, "io.modelcontextprotocol/clientInfo": map[string]string{"name": "test", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}
	if name != "" {
		params["name"] = name
		var arguments any
		_ = json.Unmarshal([]byte(args), &arguments)
		params["arguments"] = arguments
	}
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "method": method, "params": params})
	return string(data)
}
func mcpRequestForTest(s *Server, body, method, name, version string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	r.Host = "ghost-broker"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", version)
	r.Header.Set("Mcp-Method", method)
	if name != "" {
		r.Header.Set("Mcp-Name", name)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestMCPReplayMetadataAndVersionFailClosed(t *testing.T) {
	f := setup(t, nil)
	body := mcpBody("7", "tools/call", "documents.read", `{"record_id":"case_A"}`)
	first := mcpRequestForTest(f.s, body, "tools/call", "documents.read", MCPVersion)
	if first.Code != 200 {
		t.Fatalf("%d %s", first.Code, first.Body.String())
	}
	for _, tc := range []struct {
		body, method, name, version string
		status                      int
		code                        int
	}{
		{body, "tools/call", "documents.read", MCPVersion, 409, -32602},
		{body, "tools/call", "documents.delete", MCPVersion, 400, -32020},
		{body, "tools/call", "documents.read", "2025-11-25", 400, -32022},
		{mcpBody("8", "resources/read", "", ""), "resources/read", "", MCPVersion, 404, -32601},
	} {
		result := mcpRequestForTest(f.s, tc.body, tc.method, tc.name, tc.version)
		var envelope struct {
			ID    int `json:"id"`
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(result.Body.Bytes(), &envelope)
		if result.Code != tc.status || envelope.Error.Code != tc.code || envelope.ID == 0 {
			t.Fatalf("got %d %s", result.Code, result.Body.String())
		}
	}
	if f.calls.Load() != 1 {
		t.Fatal("MCP denial bypass")
	}
}
