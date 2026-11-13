// A static, dependency-pinned guest agent using the official MCP SDK. All data
// is synthetic. The application, not this client, owns employee authorization.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "MCP workflow failed:", err)
		os.Exit(1)
	}
}
func run(ctx context.Context) error {
	base := os.Getenv("GHOST_BROKER_URL")
	if base == "" {
		return fmt.Errorf("run this agent through Ghost with an explicit application broker")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "ghost-synthetic-agent", Version: "0.5.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: base + "/mcp", MaxRetries: -1, DisableStandaloneSSE: true}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		return err
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return err
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "documents.read" {
		return fmt.Errorf("expected explicitly registered documents.read tool")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "documents.read", Arguments: map[string]string{"record_id": "case_A"}})
	if err != nil {
		return err
	}
	if result.IsError || len(result.Content) == 0 {
		return fmt.Errorf("application did not provide a result")
	}
	// A document or model can ask for this, but cannot authorize it.
	if _, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "documents.read", Arguments: map[string]string{"record_id": "tenant_B_case_C"}}); err == nil {
		return fmt.Errorf("foreign resource was accepted")
	}
	fmt.Println("MCP_SCOPE_OK: case_A read; foreign record denied")
	return nil
}
