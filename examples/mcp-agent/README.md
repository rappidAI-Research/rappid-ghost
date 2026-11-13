# Official MCP SDK guest agent

This example uses official Go MCP SDK 1.8.0 and the 2026-07-28 stateless protocol.
Build the guest executable from the repository:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /path/to/staged-project/mcp-agent ./examples/mcp-agent
```

Use `agent.adapter: command`, `runtime.environment: alpine`, a read-only workspace
and the explicitly configured application broker from
[the synthetic enterprise example](../enterprise/README.md), granting only case_A.
Then `ghost run /workspace/mcp-agent` discovers the registered read tool, reads
case_A and verifies that a foreign resource is denied. The same executable/workflow
runs in Docker in `TestDockerOfficialMCPClientCannotBypassScope`.
No real personal data, database passwords or user tokens belong in the staged project.
