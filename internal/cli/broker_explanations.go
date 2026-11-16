package cli

import (
	"fmt"
	"io"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
)

// Closed explanations only. Unknown event metadata is never rendered as an
// explanation, URL, credential, tool argument or model-supplied instruction.
func brokerExplanation(reason string) string {
	switch reason {
	case "resource_not_granted":
		return "Resource absent from the explicit grant; review the trusted application's assigned resources."
	case "application_authorization_denied":
		return "Application refused current identity/resource access; check assignment or revocation in the application."
	case "unregistered_tool", "unregistered_route", "unsupported_mcp_method":
		return "Operation is outside the registered read-tool/model contract."
	case "invalid_tool_schema", "invalid_request", "invalid_body", "mcp_metadata_mismatch":
		return "Message does not match the registered input contract; correct the client parameters."
	case "replayed_request":
		return "Request ID was already consumed in this session; do not retry an uncertain operation blindly."
	case "tool_call_budget", "request_budget", "rate_limit", "concurrency_limit":
		return "A configured call/rate/concurrency ceiling was reached; reduce the workflow's requests."
	case "inactive_or_contained", "containment_fence":
		return "Session expired, ended or was contained; inspect session evidence before starting another run."
	case "upstream_unavailable", "upstream_rejected", "application_rejected":
		return "The fixed service failed, timed out or rejected the request; check its identity, health and contract."
	case "invalid_application_response", "invalid_model_response", "unsupported_response_type":
		return "Service response exceeded or violated the bounded response contract."
	case "model_not_granted", "model_protocol_not_granted":
		return "Model or protocol differs from the explicit model grant; choose a supported configured integration."
	case "audit_unavailable":
		return "Decision evidence could not be persisted; restore storage before further service access."
	default:
		return "Broker rejected an operation; review the versioned contract and trusted configuration."
	}
}

func writeBrokerExplanations(output io.Writer, sessionID string, list []events.Event) {
	count := 0
	for _, event := range list {
		if event.Type != events.BrokerDenied || event.SessionID != sessionID {
			continue
		}
		if count == 0 {
			fmt.Fprintln(output, "\nBlocked model/tool operations")
		}
		if count == 20 {
			fmt.Fprintln(output, "Additional denials are represented in the session graph; display limited to 20.")
			break
		}
		reason, _ := event.Metadata["reason"].(string)
		fmt.Fprintf(output, "  Event %d: %s\n", event.ID, brokerExplanation(reason))
		count++
	}
}
