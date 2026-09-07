package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

type securitySummary struct {
	UntrustedSources  int
	SuspiciousSources int
	ShadowAccesses    int
	NetworkDenials    int
	ApprovalRequests  int
	ApprovalsGranted  int
	ApprovalsDenied   int
	ResourceLimits    int
	PolicyViolations  int
	Contained         bool
}

func summarizeSecurity(value session.Session, storedEvents []events.Event) securitySummary {
	var summary securitySummary
	untrusted := make(map[string]bool)
	sources := make(map[string]bool)
	for _, event := range storedEvents {
		if event.SessionID != "" && event.SessionID != value.ID {
			continue
		}
		switch event.Type {
		case events.UntrustedContentObserved:
			if event.Resource != "" {
				untrusted[event.Resource] = true
			}
		case events.PromptInjectionSuspected:
			if event.Resource != "" {
				sources[event.Resource] = true
			}
		case events.DecoyAccess:
			summary.ShadowAccesses++
		case events.NetworkDeny:
			summary.NetworkDenials++
		case events.ApprovalRequired:
			summary.ApprovalRequests++
		case events.ApprovalGranted:
			summary.ApprovalsGranted++
		case events.ApprovalDenied, events.ApprovalUnavailable, events.ApprovalExpired:
			summary.ApprovalsDenied++
		case events.ResourceLimitTriggered:
			summary.ResourceLimits++
		case events.PolicyViolation:
			summary.PolicyViolations++
		}
	}
	summary.UntrustedSources = len(untrusted)
	summary.SuspiciousSources = len(sources)
	summary.Contained = value.IsContained()
	return summary
}

func (s securitySummary) relevant() bool {
	return s.SuspiciousSources > 0 || s.ShadowAccesses > 0 || s.NetworkDenials > 0 ||
		s.ApprovalRequests > 0 || s.ApprovalsGranted > 0 || s.ApprovalsDenied > 0 ||
		s.ResourceLimits > 0 || s.PolicyViolations > 0 || s.Contained
}

func writeRunSummary(output io.Writer, value session.Session, storedEvents []events.Event) {
	security := summarizeSecurity(value, storedEvents)
	if !security.relevant() {
		fmt.Fprintln(output, "No security actions required.")
		return
	}

	fmt.Fprintln(output)
	fmt.Fprintln(output, "Security")
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if security.SuspiciousSources > 0 {
		fmt.Fprintf(writer, "Suspicious instruction sources\t%d\n", security.SuspiciousSources)
	}
	if security.ShadowAccesses > 0 {
		fmt.Fprintf(writer, "SHADOW resources accessed\t%d\n", security.ShadowAccesses)
	}
	if security.NetworkDenials > 0 {
		fmt.Fprintf(writer, "Network requests blocked\t%d\n", security.NetworkDenials)
	}
	if security.ApprovalRequests > 0 || security.ApprovalsGranted > 0 || security.ApprovalsDenied > 0 {
		fmt.Fprintf(writer, "Approval requests\t%d\n", security.ApprovalRequests)
		fmt.Fprintf(writer, "Approved / denied\t%d / %d\n", security.ApprovalsGranted, security.ApprovalsDenied)
	}
	if security.ResourceLimits > 0 {
		fmt.Fprintf(writer, "Inspection or resource limits reported\t%d\n", security.ResourceLimits)
	}
	if security.PolicyViolations > 0 {
		fmt.Fprintf(writer, "Policy violations recorded\t%d\n", security.PolicyViolations)
	}
	if security.Contained {
		fmt.Fprintln(writer, "Session contained\tyes")
	}
	_ = writer.Flush()
	if value.Runtime == "docker" {
		fmt.Fprintln(output, "Host home mounted or host environment inherited: no")
	}
}
