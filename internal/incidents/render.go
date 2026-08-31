package incidents

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func WriteJSON(output io.Writer, report Report) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func WriteText(output io.Writer, report Report) {
	fmt.Fprintln(output, "Ghost Incidents")
	fmt.Fprintln(output)
	fmt.Fprintf(output, "Session: %s\n", report.Session.ID)
	fmt.Fprintf(output, "Status:  %s\n", report.Session.Status)
	fmt.Fprintf(output, "Schema:  v%d\n", report.Version)
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Incidents are reconstructed from stored evidence. Temporal order does not prove causality or intent.")
	if len(report.Incidents) == 0 {
		fmt.Fprintln(output)
		fmt.Fprintln(output, "No security incidents reconstructed.")
		return
	}
	for index, incident := range report.Incidents {
		fmt.Fprintln(output)
		fmt.Fprintf(output, "Incident %d\n", index+1)
		fmt.Fprintf(output, "ID:       %s\n", incident.ID)
		fmt.Fprintf(output, "Severity: %s\n", incident.Severity)
		fmt.Fprintf(output, "Severity evidence: %s\n", evidenceText(incident.SeverityEvidence))
		fmt.Fprintf(output, "Type:     %s\n", incident.Type)
		fmt.Fprintf(output, "Summary:  %s\n", incident.Summary)
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Timeline")
		for _, statement := range incident.Timeline {
			fmt.Fprintf(output, "  %s  %-23s  %s  [%s; %s]\n",
				statement.Timestamp.UTC().Format("15:04:05.000"), statement.Type, statement.Text,
				statement.Level, evidenceText(statement.EvidenceEventIDs))
		}
		fmt.Fprintln(output)
		fmt.Fprintf(output, "Evidence: %d events, %d provenance relationships\n",
			len(incident.EvidenceEventIDs), len(incident.RelevantEdges))
		if incident.ContainmentAction != nil {
			fmt.Fprintf(output, "Containment: %s at %s [%s]\n", incident.ContainmentAction.Action,
				incident.ContainmentAction.ActivatedAt.UTC().Format("15:04:05.000"),
				evidenceText(incident.ContainmentAction.EvidenceEventIDs))
		}
	}
}

func evidenceText(values []int64) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.FormatInt(value, 10)
	}
	if len(parts) == 1 {
		return "event " + parts[0]
	}
	return "events " + strings.Join(parts, ", ")
}
