package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

func WriteJSON(output io.Writer, report Report) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func WriteText(output io.Writer, report Report) {
	fmt.Fprintln(output, "GhostBench")
	fmt.Fprintln(output)
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	for _, result := range report.Results {
		fmt.Fprintf(table, "%s\t%s\n", result.Name, result.Status)
		if len(report.Results) > 1 && result.Status != Pass {
			fmt.Fprintf(table, "  %s\t\n", result.Detail)
		}
	}
	_ = table.Flush()
	if len(report.Results) == 1 {
		result := report.Results[0]
		fmt.Fprintln(output)
		fmt.Fprintf(output, "Property:    %s\n", result.Property)
		fmt.Fprintf(output, "Observation: %s\n", result.Detail)
		if len(result.Evidence) > 0 {
			fmt.Fprintln(output, "Evidence references:")
			for _, evidence := range result.Evidence {
				fmt.Fprintf(output, "  Session %s — %d events, %d incidents, %d graph nodes, %d graph edges\n",
					evidence.SessionID, len(evidence.EventIDs), len(evidence.IncidentIDs),
					len(evidence.ProvenanceNodeIDs), len(evidence.ProvenanceEdgeIDs))
			}
		}
	}
	fmt.Fprintln(output)
	fmt.Fprintf(output, "%d passed\n%d failed\n%d skipped\n",
		report.Summary.Passed, report.Summary.Failed, report.Summary.Skipped)
}
