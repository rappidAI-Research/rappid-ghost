package provenance

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

func WriteJSON(output io.Writer, graph Graph) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(graph)
}

func WriteText(output io.Writer, graph Graph) {
	fmt.Fprintln(output, "Ghost Provenance Graph")
	fmt.Fprintln(output)
	fmt.Fprintf(output, "Session:   %s\n", graph.Session.ID)
	fmt.Fprintf(output, "Status:    %s\n", graph.Session.Status)
	fmt.Fprintf(output, "Contained: %t\n", graph.Session.Contained)
	fmt.Fprintf(output, "Schema:    v%d\n", graph.Version)
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Relationships are reconstructed from runtime evidence; FOLLOWED_BY means temporal order, not causality.")
	fmt.Fprintln(output, "Process nodes represent the command scope; exact guest PID attribution is unavailable.")

	nodes := make(map[string]Node, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	observed := edgesAtLevel(graph.Edges, Observed)
	derived := edgesAtLevel(graph.Edges, Derived)
	writeRelationships(output, "Observed relationships", observed, nodes)
	writeRelationships(output, "Derived temporal relationships", derived, nodes)
}

func edgesAtLevel(edges []Edge, level EvidenceLevel) []Edge {
	result := make([]Edge, 0)
	for _, edge := range edges {
		if edge.Level == level {
			result = append(result, edge)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left := firstEvidence(result[i].Evidence)
		right := firstEvidence(result[j].Evidence)
		if left != right {
			return left < right
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func writeRelationships(output io.Writer, title string, edges []Edge, nodes map[string]Node) {
	fmt.Fprintln(output)
	fmt.Fprintln(output, title)
	if len(edges) == 0 {
		fmt.Fprintln(output, "  none")
		return
	}
	for _, edge := range edges {
		from, fromOK := nodes[edge.From]
		to, toOK := nodes[edge.To]
		if !fromOK || !toOK {
			continue
		}
		fmt.Fprintf(output, "  %s --%s--> %s  [%s]\n", describeNode(from), edge.Type, describeNode(to), evidenceText(edge.Evidence))
	}
}

func describeNode(node Node) string {
	return "[" + strings.ToLower(string(node.Type)) + "] " + node.Label
}

func evidenceText(values []int64) string {
	if len(values) == 0 {
		return "no event ID"
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.FormatInt(value, 10)
	}
	if len(parts) == 1 {
		return "event " + parts[0]
	}
	return "events " + strings.Join(parts, ", ")
}

func firstEvidence(values []int64) int64 {
	if len(values) == 0 {
		return int64(^uint64(0) >> 1)
	}
	return values[0]
}
