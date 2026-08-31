package incidents

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

type reconstructor struct {
	report            Report
	graph             provenance.Graph
	ordered           []events.Event
	eventOrder        map[int64]int
	nodes             map[string]provenance.Node
	incidents         []*Incident
	decoyIncidents    map[string]*Incident
	shadowByDecoy     map[string]events.Event
	pendingRequests   map[string]events.Event
	containedIncident *Incident
	latestDecoy       *Incident
	severityRecorded  map[*Incident]bool
}

// Reconstruct builds incidents from one session's persisted events and the
// provenance graph reconstructed from those same events. Foreign-session and
// untraceable events are ignored.
func Reconstruct(value session.Session, input []events.Event) Report {
	ordered := orderedEvents(value.ID, input)
	graph := provenance.Build(value, ordered)
	r := &reconstructor{
		report: Report{
			Version: SchemaVersion,
			Session: graph.Session,
		},
		graph:            graph,
		ordered:          ordered,
		eventOrder:       make(map[int64]int, len(ordered)),
		nodes:            make(map[string]provenance.Node, len(graph.Nodes)),
		decoyIncidents:   make(map[string]*Incident),
		shadowByDecoy:    make(map[string]events.Event),
		pendingRequests:  make(map[string]events.Event),
		severityRecorded: make(map[*Incident]bool),
	}
	for index, event := range ordered {
		r.eventOrder[event.ID] = index
	}
	for _, node := range graph.Nodes {
		r.nodes[node.ID] = node
	}
	for _, event := range ordered {
		r.consume(event)
	}
	return r.finish()
}

func orderedEvents(sessionID string, input []events.Event) []events.Event {
	ordered := make([]events.Event, 0, len(input))
	for _, event := range input {
		if event.SessionID == sessionID && event.ID > 0 {
			ordered = append(ordered, event)
		}
	}
	sort.SliceStable(ordered, func(left, right int) bool {
		if !ordered[left].Timestamp.Equal(ordered[right].Timestamp) {
			return ordered[left].Timestamp.Before(ordered[right].Timestamp)
		}
		if ordered[left].ID != ordered[right].ID {
			return ordered[left].ID < ordered[right].ID
		}
		if ordered[left].Type != ordered[right].Type {
			return ordered[left].Type < ordered[right].Type
		}
		return ordered[left].Resource < ordered[right].Resource
	})
	// SQLite event IDs are stable evidence identities. Ignore repeated copies of
	// the same row so callers cannot manufacture duplicate incident steps.
	seen := make(map[int64]bool, len(ordered))
	result := ordered[:0]
	for _, event := range ordered {
		if seen[event.ID] {
			continue
		}
		seen[event.ID] = true
		result = append(result, event)
	}
	return result
}

func (r *reconstructor) consume(event events.Event) {
	switch event.Type {
	case events.PolicyShadow:
		if decoyID, _ := r.nodeForEvidence(event.ID, provenance.DecoyNode); decoyID != "" {
			if _, exists := r.shadowByDecoy[decoyID]; !exists {
				r.shadowByDecoy[decoyID] = event
			}
		}
	case events.DecoyAccess:
		r.consumeDecoyAccess(event)
	case events.SecurityIncident:
		r.consumeRecordedIncident(event)
	case events.ContainmentActivated:
		r.consumeContainment(event)
	case events.NetworkRequest:
		if networkID, _ := r.nodeForEvidence(event.ID, provenance.NetworkDestinationNode); networkID != "" {
			r.pendingRequests[networkID] = event
		}
	case events.NetworkDeny:
		r.consumeNetworkDeny(event)
	}
}

func (r *reconstructor) consumeDecoyAccess(event events.Event) {
	decoyID, label := r.nodeForEvidence(event.ID, provenance.DecoyNode)
	if decoyID == "" {
		return
	}
	incident := r.decoyIncidents[decoyID]
	if incident == nil {
		incident = &Incident{
			ID:               stableID("incident", r.report.Session.ID+"\x00decoy\x00"+decoyID),
			SessionID:        r.report.Session.ID,
			Type:             DecoyAccess,
			Severity:         High,
			SeverityEvidence: []int64{event.ID},
			Summary:          "Shadow resource " + label + " was accessed.",
		}
		r.decoyIncidents[decoyID] = incident
		r.incidents = append(r.incidents, incident)
		if shadowEvent, ok := r.shadowByDecoy[decoyID]; ok {
			r.addStatement(incident, Statement{
				Type: ShadowExposed, Timestamp: shadowEvent.Timestamp,
				Text:  "Ghost exposed " + label + " as a synthetic Shadow resource.",
				Level: provenance.Observed, EvidenceEventIDs: []int64{shadowEvent.ID},
			})
		}
	}
	accessText := "Ghost observed access to " + label + "."
	if processID, _ := r.nodeForEvidence(event.ID, provenance.ProcessNode); processID != "" {
		accessText = "The command scope accessed " + label + "."
	}
	r.addStatement(incident, Statement{
		Type: DecoyAccessed, Timestamp: event.Timestamp,
		Text:  accessText,
		Level: provenance.Observed, EvidenceEventIDs: []int64{event.ID},
	})
	r.latestDecoy = incident
}

func (r *reconstructor) consumeRecordedIncident(event events.Event) {
	decoyID, _ := r.nodeForEvidence(event.ID, provenance.DecoyNode)
	incident := r.decoyIncidents[decoyID]
	if incident == nil {
		return
	}
	incident.EvidenceEventIDs = appendUnique(incident.EvidenceEventIDs, event.ID)
	if incident.EndedAt.IsZero() || event.Timestamp.After(incident.EndedAt) {
		incident.EndedAt = event.Timestamp
	}
	if severity, ok := severityFromMetadata(event.Metadata); ok {
		if !r.severityRecorded[incident] || severityRank(severity) > severityRank(incident.Severity) {
			incident.Severity = severity
			incident.SeverityEvidence = []int64{event.ID}
			r.severityRecorded[incident] = true
		}
		if incident.Type == DecoyAccessWithNetworkActivity && severityRank(incident.Severity) < severityRank(High) {
			incident.Severity = High
			incident.SeverityEvidence = appendUnique(
				append([]int64(nil), incident.ContainmentAction.EvidenceEventIDs...), event.ID,
			)
		}
	}
}

func (r *reconstructor) consumeContainment(event events.Event) {
	if r.containedIncident != nil {
		r.containedIncident.ContainmentAction.EvidenceEventIDs = appendUnique(
			r.containedIncident.ContainmentAction.EvidenceEventIDs, event.ID,
		)
		r.addStatement(r.containedIncident, Statement{
			Type: ContainmentApplied, Timestamp: event.Timestamp,
			Text:  "Ghost activated session network containment.",
			Level: provenance.Observed, EvidenceEventIDs: []int64{event.ID},
		})
		return
	}
	incident := r.latestDecoy
	if incident == nil {
		incident = &Incident{
			ID:               stableID("incident", r.report.Session.ID+"\x00containment\x00"+eventKey(event)),
			SessionID:        r.report.Session.ID,
			Type:             ContainmentActivated,
			Severity:         Medium,
			SeverityEvidence: []int64{event.ID},
			Summary:          "Session network containment was activated without linked decoy-access evidence.",
		}
		r.incidents = append(r.incidents, incident)
	}
	if incident.ContainmentAction == nil {
		incident.ContainmentAction = &ContainmentAction{
			Action: "NETWORK_DENY", ActivatedAt: event.Timestamp,
			EvidenceEventIDs: []int64{event.ID},
		}
		r.addStatement(incident, Statement{
			Type: ContainmentApplied, Timestamp: event.Timestamp,
			Text:  "Ghost activated session network containment.",
			Level: provenance.Observed, EvidenceEventIDs: []int64{event.ID},
		})
	}
	r.containedIncident = incident
}

func (r *reconstructor) consumeNetworkDeny(event events.Event) {
	networkID, label := r.nodeForEvidence(event.ID, provenance.NetworkDestinationNode)
	if networkID == "" {
		return
	}
	evidence := []int64{}
	if request, ok := r.pendingRequests[networkID]; ok && r.beforeOrEqual(request, event) {
		evidence = append(evidence, request.ID)
		delete(r.pendingRequests, networkID)
	}
	evidence = append(evidence, event.ID)

	incident := r.containedIncident
	if incident != nil && incident.ContainmentAction != nil && !event.Timestamp.Before(incident.ContainmentAction.ActivatedAt) {
		temporalEvidence := append([]int64(nil), incident.ContainmentAction.EvidenceEventIDs...)
		temporalEvidence = append(temporalEvidence, evidence...)
		r.addStatement(incident, Statement{
			Type: NetworkDenied, Timestamp: event.Timestamp,
			Text:  "A later outbound request to " + label + " was denied after containment.",
			Level: provenance.Derived, EvidenceEventIDs: temporalEvidence,
		})
		if incident.Type == DecoyAccess {
			incident.Type = DecoyAccessWithNetworkActivity
			incident.Summary = "A Shadow resource was accessed; later contained network activity was denied."
			if severityRank(incident.Severity) < severityRank(High) {
				incident.Severity = High
				incident.SeverityEvidence = append([]int64(nil), temporalEvidence...)
			}
		}
		return
	}

	incident = &Incident{
		ID:               stableID("incident", r.report.Session.ID+"\x00network-deny\x00"+eventKey(event)),
		SessionID:        r.report.Session.ID,
		Type:             NetworkPolicyViolation,
		Severity:         Medium,
		SeverityEvidence: []int64{event.ID},
		Summary:          "An outbound request to " + label + " was denied by network policy.",
	}
	r.addStatement(incident, Statement{
		Type: NetworkDenied, Timestamp: event.Timestamp,
		Text:  "Ghost denied an outbound request to " + label + ".",
		Level: provenance.Observed, EvidenceEventIDs: evidence,
	})
	r.incidents = append(r.incidents, incident)
}

func (r *reconstructor) beforeOrEqual(left, right events.Event) bool {
	return r.eventOrder[left.ID] <= r.eventOrder[right.ID]
}

func (r *reconstructor) addStatement(incident *Incident, statement Statement) {
	if len(statement.EvidenceEventIDs) == 0 {
		return
	}
	for index := range incident.Timeline {
		if incident.Timeline[index].Type == statement.Type && incident.Timeline[index].Text == statement.Text {
			for _, eventID := range statement.EvidenceEventIDs {
				incident.Timeline[index].EvidenceEventIDs = appendUnique(incident.Timeline[index].EvidenceEventIDs, eventID)
				incident.EvidenceEventIDs = appendUnique(incident.EvidenceEventIDs, eventID)
			}
			if incident.StartedAt.IsZero() || statement.Timestamp.Before(incident.StartedAt) {
				incident.StartedAt = statement.Timestamp
			}
			if incident.EndedAt.IsZero() || statement.Timestamp.After(incident.EndedAt) {
				incident.EndedAt = statement.Timestamp
			}
			return
		}
	}
	statement.EvidenceEventIDs = unique(statement.EvidenceEventIDs)
	incident.Timeline = append(incident.Timeline, statement)
	for _, eventID := range statement.EvidenceEventIDs {
		incident.EvidenceEventIDs = appendUnique(incident.EvidenceEventIDs, eventID)
	}
	if incident.StartedAt.IsZero() || statement.Timestamp.Before(incident.StartedAt) {
		incident.StartedAt = statement.Timestamp
	}
	if incident.EndedAt.IsZero() || statement.Timestamp.After(incident.EndedAt) {
		incident.EndedAt = statement.Timestamp
	}
}

func (r *reconstructor) finish() Report {
	for _, incident := range r.incidents {
		sort.SliceStable(incident.Timeline, func(left, right int) bool {
			if !incident.Timeline[left].Timestamp.Equal(incident.Timeline[right].Timestamp) {
				return incident.Timeline[left].Timestamp.Before(incident.Timeline[right].Timestamp)
			}
			return r.firstOrder(incident.Timeline[left].EvidenceEventIDs) < r.firstOrder(incident.Timeline[right].EvidenceEventIDs)
		})
		sort.SliceStable(incident.EvidenceEventIDs, func(left, right int) bool {
			return r.eventOrder[incident.EvidenceEventIDs[left]] < r.eventOrder[incident.EvidenceEventIDs[right]]
		})
		sort.SliceStable(incident.SeverityEvidence, func(left, right int) bool {
			return r.eventOrder[incident.SeverityEvidence[left]] < r.eventOrder[incident.SeverityEvidence[right]]
		})
		for index := range incident.Timeline {
			sort.SliceStable(incident.Timeline[index].EvidenceEventIDs, func(left, right int) bool {
				return r.eventOrder[incident.Timeline[index].EvidenceEventIDs[left]] < r.eventOrder[incident.Timeline[index].EvidenceEventIDs[right]]
			})
		}
		if incident.ContainmentAction != nil {
			sort.SliceStable(incident.ContainmentAction.EvidenceEventIDs, func(left, right int) bool {
				return r.eventOrder[incident.ContainmentAction.EvidenceEventIDs[left]] < r.eventOrder[incident.ContainmentAction.EvidenceEventIDs[right]]
			})
		}
		incident.RelevantNodes, incident.RelevantEdges = graphReferences(r.graph, incident.EvidenceEventIDs)
		if incident.Timeline == nil {
			incident.Timeline = []Statement{}
		}
		if incident.EvidenceEventIDs == nil {
			incident.EvidenceEventIDs = []int64{}
		}
		if incident.RelevantNodes == nil {
			incident.RelevantNodes = []string{}
		}
		if incident.RelevantEdges == nil {
			incident.RelevantEdges = []string{}
		}
		r.report.Incidents = append(r.report.Incidents, *incident)
	}
	sort.SliceStable(r.report.Incidents, func(left, right int) bool {
		if !r.report.Incidents[left].StartedAt.Equal(r.report.Incidents[right].StartedAt) {
			return r.report.Incidents[left].StartedAt.Before(r.report.Incidents[right].StartedAt)
		}
		return r.report.Incidents[left].ID < r.report.Incidents[right].ID
	})
	if r.report.Incidents == nil {
		r.report.Incidents = []Incident{}
	}
	return r.report
}

func (r *reconstructor) firstOrder(values []int64) int {
	if len(values) == 0 {
		return len(r.ordered)
	}
	return r.eventOrder[values[0]]
}

func (r *reconstructor) nodeForEvidence(eventID int64, nodeType provenance.NodeType) (string, string) {
	for _, node := range r.graph.Nodes {
		if node.Type == nodeType && containsID(node.Evidence, eventID) {
			return node.ID, node.Label
		}
	}
	for _, edge := range r.graph.Edges {
		if !containsID(edge.Evidence, eventID) {
			continue
		}
		if node, ok := r.nodes[edge.From]; ok && node.Type == nodeType {
			return node.ID, node.Label
		}
		if node, ok := r.nodes[edge.To]; ok && node.Type == nodeType {
			return node.ID, node.Label
		}
	}
	return "", ""
}

func graphReferences(graph provenance.Graph, evidence []int64) ([]string, []string) {
	evidenceSet := make(map[int64]bool, len(evidence))
	for _, eventID := range evidence {
		evidenceSet[eventID] = true
	}
	nodeSet := make(map[string]bool)
	for _, node := range graph.Nodes {
		if intersects(node.Evidence, evidenceSet) {
			nodeSet[node.ID] = true
		}
	}
	edges := make([]string, 0)
	for _, edge := range graph.Edges {
		if len(edge.Evidence) > 0 && containsAll(evidenceSet, edge.Evidence) {
			edges = append(edges, edge.ID)
			nodeSet[edge.From] = true
			nodeSet[edge.To] = true
		}
	}
	nodes := make([]string, 0, len(nodeSet))
	for nodeID := range nodeSet {
		nodes = append(nodes, nodeID)
	}
	sort.Strings(nodes)
	sort.Strings(edges)
	return nodes, edges
}

func severityFromMetadata(metadata map[string]any) (Severity, bool) {
	value, _ := metadata["severity"].(string)
	switch Severity(strings.ToUpper(strings.TrimSpace(value))) {
	case Low:
		return Low, true
	case Medium:
		return Medium, true
	case High:
		return High, true
	case Critical:
		return Critical, true
	default:
		return "", false
	}
}

func severityRank(value Severity) int {
	switch value {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

func stableID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return prefix + ":" + hex.EncodeToString(sum[:8])
}

func eventKey(event events.Event) string {
	return strconv.FormatInt(event.ID, 10)
}

func appendUnique(values []int64, candidate int64) []int64 {
	if candidate <= 0 || containsID(values, candidate) {
		return values
	}
	return append(values, candidate)
}

func unique(values []int64) []int64 {
	result := make([]int64, 0, len(values))
	for _, value := range values {
		result = appendUnique(result, value)
	}
	return result
}

func containsID(values []int64, candidate int64) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func intersects(values []int64, set map[int64]bool) bool {
	for _, value := range values {
		if set[value] {
			return true
		}
	}
	return false
}

func containsAll(set map[int64]bool, values []int64) bool {
	for _, value := range values {
		if !set[value] {
			return false
		}
	}
	return true
}
