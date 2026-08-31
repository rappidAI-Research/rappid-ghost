package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

type builder struct {
	graph       Graph
	nodes       map[string]*Node
	edges       map[string]*Edge
	decoyByPath map[string]string
	anchors     map[int64]string
	processID   string
}

// Build deterministically reconstructs a graph from one session and its
// persisted events. Events belonging to any other session are ignored.
func Build(value session.Session, input []events.Event) Graph {
	ordered := make([]events.Event, 0, len(input))
	for _, event := range input {
		if event.SessionID == value.ID {
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

	b := &builder{
		graph: Graph{
			Version: SchemaVersion,
			Session: SessionSummary{ID: value.ID, Status: value.Status, Runtime: value.Runtime, Contained: value.Contained},
		},
		nodes:       make(map[string]*Node),
		edges:       make(map[string]*Edge),
		decoyByPath: make(map[string]string),
		anchors:     make(map[int64]string),
	}
	b.addNode("session", SessionNode, "session "+shortID(value.ID))

	for _, event := range ordered {
		if event.ID > 0 {
			b.graph.Evidence = append(b.graph.Evidence, Evidence{EventID: event.ID, Timestamp: event.Timestamp, Type: event.Type})
		}
		if event.Type == events.DecoyCreated || event.Type == events.PolicyShadow {
			b.ensureDecoy(event)
		}
		if event.Type == events.ProcessStart && b.processID == "" {
			b.consumeProcessStart(event)
		}
	}
	for _, event := range ordered {
		b.consume(event)
	}
	b.addTemporalEdges(ordered)
	return b.finish()
}

func (b *builder) consume(event events.Event) {
	switch event.Type {
	case events.SessionStart:
		b.addNodeEvidence("session", event.ID)
	case events.ProcessStart:
		return
	case events.DecoyCreated:
		b.addNodeEvidence(b.ensureDecoy(event), event.ID)
	case events.PolicyAllow, events.PolicyDeny, events.PolicyShadow:
		b.consumePolicy(event)
	case events.DecoyAccess:
		decoyID := b.ensureDecoy(event)
		b.setAnchor(event.ID, decoyID)
		if b.processID != "" {
			b.addObservedEdge(Accessed, b.processID, decoyID, event.ID)
		}
	case events.NetworkRequest:
		if networkID := b.ensureNetwork(event); networkID != "" {
			b.setAnchor(event.ID, networkID)
			if b.processID != "" {
				b.addObservedEdge(Requested, b.processID, networkID, event.ID)
			}
		}
	case events.NetworkAllow, events.NetworkDeny:
		b.consumeNetworkDecision(event)
	case events.ContainmentActivated:
		decisionID := b.decisionNode(event, "network containment")
		b.setAnchor(event.ID, decisionID)
		b.addObservedEdge(Contained, "session", decisionID, event.ID)
	case events.SecurityIncident:
		b.consumeIncident(event)
	}
}

func (b *builder) consumeProcessStart(event events.Event) {
	name := executableName(event.Subject)
	if name == "" {
		return
	}
	b.processID = "process:root"
	b.addNode(b.processID, ProcessNode, "command scope: "+name)
	b.addNodeEvidence(b.processID, event.ID)
	b.addObservedEdge(Started, "session", b.processID, event.ID)
}

func (b *builder) consumePolicy(event events.Event) {
	if event.Decision == nil || !event.Decision.Valid() {
		return
	}
	targetID := ""
	context := ""
	switch event.Subject {
	case "home":
		context = "home"
		if *event.Decision == policy.Shadow {
			targetID = b.ensureDecoy(event)
		} else if label := resourceLabel(event.Resource); label != "" {
			targetID = stableID("resource", label)
			b.addNode(targetID, ResourceNode, label)
		}
	case "workspace":
		context = "workspace"
		targetID = stableID("resource", "workspace:/workspace")
		b.addNode(targetID, ResourceNode, "workspace:/workspace")
	case "network":
		context = "network policy"
		targetID = stableID("resource", "network policy")
		b.addNode(targetID, ResourceNode, "network policy")
	}
	if targetID == "" {
		return
	}
	decisionID := b.decisionNode(event, context)
	b.addNodeEvidence(targetID, event.ID)
	b.addObservedEdge(edgeForDecision(*event.Decision), targetID, decisionID, event.ID)
}

func (b *builder) consumeNetworkDecision(event events.Event) {
	networkID := b.ensureNetwork(event)
	if networkID == "" || event.Decision == nil || (*event.Decision != policy.Allow && *event.Decision != policy.Deny) {
		return
	}
	decisionID := b.decisionNode(event, "network")
	b.setAnchor(event.ID, decisionID)
	b.addObservedEdge(edgeForDecision(*event.Decision), networkID, decisionID, event.ID)
}

func (b *builder) consumeIncident(event events.Event) {
	severity := strings.ToUpper(metadataString(event.Metadata, "severity"))
	if severity != "LOW" && severity != "MEDIUM" && severity != "HIGH" {
		severity = ""
	}
	label := "security incident"
	if severity != "" {
		label += " (" + severity + ")"
	}
	incidentID := eventNodeID("incident", event)
	b.addNode(incidentID, IncidentNode, label)
	b.addNodeEvidence(incidentID, event.ID)
	b.setAnchor(event.ID, incidentID)
	if decoyID := b.decoyForEvent(event); decoyID != "" {
		b.addObservedEdge(Triggered, decoyID, incidentID, event.ID)
	}
}

func (b *builder) ensureDecoy(event events.Event) string {
	if existing := b.decoyForEvent(event); existing != "" {
		b.addNodeEvidence(existing, event.ID)
		return existing
	}
	decoyID := metadataString(event.Metadata, "decoy_id")
	if !safeOpaqueID(decoyID) {
		decoyID = "event-" + eventKey(event)
	}
	id := stableID("decoy", decoyID)
	label := decoyLabel(event.Resource)
	b.addNode(id, DecoyNode, label)
	b.addNodeEvidence(id, event.ID)
	if normalized := normalizeGuestPath(event.Resource); normalized != "" {
		b.decoyByPath[normalized] = id
	}
	return id
}

func (b *builder) decoyForEvent(event events.Event) string {
	if id := metadataString(event.Metadata, "decoy_id"); safeOpaqueID(id) {
		candidate := stableID("decoy", id)
		if _, ok := b.nodes[candidate]; ok {
			return candidate
		}
	}
	if normalized := normalizeGuestPath(event.Resource); normalized != "" {
		return b.decoyByPath[normalized]
	}
	return ""
}

func (b *builder) ensureNetwork(event events.Event) string {
	host, port, ok := networkDestination(event)
	if !ok {
		return ""
	}
	label := "network:" + host + ":" + strconv.Itoa(port)
	id := stableID("network", label)
	b.addNode(id, NetworkDestinationNode, label)
	b.addNodeEvidence(id, event.ID)
	return id
}

func (b *builder) decisionNode(event events.Event, context string) string {
	id := eventNodeID("decision", event)
	label := safeLabel(context, "policy")
	if event.Decision != nil && event.Decision.Valid() {
		label += " " + string(*event.Decision)
	}
	b.addNode(id, PolicyDecisionNode, label)
	b.addNodeEvidence(id, event.ID)
	return id
}

func (b *builder) addTemporalEdges(ordered []events.Event) {
	var previous *events.Event
	for index := range ordered {
		event := &ordered[index]
		to := b.anchors[event.ID]
		if to == "" {
			continue
		}
		if previous != nil {
			from := b.anchors[previous.ID]
			if from != "" && from != to {
				b.addEdge(FollowedBy, from, to, Derived, []int64{previous.ID, event.ID})
			}
		}
		previous = event
	}
}

func (b *builder) addNode(id string, nodeType NodeType, label string) {
	if id == "" || label == "" {
		return
	}
	if _, exists := b.nodes[id]; !exists {
		b.nodes[id] = &Node{ID: id, Type: nodeType, Label: label}
	}
}

func (b *builder) addNodeEvidence(id string, eventID int64) {
	if node := b.nodes[id]; node != nil && eventID > 0 {
		node.Evidence = appendUnique(node.Evidence, eventID)
	}
}

func (b *builder) setAnchor(eventID int64, nodeID string) {
	if eventID > 0 && nodeID != "" {
		b.anchors[eventID] = nodeID
	}
}

func (b *builder) addObservedEdge(edgeType EdgeType, from, to string, eventID int64) {
	b.addEdge(edgeType, from, to, Observed, []int64{eventID})
}

func (b *builder) addEdge(edgeType EdgeType, from, to string, level EvidenceLevel, evidence []int64) {
	if b.nodes[from] == nil || b.nodes[to] == nil {
		return
	}
	validEvidence := make([]int64, 0, len(evidence))
	for _, id := range evidence {
		if id > 0 {
			validEvidence = appendUnique(validEvidence, id)
		}
	}
	key := string(edgeType) + "\x00" + from + "\x00" + to + "\x00" + string(level) + "\x00" + evidenceKey(validEvidence)
	id := stableID("edge", key)
	if _, exists := b.edges[id]; !exists {
		b.edges[id] = &Edge{ID: id, Type: edgeType, From: from, To: to, Level: level, Evidence: validEvidence}
	}
}

func (b *builder) finish() Graph {
	for _, node := range b.nodes {
		sort.Slice(node.Evidence, func(i, j int) bool { return node.Evidence[i] < node.Evidence[j] })
		b.graph.Nodes = append(b.graph.Nodes, *node)
	}
	for _, edge := range b.edges {
		sort.Slice(edge.Evidence, func(i, j int) bool { return edge.Evidence[i] < edge.Evidence[j] })
		b.graph.Edges = append(b.graph.Edges, *edge)
	}
	sort.Slice(b.graph.Nodes, func(i, j int) bool { return b.graph.Nodes[i].ID < b.graph.Nodes[j].ID })
	sort.Slice(b.graph.Edges, func(i, j int) bool { return b.graph.Edges[i].ID < b.graph.Edges[j].ID })
	sort.Slice(b.graph.Evidence, func(i, j int) bool {
		if !b.graph.Evidence[i].Timestamp.Equal(b.graph.Evidence[j].Timestamp) {
			return b.graph.Evidence[i].Timestamp.Before(b.graph.Evidence[j].Timestamp)
		}
		return b.graph.Evidence[i].EventID < b.graph.Evidence[j].EventID
	})
	if b.graph.Nodes == nil {
		b.graph.Nodes = []Node{}
	}
	if b.graph.Edges == nil {
		b.graph.Edges = []Edge{}
	}
	if b.graph.Evidence == nil {
		b.graph.Evidence = []Evidence{}
	}
	return b.graph
}

func edgeForDecision(decision policy.Decision) EdgeType {
	switch decision {
	case policy.Allow:
		return Allowed
	case policy.Shadow:
		return Shadowed
	default:
		return Denied
	}
}

func eventNodeID(prefix string, event events.Event) string {
	return prefix + ":event:" + eventKey(event)
}

func eventKey(event events.Event) string {
	if event.ID > 0 {
		return strconv.FormatInt(event.ID, 10)
	}
	return stableID("unknown", string(event.Type)+"\x00"+event.Timestamp.UTC().Format("20060102T150405.000000000Z")+"\x00"+event.Resource)
}

func stableID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return prefix + ":" + hex.EncodeToString(sum[:8])
}

func appendUnique(values []int64, candidate int64) []int64 {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func evidenceKey(values []int64) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.FormatInt(value, 10)
	}
	return strings.Join(parts, ",")
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

func metadataInt(metadata map[string]any, key string) (int, bool) {
	switch value := metadata[key].(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		if value != float64(int(value)) {
			return 0, false
		}
		return int(value), true
	case string:
		parsed, err := strconv.Atoi(value)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func networkDestination(event events.Event) (string, int, bool) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(metadataString(event.Metadata, "host")), "."))
	port, ok := metadataInt(event.Metadata, "port")
	if !ok || port < 1 || port > 65535 || host == "" || len(host) > 253 || containsUnsafeText(host) {
		return "", 0, false
	}
	if parsed := net.ParseIP(host); parsed != nil {
		host = parsed.String()
	} else {
		normalized, err := ghostnetwork.NormalizeHostname(host)
		if err != nil {
			return "", 0, false
		}
		host = normalized
	}
	return host, port, true
}

func safeOpaqueID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func executableName(value string) string {
	value = safeLabel(value, "")
	if value == "" {
		return ""
	}
	return path.Base(value)
}

func normalizeGuestPath(value string) string {
	if value == "" || containsUnsafeText(value) {
		return ""
	}
	clean := path.Clean(value)
	if clean == deception.GuestHome || !strings.HasPrefix(clean, deception.GuestHome+"/") {
		return ""
	}
	return clean
}

func decoyLabel(value string) string {
	if clean := normalizeGuestPath(value); clean != "" {
		return "shadow:~" + strings.TrimPrefix(clean, deception.GuestHome)
	}
	return "shadow resource"
}

func resourceLabel(value string) string {
	if clean := normalizeGuestPath(value); clean != "" {
		return "resource:~" + strings.TrimPrefix(clean, deception.GuestHome)
	}
	if value == "/workspace" {
		return "workspace:/workspace"
	}
	return ""
}

func safeLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || containsUnsafeText(value) {
		return fallback
	}
	return value
}

func containsUnsafeText(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) || character == '\\' || character == '"' {
			return true
		}
	}
	return false
}

func shortID(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}
