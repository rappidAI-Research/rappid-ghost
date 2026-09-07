package provenance

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/trust"
)

func TestBuildReconstructsObservedAndTemporalRelationships(t *testing.T) {
	value, eventValues := graphFixture()
	graph := Build(value, eventValues)

	for _, edgeType := range []EdgeType{Started, Shadowed, Accessed, Contained, Requested, Denied, Triggered, FollowedBy} {
		if !hasEdgeType(graph, edgeType) {
			t.Errorf("graph missing %s edge: %#v", edgeType, graph.Edges)
		}
	}
	for _, nodeType := range []NodeType{SessionNode, ProcessNode, ResourceNode, DecoyNode, NetworkDestinationNode, PolicyDecisionNode, IncidentNode} {
		if !hasNodeType(graph, nodeType) {
			t.Errorf("graph missing %s node: %#v", nodeType, graph.Nodes)
		}
	}

	for _, edge := range graph.Edges {
		if edge.Type == FollowedBy {
			if edge.Level != Derived || len(edge.Evidence) != 2 || edge.Evidence[0] >= edge.Evidence[1] {
				t.Errorf("invalid temporal edge: %#v", edge)
			}
			continue
		}
		if edge.Level != Observed || len(edge.Evidence) != 1 {
			t.Errorf("invalid observed edge: %#v", edge)
		}
	}
}

func TestBuildIsDeterministicAndDoesNotMutateEvidence(t *testing.T) {
	value, eventValues := graphFixture()
	originalSession := value
	originalEvents := cloneEvents(eventValues)

	first := Build(value, eventValues)
	slices.Reverse(eventValues)
	second := Build(value, eventValues)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("graph depends on event input order:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if !reflect.DeepEqual(value, originalSession) {
		t.Fatal("Build modified session security state")
	}
	slices.Reverse(eventValues)
	if !reflect.DeepEqual(eventValues, originalEvents) {
		t.Fatal("Build modified stored events")
	}
}

func TestBuildNeverMixesSessions(t *testing.T) {
	value, eventValues := graphFixture()
	allow := policy.Allow
	eventValues = append(eventValues,
		events.Event{ID: 100, SessionID: "other-session", Timestamp: eventValues[0].Timestamp, Type: events.NetworkRequest, Metadata: map[string]any{"host": "other.test", "port": 443}},
		events.Event{ID: 101, SessionID: "other-session", Timestamp: eventValues[0].Timestamp, Type: events.NetworkAllow, Decision: &allow, Metadata: map[string]any{"host": "other.test", "port": 443}},
	)
	graph := Build(value, eventValues)
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("other.test")) || bytes.Contains(encoded, []byte("other-session")) {
		t.Fatalf("graph contains another session: %s", encoded)
	}
	for _, evidence := range graph.Evidence {
		if evidence.EventID >= 100 {
			t.Fatalf("foreign evidence entered graph: %#v", evidence)
		}
	}
}

func TestMissingEvidenceDoesNotInventRelationships(t *testing.T) {
	deny := policy.Deny
	value := session.Session{ID: "incomplete", Status: session.Failed, Runtime: "docker", NetworkMode: ghostnetwork.Deny}
	input := []events.Event{
		{ID: 1, SessionID: value.ID, Type: events.DecoyAccess, Resource: "../../host-secret", Decision: &deny},
		{ID: 2, SessionID: value.ID, Type: events.NetworkDeny, Decision: &deny, Metadata: map[string]any{"host": "bad host", "port": "invalid"}},
	}
	graph := Build(value, input)
	for _, edgeType := range []EdgeType{Accessed, Requested, Denied, FollowedBy} {
		if hasEdgeType(graph, edgeType) {
			t.Errorf("incomplete evidence invented %s: %#v", edgeType, graph.Edges)
		}
	}
	if hasNodeType(graph, ProcessNode) || hasNodeType(graph, NetworkDestinationNode) {
		t.Fatalf("incomplete evidence invented identity: %#v", graph.Nodes)
	}
}

func TestNetworkAllowCreatesDestinationDecisionRelationship(t *testing.T) {
	allow := policy.Allow
	value := session.Session{ID: "allowed-session", Status: session.Completed, Runtime: "docker", NetworkMode: ghostnetwork.Allowlist}
	input := []events.Event{
		{ID: 1, SessionID: value.ID, Type: events.ProcessStart, Subject: "wget"},
		{ID: 2, SessionID: value.ID, Type: events.NetworkRequest, Metadata: map[string]any{"host": "Allowed.Test.", "port": 80}},
		{ID: 3, SessionID: value.ID, Type: events.NetworkAllow, Decision: &allow, Metadata: map[string]any{"host": "allowed.test", "port": 80}},
	}
	graph := Build(value, input)
	if !hasEdgeType(graph, Requested) || !hasEdgeType(graph, Allowed) || hasEdgeType(graph, Denied) {
		t.Fatalf("network allow graph = %#v", graph.Edges)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte("network:allowed.test:80")) {
		t.Fatalf("normalized destination missing: %s", encoded)
	}
}

func TestGenericSecuritySignalIsRepresentedWithoutMetadataLeak(t *testing.T) {
	value := session.Session{ID: "signal-session", Status: session.Completed, Runtime: "docker"}
	input := []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: time.Now().UTC(), Type: events.ProcessStart, Subject: "agent"},
		{ID: 2, SessionID: value.ID, Timestamp: time.Now().UTC().Add(time.Millisecond), Type: events.UntrustedContentObserved, Subject: "agent", Metadata: map[string]any{"raw_content": "DO_NOT_EXPORT_SIGNAL_CONTENT"}},
	}
	graph := Build(value, input)
	if !hasNodeType(graph, SecuritySignalNode) || !hasEdgeType(graph, Signaled) {
		t.Fatalf("generic signal graph = %#v", graph)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("DO_NOT_EXPORT_SIGNAL_CONTENT")) {
		t.Fatalf("generic signal metadata leaked: %s", encoded)
	}
}

func TestPromptSignalLinksWorkspaceEvidenceWithoutInventingProcessAttribution(t *testing.T) {
	value := session.Session{ID: "prompt-session", Status: session.Completed, Runtime: "docker"}
	now := time.Now().UTC()
	input := []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.PromptInjectionSuspected, Subject: "workspace", Resource: "workspace:AGENTS.md", Metadata: map[string]any{
			"severity": "CRITICAL", "content": "DO_NOT_EXPORT_PROMPT_CONTENT",
		}},
		{ID: 2, SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.ProcessStart, Subject: "agent"},
	}
	graph := Build(value, input)
	var resourceID, signalID, processID string
	for _, node := range graph.Nodes {
		switch {
		case node.Type == ResourceNode && node.Label == "workspace:AGENTS.md":
			resourceID = node.ID
		case node.Type == SecuritySignalNode:
			signalID = node.ID
		case node.Type == ProcessNode:
			processID = node.ID
		}
	}
	if resourceID == "" || signalID == "" || processID == "" {
		t.Fatalf("prompt graph nodes = %#v", graph.Nodes)
	}
	found := false
	for _, edge := range graph.Edges {
		if edge.Type == Signaled && edge.From == resourceID && edge.To == signalID && edge.Level == Observed && reflect.DeepEqual(edge.Evidence, []int64{1}) {
			found = true
		}
		if edge.Type == Signaled && edge.From == processID {
			t.Fatalf("pre-run workspace inspection was attributed to process: %#v", edge)
		}
	}
	if !found {
		t.Fatalf("workspace-to-signal evidence edge missing: %#v", graph.Edges)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("DO_NOT_EXPORT_PROMPT_CONTENT")) || !bytes.Contains(encoded, []byte("PROMPT_INJECTION_SUSPECTED (CRITICAL)")) {
		t.Fatalf("prompt graph export = %s", encoded)
	}
}

func TestFollowedByUsesStableEventOrderForEqualTimestamps(t *testing.T) {
	shadow := policy.Shadow
	deny := policy.Deny
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	value := session.Session{ID: "ordered-session", Status: session.Completed, Runtime: "docker"}
	input := []events.Event{
		{ID: 11, SessionID: value.ID, Timestamp: now, Type: events.NetworkDeny, Decision: &deny, Metadata: map[string]any{"host": "example.com", "port": 443}},
		{ID: 10, SessionID: value.ID, Timestamp: now, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.env", Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_ordered"}},
	}
	graph := Build(value, input)
	for _, edge := range graph.Edges {
		if edge.Type == FollowedBy {
			if !reflect.DeepEqual(edge.Evidence, []int64{10, 11}) {
				t.Fatalf("FOLLOWED_BY evidence = %v, want [10 11]", edge.Evidence)
			}
			return
		}
	}
	t.Fatal("FOLLOWED_BY edge missing")
}

func TestJSONSchemaIsStableAndOmitsSensitiveMaterial(t *testing.T) {
	value, eventValues := graphFixture()
	var output bytes.Buffer
	if err := WriteJSON(&output, Build(value, eventValues)); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"TOP_SECRET_ARGUMENT", "GHOST_SECRET_MARKER", "Bearer should-not-persist", "request-body-secret", "DO_NOT_EXPORT_POLICY_SECRET", "dcy_fixture"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("graph JSON contains sensitive material %q:\n%s", secret, output.String())
		}
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 5 {
		t.Fatalf("top-level JSON fields = %v", reflect.ValueOf(document).MapKeys())
	}
	for _, required := range []string{"version", "session", "nodes", "edges", "evidence"} {
		if _, ok := document[required]; !ok {
			t.Errorf("JSON missing %q", required)
		}
	}
	var version int
	if SchemaVersion != 2 {
		t.Fatalf("unexpected compile-time schema version %d", SchemaVersion)
	}
	if err := json.Unmarshal(document["version"], &version); err != nil || version != SchemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
}

func TestTextRendererStatesTemporalEvidenceIsNotCausality(t *testing.T) {
	value, eventValues := graphFixture()
	var output bytes.Buffer
	WriteText(&output, Build(value, eventValues))
	for _, expected := range []string{"Ghost Provenance Graph", "Observed relationships", "Derived relationships", "FOLLOWED_BY", "temporal order, not causality"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output missing %q:\n%s", expected, output.String())
		}
	}
	if strings.Contains(strings.ToLower(output.String()), "caused") {
		t.Fatalf("text output makes causal claim:\n%s", output.String())
	}
}

func TestTrustExposureAndSensitiveRequestUseEvidenceWithoutInventingRead(t *testing.T) {
	now := time.Now().UTC()
	shadow := policy.Shadow
	value := session.Session{ID: "trust-session", Status: session.Completed, Runtime: "docker"}
	path := deception.GuestHome + "/.aws/credentials"
	input := []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.UntrustedContentObserved, Subject: "prompt_guard", Resource: "workspace:AGENTS.md", Metadata: map[string]any{"trust_class": "UNTRUSTED", "content": "DO_NOT_EXPORT_SOURCE"}},
		{ID: 2, SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.PromptInjectionSuspected, Subject: "workspace", Resource: "workspace:AGENTS.md", Metadata: map[string]any{"severity": "HIGH"}},
		{ID: 3, SessionID: value.ID, Timestamp: now.Add(2 * time.Millisecond), Type: events.ProcessStart, Subject: "sh"},
		{ID: 4, SessionID: value.ID, Timestamp: now.Add(3 * time.Millisecond), Type: events.DecoyAccess, Subject: "agent", Resource: path, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_trust"}},
		{ID: 5, SessionID: value.ID, Timestamp: now.Add(3 * time.Millisecond), Type: events.SensitiveResourceRequest, Subject: "agent", Resource: path, Decision: &shadow, Metadata: map[string]any{"source_event_id": int64(4), "content": "DO_NOT_EXPORT_SECRET"}},
	}
	graph := Build(value, input)
	if !hasTrustedNode(graph, "workspace:AGENTS.md", trust.Untrusted) || !hasTrustedNode(graph, "shadow:~/.aws/credentials", trust.Shadow) ||
		!hasTrustedNode(graph, "resource:~/.aws/credentials", trust.Sensitive) {
		t.Fatalf("trust classifications = %#v", graph.Nodes)
	}
	if !hasEdgeAtLevel(graph, ExposedTo, Derived) || !hasEdgeAtLevel(graph, Accessed, Observed) || !hasEdgeAtLevel(graph, Requested, Derived) {
		t.Fatalf("trust relationships = %#v", graph.Edges)
	}
	if hasEdgeType(graph, Read) {
		t.Fatalf("graph invented a file read: %#v", graph.Edges)
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"DO_NOT_EXPORT_SOURCE", "DO_NOT_EXPORT_SECRET", "CAUSED", "CAUSED_BY"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("graph exported unsupported or sensitive data %q: %s", forbidden, encoded)
		}
	}
}

func graphFixture() (session.Session, []events.Event) {
	base := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	shadow := policy.Shadow
	deny := policy.Deny
	allow := policy.Allow
	value := session.Session{
		ID: "session-one", Status: session.Completed, Runtime: "docker",
		NetworkMode: ghostnetwork.Allowlist, SecurityState: policy.StateContained,
	}
	decoyPath := deception.GuestHome + "/.aws/credentials"
	return value, []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: base, Type: events.SessionStart},
		{ID: 2, SessionID: value.ID, Timestamp: base.Add(time.Millisecond), Type: events.PolicyAllow, Subject: "workspace", Resource: "/workspace", Decision: &allow},
		{ID: 3, SessionID: value.ID, Timestamp: base.Add(2 * time.Millisecond), Type: events.DecoyCreated, Resource: decoyPath, Metadata: map[string]any{"decoy_id": "dcy_fixture", "type": "aws_credentials", "marker": "GHOST_SECRET_MARKER"}},
		{ID: 4, SessionID: value.ID, Timestamp: base.Add(3 * time.Millisecond), Type: events.PolicyShadow, Subject: "home", Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_fixture"}},
		{ID: 5, SessionID: value.ID, Timestamp: base.Add(4 * time.Millisecond), Type: events.ProcessStart, Subject: "sh", Metadata: map[string]any{"argv": []any{"sh", "TOP_SECRET_ARGUMENT"}}},
		{ID: 6, SessionID: value.ID, Timestamp: base.Add(5 * time.Millisecond), Type: events.DecoyAccess, Subject: "agent", Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_fixture"}},
		{ID: 7, SessionID: value.ID, Timestamp: base.Add(6 * time.Millisecond), Type: events.ContainmentActivated, Resource: "network", Decision: &deny},
		{ID: 8, SessionID: value.ID, Timestamp: base.Add(7 * time.Millisecond), Type: events.SecurityIncident, Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_fixture", "severity": "high"}},
		{ID: 9, SessionID: value.ID, Timestamp: base.Add(8 * time.Millisecond), Type: events.NetworkRequest, Resource: "example.com:443", Metadata: map[string]any{"host": "example.com", "port": float64(443), "method": "CONNECT", "authorization": "Bearer should-not-persist", "body": "request-body-secret"}},
		{ID: 10, SessionID: value.ID, Timestamp: base.Add(9 * time.Millisecond), Type: events.NetworkDeny, Resource: "example.com:443", Decision: &deny, Metadata: map[string]any{"host": "example.com", "port": float64(443), "method": "CONNECT", "contained": true}},
		{ID: 11, SessionID: value.ID, Timestamp: base.Add(10 * time.Millisecond), Type: events.PolicyDeny, Subject: "DO_NOT_EXPORT_POLICY_SECRET", Resource: "/unknown", Decision: &deny},
	}
}

func cloneEvents(values []events.Event) []events.Event {
	result := make([]events.Event, len(values))
	copy(result, values)
	for index := range result {
		if values[index].Metadata != nil {
			result[index].Metadata = make(map[string]any, len(values[index].Metadata))
			for key, value := range values[index].Metadata {
				result[index].Metadata[key] = value
			}
		}
	}
	return result
}

func hasNodeType(graph Graph, nodeType NodeType) bool {
	for _, node := range graph.Nodes {
		if node.Type == nodeType {
			return true
		}
	}
	return false
}

func hasEdgeType(graph Graph, edgeType EdgeType) bool {
	for _, edge := range graph.Edges {
		if edge.Type == edgeType {
			return true
		}
	}
	return false
}

func hasEdgeAtLevel(graph Graph, edgeType EdgeType, level EvidenceLevel) bool {
	for _, edge := range graph.Edges {
		if edge.Type == edgeType && edge.Level == level && len(edge.Evidence) > 0 {
			return true
		}
	}
	return false
}

func hasTrustedNode(graph Graph, label string, class trust.Class) bool {
	for _, node := range graph.Nodes {
		if node.Label == label && node.Trust == class {
			return true
		}
	}
	return false
}
