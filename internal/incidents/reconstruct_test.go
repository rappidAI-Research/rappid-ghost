package incidents

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
	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func TestReconstructsDecoyContainmentAndLaterNetworkDenial(t *testing.T) {
	value, eventValues := incidentFixture()
	report := Reconstruct(value, eventValues)
	if len(report.Incidents) != 1 {
		t.Fatalf("incidents = %#v", report.Incidents)
	}
	incident := report.Incidents[0]
	if incident.Type != DecoyAccessWithNetworkActivity || incident.Severity != High {
		t.Fatalf("incident classification = %s/%s", incident.Type, incident.Severity)
	}
	if len(incident.SeverityEvidence) == 0 {
		t.Fatal("severity lacks evidence")
	}
	if incident.ContainmentAction == nil || incident.ContainmentAction.Action != "NETWORK_DENY" {
		t.Fatalf("containment = %#v", incident.ContainmentAction)
	}
	for _, stepType := range []StepType{ShadowExposed, DecoyAccessed, ContainmentApplied, NetworkDenied} {
		if !hasStep(incident, stepType) {
			t.Errorf("timeline missing %s: %#v", stepType, incident.Timeline)
		}
	}
	if got, want := incident.EvidenceEventIDs, []int64{2, 4, 5, 6, 7, 8}; !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %v, want %v", got, want)
	}
	if len(incident.RelevantNodes) == 0 || len(incident.RelevantEdges) == 0 {
		t.Fatalf("provenance references missing: %#v", incident)
	}
	for _, statement := range incident.Timeline {
		if len(statement.EvidenceEventIDs) == 0 {
			t.Fatalf("statement lacks evidence: %#v", statement)
		}
	}
	networkStep := step(incident, NetworkDenied)
	if networkStep.Level != provenance.Derived || !reflect.DeepEqual(networkStep.EvidenceEventIDs, []int64{5, 7, 8}) {
		t.Fatalf("network temporal evidence = %#v", networkStep)
	}
}

func TestReconstructionIsDeterministicAndReadOnly(t *testing.T) {
	value, eventValues := incidentFixture()
	originalSession := value
	originalEvents := cloneEvents(eventValues)
	first := Reconstruct(value, eventValues)
	slices.Reverse(eventValues)
	second := Reconstruct(value, eventValues)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("reconstruction depends on input order:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if !reflect.DeepEqual(value, originalSession) {
		t.Fatal("reconstruction changed session security state")
	}
	slices.Reverse(eventValues)
	if !reflect.DeepEqual(eventValues, originalEvents) {
		t.Fatal("reconstruction changed stored events")
	}
}

func TestEventsFromOtherSessionsNeverMix(t *testing.T) {
	value, eventValues := incidentFixture()
	deny := policy.Deny
	eventValues = append(eventValues,
		events.Event{ID: 100, SessionID: "other-session", Timestamp: eventValues[0].Timestamp, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.env", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_other"}},
		events.Event{ID: 101, SessionID: "other-session", Timestamp: eventValues[0].Timestamp, Type: events.NetworkDeny, Resource: "other.test:443", Decision: &deny, Metadata: map[string]any{"host": "other.test", "port": 443}},
	)
	encoded := encodeReport(t, Reconstruct(value, eventValues))
	if bytes.Contains(encoded, []byte("other-session")) || bytes.Contains(encoded, []byte("other.test")) {
		t.Fatalf("foreign evidence entered report: %s", encoded)
	}
}

func TestIncompleteHistoricalEvidenceDegradesGracefully(t *testing.T) {
	value := session.Session{ID: "incomplete", Runtime: "docker", Status: session.Failed}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	report := Reconstruct(value, []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.env", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_incomplete"}},
		{ID: 2, SessionID: value.ID, Timestamp: now.Add(time.Second), Type: events.NetworkDeny, Decision: decision(policy.Deny), Metadata: map[string]any{"host": "bad host", "port": "invalid"}},
	})
	if len(report.Incidents) != 1 || report.Incidents[0].Type != DecoyAccess || len(report.Incidents[0].Timeline) != 1 {
		t.Fatalf("incomplete report = %#v", report)
	}
	if strings.Contains(strings.ToLower(report.Incidents[0].Timeline[0].Text), "command scope") {
		t.Fatalf("incomplete evidence invented process attribution: %#v", report.Incidents[0].Timeline)
	}

	orphan := Reconstruct(value, []events.Event{{
		ID: 3, SessionID: value.ID, Timestamp: now, Type: events.ContainmentActivated,
		Resource: "network", Decision: decision(policy.Deny),
	}})
	if len(orphan.Incidents) != 1 || orphan.Incidents[0].Type != ContainmentActivated {
		t.Fatalf("orphan containment report = %#v", orphan)
	}
}

func TestDuplicateAccessEvidenceDoesNotDuplicateIncident(t *testing.T) {
	value := session.Session{ID: "duplicates", Runtime: "docker", Status: session.Completed}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	first := events.Event{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.aws/credentials", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_same"}}
	second := first
	second.ID = 2
	second.Timestamp = now.Add(time.Millisecond)
	report := Reconstruct(value, []events.Event{first, first, second})
	if len(report.Incidents) != 1 {
		t.Fatalf("duplicate access created incidents: %#v", report.Incidents)
	}
	if got := step(report.Incidents[0], DecoyAccessed).EvidenceEventIDs; !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Fatalf("deduplicated evidence = %v", got)
	}
}

func TestIndependentDecoysRemainSeparate(t *testing.T) {
	value := session.Session{ID: "multiple", Runtime: "docker", Status: session.Completed}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	report := Reconstruct(value, []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.aws/credentials", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_aws"}},
		{ID: 2, SessionID: value.ID, Timestamp: now.Add(time.Second), Type: events.DecoyAccess, Resource: deception.GuestHome + "/.env", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_env"}},
	})
	if len(report.Incidents) != 2 || report.Incidents[0].ID == report.Incidents[1].ID {
		t.Fatalf("independent incidents = %#v", report.Incidents)
	}
}

func TestSeverityRulesAreDeterministic(t *testing.T) {
	value := session.Session{ID: "severity", Runtime: "docker", Status: session.Completed}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	base := []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.env", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_severity"}},
		{ID: 2, SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.SecurityIncident, Resource: deception.GuestHome + "/.env", Decision: decision(policy.Shadow), Metadata: map[string]any{"decoy_id": "dcy_severity", "severity": "medium"}},
	}
	standalone := Reconstruct(value, base)
	if standalone.Incidents[0].Severity != Medium {
		t.Fatalf("configured severity = %s", standalone.Incidents[0].Severity)
	}
	if !reflect.DeepEqual(standalone.Incidents[0].SeverityEvidence, []int64{2}) {
		t.Fatalf("configured severity evidence = %v", standalone.Incidents[0].SeverityEvidence)
	}
	withNetwork := append(cloneEvents(base),
		events.Event{ID: 3, SessionID: value.ID, Timestamp: now.Add(2 * time.Millisecond), Type: events.ContainmentActivated, Resource: "network", Decision: decision(policy.Deny)},
		events.Event{ID: 4, SessionID: value.ID, Timestamp: now.Add(3 * time.Millisecond), Type: events.NetworkRequest, Resource: "example.com:443", Metadata: map[string]any{"host": "example.com", "port": 443}},
		events.Event{ID: 5, SessionID: value.ID, Timestamp: now.Add(4 * time.Millisecond), Type: events.NetworkDeny, Resource: "example.com:443", Decision: decision(policy.Deny), Metadata: map[string]any{"host": "example.com", "port": 443, "contained": true}},
	)
	if got := Reconstruct(value, withNetwork).Incidents[0].Severity; got != High {
		t.Fatalf("contained network severity = %s", got)
	}
}

func TestIndependentNetworkDenialIsSeparateMediumIncident(t *testing.T) {
	value, eventValues := incidentFixture()
	deny := policy.Deny
	base := eventValues[0].Timestamp.Add(-time.Second)
	eventValues = append(eventValues,
		events.Event{ID: 20, SessionID: value.ID, Timestamp: base, Type: events.NetworkRequest, Resource: "blocked.test:443", Metadata: map[string]any{"host": "blocked.test", "port": 443}},
		events.Event{ID: 21, SessionID: value.ID, Timestamp: base.Add(time.Millisecond), Type: events.NetworkDeny, Resource: "blocked.test:443", Decision: &deny, Metadata: map[string]any{"host": "blocked.test", "port": 443}},
	)
	report := Reconstruct(value, eventValues)
	if len(report.Incidents) != 2 || report.Incidents[0].Type != NetworkPolicyViolation || report.Incidents[0].Severity != Medium {
		t.Fatalf("independent network incident = %#v", report.Incidents)
	}
}

func TestJSONSchemaOmitsSecretsAndRawMetadata(t *testing.T) {
	value, eventValues := incidentFixture()
	value.Command = []string{"sh", "TOP_SECRET_ARGUMENT"}
	eventValues[1].Metadata["marker"] = "DO_NOT_EXPORT_MARKER"
	eventValues[6].Metadata["authorization"] = "Bearer DO_NOT_EXPORT_TOKEN"
	eventValues[6].Metadata["body"] = "DO_NOT_EXPORT_BODY"
	encoded := encodeReport(t, Reconstruct(value, eventValues))
	for _, secret := range []string{"TOP_SECRET_ARGUMENT", "DO_NOT_EXPORT_MARKER", "DO_NOT_EXPORT_TOKEN", "DO_NOT_EXPORT_BODY", "dcy_fixture"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("incident JSON contains %q: %s", secret, encoded)
		}
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 3 || document["version"] == nil || document["session"] == nil || document["incidents"] == nil {
		t.Fatalf("unstable top-level schema: %v", reflect.ValueOf(document).MapKeys())
	}
	if SchemaVersion != 1 {
		t.Fatalf("schema version = %d", SchemaVersion)
	}
}

func TestTextRendererDistinguishesTemporalOrderFromCausality(t *testing.T) {
	value, eventValues := incidentFixture()
	var output bytes.Buffer
	WriteText(&output, Reconstruct(value, eventValues))
	for _, expected := range []string{"Ghost Incidents", "DECOY_ACCESS_WITH_NETWORK_ACTIVITY", "A later outbound request", "Temporal order does not prove causality or intent"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output missing %q:\n%s", expected, output.String())
		}
	}
	if strings.Contains(strings.ToLower(output.String()), "exfiltrat") || strings.Contains(strings.ToLower(output.String()), "caused") {
		t.Fatalf("text output overclaims evidence:\n%s", output.String())
	}
}

func incidentFixture() (session.Session, []events.Event) {
	now := time.Date(2026, 8, 30, 12, 4, 17, 0, time.UTC)
	value := session.Session{ID: "incident-session", Runtime: "docker", Status: session.Completed, NetworkMode: ghostnetwork.Allowlist, Contained: true}
	shadow := policy.Shadow
	deny := policy.Deny
	allow := policy.Allow
	path := deception.GuestHome + "/.aws/credentials"
	return value, []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now.Add(-time.Second), Type: events.PolicyAllow, Subject: "workspace", Resource: "/workspace", Decision: &allow},
		{ID: 2, SessionID: value.ID, Timestamp: now, Type: events.PolicyShadow, Subject: "home", Resource: path, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_fixture"}},
		{ID: 3, SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.ProcessStart, Subject: "sh", Metadata: map[string]any{"argv": []any{"sh", "secret"}}},
		{ID: 4, SessionID: value.ID, Timestamp: now.Add(2 * time.Millisecond), Type: events.DecoyAccess, Subject: "agent", Resource: path, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_fixture"}},
		{ID: 5, SessionID: value.ID, Timestamp: now.Add(3 * time.Millisecond), Type: events.ContainmentActivated, Subject: "ghost", Resource: "network", Decision: &deny},
		{ID: 6, SessionID: value.ID, Timestamp: now.Add(4 * time.Millisecond), Type: events.SecurityIncident, Subject: "agent", Resource: path, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_fixture", "severity": "high"}},
		{ID: 7, SessionID: value.ID, Timestamp: now.Add(5 * time.Millisecond), Type: events.NetworkRequest, Subject: "agent", Resource: "example.com:443", Metadata: map[string]any{"host": "example.com", "port": 443, "method": "CONNECT"}},
		{ID: 8, SessionID: value.ID, Timestamp: now.Add(6 * time.Millisecond), Type: events.NetworkDeny, Subject: "gateway", Resource: "example.com:443", Decision: &deny, Metadata: map[string]any{"host": "example.com", "port": 443, "method": "CONNECT", "contained": true}},
		{ID: 9, SessionID: value.ID, Timestamp: now.Add(7 * time.Millisecond), Type: events.ProcessExit, Subject: "sh"},
	}
}

func decision(value policy.Decision) *policy.Decision { return &value }

func hasStep(incident Incident, stepType StepType) bool {
	for _, value := range incident.Timeline {
		if value.Type == stepType {
			return true
		}
	}
	return false
}

func step(incident Incident, stepType StepType) Statement {
	for _, value := range incident.Timeline {
		if value.Type == stepType {
			return value
		}
	}
	return Statement{}
}

func encodeReport(t *testing.T, report Report) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
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
