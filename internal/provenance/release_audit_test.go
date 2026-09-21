package provenance

import (
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"testing"
	"time"
)

func TestLaunchIntentAloneCannotProveProcessOrExposure(t *testing.T) {
	now := time.Now()
	value := session.Session{ID: "audit", Status: session.Failed, Runtime: "docker"}
	input := []events.Event{
		{ID: 1, SessionID: value.ID, Timestamp: now, Type: events.UntrustedContentObserved, Resource: "workspace:AGENTS.md", Subject: "prompt_guard"},
		{ID: 2, SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.ProcessStart, Subject: "sh"},
		{ID: 3, SessionID: "another-session", Timestamp: now.Add(2 * time.Millisecond), Type: events.ProcessExit, Subject: "sh", Metadata: map[string]any{"exit_code": 0}},
	}
	graph := Build(value, input)
	if hasNodeType(graph, ProcessNode) || hasEdgeType(graph, ExposedTo) || hasEdgeType(graph, Started) {
		t.Fatal("failed launch or foreign evidence invented a process")
	}
	input[2].SessionID = value.ID
	graph = Build(value, input)
	if !hasEdgeAtLevel(graph, Started, Derived) || !hasEdgeAtLevel(graph, ExposedTo, Derived) {
		t.Fatal("confirmed runtime scope lost")
	}
	for _, edge := range graph.Edges {
		if edge.Type == ExposedTo && len(edge.Evidence) != 3 {
			t.Fatalf("exposure omits confirming evidence: %+v", edge)
		}
	}
}
