package events

import (
	"context"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

type recordingSink struct {
	event *Event
}

func (s *recordingSink) AddEvent(_ context.Context, event *Event) error {
	event.ID = 42
	s.event = event
	return nil
}

func TestPipelineUsesExistingEventSourceOfTruth(t *testing.T) {
	sink := &recordingSink{}
	decision := policy.Deny
	timestamp := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	recorded, err := NewPipeline(sink).Record(context.Background(), "session-one", Signal{
		Timestamp: timestamp,
		Type:      SensitiveResourceRequest,
		Subject:   "agent",
		Resource:  "shadow:~/.aws/credentials",
		Action:    "request",
		Decision:  &decision,
		Metadata:  map[string]any{"source": "runtime"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if recorded != sink.event || recorded.ID != 42 || recorded.Type != SensitiveResourceRequest || recorded.Type.Category() != Observation {
		t.Fatalf("recorded event = %#v", recorded)
	}
}

func TestPipelineRejectsMalformedSignal(t *testing.T) {
	invalid := policy.Decision("MAYBE")
	for _, signal := range []Signal{
		{Timestamp: time.Now().UTC(), Type: PolicyViolation, Decision: &invalid},
		{Type: PolicyViolation},
	} {
		if _, err := NewPipeline(&recordingSink{}).Record(context.Background(), "session", signal); err == nil {
			t.Fatalf("accepted malformed signal: %#v", signal)
		}
	}
}

func TestReservedSignalCategories(t *testing.T) {
	want := map[Type]Category{
		UntrustedContentObserved: Observation,
		PromptInjectionSuspected: Observation,
		SensitiveResourceRequest: Observation,
		PolicyViolation:          Incident,
		ResourceLimitTriggered:   Incident,
	}
	for eventType, category := range want {
		if !eventType.GenericSecuritySignal() || eventType.Category() != category {
			t.Errorf("%s category = %s, generic=%t", eventType, eventType.Category(), eventType.GenericSecuritySignal())
		}
	}
}
