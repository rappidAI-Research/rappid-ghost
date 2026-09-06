package events

import (
	"context"
	"fmt"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

// Signal is the structured pre-persistence form of security-relevant runtime
// evidence. Pipeline converts it into the existing Event source of truth; it
// deliberately does not introduce a second event store.
type Signal struct {
	Timestamp time.Time
	Type      Type
	Subject   string
	Resource  string
	Action    string
	Decision  *policy.Decision
	Metadata  map[string]any
}

type Sink interface {
	AddEvent(context.Context, *Event) error
}

type Pipeline struct {
	sink Sink
}

func NewPipeline(sink Sink) *Pipeline {
	return &Pipeline{sink: sink}
}

func (p *Pipeline) Record(ctx context.Context, sessionID string, signal Signal) (*Event, error) {
	if p == nil || p.sink == nil {
		return nil, fmt.Errorf("security signal pipeline has no event sink")
	}
	event := &Event{
		SessionID: sessionID,
		Timestamp: signal.Timestamp,
		Type:      signal.Type,
		Subject:   signal.Subject,
		Resource:  signal.Resource,
		Action:    signal.Action,
		Decision:  signal.Decision,
		Metadata:  signal.Metadata,
	}
	if err := event.Validate(); err != nil {
		return nil, fmt.Errorf("invalid security signal: %w", err)
	}
	if err := p.sink.AddEvent(ctx, event); err != nil {
		return nil, err
	}
	return event, nil
}
