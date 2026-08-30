package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func TestSessionsAndEventsPersistWithStableOrdering(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ghost.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	created := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	first := session.Session{ID: "first", CreatedAt: created, Command: []string{"echo", "first"}, Runtime: "docker", Status: session.Created}
	second := session.Session{ID: "second", CreatedAt: created, Command: []string{"echo", "second"}, Runtime: "docker", Status: session.Created}
	if err := store.CreateSession(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, second); err != nil {
		t.Fatal(err)
	}

	sameTime := created.Add(time.Second)
	for _, eventType := range []events.Type{events.SessionStart, events.ProcessStart, events.ProcessExit} {
		event := &events.Event{SessionID: second.ID, Timestamp: sameTime, Type: eventType, Metadata: map[string]any{"stored": true}}
		if err := store.AddEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	latest, err := store.LatestSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != second.ID {
		t.Fatalf("latest session = %q, want %q", latest.ID, second.ID)
	}
	loaded, err := store.Session(ctx, first.ID)
	if err != nil || loaded.Command[1] != "first" {
		t.Fatalf("persisted session = %#v, %v", loaded, err)
	}
	persistedEvents, err := store.Events(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(persistedEvents) != 3 {
		t.Fatalf("event count = %d, want 3", len(persistedEvents))
	}
	for i, want := range []events.Type{events.SessionStart, events.ProcessStart, events.ProcessExit} {
		if persistedEvents[i].Type != want {
			t.Fatalf("event %d = %s, want %s", i, persistedEvents[i].Type, want)
		}
		if persistedEvents[i].ID == 0 {
			t.Fatalf("event %d has no stable ID", i)
		}
	}
}
