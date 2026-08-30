package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
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
	if loaded.NetworkMode != ghostnetwork.Deny || loaded.Contained {
		t.Fatalf("safe migrated network state = %+v", loaded)
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

func TestMigrationUpgradesVersionOneDatabase(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ghost.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ns INTEGER NOT NULL);
`+migrations[0]); err != nil {
		t.Fatalf("create v1 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at_ns) VALUES (1, ?)", time.Now().UTC().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open(v1 database) error = %v", err)
	}
	defer store.Close()
	value := session.Session{ID: "after-migration", CreatedAt: time.Now().UTC(), Command: []string{"true"}, Runtime: "docker", Status: session.Created}
	if err := store.CreateSession(ctx, value); err != nil {
		t.Fatal(err)
	}
	persistedSession, err := store.Session(ctx, value.ID)
	if err != nil || persistedSession.NetworkMode != ghostnetwork.Deny {
		t.Fatalf("migrated session network state = %+v, %v", persistedSession, err)
	}
	decoy := deception.Decoy{
		ID: "dcy_migrated", SessionID: value.ID, Type: deception.EnvFile,
		GuestPath: deception.GuestHome + "/.env", Marker: "marker", CreatedAt: time.Now().UTC(),
	}
	if err := store.CreateDecoy(ctx, decoy); err != nil {
		t.Fatalf("CreateDecoy() after migration error = %v", err)
	}
}

func TestDecoysPersistAndTriggerIdempotently(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ghost.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)
	value := session.Session{ID: "shadow-session", CreatedAt: created, Command: []string{"cat"}, Runtime: "docker", Status: session.Created}
	if err := store.CreateSession(ctx, value); err != nil {
		t.Fatal(err)
	}
	decoy := deception.Decoy{
		ID: "dcy_one", SessionID: value.ID, Type: deception.AWSCredentials,
		GuestPath: deception.GuestHome + "/.aws/credentials", Marker: "opaque-marker", CreatedAt: created,
	}
	if err := store.CreateDecoy(ctx, decoy); err != nil {
		t.Fatal(err)
	}
	triggeredAt := created.Add(time.Second)
	if changed, err := store.TriggerDecoy(ctx, "other-session", decoy.ID, triggeredAt); err == nil || changed {
		t.Fatalf("cross-session TriggerDecoy = %v, %v, want not found", changed, err)
	}
	changed, err := store.TriggerDecoy(ctx, value.ID, decoy.ID, triggeredAt)
	if err != nil || !changed {
		t.Fatalf("first TriggerDecoy = %v, %v", changed, err)
	}
	changed, err = store.TriggerDecoy(ctx, value.ID, decoy.ID, triggeredAt.Add(time.Second))
	if err != nil || changed {
		t.Fatalf("second TriggerDecoy = %v, %v", changed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	persisted, err := store.Decoys(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 1 || !persisted[0].Triggered || persisted[0].TriggeredAt == nil {
		t.Fatalf("persisted decoys = %#v", persisted)
	}
	if !persisted[0].TriggeredAt.Equal(triggeredAt) {
		t.Fatalf("TriggeredAt = %v, want %v", persisted[0].TriggeredAt, triggeredAt)
	}
}
