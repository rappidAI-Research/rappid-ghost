package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func TestStaleSessionCannotResetPersistedContainment(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "ghost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	normal := session.Session{ID: "audit", CreatedAt: time.Now(), Command: []string{"true"}, Runtime: "docker", Status: session.Running, SecurityState: policy.StateNormal}
	if err := store.CreateSession(ctx, normal); err != nil {
		t.Fatal(err)
	}
	contained := normal
	contained.SecurityState = policy.StateContained
	if err := store.UpdateSession(ctx, contained); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateSession(ctx, normal); err == nil {
		t.Fatal("stale snapshot reset containment")
	}
	actual, err := store.Session(ctx, normal.ID)
	if err != nil || !actual.IsContained() {
		t.Fatalf("state regressed: %+v %v", actual, err)
	}
	contained.Status = session.Failed
	if err := store.UpdateSession(ctx, contained); err != nil {
		t.Fatal(err)
	}
}
