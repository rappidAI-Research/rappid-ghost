package session_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

func TestFailedEvidenceFinalizationPreservesContainmentWithoutInventingAccess(t *testing.T) {
	for _, invalidResource := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-access", true: "invalid-resource"}[invalidResource], func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			store, err := storage.Open(ctx, filepath.Join(root, "ghost.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			result := ghruntime.RunResult{Started: true, ExitCode: 0, SecurityState: policy.StateContained}
			if invalidResource {
				result.Resources = []ghruntime.ResourceEvidence{{Kind: "invalid"}}
			}
			runner := &fakeRuntime{result: result, err: errors.New("evidence collection failed")}
			value, err := session.NewManager(store, runner).Run(ctx, denyRequest(t, root))
			if err == nil || value.Status != session.Failed || !value.IsContained() {
				t.Fatalf("lost failed containment: %+v, %v", value, err)
			}
			persisted, err := store.Session(ctx, value.ID)
			if err != nil || !persisted.IsContained() || persisted.Status != session.Failed {
				t.Fatalf("lost durable containment: %+v, %v", persisted, err)
			}
			storedEvents, err := store.Events(ctx, value.ID)
			if err != nil {
				t.Fatal(err)
			}
			if hasEvent(storedEvents, events.DecoyAccess) || !hasEvent(storedEvents, events.SessionEnd) {
				t.Fatalf("invented access or lost failure evidence: %+v", storedEvents)
			}
		})
	}
}
