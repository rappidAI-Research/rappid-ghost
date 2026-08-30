package session_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

type fakeRuntime struct {
	result ghruntime.RunResult
	err    error
}

func (fakeRuntime) Name() string { return "docker" }
func (f fakeRuntime) Run(context.Context, ghruntime.RunRequest) (ghruntime.RunResult, error) {
	return f.result, f.err
}

func TestManagerPersistsSuccessAndFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		runner     fakeRuntime
		wantStatus session.Status
		wantExit   *int
		wantEvents []events.Type
	}{
		{
			name:       "success",
			runner:     fakeRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 0}},
			wantStatus: session.Completed,
			wantExit:   intPointer(0),
			wantEvents: []events.Type{events.SessionStart, events.ProcessStart, events.ProcessExit, events.SessionEnd},
		},
		{
			name:       "guest exit failure",
			runner:     fakeRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 7}},
			wantStatus: session.Failed,
			wantExit:   intPointer(7),
			wantEvents: []events.Type{events.SessionStart, events.ProcessStart, events.ProcessExit, events.SessionEnd},
		},
		{
			name:       "runtime unavailable",
			runner:     fakeRuntime{err: errors.New("Docker unavailable")},
			wantStatus: session.Failed,
			wantEvents: []events.Type{events.SessionStart, events.ProcessStart, events.SessionEnd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "ghost.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			manager := session.NewManager(store, tt.runner)
			value, _ := manager.Run(ctx, ghruntime.RunRequest{Command: []string{"test-command"}, Workspace: t.TempDir()})
			persisted, err := store.Session(ctx, value.ID)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.Status != tt.wantStatus {
				t.Fatalf("status = %s, want %s", persisted.Status, tt.wantStatus)
			}
			if !equalIntPointer(persisted.ExitCode, tt.wantExit) {
				t.Fatalf("exit code = %v, want %v", persisted.ExitCode, tt.wantExit)
			}
			storedEvents, err := store.Events(ctx, value.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(storedEvents) != len(tt.wantEvents) {
				t.Fatalf("event count = %d, want %d", len(storedEvents), len(tt.wantEvents))
			}
			for i, want := range tt.wantEvents {
				if storedEvents[i].Type != want {
					t.Fatalf("event %d = %s, want %s", i, storedEvents[i].Type, want)
				}
			}
		})
	}
}

func intPointer(value int) *int { return &value }

func equalIntPointer(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
