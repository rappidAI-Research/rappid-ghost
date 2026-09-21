package session_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

func TestCommandArgumentsExecuteWithoutEnteringEvidence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, "ghost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const secret = "audit_synthetic_token_do_not_persist"
	request := denyRequest(t, root)
	request.Runtime.Command = []string{"sh", "-c", "printf '%s' " + secret}
	called := false
	runner := &fakeRuntime{run: func(r ghruntime.RunRequest) (ghruntime.RunResult, error) {
		called = true
		if r.Command[2] != request.Runtime.Command[2] {
			t.Fatal("execution arguments changed")
		}
		return ghruntime.RunResult{Started: true, SecurityState: policy.StateNormal}, nil
	}}
	value, err := session.NewManager(store, runner).Run(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("runtime not called")
	}
	stored, err := store.Session(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := store.Events(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal([]any{stored, evidence})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), `"argv"`) {
		t.Fatal("command arguments leaked into durable evidence")
	}
}
