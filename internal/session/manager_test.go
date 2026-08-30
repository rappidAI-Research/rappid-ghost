package session_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

type fakeRuntime struct {
	result ghruntime.RunResult
	err    error
	run    func(ghruntime.RunRequest) (ghruntime.RunResult, error)
}

func (*fakeRuntime) Name() string { return "docker" }
func (f *fakeRuntime) Run(_ context.Context, request ghruntime.RunRequest) (ghruntime.RunResult, error) {
	if f.run != nil {
		return f.run(request)
	}
	return f.result, f.err
}

func TestManagerPersistsSuccessAndFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		runner          *fakeRuntime
		wantStatus      session.Status
		wantExit        *int
		wantProcessExit bool
	}{
		{
			name: "success", runner: &fakeRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 0}},
			wantStatus: session.Completed, wantExit: intPointer(0), wantProcessExit: true,
		},
		{
			name: "guest exit failure", runner: &fakeRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 7}},
			wantStatus: session.Failed, wantExit: intPointer(7), wantProcessExit: true,
		},
		{
			name: "runtime unavailable", runner: &fakeRuntime{err: errors.New("Docker unavailable")},
			wantStatus: session.Failed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			store, err := storage.Open(ctx, filepath.Join(root, "ghost.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			manager := session.NewManager(store, tt.runner)
			value, _ := manager.Run(ctx, denyRequest(t, root))
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
			for _, required := range []events.Type{events.SessionStart, events.PolicyAllow, events.PolicyDeny, events.ProcessStart, events.SessionEnd} {
				if !hasEvent(storedEvents, required) {
					t.Errorf("missing event %s", required)
				}
			}
			if hasEvent(storedEvents, events.ProcessExit) != tt.wantProcessExit {
				t.Errorf("PROCESS_EXIT present = %v, want %v", hasEvent(storedEvents, events.ProcessExit), tt.wantProcessExit)
			}
		})
	}
}

func TestManagerPersistsActualDecoyAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, "ghost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runner := &fakeRuntime{run: func(request ghruntime.RunRequest) (ghruntime.RunResult, error) {
		if len(request.ShadowResources) != 3 {
			t.Fatalf("ShadowResources = %d, want 3", len(request.ShadowResources))
		}
		resource := request.ShadowResources[0]
		return ghruntime.RunResult{
			Started: true, ExitCode: 0,
			Accesses: []ghruntime.AccessEvidence{{
				DecoyID: resource.DecoyID, GuestPath: resource.GuestPath,
				DetectedAt: time.Now().UTC(), Events: "r",
			}},
		}, nil
	}}
	manager := session.NewManager(store, runner)
	request := denyRequest(t, root)
	request.HomePolicy = policy.HomeShadow
	request.DeceptionEnabled = true
	request.Resources = session.ResourcePolicy{AWSCredentials: true, SSHPrivateKey: true, EnvFile: true}
	request.RecordIncident = true
	request.IncidentSeverity = "high"
	value, err := manager.Run(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	decoys, err := store.Decoys(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoys) != 3 || !decoys[0].Triggered || decoys[1].Triggered || decoys[2].Triggered {
		t.Fatalf("decoys = %#v", decoys)
	}
	storedEvents, err := store.Events(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []events.Type{events.DecoyCreated, events.PolicyShadow, events.DecoyAccess, events.SecurityIncident} {
		if !hasEvent(storedEvents, required) {
			t.Errorf("missing event %s", required)
		}
	}
}

func TestDeceptionDisabledCreatesEmptyHomeAndDenyDecisions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, "ghost.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runner := &fakeRuntime{run: func(request ghruntime.RunRequest) (ghruntime.RunResult, error) {
		if len(request.ShadowResources) != 0 {
			t.Fatalf("disabled deception passed %d Shadow resources", len(request.ShadowResources))
		}
		entries, readErr := os.ReadDir(request.SyntheticHome)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("synthetic home is not empty: %v, %v", entries, readErr)
		}
		return ghruntime.RunResult{Started: true, ExitCode: 0}, nil
	}}
	request := denyRequest(t, root)
	request.HomePolicy = policy.HomeShadow
	request.DeceptionEnabled = false
	request.Resources = session.ResourcePolicy{AWSCredentials: true, SSHPrivateKey: true, EnvFile: true}
	value, err := session.NewManager(store, runner).Run(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	decoys, err := store.Decoys(ctx, value.ID)
	if err != nil || len(decoys) != 0 {
		t.Fatalf("decoys = %#v, %v", decoys, err)
	}
	eventValues, err := store.Events(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if hasEvent(eventValues, events.PolicyShadow) {
		t.Fatal("disabled deception emitted POLICY_SHADOW")
	}
}

func denyRequest(t *testing.T, root string) session.RunRequest {
	t.Helper()
	sessionsDir := filepath.Join(root, "sessions")
	if err := os.Mkdir(sessionsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return session.RunRequest{
		Runtime:     ghruntime.RunRequest{Command: []string{"test-command"}, Workspace: root},
		SessionsDir: sessionsDir, HomePolicy: policy.HomeDeny,
	}
}

func hasEvent(values []events.Event, eventType events.Type) bool {
	for _, value := range values {
		if value.Type == eventType {
			return true
		}
	}
	return false
}

func intPointer(value int) *int { return &value }

func equalIntPointer(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
