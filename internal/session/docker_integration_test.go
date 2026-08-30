package session_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

func TestDockerShadowIntegration(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 to run Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker CLI unavailable: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, output)
	}

	t.Run("Shadow AWS access produces evidence", func(t *testing.T) {
		result := runDockerSession(t, policy.HomeShadow, true, []string{"sh", "-c", `cat "$HOME/.aws/credentials"`})
		if result.value.Status != session.Completed || !strings.Contains(result.output, "GHOST_AWS_") {
			t.Fatalf("status = %s, output = %q", result.value.Status, result.output)
		}
		aws := findDecoy(t, result.decoys, deception.AWSCredentials)
		if !aws.Triggered {
			t.Fatal("AWS decoy was accessed but is not triggered")
		}
		for _, eventType := range []events.Type{events.DecoyAccess, events.SecurityIncident} {
			if !hasEvent(result.events, eventType) {
				t.Errorf("missing event %s", eventType)
			}
		}
	})

	t.Run("untouched decoys remain untriggered", func(t *testing.T) {
		result := runDockerSession(t, policy.HomeShadow, true, []string{"echo", "safe"})
		if len(result.decoys) != 3 {
			t.Fatalf("decoys = %d, want 3", len(result.decoys))
		}
		for _, decoy := range result.decoys {
			if decoy.Triggered {
				t.Errorf("untouched decoy %s was falsely triggered", decoy.GuestPath)
			}
		}
		if hasEvent(result.events, events.DecoyAccess) || hasEvent(result.events, events.SecurityIncident) {
			t.Fatal("safe command produced decoy access evidence")
		}
	})

	t.Run("deny home exposes no AWS resource", func(t *testing.T) {
		result := runDockerSession(t, policy.HomeDeny, true, []string{"sh", "-c", `test ! -e "$HOME/.aws/credentials"`})
		if result.value.Status != session.Completed || len(result.decoys) != 0 {
			t.Fatalf("status = %s, decoys = %d, output = %q", result.value.Status, len(result.decoys), result.output)
		}
	})

	t.Run("host secret environment is not inherited", func(t *testing.T) {
		for _, name := range []string{
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "OPENAI_API_KEY",
			"ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
			"SSH_AUTH_SOCK", "DATABASE_URL",
		} {
			t.Setenv(name, "HOST_SECRET_SENTINEL")
		}
		result := runDockerSession(t, policy.HomeDeny, false, []string{"env"})
		if result.value.Status != session.Completed {
			t.Fatalf("status = %s, output = %q", result.value.Status, result.output)
		}
		if strings.Contains(result.output, "HOST_SECRET_SENTINEL") {
			t.Fatalf("guest environment contains a host secret: %q", result.output)
		}
	})
}

type dockerSessionResult struct {
	value  session.Session
	output string
	decoys []deception.Decoy
	events []events.Event
}

func runDockerSession(t *testing.T, homePolicy string, deceptionEnabled bool, command []string) dockerSessionResult {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	runtimeDir := filepath.Join(root, config.RuntimeDirName)
	sessionsDir := filepath.Join(runtimeDir, config.SessionsDir)
	if err := os.MkdirAll(sessionsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(ctx, filepath.Join(runtimeDir, config.DatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var output bytes.Buffer
	request := session.RunRequest{
		Runtime: ghruntime.RunRequest{
			Command: command, Workspace: root, Stdout: &output, Stderr: &output,
		},
		SessionsDir: sessionsDir, HomePolicy: homePolicy, DeceptionEnabled: deceptionEnabled,
		Resources:        session.ResourcePolicy{AWSCredentials: true, SSHPrivateKey: true, EnvFile: true},
		IncidentSeverity: "high", RecordIncident: true,
	}
	value, runErr := session.NewManager(store, ghruntime.NewDocker()).Run(ctx, request)
	if runErr != nil {
		t.Fatalf("Run() error = %v, output = %q", runErr, output.String())
	}
	decoys, err := store.Decoys(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	eventValues, err := store.Events(ctx, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	return dockerSessionResult{value: value, output: output.String(), decoys: decoys, events: eventValues}
}

func findDecoy(t *testing.T, values []deception.Decoy, decoyType deception.Type) deception.Decoy {
	t.Helper()
	for _, value := range values {
		if value.Type == decoyType {
			return value
		}
	}
	t.Fatalf("decoy type %s not found", decoyType)
	return deception.Decoy{}
}
