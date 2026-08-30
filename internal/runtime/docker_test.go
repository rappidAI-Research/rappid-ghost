package runtime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDockerArgumentsPreserveCommandAndSecurityBoundaries(t *testing.T) {
	t.Parallel()

	docker := &DockerRuntime{binary: "docker", image: DefaultDockerImage}
	command := []string{"printf", "%s %s", "hello world", "$(id)"}
	args := docker.arguments("/tmp/project", RunRequest{Command: command})

	imageIndex := -1
	for i, arg := range args {
		if arg == DefaultDockerImage {
			imageIndex = i
			break
		}
	}
	if imageIndex < 0 {
		t.Fatal("Docker image missing from arguments")
	}
	if got := args[imageIndex+1:]; !reflect.DeepEqual(got, command) {
		t.Fatalf("guest command = %#v, want %#v", got, command)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"--network none", "--cap-drop ALL", "no-new-privileges", "--read-only", "destination=/workspace/.ghost"} {
		if !strings.Contains(joined, required) {
			t.Errorf("Docker arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network host", "/var/run/docker.sock"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("Docker arguments contain forbidden value %q: %s", forbidden, joined)
		}
	}
}

func TestMissingDockerNeverFallsBackToHostExecution(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	marker := filepath.Join(workspace, "host-executed")
	docker := &DockerRuntime{binary: "ghost-docker-definitely-missing", image: DefaultDockerImage}
	result, err := docker.Run(context.Background(), RunRequest{
		Workspace: workspace,
		Command:   []string{"sh", "-c", "touch " + marker},
		Stderr:    &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "Docker CLI not found") {
		t.Fatalf("Run error = %v, want missing Docker error", err)
	}
	if result.Started {
		t.Fatal("result incorrectly reports a started process")
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("host command appears to have executed: %v", statErr)
	}
}

func TestWorkspaceExposureValidation(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("home directory unavailable: %v", err)
	}
	if _, err := validateWorkspaceExposure(home); err == nil || !strings.Contains(err.Error(), "host home") {
		t.Fatalf("home workspace error = %v, want refusal", err)
	}

	workspace := t.TempDir()
	socket := filepath.Join(workspace, "docker.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+socket)
	if _, err := validateWorkspaceExposure(workspace); err == nil || !strings.Contains(err.Error(), "Docker socket") {
		t.Fatalf("socket workspace error = %v, want refusal", err)
	}
}

func TestDockerIntegration(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 to run Docker integration tests")
	}

	workspace := t.TempDir()
	var output bytes.Buffer
	result, err := NewDocker().Run(context.Background(), RunRequest{
		Workspace: workspace,
		Command:   []string{"echo", "hello from ghost"},
		Stdout:    &output,
		Stderr:    &output,
	})
	if err != nil {
		t.Fatalf("Docker integration: %v", err)
	}
	if result.ExitCode != 0 || !strings.Contains(output.String(), "hello from ghost") {
		t.Fatalf("result = %#v, output = %q", result, output.String())
	}
}
