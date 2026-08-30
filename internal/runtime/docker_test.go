package runtime

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDockerArgumentsPreserveCommandAndSecurityBoundaries(t *testing.T) {
	t.Parallel()

	docker := &DockerRuntime{binary: "docker", image: DefaultDockerImage}
	command := []string{"printf", "%s %s", "hello world", "$(id)"}
	args := docker.arguments("/tmp/project", "/tmp/synthetic-home", RunRequest{Command: command})

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
	for _, required := range []string{"--network none", "--cap-drop ALL", "no-new-privileges", "--read-only", "destination=/workspace/.ghost", "dst=/home/ghost,readonly", "HOME=/home/ghost"} {
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
	home := t.TempDir()
	marker := filepath.Join(workspace, "host-executed")
	docker := &DockerRuntime{binary: "ghost-docker-definitely-missing", image: DefaultDockerImage}
	result, err := docker.Run(context.Background(), RunRequest{
		Workspace: workspace, SyntheticHome: home,
		Command: []string{"sh", "-c", "touch " + marker}, Stderr: &bytes.Buffer{},
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

func TestDockerArgumentsDoNotPropagateHostSecrets(t *testing.T) {
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "OPENAI_API_KEY",
		"ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN", "GH_TOKEN",
		"SSH_AUTH_SOCK", "DATABASE_URL",
	} {
		t.Setenv(name, "HOST_SECRET_SENTINEL")
	}
	args := (&DockerRuntime{image: DefaultDockerImage}).arguments("/tmp/project", "/tmp/home", RunRequest{Command: []string{"env"}})
	joined := strings.Join(args, "\n")
	if strings.Contains(joined, "HOST_SECRET_SENTINEL") {
		t.Fatal("Docker arguments contain a host secret value")
	}
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "OPENAI_API_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "DATABASE_URL"} {
		if strings.Contains(joined, name) {
			t.Errorf("Docker arguments propagate %s", name)
		}
	}
}

func TestSentinelArgumentsKeepSecurityBoundaries(t *testing.T) {
	docker := &DockerRuntime{image: DefaultDockerImage}
	request := RunRequest{
		SessionID: "safe_session",
		ShadowResources: []ShadowResource{{
			DecoyID: "dcy_one", GuestPath: "/home/ghost/.aws/credentials",
		}},
	}
	args := docker.sentinelArguments("ghost-sentinel-safe", "/tmp/home", "/tmp/sentinel", request)
	joined := strings.Join(args, " ")
	for _, required := range []string{"--network none", "--cap-drop ALL", "no-new-privileges", "--read-only", "ghost.component=sentinel", "/home/ghost/.aws/credentials:ra"} {
		if !strings.Contains(joined, required) {
			t.Errorf("sentinel arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network host", "/var/run/docker.sock", "/workspace", "ghost.db"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("sentinel arguments contain forbidden value %q: %s", forbidden, joined)
		}
	}
}

func TestShadowResourceValidationRejectsTraversal(t *testing.T) {
	tests := []string{"/home/ghost", "/home/ghost/../root/secret", "/etc/passwd", "relative"}
	for _, path := range tests {
		if err := validateShadowResources([]ShadowResource{{DecoyID: "dcy", GuestPath: path}}); err == nil {
			t.Errorf("accepted Shadow path %q", path)
		}
	}
}

func TestReadSentinelEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	data := "{\"kind\":\"barrier\"}\n{\"kind\":\"access\",\"path\":\"/home/ghost/.env\",\"events\":\"r\"}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := readSentinelEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[1].Kind != "access" || values[1].Path != "/home/ghost/.env" {
		t.Fatalf("events = %#v", values)
	}
}

func TestReadSentinelEventsIgnoresConcurrentPartialAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	data := "{\"kind\":\"barrier\"}\n{\"kind\":\"access\""
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := readSentinelEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Kind != "barrier" {
		t.Fatalf("events = %#v", values)
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
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker CLI unavailable: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, output)
	}

	workspace := t.TempDir()
	home := t.TempDir()
	var output bytes.Buffer
	result, err := NewDocker().Run(context.Background(), RunRequest{
		Workspace: workspace, SyntheticHome: home,
		Command: []string{"echo", "hello from ghost"}, Stdout: &output, Stderr: &output,
	})
	if err != nil {
		t.Fatalf("Docker integration: %v", err)
	}
	if result.ExitCode != 0 || !strings.Contains(output.String(), "hello from ghost") {
		t.Fatalf("result = %#v, output = %q", result, output.String())
	}
}
