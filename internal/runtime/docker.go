package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

const DefaultDockerImage = "alpine:3.22"

type DockerRuntime struct {
	binary string
	image  string
}

func NewDocker() *DockerRuntime {
	return &DockerRuntime{binary: "docker", image: DefaultDockerImage}
}

func (d *DockerRuntime) Name() string { return "docker" }

func (d *DockerRuntime) Run(ctx context.Context, request RunRequest) (RunResult, error) {
	if len(request.Command) == 0 {
		return RunResult{}, errors.New("no command provided")
	}
	workspace, err := validateWorkspaceExposure(request.Workspace)
	if err != nil {
		return RunResult{}, err
	}
	if err := d.available(ctx); err != nil {
		return RunResult{}, err
	}

	args := d.arguments(workspace, request)
	command := exec.CommandContext(ctx, d.binary, args...)
	command.Stdin = request.Stdin
	if request.Stdout != nil {
		command.Stdout = request.Stdout
	}
	var stderr bytes.Buffer
	if request.Stderr == nil {
		command.Stderr = &stderr
	} else {
		command.Stderr = io.MultiWriter(request.Stderr, &stderr)
	}

	err = command.Run()
	if err == nil {
		return RunResult{Started: true, ExitCode: 0}, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return RunResult{Started: true, ExitCode: 125}, fmt.Errorf("Docker execution interrupted: %w", ctxErr)
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return RunResult{}, fmt.Errorf("start Docker: %w", err)
	}
	exitCode := exitErr.ExitCode()
	result := RunResult{Started: true, ExitCode: exitCode}
	switch exitCode {
	case 125:
		result.Started = false
		return result, fmt.Errorf("Docker could not start the isolated command (exit 125): %s", lastMessage(stderr.String()))
	case 126:
		return result, fmt.Errorf("command cannot be invoked inside the Ghost container (exit 126): %s", request.Command[0])
	case 127:
		return result, fmt.Errorf("command not found inside the Ghost base image (exit 127): %s", request.Command[0])
	default:
		// A non-zero guest exit is a completed isolated execution, not a
		// runtime failure. The session manager records it as failed.
		return result, nil
	}
}

func validateWorkspaceExposure(workspace string) (string, error) {
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	realWorkspace, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve workspace symlinks: %w", err)
	}
	info, err := os.Stat(realWorkspace)
	if err != nil {
		return "", fmt.Errorf("inspect workspace: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("workspace is not a directory")
	}

	home, homeErr := trustedHomeDirectory()
	if homeErr == nil {
		if realHome, err := filepath.EvalSymlinks(home); err == nil {
			home = realHome
		}
		if pathContains(realWorkspace, home) {
			return "", errors.New("refusing to expose a workspace that contains the host home directory")
		}
	}

	socketCandidates := []string{"/var/run/docker.sock", "/run/docker.sock"}
	if homeErr == nil {
		socketCandidates = append(socketCandidates, filepath.Join(home, ".docker", "run", "docker.sock"))
	}
	if dockerHost := os.Getenv("DOCKER_HOST"); strings.HasPrefix(dockerHost, "unix://") {
		socketCandidates = append(socketCandidates, strings.TrimPrefix(dockerHost, "unix://"))
	}
	for _, socket := range socketCandidates {
		if _, err := os.Lstat(socket); err == nil && pathContains(realWorkspace, socket) {
			return "", fmt.Errorf("refusing to expose a workspace containing a Docker socket: %s", socket)
		}
	}
	return realWorkspace, nil
}

func trustedHomeDirectory() (string, error) {
	current, err := user.Current()
	if err == nil && current.HomeDir != "" {
		return current.HomeDir, nil
	}
	return os.UserHomeDir()
}

func pathContains(base, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func (d *DockerRuntime) available(ctx context.Context) error {
	if _, err := exec.LookPath(d.binary); err != nil {
		return errors.New("Docker CLI not found in PATH; install Docker and ensure it is available")
	}
	command := exec.CommandContext(ctx, d.binary, "info", "--format", "{{.ServerVersion}}")
	output, err := command.CombinedOutput()
	if err != nil {
		message := lastMessage(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("Docker daemon is unavailable: %s", message)
	}
	return nil
}

func (d *DockerRuntime) arguments(workspace string, request RunRequest) []string {
	workspaceMount := "type=bind,src=" + workspace + ",dst=/workspace"
	if request.WorkspaceReadOnly {
		workspaceMount += ",readonly"
	}

	args := []string{
		"run", "--rm", "--init", "--interactive",
		"--network", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "256",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
		"--mount", workspaceMount,
		// A tmpfs at the nested path masks host-side session data from the guest.
		"--mount", "type=tmpfs,destination=/workspace/.ghost,tmpfs-mode=0700",
		"--workdir", "/workspace",
		"--env", "HOME=/tmp",
	}
	if identity := numericUser(); identity != "" {
		args = append(args, "--user", identity)
	}
	args = append(args, d.image)
	return append(args, request.Command...)
}

var numericID = regexp.MustCompile(`^[0-9]+$`)

func numericUser() string {
	current, err := user.Current()
	if err != nil || !numericID.MatchString(current.Uid) || !numericID.MatchString(current.Gid) {
		return ""
	}
	return current.Uid + ":" + current.Gid
}

func lastMessage(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
