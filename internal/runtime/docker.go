package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultDockerImage = "alpine:3.22"
	guestHome          = "/home/ghost"
	guestPath          = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

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
	home, err := validateSyntheticHome(request.SyntheticHome)
	if err != nil {
		return RunResult{}, err
	}
	if err := validateShadowResources(request.ShadowResources); err != nil {
		return RunResult{}, err
	}
	if err := d.available(ctx); err != nil {
		return RunResult{}, err
	}

	var sentinel *sentinelProcess
	if len(request.ShadowResources) > 0 {
		sentinel, err = d.startSentinel(ctx, request, home)
		if err != nil {
			return RunResult{}, err
		}
		defer func() {
			if sentinel != nil {
				_ = sentinel.stop()
			}
		}()
	}

	result, runErr := d.runAgent(ctx, workspace, home, request)
	if sentinel != nil {
		accesses, evidenceErr := sentinel.finish(request.ShadowResources)
		result.Accesses = accesses
		cleanupErr := sentinel.stop()
		sentinel = nil
		if evidenceErr != nil {
			if runErr != nil {
				return result, fmt.Errorf("%v; collect decoy access evidence: %w", runErr, evidenceErr)
			}
			return result, fmt.Errorf("collect decoy access evidence: %w", evidenceErr)
		}
		if cleanupErr != nil {
			return result, cleanupErr
		}
	}
	return result, runErr
}

func (d *DockerRuntime) runAgent(ctx context.Context, workspace, home string, request RunRequest) (RunResult, error) {
	args := d.arguments(workspace, home, request)
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

	err := command.Run()
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

func validateSyntheticHome(home string) (string, error) {
	if home == "" {
		return "", errors.New("synthetic home is required; refusing to expose any implicit home")
	}
	absolute, err := filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("resolve synthetic home: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect synthetic home: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("synthetic home must be a real directory")
	}
	return absolute, nil
}

func validateShadowResources(resources []ShadowResource) error {
	seen := make(map[string]bool, len(resources))
	for _, resource := range resources {
		if resource.DecoyID == "" || resource.GuestPath == "" {
			return errors.New("invalid Shadow resource")
		}
		clean := filepath.ToSlash(filepath.Clean(resource.GuestPath))
		if clean == guestHome || !strings.HasPrefix(clean, guestHome+"/") {
			return fmt.Errorf("Shadow path escapes synthetic home: %q", resource.GuestPath)
		}
		if seen[clean] {
			return fmt.Errorf("duplicate Shadow path: %q", clean)
		}
		seen[clean] = true
	}
	return nil
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

func (d *DockerRuntime) arguments(workspace, home string, request RunRequest) []string {
	workspaceMount := "type=bind,src=" + workspace + ",dst=/workspace"
	if request.WorkspaceReadOnly {
		workspaceMount += ",readonly"
	}
	homeMount := "type=bind,src=" + home + ",dst=" + guestHome + ",readonly"
	args := []string{
		"run", "--rm", "--init", "--interactive",
		"--network", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "256",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
		"--mount", workspaceMount,
		"--mount", "type=tmpfs,destination=/workspace/.ghost,tmpfs-mode=0700",
		"--mount", homeMount,
		"--workdir", "/workspace",
		"--env", "HOME=" + guestHome,
		"--env", "PATH=" + guestPath,
	}
	if identity := numericUser(); identity != "" {
		args = append(args, "--user", identity)
	}
	args = append(args, d.image)
	return append(args, request.Command...)
}

type sentinelProcess struct {
	binary      string
	name        string
	eventsPath  string
	controlPath string
	barriers    int
}

type sentinelEvent struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Events string `json:"events,omitempty"`
}

const sentinelHandler = `#!/bin/sh
events="$1"
watched="$2"
if [ "$watched" = "/run/ghost/control" ]; then
  printf '%s\n' '{"kind":"barrier"}' >> /run/ghost/events.jsonl
  exit 0
fi
case "$events" in
  *r*|*a*) printf '{"kind":"access","path":"%s","events":"%s"}\n' "$watched" "$events" >> /run/ghost/events.jsonl ;;
esac
`

func (d *DockerRuntime) startSentinel(ctx context.Context, request RunRequest, home string) (*sentinelProcess, error) {
	if request.SessionID == "" || request.SessionDir == "" {
		return nil, errors.New("session identity is required for Shadow monitoring")
	}
	if !safeContainerComponent.MatchString(request.SessionID) {
		return nil, errors.New("invalid session identity for Shadow monitoring")
	}
	sessionDir, err := filepath.Abs(request.SessionDir)
	if err != nil || sessionDir != filepath.Dir(home) {
		return nil, errors.New("sentinel directory must belong to the synthetic-home session")
	}
	sessionInfo, err := os.Lstat(sessionDir)
	if err != nil || !sessionInfo.IsDir() || sessionInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("sentinel session path must be a real directory")
	}
	sentinelDir := filepath.Join(sessionDir, "sentinel")
	if err := os.Mkdir(sentinelDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sentinel directory: %w", err)
	}
	handlerPath := filepath.Join(sentinelDir, "handler")
	controlPath := filepath.Join(sentinelDir, "control")
	eventsPath := filepath.Join(sentinelDir, "events.jsonl")
	if err := writeExclusive(handlerPath, []byte(sentinelHandler), 0o700); err != nil {
		return nil, fmt.Errorf("create sentinel handler: %w", err)
	}
	if err := writeExclusive(controlPath, nil, 0o600); err != nil {
		return nil, fmt.Errorf("create sentinel control: %w", err)
	}
	if err := writeExclusive(eventsPath, nil, 0o600); err != nil {
		return nil, fmt.Errorf("create sentinel event log: %w", err)
	}

	name := "ghost-sentinel-" + strings.ToLower(request.SessionID)
	args := d.sentinelArguments(name, home, sentinelDir, request)
	command := exec.CommandContext(ctx, d.binary, args...)
	if output, err := command.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("start Shadow sentinel: %s", lastMessage(string(output)))
	}

	process := &sentinelProcess{binary: d.binary, name: name, eventsPath: eventsPath, controlPath: controlPath}
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := process.barrier(readyCtx); err != nil {
		_ = process.stop()
		return nil, fmt.Errorf("Shadow sentinel readiness: %w", err)
	}
	return process, nil
}

func (d *DockerRuntime) sentinelArguments(name, home, sentinelDir string, request RunRequest) []string {
	homeMount := "type=bind,src=" + home + ",dst=" + guestHome + ",readonly"
	sentinelMount := "type=bind,src=" + sentinelDir + ",dst=/run/ghost"
	args := []string{
		"run", "--detach", "--name", name,
		"--label", "ghost.component=sentinel",
		"--label", "ghost.session=" + request.SessionID,
		"--network", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "32",
		"--read-only",
		"--mount", homeMount,
		"--mount", sentinelMount,
		"--env", "HOME=" + guestHome,
		"--env", "PATH=" + guestPath,
	}
	if identity := numericUser(); identity != "" {
		args = append(args, "--user", identity)
	}
	args = append(args, d.image, "inotifyd", "/run/ghost/handler", "/run/ghost/control:c")
	for _, resource := range request.ShadowResources {
		args = append(args, resource.GuestPath+":ra")
	}
	return args
}

func (s *sentinelProcess) finish(resources []ShadowResource) ([]AccessEvidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.barrier(ctx); err != nil {
		return nil, err
	}
	events, err := readSentinelEvents(s.eventsPath)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]ShadowResource, len(resources))
	for _, resource := range resources {
		byPath[resource.GuestPath] = resource
	}
	seen := make(map[string]bool, len(resources))
	accesses := make([]AccessEvidence, 0)
	for _, event := range events {
		if event.Kind != "access" || seen[event.Path] {
			continue
		}
		resource, ok := byPath[event.Path]
		if !ok {
			continue
		}
		seen[event.Path] = true
		accesses = append(accesses, AccessEvidence{
			DecoyID: resource.DecoyID, GuestPath: resource.GuestPath,
			DetectedAt: time.Now().UTC(), Events: event.Events,
		})
	}
	return accesses, nil
}

func (s *sentinelProcess) barrier(ctx context.Context) error {
	target := s.barriers + 1
	if err := s.signal(); err != nil {
		return err
	}
	pollTicker := time.NewTicker(10 * time.Millisecond)
	retryTicker := time.NewTicker(100 * time.Millisecond)
	defer pollTicker.Stop()
	defer retryTicker.Stop()
	for {
		events, readErr := readSentinelEvents(s.eventsPath)
		if readErr != nil {
			return readErr
		}
		count := 0
		for _, event := range events {
			if event.Kind == "barrier" {
				count++
			}
		}
		if count >= target {
			s.barriers = count
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for sentinel barrier: %w", ctx.Err())
		case <-retryTicker.C:
			// Docker reports a detached container before its process has
			// necessarily installed every watch. Re-signal until the first
			// barrier proves inotifyd is ready; the agent starts only afterward.
			if err := s.signal(); err != nil {
				return err
			}
		case <-pollTicker.C:
		}
	}
}

func (s *sentinelProcess) signal() error {
	file, err := os.OpenFile(s.controlPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open sentinel control: %w", err)
	}
	if _, err := file.WriteString("\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("signal sentinel: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close sentinel control: %w", err)
	}
	return nil
}

func (s *sentinelProcess) stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, s.binary, "rm", "--force", s.name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove Shadow sentinel: %s", lastMessage(string(output)))
	}
	return nil
}

func readSentinelEvents(path string) ([]sentinelEvent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open sentinel event log: %w", err)
	}
	var result []sentinelEvent
	lines := bytes.Split(data, []byte("\n"))
	complete := len(data) == 0 || data[len(data)-1] == '\n'
	for index, line := range lines {
		if len(line) == 0 {
			continue
		}
		// A concurrent append can expose a trailing partial line. It is
		// retried on the next poll; complete malformed records fail closed.
		if index == len(lines)-1 && !complete {
			continue
		}
		var event sentinelEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode sentinel event: %w", err)
		}
		result = append(result, event)
	}
	return result, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := file.Write(data); err != nil {
			_ = file.Close()
			return err
		}
	}
	return file.Close()
}

var (
	numericID              = regexp.MustCompile(`^[0-9]+$`)
	safeContainerComponent = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

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
