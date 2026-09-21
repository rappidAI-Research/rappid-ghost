package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The CLI owns daemon connection/authentication (including TLS, SSH contexts
// and rootless sockets). Its raw stdio transport lets us retain an exec ID
// without introducing a second Docker connection configuration or SDK.
// Unversioned routes use the daemon's current API; these exec fields are stable.
func dockerRequest(method, path string, body any, upgrade bool) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(method, "http://docker"+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Close = !upgrade
	if upgrade {
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "tcp")
	}
	var raw bytes.Buffer
	if err := request.Write(&raw); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}

func (d *DockerRuntime) dockerJSON(ctx context.Context, method, path string, body, result any) error {
	raw, err := dockerRequest(method, path, body, false)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, d.binary, "system", "dial-stdio")
	command.WaitDelay = time.Second
	command.Stdin = bytes.NewReader(raw)
	command.Stderr = io.Discard
	var output oomOutput // 64 KiB bound applies while reading, not afterwards.
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("Docker API transport failed: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(output.Bytes())), nil)
	if err != nil {
		return errors.New("Docker returned an invalid API response")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Docker API request failed (HTTP %d)", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return errors.New("Docker returned invalid execution metadata")
	}
	return nil
}

type dockerExecConfig struct {
	Cmd                                     []string
	User, WorkingDir                        string
	AttachStdin, AttachStdout, AttachStderr bool
	Tty, Privileged                         bool
}

func agentExecConfig(request RunRequest, identity string) dockerExecConfig {
	return dockerExecConfig{Cmd: append([]string(nil), request.Command...), User: identity, WorkingDir: "/workspace", AttachStdin: request.Stdin != nil, AttachStdout: true, AttachStderr: true}
}

func (d *DockerRuntime) createExec(ctx context.Context, container string, config dockerExecConfig) (string, error) {
	var created struct{ ID string }
	if err := d.dockerJSON(ctx, "POST", "/containers/"+container+"/exec", config, &created); err != nil {
		return "", err
	}
	if !containerIDPattern.MatchString(created.ID) {
		return "", errors.New("Docker returned an invalid execution identity")
	}
	return created.ID, nil
}

type dockerExecState struct {
	ID, ContainerID string
	Running         bool
	ExitCode        *int
	Pid             int
}

func (d *DockerRuntime) inspectExec(ctx context.Context, container, id string) (dockerExecState, error) {
	var state dockerExecState
	err := d.dockerJSON(ctx, "GET", "/exec/"+id+"/json", nil, &state)
	if err == nil && (state.ID != id || state.ContainerID != container || state.Pid < 0 || (!state.Running && state.ExitCode == nil) || (state.ExitCode != nil && (*state.ExitCode < 0 || *state.ExitCode > 255))) {
		err = errors.New("Docker returned inconsistent execution state")
	}
	return state, err
}

// Read only a bounded HTTP header before handing the remaining stream to the
// Docker multiplex decoder. Guest output is streamed but never used in errors.
func readExecHeader(reader *bufio.Reader) error {
	var header bytes.Buffer
	for header.Len() < 16*1024 {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return errors.New("invalid Docker execution response header")
		}
		header.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			response, err := http.ReadResponse(bufio.NewReader(&header), nil)
			if err != nil || response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "tcp") {
				return errors.New("Docker refused the execution stream")
			}
			return nil
		}
	}
	return errors.New("Docker execution header exceeds its bound")
}

func copyDockerStream(reader io.Reader, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	for {
		var header [8]byte
		_, err := io.ReadFull(reader, header[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("truncated Docker execution stream")
		}
		if header[1] != 0 || header[2] != 0 || header[3] != 0 || (header[0] != 1 && header[0] != 2) {
			return errors.New("invalid Docker execution stream")
		}
		target := stdout
		if header[0] == 2 {
			target = stderr
		}
		// CopyN uses bounded chunks even for a hostile advertised frame length.
		if _, err := io.CopyN(target, reader, int64(binary.BigEndian.Uint32(header[4:]))); err != nil {
			return errors.New("incomplete Docker execution output")
		}
	}
}

func (d *DockerRuntime) attachExec(ctx context.Context, id string, request RunRequest) error {
	raw, err := dockerRequest("POST", "/exec/"+id+"/start", struct{ Detach, Tty bool }{}, true)
	if err != nil {
		return err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(streamCtx, d.binary, "system", "dial-stdio")
	command.WaitDelay = time.Second
	command.Stderr = io.Discard
	inputCtx, cancelInput := context.WithCancel(ctx)
	defer cancelInput()
	ready := make(chan struct{})
	command.Stdin = io.MultiReader(bytes.NewReader(raw), execStdin{ctx: inputCtx, ready: ready, source: request.Stdin})
	// A terminal approval mux supplies a pipe owned by this session. Unblock a
	// pending pipe read when the execution stream closes; never close os.Stdin.
	if pipe, ok := request.Stdin.(*io.PipeReader); ok {
		stop := context.AfterFunc(inputCtx, func() { _ = pipe.Close() })
		defer stop()
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Docker execution stream: %w", err)
	}
	reader := bufio.NewReader(output)
	streamErr := readExecHeader(reader)
	if streamErr == nil {
		close(ready) // Docker discards bytes sent before its HTTP hijack completes.
		streamErr = copyDockerStream(reader, request.Stdout, request.Stderr)
	}
	if streamErr != nil {
		cancel()
	}
	cancelInput()
	waitErr := command.Wait()
	if streamErr != nil {
		return streamErr
	}
	if waitErr != nil {
		return fmt.Errorf("Docker execution transport failed: %w", waitErr)
	}
	return nil
}

// A distinct, non-root identity prevents the agent from killing the keeper or
// forging probe output through /proc/<pid>/fd. No extra capability is granted.
func keeperIdentity(agent string) string {
	if strings.SplitN(agent, ":", 2)[0] == "65534" {
		return "65533:65533"
	}
	return "65534:65534"
}

const memoryCounterCommand = `if [ -r /sys/fs/cgroup/memory.events ]; then exec /bin/cat /sys/fs/cgroup/memory.events; else exec /bin/cat /sys/fs/cgroup/memory/memory.oom_control; fi`

func (d *DockerRuntime) memoryOOMCount(ctx context.Context, container, identity string) (uint64, error) {
	command := exec.CommandContext(ctx, d.binary, "exec", "--user", keeperIdentity(identity), "--workdir", "/", container, "/bin/sh", "-c", memoryCounterCommand)
	command.WaitDelay = time.Second
	command.Stderr = io.Discard
	var output oomOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return 0, fmt.Errorf("read container kernel OOM counter: %w", err)
	}
	return parseOOMCounter(output.Bytes())
}

func parseOOMCounter(data []byte) (uint64, error) {
	if len(data) > 4096 {
		return 0, errors.New("container OOM counter exceeds its bound")
	}
	seen := make(map[string]bool)
	var count uint64
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] {
			return 0, errors.New("invalid container OOM counter")
		}
		seen[fields[0]] = true
		for _, c := range fields[1] {
			if c < '0' || c > '9' {
				return 0, errors.New("invalid container OOM counter")
			}
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, errors.New("invalid container OOM counter")
		}
		if fields[0] == "oom_kill" {
			count = value
		}
	}
	if !seen["oom_kill"] {
		return 0, errors.New("container does not expose a kernel OOM kill counter")
	}
	return count, nil
}

func (d *DockerRuntime) waitExec(ctx context.Context, container, id string) error {
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		state, err := d.inspectExec(probeCtx, container, id)
		cancel()
		if err != nil {
			return err
		}
		if !state.Running {
			return nil
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (d *DockerRuntime) signalAgent(container, identity string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, d.binary, "exec", "--user", identity, "--workdir", "/", container, "/bin/kill", "-TERM", "-1")
	command.WaitDelay = time.Second
	// Failure to create the signal process (e.g. PID saturation) is followed by
	// mandatory bounded stop/kill. Never retry with a larger resource boundary.
	_ = command.Run()
}

// File input is polled so a quiet interactive terminal cannot hold command.Wait
// or a copier goroutine after execution ends. Other session readers retain the
// usual io.Reader contract; session-owned approval pipes are closed above.
type execStdin struct {
	ctx    context.Context
	ready  <-chan struct{}
	source io.Reader
}

func (r execStdin) Read(data []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, io.EOF
	case <-r.ready:
	}
	if r.source == nil {
		return 0, io.EOF
	}
	if file, ok := r.source.(*os.File); ok {
		for {
			if r.ctx.Err() != nil {
				return 0, io.EOF
			}
			fds := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 50)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return 0, err
			}
			if n == 0 {
				continue
			}
			if fds[0].Revents&unix.POLLNVAL != 0 {
				return 0, os.ErrClosed
			}
			return file.Read(data)
		}
	}
	n, err := r.source.Read(data)
	if r.ctx.Err() != nil {
		return 0, io.EOF
	}
	return n, err
}
