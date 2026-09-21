package runtime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This subprocess models only the Docker API contract. Security/enforcement
// properties are additionally exercised against the real unmodified daemon.
func TestDockerExecHelper(t *testing.T) {
	root := os.Getenv("GHOST_DOCKER_HELPER_DIR")
	if root == "" {
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(os.Stdin))
	if err != nil {
		os.Exit(2)
	}
	id, container := strings.Repeat("2", 64), strings.Repeat("0", 63)+"1"
	statePath := filepath.Join(root, "exec-state")
	respond := func(value any) {
		data, _ := json.Marshal(value)
		fmt.Fprintf(os.Stdout, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(data), data)
	}
	if strings.HasSuffix(request.URL.Path, "/exec") {
		var config dockerExecConfig
		if json.NewDecoder(request.Body).Decode(&config) != nil {
			os.Exit(2)
		}
		data, _ := json.Marshal(config)
		if os.WriteFile(filepath.Join(root, "exec-config"), data, 0600) != nil {
			os.Exit(2)
		}
		respond(map[string]string{"ID": id})
	} else if strings.HasSuffix(request.URL.Path, "/start") {
		_, _ = io.Copy(io.Discard, request.Body)
		state := dockerExecState{ID: id, ContainerID: container, Running: true, Pid: 777, ExitCode: new(int)}
		writeState := func() {
			data, _ := json.Marshal(state)
			if os.WriteFile(statePath, data, 0600) != nil {
				os.Exit(2)
			}
		}
		writeState()
		fmt.Print("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		var mu sync.Mutex
		command := exec.Command("sh", filepath.Join(root, "agent"))
		command.Stdout = testDockerFrameWriter{&mu, 1}
		command.Stderr = testDockerFrameWriter{&mu, 2}
		err := command.Run()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			os.Exit(2)
		}
		state.Running = false
		state.ExitCode = &code
		writeState()
		if _, err := os.Stat(filepath.Join(root, "broken-stream")); err == nil {
			fmt.Print("bad")
			os.Exit(1)
		}
	} else if strings.HasSuffix(request.URL.Path, "/json") {
		data, err := os.ReadFile(statePath)
		if err != nil {
			os.Exit(2)
		}
		var state dockerExecState
		if json.Unmarshal(data, &state) != nil {
			os.Exit(2)
		}
		respond(state)
	} else {
		os.Exit(2)
	}
	os.Exit(0)
}

type testDockerFrameWriter struct {
	mu     *sync.Mutex
	stream byte
}

func (w testDockerFrameWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var header [8]byte
	header[0] = w.stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
	if _, err := os.Stdout.Write(header[:]); err != nil {
		return 0, err
	}
	return os.Stdout.Write(data)
}

func TestKernelOOMCounterRequiresObservedKill(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		count uint64
		valid bool
	}{
		{"low 0\nhigh 0\nmax 19\noom 1\noom_kill 0\noom_group_kill 0\n", 0, true},
		{"oom_kill 1\n", 1, true}, {"oom_kill 17\n", 17, true},
		{"oom_kill_disable 0\nunder_oom 0\noom_kill 1\n", 1, true},
		{"exit 137\n", 0, false}, {"oom_kill -1\n", 0, false}, {"oom_kill +1\n", 0, false},
		{"oom_kill 18446744073709551616\n", 0, false}, {"oom_kill 0\noom_kill 1\n", 0, false},
		{"oom_kill 1\n" + strings.Repeat(" ", 4096), 0, false}, {"", 0, false},
	} {
		count, err := parseOOMCounter([]byte(tc.raw))
		if (err == nil) != tc.valid || count != tc.count {
			t.Fatalf("%q => %d %v", tc.raw, count, err)
		}
	}
}

func TestKeeperIdentityCannotMatchAgent(t *testing.T) {
	for _, agent := range []string{"1000:1000", "65534:65534", "65533:1"} {
		keeper := keeperIdentity(agent)
		if strings.Split(keeper, ":")[0] == strings.Split(agent, ":")[0] || strings.HasPrefix(keeper, "0:") {
			t.Fatalf("unsafe keeper %s for %s", keeper, agent)
		}
	}
}

func TestDockerStreamRejectsMalformedAndTruncatedFrames(t *testing.T) {
	for _, raw := range [][]byte{[]byte("bad"), {3, 0, 0, 0, 0, 0, 0, 0}, {1, 1, 0, 0, 0, 0, 0, 0}, {1, 0, 0, 0, 255, 255, 255, 255}} {
		if err := copyDockerStream(bytes.NewReader(raw), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted invalid frame %v", raw)
		}
	}
	var out, errout bytes.Buffer
	raw := []byte{1, 0, 0, 0, 0, 0, 0, 2, 'o', 'k', 2, 0, 0, 0, 0, 0, 0, 3, 'e', 'r', 'r'}
	if err := copyDockerStream(bytes.NewReader(raw), &out, &errout); err != nil || out.String() != "ok" || errout.String() != "err" {
		t.Fatalf("stream %q %q %v", out.String(), errout.String(), err)
	}
}

func TestKernelCounterFailurePreventsAgentLaunch(t *testing.T) {
	for _, counter := range []string{"", "oom_kill 1\n", "oom_kill -1\n"} {
		marker := filepath.Join(t.TempDir(), "launched")
		script := controlledDocker(t, "touch '"+marker+"'", "")
		if err := os.WriteFile(filepath.Join(filepath.Dir(script), "counter"), []byte(counter), 0600); err != nil {
			t.Fatal(err)
		}
		result, err := (&DockerRuntime{binary: script, image: DefaultDockerImage}).runAgent(context.Background(), t.TempDir(), t.TempDir(), RunRequest{Command: []string{"true"}}, nil, "1000:1000")
		if err == nil || result.Started {
			t.Fatalf("unsafe launch: %+v %v", result, err)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("agent launched without fresh counter")
		}
	}
}

func TestKernelOOMSurvivesAbsentDaemonNotification(t *testing.T) {
	script := controlledDocker(t, "exit 0", "")
	root := filepath.Dir(script)
	// Neither State.OOMKilled nor Docker events report this controlled kill.
	content := "printf 'oom_kill 1\\n' > '" + filepath.Join(root, "counter") + "'; exit 0"
	if err := os.WriteFile(filepath.Join(root, "agent"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := (&DockerRuntime{binary: script, image: DefaultDockerImage}).runAgent(context.Background(), t.TempDir(), t.TempDir(), RunRequest{Command: []string{"true"}}, nil, "1000:1000")
	if err == nil || result.ExitCode != 0 || !result.Started || !hasResource(result, ResourceOOM) {
		t.Fatalf("lost kernel evidence: %+v %v", result, err)
	}
}

func TestExecInputWaitsForUpgradeAndCancelsQuietFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := (execStdin{ctx: ctx, ready: ready, source: input}).Read(make([]byte, 32))
		done <- err
	}()
	close(ready)
	cancel()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("quiet stdin did not cancel")
	}
	// No data may be read or half-closed before the upgrade handshake.
	ctx2, cancel2 := context.WithCancel(context.Background())
	ready2 := make(chan struct{})
	reader := execStdin{ctx: ctx2, ready: ready2, source: strings.NewReader("secret input")}
	cancel2()
	if n, err := reader.Read(make([]byte, 32)); n != 0 || err != io.EOF {
		t.Fatalf("pre-upgrade input: %d %v", n, err)
	}
}
