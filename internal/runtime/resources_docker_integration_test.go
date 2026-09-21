package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func requireResourceDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 for real Docker tests")
	}
	if err := NewDocker().available(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func resourceDockerRequest(t *testing.T) RunRequest {
	t.Helper()
	limits := DefaultLimits()
	limits.TimeoutSeconds = 20
	limits.GraceSeconds = 1
	return RunRequest{Workspace: t.TempDir(), SyntheticHome: t.TempDir(), SessionID: fmt.Sprintf("resources_%d", time.Now().UnixNano()), Limits: &limits}
}

func assertAgentRemoved(t *testing.T, request RunRequest) {
	t.Helper()
	output, err := exec.Command("docker", "inspect", "ghost-agent-"+request.SessionID).CombinedOutput()
	if err == nil || !dockerObjectMissing(output) {
		t.Fatalf("container tree was not removed: %s %v", output, err)
	}
}

func buildResourceFixture(t *testing.T, workspace string) {
	t.Helper()
	output, err := exec.Command("cc", "-static", "-O0", "-o", filepath.Join(workspace, "resource-fixture"), "testdata/resource_fixture.c").CombinedOutput()
	if err != nil {
		t.Fatalf("compile bounded container-only fixture: %s %v", output, err)
	}
}

func hasResource(result RunResult, kind string) bool {
	for _, e := range result.Resources {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestDockerResourceChildBoundariesAndTemporaryStorage(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Limits.TmpMiB = 1
	request.Command = []string{"sh", "-c", `set -eu
# Read actual cgroup values from a child, not only Docker configuration.
sh -c '
if [ -f /sys/fs/cgroup/memory.max ]; then
 [ "$(cat /sys/fs/cgroup/memory.max)" = 2147483648 ]
 [ "$(cat /sys/fs/cgroup/memory.swap.max)" = 0 ]
 [ "$(cat /sys/fs/cgroup/pids.max)" = 256 ]
 [ "$(cat /sys/fs/cgroup/cpu.max)" = "100000 100000" ]
else
 [ "$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)" = 2147483648 ]
 [ "$(cat /sys/fs/cgroup/pids/pids.max)" = 256 ]
fi'
grep -Eq '^Seccomp:[[:space:]]+2' /proc/self/status
if dd if=/dev/zero of=/tmp/too-large bs=1048576 count=2 2>/dev/null; then exit 10; fi
rm -f /tmp/too-large
if touch /etc/forbidden 2>/dev/null; then exit 11; fi
printf 'normal workspace development\n' > /workspace/generated.txt
printf 'hello from ghost\n'`}
	var output bytes.Buffer
	request.Stdout = &output
	request.Stderr = &output
	result, err := NewDocker().Run(context.Background(), request)
	if err != nil || result.ExitCode != 0 || !strings.Contains(output.String(), "hello from ghost") {
		t.Fatalf("normal/child/tmpfs checks: %+v %v %s", result, err, output.String())
	}
	if len(result.Resources) != 0 {
		t.Fatalf("invented resource evidence: %+v", result)
	}
	assertAgentRemoved(t, request)
}

func TestDockerResourcePIDGrowthIsContained(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Limits.PIDs = 16
	buildResourceFixture(t, request.Workspace)
	request.Command = []string{"/workspace/resource-fixture", "pids"}
	result, err := NewDocker().Run(context.Background(), request)
	if err == nil || !hasResource(result, ResourcePIDs) {
		t.Fatalf("PID saturation did not terminate safely: %+v %v", result, err)
	}
	data, readErr := os.ReadFile(filepath.Join(request.Workspace, "fork-result"))
	fields := strings.Fields(string(data))
	if readErr != nil || len(fields) != 2 || fields[1] != "1" {
		t.Fatalf("fixture did not observe bounded EAGAIN: %q %v", data, readErr)
	}
	children, _ := strconv.Atoi(fields[0])
	if children > 14 {
		t.Fatalf("children escaped PID boundary: %d", children)
	}
	assertAgentRemoved(t, request)
}

func TestDockerResourceChildOOMHasDaemonEvidence(t *testing.T) {
	requireResourceDocker(t)
	for attempt := 0; attempt < 3; attempt++ {
		started := time.Now().UTC()
		request := resourceDockerRequest(t)
		request.Limits.MemoryMiB = 64
		buildResourceFixture(t, request.Workspace)
		// Parent exits immediately (and successfully) after a killed child.
		// Do not hide asynchronous daemon evidence races with a fixture delay.
		request.Command = []string{"sh", "-c", `/workspace/resource-fixture memory & child=$!; wait "$child"; printf '%s' "$?" > /workspace/child-exit; exit 0`}
		result, err := NewDocker().Run(context.Background(), request)
		childExit, _ := os.ReadFile(filepath.Join(request.Workspace, "child-exit"))
		if err == nil || !hasResource(result, ResourceOOM) {
			// Preserve the daemon's own history on failure, including events
			// arriving after cleanup. Do not infer OOM from the fixture's exit.
			history, historyErr := dockerCleanup("docker", "events", "--since", started.Format(time.RFC3339Nano),
				"--until", time.Now().UTC().Format(time.RFC3339Nano), "--filter", "type=container",
				"--filter", "label=ghost.session="+request.SessionID, "--format", "{{json .}}")
			t.Logf("daemon history: %s (%v)", history, historyErr)
			t.Fatalf("attempt %d: child OOM evidence missing: %+v %v (child exit %q)", attempt, result, err, childExit)
		}
		assertAgentRemoved(t, request)
	}
}

func TestDockerResourceTimeoutStopsIgnoringDescendants(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Limits.TimeoutSeconds = 4
	request.Command = []string{"sh", "-c", `trap '' TERM; (trap '' TERM; while :; do date +%s%N > /workspace/heartbeat; sleep 0.05; done) & wait`}
	started := time.Now()
	result, err := NewDocker().Run(context.Background(), request)
	if err == nil || !hasResource(result, ResourceTimeout) || time.Since(started) > 15*time.Second {
		t.Fatalf("timeout did not bound process tree: %+v %v", result, err)
	}
	assertAgentRemoved(t, request)
	path := filepath.Join(request.Workspace, "heartbeat")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("descendant fixture never started:", err)
	}
	time.Sleep(150 * time.Millisecond)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("descendant continued after timeout cleanup")
	}
}

func TestDockerResourceCreateConflictDoesNotRemoveUnrelatedContainer(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Command = []string{"true"}
	name := "ghost-agent-" + request.SessionID
	id, err := exec.Command("docker", "create", "--name", name, "--label", "unrelated.fixture=yes", DefaultDockerImage, "true").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", strings.TrimSpace(string(id))).CombinedOutput() })
	result, err := NewDocker().Run(context.Background(), request)
	if err == nil || result.Started {
		t.Fatalf("name conflict was not fail closed: %+v %v", result, err)
	}
	if output, err := exec.Command("docker", "inspect", strings.TrimSpace(string(id))).CombinedOutput(); err != nil {
		t.Fatalf("unrelated container removed: %s %v", output, err)
	}
}

func TestDockerExecPreservesStdinExitAndFailedLaunch(t *testing.T) {
	requireResourceDocker(t)
	for _, tc := range []struct {
		name            string
		cmd             []string
		stdin, stdout   string
		code            int
		started, failed bool
	}{
		{"stdin", []string{"sh", "-c", "read -r value; printf '%s' \"$value\""}, "controlled input\n", "controlled input", 0, true, false},
		{"nonzero", []string{"sh", "-c", "exit 19"}, "", "", 19, true, false},
		{"not-found", []string{"/ghost-deliberately-missing-command"}, "", "", 127, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := resourceDockerRequest(t)
			request.Command = tc.cmd
			if tc.stdin != "" {
				request.Stdin = strings.NewReader(tc.stdin)
			}
			var stdout bytes.Buffer
			request.Stdout = &stdout
			result, err := NewDocker().Run(context.Background(), request)
			if (err != nil) != tc.failed || result.Started != tc.started || result.ExitCode != tc.code || (tc.started && stdout.String() != tc.stdout) {
				t.Fatalf("result=%+v error=%v output=%q", result, err, stdout.String())
			}
			assertAgentRemoved(t, request)
		})
	}
}

func TestDockerTimeoutOffersAgentGracefulShutdown(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Limits.TimeoutSeconds = 4
	request.Limits.GraceSeconds = 1
	request.Command = []string{"sh", "-c", `trap 'printf graceful > /workspace/terminated; exit 0' TERM; while :; do sleep 0.1; done`}
	result, err := NewDocker().Run(context.Background(), request)
	data, readErr := os.ReadFile(filepath.Join(request.Workspace, "terminated"))
	if err == nil || !hasResource(result, ResourceTimeout) || readErr != nil || string(data) != "graceful" {
		t.Fatalf("graceful termination: %+v %v marker=%q %v", result, err, data, readErr)
	}
	assertAgentRemoved(t, request)
}

func TestDockerAgentCannotKillKeeperOrForgeKernelCounter(t *testing.T) {
	requireResourceDocker(t)
	request := resourceDockerRequest(t)
	request.Command = []string{"sh", "-c", `set -eu
keeper=
for p in /proc/[0-9]*; do
 [ -r "$p/comm" ] || continue
 if [ "$(cat "$p/comm")" = sleep ]; then keeper=${p##*/}; break; fi
done
[ -n "$keeper" ]
if kill -KILL "$keeper" 2>/dev/null; then exit 10; fi
if (echo 'oom_kill 99' > /sys/fs/cgroup/memory.events) 2>/dev/null; then exit 11; fi
printf 'keeper protected\n'`}
	var output bytes.Buffer
	request.Stdout = &output
	result, err := NewDocker().Run(context.Background(), request)
	if err != nil || result.ExitCode != 0 || len(result.Resources) != 0 || !strings.Contains(output.String(), "keeper protected") {
		t.Fatalf("keeper/counter protection: %+v %v %s", result, err, output.String())
	}
	assertAgentRemoved(t, request)
}
