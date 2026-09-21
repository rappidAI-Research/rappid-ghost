package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Emulates the daemon contract, not container confinement. Real confinement
// and descendant behavior are tested separately with Docker integration.
func controlledDocker(t *testing.T, start, overrides string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controlled-docker")
	script := `#!/bin/sh
` + overrides + `
case "$1" in
create) printf '%064d\n' 1 ;;
inspect)
  case "$3" in
  '{{json .HostConfig}}') printf '%s\n' '{"Memory":2147483648,"MemorySwap":2147483648,"CPUPeriod":100000,"CPUQuota":100000,"PidsLimit":256,"ReadonlyRootfs":true}' ;;
  '{{json .State}}') printf '%s\n' '{"Status":"exited","Running":false,"OOMKilled":false,"ExitCode":0}' ;;
  esac ;;
start)
` + start + `
;;
stats) printf '1\n' ;;
stop|kill|rm) exit 0 ;;
ps) exit 0 ;;
*) exit 1 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResourceLimitsRejectUnlimitedAndUnsafeValues(t *testing.T) {
	t.Parallel()
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Limits){
		func(l *Limits) { l.MemoryMiB = 0 }, func(l *Limits) { l.MemoryMiB = -1 },
		func(l *Limits) { l.CPUMillis = 0 }, func(l *Limits) { l.CPUMillis = 8001 },
		func(l *Limits) { l.PIDs = -1 }, func(l *Limits) { l.PIDs = 4097 },
		func(l *Limits) { l.TimeoutSeconds = 0 }, func(l *Limits) { l.TimeoutSeconds = 86401 },
		func(l *Limits) { l.GraceSeconds = 0 }, func(l *Limits) { l.GraceSeconds = 31 },
		func(l *Limits) { l.TmpMiB = 0 }, func(l *Limits) { l.MemoryMiB = 64; l.TmpMiB = 65 },
	} {
		limits := DefaultLimits()
		mutate(&limits)
		if limits.Validate() == nil {
			t.Fatalf("accepted unsafe limits: %+v", limits)
		}
		prepared, err := NewDockerWithOptions(DockerOptions{Binary: "missing-docker"}).Preflight(context.Background(), RunRequest{Command: []string{"true"}, Limits: &limits})
		var preflight *PreflightError
		if prepared != nil || !errors.As(err, &preflight) || preflight.Area != PreflightPolicy {
			t.Fatalf("invalid limits escaped preflight: %v", err)
		}
	}
}

func TestDockerCapabilitiesFailClosed(t *testing.T) {
	base := map[string]any{"OSType": "linux", "MemoryLimit": true, "SwapLimit": true, "CPUCfsQuota": true, "CPUCfsPeriod": true, "PidsLimit": true, "CgroupVersion": "2", "CgroupDriver": "systemd", "SecurityOptions": []string{"name=seccomp,profile=builtin"}}
	raw, _ := json.Marshal(base)
	if err := validateDockerCapabilities(raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"MemoryLimit", "SwapLimit", "CPUCfsQuota", "CPUCfsPeriod", "PidsLimit"} {
		base[field] = false
		raw, _ = json.Marshal(base)
		if validateDockerCapabilities(raw) == nil {
			t.Fatalf("accepted missing %s", field)
		}
		base[field] = true
	}
	base["SecurityOptions"] = []string{"name=seccomp,profile=unconfined"}
	raw, _ = json.Marshal(base)
	if validateDockerCapabilities(raw) == nil {
		t.Fatal("accepted unconfined seccomp")
	}
	base["SecurityOptions"] = []string{"name=seccomp,profile=builtin", "name=rootless"}
	base["CgroupVersion"] = "1"
	raw, _ = json.Marshal(base)
	if validateDockerCapabilities(raw) == nil {
		t.Fatal("accepted rootless cgroup v1")
	}
	base["CgroupVersion"] = "2"
	raw, _ = json.Marshal(base)
	if err := validateDockerCapabilities(raw); err != nil {
		t.Fatal(err)
	}
	base["CgroupDriver"] = "cgroupfs"
	raw, _ = json.Marshal(base)
	if validateDockerCapabilities(raw) == nil {
		t.Fatal("accepted unsupported rootless delegation")
	}
}

func TestResourceArgumentsCoverEveryRole(t *testing.T) {
	d := NewDocker()
	request := RunRequest{SessionID: "safe"}
	for role, args := range map[string][]string{
		"agent":    d.arguments(t.TempDir(), t.TempDir(), request, "1000:1000"),
		"sentinel": d.sentinelArguments("sentinel", "/home", "/observation", "/handler", request, "1000:1000"),
		"gateway":  d.gatewayArguments(&networkBoundary{}, request, "/handler", "/allow", "/ask", "/observation", "1000:1000"),
	} {
		joined := strings.Join(args, " ")
		for _, required := range []string{"--memory ", "--memory-swap ", "--cpu-period 100000", "--cpu-quota ", "--pids-limit ", "--read-only", "--log-driver none", "--shm-size 16m"} {
			if !strings.Contains(joined, required) {
				t.Errorf("%s missing %s", role, required)
			}
		}
		if strings.Contains(joined, "unconfined") || strings.Contains(joined, "oom-kill-disable") {
			t.Errorf("%s weakens boundary", role)
		}
	}
}

func TestAlteredDockerLimitsPreventStart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	// Deliberately missing all HostConfig fields emulates silently ignored limits.
	script := controlledDocker(t, "touch '"+marker+"'", `if [ "$1" = inspect ] && [ "$3" = '{{json .HostConfig}}' ]; then echo '{}'; exit 0; fi`)
	result, err := (&DockerRuntime{binary: script, image: DefaultDockerImage}).runAgent(context.Background(), t.TempDir(), t.TempDir(), RunRequest{Command: []string{"true"}}, nil, "1000:1000")
	if err == nil || result.Started {
		t.Fatalf("unsafe execution: %+v %v", result, err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("command started before limit validation")
	}
}

func TestExit137IsNotAssumedToBeOOM(t *testing.T) {
	for _, oom := range []bool{false, true} {
		state, _ := json.Marshal(map[string]any{"Status": "exited", "Running": false, "OOMKilled": oom, "ExitCode": 137})
		script := controlledDocker(t, "exit 137", `if [ "$1" = inspect ] && [ "$3" = '{{json .State}}' ]; then echo '`+string(state)+`'; exit 0; fi`)
		result, err := (&DockerRuntime{binary: script, image: DefaultDockerImage}).runAgent(context.Background(), t.TempDir(), t.TempDir(), RunRequest{Command: []string{"true"}}, nil, "1000:1000")
		if result.ExitCode != 137 || (len(result.Resources) > 0) != oom || (err != nil) != oom {
			t.Fatalf("oom=%t: %+v, %v", oom, result, err)
		}
	}
}

func TestGracefulStopHasForcedFallback(t *testing.T) {
	log := filepath.Join(t.TempDir(), "actions")
	script := controlledDocker(t, "exit 0", `printf '%s\n' "$1" >> '`+log+`'
if [ "$1" = stop ]; then exit 1; fi`)
	if err := (&DockerRuntime{binary: script}).stopAgent(strings.Repeat("a", 64), 1); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if string(data) != "stop\nkill\n" {
		t.Fatalf("shutdown order = %q", data)
	}
}

func TestDiagnosticCaptureIsBounded(t *testing.T) {
	var tail diagnosticTail
	data := bytes.Repeat([]byte("x"), 1024*1024)
	if n, err := tail.Write(data); err != nil || n != len(data) {
		t.Fatal("short diagnostic write")
	}
	_, _ = tail.Write([]byte("last message"))
	if len(tail.data) > 64*1024 || !strings.HasSuffix(tail.String(), "last message") {
		t.Fatal("diagnostic capture is not a bounded tail")
	}
}

func TestResourceEvidenceRejectsInventedObservations(t *testing.T) {
	for _, e := range []ResourceEvidence{
		{Kind: "unknown", DetectedAt: time.Now(), Limit: 1},
		{Kind: ResourcePIDs, DetectedAt: time.Now(), Limit: 16, Observed: 15},
		{Kind: ResourceOOM, DetectedAt: time.Now(), Limit: 1, Observed: 137},
		{Kind: ResourceTimeout, Limit: 1},
	} {
		if e.Validate() == nil {
			t.Fatalf("accepted %+v", e)
		}
	}
}

func TestPreparedRuntimeDeadlineStopsContainerAndPersistsObservation(t *testing.T) {
	root := t.TempDir()
	stopped := filepath.Join(root, "stopped")
	log := filepath.Join(root, "actions")
	script := controlledDocker(t, `while [ ! -e '`+stopped+`' ]; do sleep 0.02; done`, `
printf '%s\n' "$1" >> '`+log+`'
if [ "$1" = stop ]; then touch '`+stopped+`'; exit 0; fi
if [ "$1" = inspect ] && [ "$3" = '{{json .State}}' ]; then
 if [ -e '`+stopped+`' ]; then echo '{"Status":"exited","Running":false,"ExitCode":143}'; else echo '{"Status":"running","Running":true}'; fi
 exit 0
fi`)
	limits := DefaultLimits()
	limits.TimeoutSeconds = 1
	limits.GraceSeconds = 1
	prepared := &dockerPreparedRun{runtime: &DockerRuntime{binary: script, image: DefaultDockerImage}, request: RunRequest{Command: []string{"true"}, Limits: &limits}, workspace: t.TempDir(), home: t.TempDir(), identity: "1000:1000"}
	started := time.Now()
	result, err := prepared.Run(context.Background())
	if !errors.Is(err, ErrSessionTimeout) || !hasResource(result, ResourceTimeout) || time.Since(started) > 5*time.Second {
		t.Fatalf("deadline result: %+v %v", result, err)
	}
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), "stop\n") || !strings.HasSuffix(string(data), "rm\n") {
		t.Fatalf("container stop/cleanup missing: %s", data)
	}
}

func TestCleanupRefusesUnrelatedNamedResources(t *testing.T) {
	for _, network := range []bool{false, true} {
		marker := filepath.Join(t.TempDir(), "removed")
		script := controlledDocker(t, "exit 0", `if [ "$1" = rm ] || [ "$2" = rm ]; then touch '`+marker+`'; exit 0; fi
if [ "$1" = inspect ] || [ "$2" = inspect ]; then echo '{"Id":"`+strings.Repeat("a", 64)+`","Name":"ghost-agent-safe","Labels":{"unrelated":"yes"},"Config":{"Labels":{"unrelated":"yes"}}}';exit 0;fi`)
		component := "agent"
		if network {
			component = "network"
		}
		if err := removeOwnedResource(script, "ghost-agent-safe", "safe", component, network); err == nil {
			t.Fatal("accepted ambiguous cleanup")
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("deleted unrelated resource")
		}
	}
}

func TestStalledGracefulStopIsBounded(t *testing.T) {
	script := controlledDocker(t, "exit 0", `if [ "$1" = stop ]; then exec sleep 30; fi`)
	started := time.Now()
	if err := (&DockerRuntime{binary: script}).stopAgent(strings.Repeat("a", 64), 1); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("stalled graceful shutdown exceeded forced-fallback bound")
	}
}
