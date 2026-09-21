package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func resourceArguments(memoryMiB, cpuMillis int64) []string {
	memory := strconv.FormatInt(memoryMiB*1024*1024, 10)
	return []string{"--memory", memory, "--memory-swap", memory,
		"--cpu-period", "100000", "--cpu-quota", strconv.FormatInt(cpuMillis*100, 10)}
}

// Names can collide with unrelated user resources. Inspect ownership first
// and remove the returned immutable ID, never whatever currently has a name.
func removeOwnedResource(binary, name, sessionID, component string, network bool) error {
	if !safeContainerComponent.MatchString(sessionID) {
		return errors.New("invalid resource cleanup identity")
	}
	args := []string{"inspect", "--format", "{{json .}}", name}
	if network {
		args = append([]string{"network"}, args...)
	}
	output, err := dockerCleanup(binary, args...)
	if err != nil {
		if dockerObjectMissing(output) {
			return nil
		}
		return fmt.Errorf("inspect resource before cleanup: %s", lastMessage(string(output)))
	}
	var object struct {
		ID     string `json:"Id"`
		Name   string
		Labels map[string]string
		Config struct{ Labels map[string]string }
	}
	if err := json.Unmarshal(output, &object); err != nil {
		return fmt.Errorf("decode cleanup ownership: %w", err)
	}
	labels := object.Config.Labels
	validName := validContainerOwnership(sessionID, component, strings.TrimPrefix(object.Name, "/"))
	if network {
		labels = object.Labels
		validName = validNetworkOwnership(sessionID, object.Name)
	}
	if !containerIDPattern.MatchString(object.ID) || !validName || labels["ghost.session"] != sessionID || labels["ghost.component"] != component {
		return fmt.Errorf("refusing cleanup of ambiguously owned %s", name)
	}
	args = []string{"rm", "--force", object.ID}
	if network {
		args = []string{"network", "rm", object.ID}
	}
	output, err = dockerCleanup(binary, args...)
	if err != nil && !dockerObjectMissing(output) {
		return fmt.Errorf("remove owned %s: %s", component, lastMessage(string(output)))
	}
	return nil
}

func validateDockerCapabilities(raw []byte) error {
	var info struct {
		OSType                                                       string
		MemoryLimit, SwapLimit, CPUCfsQuota, CPUCfsPeriod, PidsLimit bool
		CgroupVersion, CgroupDriver                                  string
		SecurityOptions                                              []string
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("decode Docker security capabilities: %w", err)
	}
	if info.OSType != "linux" || !info.MemoryLimit || !info.SwapLimit || !info.CPUCfsQuota || !info.CPUCfsPeriod || !info.PidsLimit {
		return errors.New("Docker must enforce Linux memory, swap, CPU quota and PID limits; configure supported cgroups (no unlimited fallback)")
	}
	seccomp, rootless := false, false
	for _, option := range info.SecurityOptions {
		if option == "name=rootless" {
			rootless = true
		}
		if option == "name=seccomp,profile=builtin" || option == "name=seccomp,profile=default" {
			seccomp = true
		}
	}
	if !seccomp {
		return errors.New("Docker's built-in default seccomp profile is required")
	}
	if rootless && (info.CgroupVersion != "2" || info.CgroupDriver != "systemd") {
		return errors.New("rootless Docker requires cgroup v2 with systemd delegation for mandatory resource limits")
	}
	return nil
}

type containerState struct {
	Running   bool
	OOMKilled bool
	ExitCode  int
	Status    string
}

func (d *DockerRuntime) agentState(id string) (containerState, error) {
	output, err := dockerCleanup(d.binary, "inspect", "--format", "{{json .State}}", id)
	var state containerState
	if err != nil {
		return state, fmt.Errorf("inspect isolated command state: %s", lastMessage(string(output)))
	}
	if err := json.Unmarshal(output, &state); err != nil {
		return state, fmt.Errorf("decode isolated command state: %w", err)
	}
	if state.Status == "" {
		return state, errors.New("Docker returned incomplete command state")
	}
	return state, nil
}

// Inspect before start: Docker can warn and discard unsupported settings.
// Refuse altered limits while the untrusted command has not run yet.
func (d *DockerRuntime) verifyAgentLimits(ctx context.Context, id string, limits Limits) error {
	output, err := exec.CommandContext(ctx, d.binary, "inspect", "--format", "{{json .HostConfig}}", id).CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect mandatory resource limits: %s", lastMessage(string(output)))
	}
	var host struct {
		Memory, MemorySwap, CPUPeriod, CPUQuota, PidsLimit int64
		ReadonlyRootfs                                     bool
		OomKillDisable                                     bool
	}
	if err := json.Unmarshal(output, &host); err != nil {
		return fmt.Errorf("decode mandatory resource limits: %w", err)
	}
	if host.Memory != limits.MemoryMiB*1024*1024 || host.MemorySwap != host.Memory ||
		host.CPUPeriod != 100000 || host.CPUQuota != limits.CPUMillis*100 || host.PidsLimit != limits.PIDs ||
		!host.ReadonlyRootfs || host.OomKillDisable {
		return errors.New("Docker did not retain the mandatory resource/isolation boundaries; refusing to start")
	}
	return nil
}

// stopAgent targets the immutable ID returned by this invocation's create.
// Docker stop sends TERM, waits a bounded grace, then KILL to the container.
// A failed/stalled stop still falls back to force removal of the entire tree.
func (d *DockerRuntime) stopAgent(id string, grace int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(grace+2)*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, d.binary, "stop", "--signal", "SIGTERM", "--time", strconv.FormatInt(grace, 10), id)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	stopErr := fmt.Errorf("graceful container stop failed: %s", lastMessage(string(output)))
	output, err = dockerCleanup(d.binary, "kill", "--signal", "SIGKILL", id)
	if err == nil {
		return nil
	}
	return errors.Join(stopErr, fmt.Errorf("forced container stop failed: %s", lastMessage(string(output))))
}

type resourceObservation struct {
	evidence *ResourceEvidence
	err      error
}

// Kernel limits apply continuously to descendants. This sampling only adds
// termination/evidence when Docker reports saturation; it cannot count every
// rejected clone/fork or attribute malicious intent.
func (d *DockerRuntime) observeResources(ctx context.Context, id string, limits Limits, result chan<- resourceObservation) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		output, err := exec.CommandContext(probeCtx, d.binary, "stats", "--no-stream", "--format", "{{.PIDs}}", id).CombinedOutput()
		cancel()
		if ctx.Err() != nil {
			return
		}
		state, stateErr := d.agentState(id)
		if stateErr != nil {
			result <- resourceObservation{err: stateErr}
			return
		}
		if state.OOMKilled {
			result <- resourceObservation{evidence: &ResourceEvidence{Kind: ResourceOOM, DetectedAt: time.Now().UTC(), Limit: limits.MemoryMiB * 1024 * 1024}}
			return
		}
		if state.Status == "created" {
			continue
		}
		if !state.Running {
			return
		}
		if err != nil {
			result <- resourceObservation{err: fmt.Errorf("observe container resources: %w", err)}
			return
		}
		pids, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
		if err != nil || pids < 0 {
			result <- resourceObservation{err: errors.New("Docker returned invalid process-count evidence")}
			return
		}
		if pids >= limits.PIDs {
			result <- resourceObservation{evidence: &ResourceEvidence{Kind: ResourcePIDs, DetectedAt: time.Now().UTC(), Limit: limits.PIDs, Observed: pids}}
			return
		}
	}
}
