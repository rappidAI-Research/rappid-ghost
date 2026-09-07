package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/approval"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

func TestDockerNetworkBoundaryIntegration(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 to run Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker CLI unavailable: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, output)
	}

	upstreamNetwork := "ghost-test-upstream-" + randomSuffix(t)
	fixtureName := "ghost-test-fixture-" + randomSuffix(t)
	const fixtureIP = "93.184.216.34"
	fixtureCommand := `printf '%s\n' '#!/bin/sh' 'printf "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed"' >/tmp/fixture-handler; chmod 700 /tmp/fixture-handler; exec nc -ll -p 80 -e /tmp/fixture-handler`
	runDockerCommand(t, "network", "create", "--internal", "--subnet", "93.184.216.0/26", upstreamNetwork)
	t.Cleanup(func() { _, _ = exec.Command("docker", "network", "rm", upstreamNetwork).CombinedOutput() })
	runDockerCommand(t,
		"run", "--detach", "--name", fixtureName, "--network", upstreamNetwork,
		"--ip", fixtureIP, "--network-alias", "allowed.test", DefaultDockerImage,
		"sh", "-c", fixtureCommand,
	)
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", fixtureName).CombinedOutput() })
	waitForFixture(t, fixtureName)
	actualFixtureIP := strings.TrimSpace(runDockerCommand(t, "inspect", "--format",
		"{{(index .NetworkSettings.Networks \""+upstreamNetwork+"\").IPAddress}}", fixtureName))
	if actualFixtureIP != fixtureIP {
		t.Fatalf("fixture address = %q, want %q", actualFixtureIP, fixtureIP)
	}

	policyValue, err := ghostnetwork.NewPolicy("allowlist", []string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	docker := &DockerRuntime{binary: "docker", image: DefaultDockerImage, gatewayUpstreamNetwork: upstreamNetwork}

	t.Run("deny mode has no outbound network", func(t *testing.T) {
		denyPolicy, policyErr := ghostnetwork.NewPolicy("deny", nil)
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		result, _ := runNetworkRuntime(t, docker, denyPolicy, false, nil,
			[]string{"wget", "-T", "2", "-qO-", "http://" + fixtureIP})
		if result.ExitCode == 0 || len(result.Network) != 0 {
			t.Fatalf("deny-mode egress result = %#v", result)
		}
	})

	t.Run("approved HTTP destination is allowed", func(t *testing.T) {
		result, output := runNetworkRuntime(t, docker, policyValue, false, nil,
			[]string{"wget", "-qO-", "http://allowed.test"})
		if result.ExitCode != 0 || !strings.Contains(output, "allowed") {
			t.Fatalf("result=%#v output=%q", result, output)
		}
		if len(result.Network) != 1 || result.Network[0].Decision != policy.Allow {
			t.Fatalf("network evidence = %#v", result.Network)
		}
	})

	t.Run("approval unavailable denies non-interactive request", func(t *testing.T) {
		askPolicy, policyErr := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"allowed.test"})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		result, _ := runNetworkRuntime(t, docker, askPolicy, false, nil,
			[]string{"wget", "-T", "2", "-qO-", "http://allowed.test"})
		if result.ExitCode == 0 || len(result.Approvals) != 2 || len(result.Network) != 1 ||
			result.Approvals[0].Kind != approval.Required || result.Approvals[1].Kind != approval.Unavailable ||
			result.Network[0].Decision != policy.Deny || result.Network[0].RequestID == "" {
			t.Fatalf("non-interactive approval result = %#v", result)
		}
	})

	t.Run("allow once cannot authorize a second request", func(t *testing.T) {
		askPolicy, policyErr := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"allowed.test"})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		calls := 0
		result, output, runErr := runNetworkRuntimeAllowError(t, docker, askPolicy,
			[]string{"sh", "-c", "wget -qO /tmp/first http://allowed.test && if wget -T 2 -qO- http://allowed.test; then exit 42; fi; cat /tmp/first"},
			func(request *RunRequest) {
				request.ApprovalHandler = approvalHandlerFunc(func(context.Context, approval.Request) (approval.Response, error) {
					calls++
					if calls == 1 {
						return approval.Response{Scope: approval.AllowOnce}, nil
					}
					return approval.Response{Scope: approval.Deny}, nil
				})
			},
		)
		if runErr != nil || result.ExitCode != 0 || !strings.Contains(output, "allowed") || calls != 2 ||
			len(result.Approvals) != 4 || len(result.Network) != 2 ||
			result.Network[0].Decision != policy.Allow || result.Network[1].Decision != policy.Deny ||
			result.Network[0].RequestID == result.Network[1].RequestID {
			t.Fatalf("allow-once result=%#v calls=%d error=%v output=%q", result, calls, runErr, output)
		}
	})

	t.Run("session approval is exact and does not cross sessions", func(t *testing.T) {
		askPolicy, policyErr := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"allowed.test"})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		calls := 0
		first, output, runErr := runNetworkRuntimeAllowError(t, docker, askPolicy,
			[]string{"sh", "-c", "wget -qO /tmp/first http://allowed.test && wget -qO /tmp/second http://allowed.test && cat /tmp/first /tmp/second"},
			func(request *RunRequest) {
				request.ApprovalHandler = approvalHandlerFunc(func(context.Context, approval.Request) (approval.Response, error) {
					calls++
					return approval.Response{Scope: approval.AllowSession}, nil
				})
			},
		)
		if runErr != nil || first.ExitCode != 0 || strings.Count(output, "allowed") != 2 || calls != 1 ||
			len(first.Approvals) != 4 || first.Approvals[1].Source != approval.SourceUser ||
			first.Approvals[3].Source != approval.SourceSessionApproval || len(first.Network) != 2 {
			t.Fatalf("session approval result=%#v calls=%d error=%v output=%q", first, calls, runErr, output)
		}
		second, _ := runNetworkRuntime(t, docker, askPolicy, false, nil,
			[]string{"wget", "-T", "2", "-qO-", "http://allowed.test"})
		if second.ExitCode == 0 || len(second.Approvals) != 2 || second.Approvals[1].Kind != approval.Unavailable ||
			len(second.Network) != 1 || second.Network[0].Decision != policy.Deny {
			t.Fatalf("session approval leaked to another run: %#v", second)
		}
	})

	t.Run("containment overrides prior session approval", func(t *testing.T) {
		askPolicy, policyErr := ghostnetwork.NewPolicyWithApproval("allowlist", nil, []string{"allowed.test"})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		resource := &ShadowResource{DecoyID: "dcy_approval", GuestPath: "/home/ghost/.env"}
		calls := 0
		result, output, runErr := runNetworkRuntimeAllowError(t, docker, askPolicy,
			[]string{"sh", "-c", "wget -qO /tmp/first http://allowed.test && cat /home/ghost/.env >/dev/null && if wget -T 2 -qO- http://allowed.test; then exit 42; fi; cat /tmp/first"},
			func(request *RunRequest) {
				request.ContainOnDecoy = true
				if err := os.WriteFile(filepath.Join(request.SyntheticHome, ".env"), []byte("GHOST_DECOY=synthetic\n"), 0o400); err != nil {
					t.Fatal(err)
				}
				request.ShadowResources = []ShadowResource{*resource}
				request.ApprovalHandler = approvalHandlerFunc(func(context.Context, approval.Request) (approval.Response, error) {
					calls++
					return approval.Response{Scope: approval.AllowSession}, nil
				})
			},
		)
		if runErr != nil || result.ExitCode != 0 || !result.SecurityState.IsContained() ||
			!strings.Contains(output, "allowed") || calls != 1 || len(result.Approvals) != 2 ||
			len(result.Network) != 2 || result.Network[0].Decision != policy.Allow ||
			result.Network[1].Decision != policy.Deny || !result.Network[1].SecurityState.IsContained() ||
			result.Network[1].RequestID != "" {
			t.Fatalf("containment precedence result=%#v calls=%d error=%v output=%q", result, calls, runErr, output)
		}
	})

	t.Run("unapproved hostname and raw IP are denied", func(t *testing.T) {
		for _, destination := range []string{"denied.test", fixtureIP} {
			result, _ := runNetworkRuntime(t, docker, policyValue, false, nil,
				[]string{"wget", "-T", "2", "-qO-", "http://" + destination})
			if result.ExitCode == 0 {
				t.Fatalf("request to %s unexpectedly succeeded", destination)
			}
			if len(result.Network) != 1 || result.Network[0].Decision != policy.Deny {
				t.Fatalf("request to %s evidence = %#v", destination, result.Network)
			}
		}
	})

	t.Run("allowlisted hostname resolving to private address is denied", func(t *testing.T) {
		privateNetwork := "ghost-test-private-" + randomSuffix(t)
		privateFixture := "ghost-test-private-fixture-" + randomSuffix(t)
		runDockerCommand(t, "network", "create", "--internal", "--subnet", "10.77.0.0/24", privateNetwork)
		t.Cleanup(func() { _, _ = exec.Command("docker", "network", "rm", privateNetwork).CombinedOutput() })
		runDockerCommand(t, "run", "--detach", "--name", privateFixture, "--network", privateNetwork,
			"--ip", "10.77.0.10", "--network-alias", "private.test", DefaultDockerImage, "sleep", "300")
		t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", privateFixture).CombinedOutput() })

		privatePolicy, policyErr := ghostnetwork.NewPolicy("allowlist", []string{"private.test"})
		if policyErr != nil {
			t.Fatal(policyErr)
		}
		privateDocker := &DockerRuntime{binary: "docker", image: DefaultDockerImage, gatewayUpstreamNetwork: privateNetwork}
		result, _ := runNetworkRuntime(t, privateDocker, privatePolicy, false, nil,
			[]string{"wget", "-T", "2", "-qO-", "http://private.test"})
		if result.ExitCode == 0 || len(result.Network) != 1 || result.Network[0].Decision != policy.Deny {
			t.Fatalf("private-resolution result = %#v", result)
		}
	})

	t.Run("proxy variables cannot be unset to bypass topology", func(t *testing.T) {
		command := fmt.Sprintf(
			"unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; wget -T 2 -qO- http://%s", fixtureIP,
		)
		result, _ := runNetworkRuntime(t, docker, policyValue, false, nil, []string{"sh", "-c", command})
		if result.ExitCode == 0 {
			t.Fatal("direct external-network connection bypassed the internal network")
		}
		if len(result.Network) != 0 {
			t.Fatalf("direct bypass unexpectedly reached gateway: %#v", result.Network)
		}
	})

	t.Run("child process cannot make direct egress", func(t *testing.T) {
		command := fmt.Sprintf(
			"sh -c 'unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; wget -T 2 -qO- http://%s'", fixtureIP,
		)
		result, _ := runNetworkRuntime(t, docker, policyValue, false, nil, []string{"sh", "-c", command})
		if result.ExitCode == 0 || len(result.Network) != 0 {
			t.Fatalf("child bypass result=%#v", result)
		}
	})

	t.Run("agent has no usable external DNS resolver", func(t *testing.T) {
		command := "if nslookup example.com >/dev/null 2>&1; then exit 51; fi"
		result, _ := runNetworkRuntime(t, docker, policyValue, false, nil, []string{"sh", "-c", command})
		if result.ExitCode != 0 || len(result.Network) != 0 {
			t.Fatalf("guest DNS unexpectedly resolved outside the gateway: %#v", result)
		}
	})

	t.Run("decoy access activates containment before the next request", func(t *testing.T) {
		for attempt := range 5 {
			resource := &ShadowResource{DecoyID: "dcy_network", GuestPath: "/home/ghost/.env"}
			command := []string{"sh", "-c",
				"wget -qO /tmp/first http://allowed.test && cat /home/ghost/.env >/dev/null && " +
					"if wget -qO /tmp/second http://allowed.test; then exit 40; fi; " +
					"if wget -qO /tmp/third http://allowed.test; then exit 41; fi; cat /tmp/first",
			}
			result, output := runNetworkRuntime(t, docker, policyValue, true, resource, command)
			if result.ExitCode != 0 || !result.SecurityState.IsContained() || !strings.Contains(output, "allowed") {
				t.Fatalf("attempt %d: result=%#v output=%q", attempt, result, output)
			}
			if len(result.Accesses) != 1 || len(result.Network) != 3 ||
				result.Network[0].Decision != policy.Allow ||
				result.Network[1].Decision != policy.Deny || result.Network[2].Decision != policy.Deny ||
				!result.Network[1].SecurityState.IsContained() || !result.Network[2].SecurityState.IsContained() ||
				result.Network[0].Sequence >= result.Accesses[0].Sequence ||
				result.Accesses[0].Sequence >= result.Network[1].Sequence ||
				result.Network[1].Sequence >= result.Network[2].Sequence {
				t.Fatalf("attempt %d containment evidence: accesses=%#v network=%#v", attempt, result.Accesses, result.Network)
			}
		}
	})

	t.Run("gateway setup failure fails closed", func(t *testing.T) {
		broken := &DockerRuntime{binary: "docker", image: DefaultDockerImage, gatewayUpstreamNetwork: "ghost-missing-network"}
		marker := filepath.Join(t.TempDir(), "host-executed")
		_, _, _ = runNetworkRuntimeAllowError(t, broken, policyValue, []string{"sh", "-c", "touch " + marker})
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("command escaped to host after gateway failure: %v", err)
		}
	})

	t.Run("unexpected gateway termination remains fail closed and visible", func(t *testing.T) {
		workspace := t.TempDir()
		sessionDir := filepath.Join(t.TempDir(), "session")
		home := filepath.Join(sessionDir, "shadow-home")
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		sessionID := "gateway_crash_" + randomSuffix(t)
		gatewayName := "ghost-gateway-" + strings.ToLower(sessionID)
		agentName := "ghost-agent-" + strings.ToLower(sessionID)
		var output bytes.Buffer
		type outcome struct {
			result RunResult
			err    error
		}
		finished := make(chan outcome, 1)
		runCtx, cancelRun := context.WithCancel(context.Background())
		defer cancelRun()
		go func() {
			result, err := docker.Run(runCtx, RunRequest{
				Command:   []string{"sh", "-c", "sleep 2; if wget -T 1 -qO- http://allowed.test; then exit 50; fi"},
				Workspace: workspace, SessionID: sessionID, SessionDir: sessionDir,
				SyntheticHome: home, NetworkPolicy: policyValue, Stdout: &output, Stderr: &output,
			})
			finished <- outcome{result: result, err: err}
		}()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if exec.Command("docker", "inspect", "--format", "{{.State.Running}}", agentName).Run() == nil {
				break
			}
			if time.Now().After(deadline) {
				cancelRun()
				<-finished
				t.Fatal("gateway did not start before crash test deadline")
			}
			time.Sleep(25 * time.Millisecond)
		}
		runDockerCommand(t, "kill", gatewayName)
		observed := <-finished
		if observed.err == nil || !strings.Contains(observed.err.Error(), "egress gateway stopped unexpectedly") || observed.result.ExitCode != 0 {
			t.Fatalf("gateway crash result=%#v error=%v output=%q", observed.result, observed.err, output.String())
		}
		assertSessionResourcesRemoved(t, sessionID)
	})
}

func TestDockerRecoveryIntegration(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 to run Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker CLI unavailable: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, output)
	}

	sessionID := "recovery_" + randomSuffix(t)
	otherSessionID := "unrelated_" + randomSuffix(t)
	ownedNetwork := "ghost-agent-" + strings.ToLower(sessionID)
	ownedContainer := "ghost-sentinel-" + strings.ToLower(sessionID)
	unrelatedNetwork := "ghost-agent-" + strings.ToLower(otherSessionID)
	unrelatedContainer := "ghost-sentinel-" + strings.ToLower(otherSessionID)
	for _, name := range []string{ownedContainer, unrelatedContainer} {
		t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", name).CombinedOutput() })
	}
	for _, name := range []string{ownedNetwork, unrelatedNetwork} {
		t.Cleanup(func() { _, _ = exec.Command("docker", "network", "rm", name).CombinedOutput() })
	}
	runDockerCommand(t, "network", "create", "--internal", "--label", "ghost.component=network", "--label", "ghost.session="+sessionID, ownedNetwork)
	runDockerCommand(t, "network", "create", "--internal", "--label", "ghost.component=network", "--label", "ghost.session="+otherSessionID, unrelatedNetwork)
	runDockerCommand(t, "run", "--detach", "--name", ownedContainer,
		"--label", "ghost.component=sentinel", "--label", "ghost.session="+sessionID,
		"--network", "none", DefaultDockerImage, "sleep", "300")
	runDockerCommand(t, "run", "--detach", "--name", unrelatedContainer,
		"--label", "ghost.component=sentinel", "--label", "ghost.session="+otherSessionID,
		"--network", "none", DefaultDockerImage, "sleep", "300")

	docker := &DockerRuntime{binary: "docker", image: DefaultDockerImage}
	if err := docker.Recover(context.Background(), []string{sessionID}); err != nil {
		t.Fatal(err)
	}
	assertSessionResourcesRemoved(t, sessionID)
	for _, check := range [][]string{
		{"inspect", unrelatedContainer},
		{"network", "inspect", unrelatedNetwork},
	} {
		if output, err := exec.Command("docker", check...).CombinedOutput(); err != nil {
			t.Fatalf("unrelated Docker resource was removed: docker %s: %v: %s", strings.Join(check, " "), err, output)
		}
	}

	ambiguousName := "ghost-unowned-" + randomSuffix(t)
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", ambiguousName).CombinedOutput() })
	runDockerCommand(t, "run", "--detach", "--name", ambiguousName,
		"--label", "ghost.component=sentinel", "--label", "ghost.session="+sessionID,
		"--network", "none", DefaultDockerImage, "sleep", "300")
	if err := docker.Recover(context.Background(), []string{sessionID}); err == nil {
		t.Fatal("recovery accepted a mislabeled container with an unexpected name")
	}
	if output, err := exec.Command("docker", "inspect", ambiguousName).CombinedOutput(); err != nil {
		t.Fatalf("ambiguous resource was deleted instead of reported: %v: %s", err, output)
	}
}

func runNetworkRuntime(t *testing.T, docker *DockerRuntime, policyValue ghostnetwork.Policy, contain bool, resource *ShadowResource, command []string) (RunResult, string) {
	t.Helper()
	result, output, err := runNetworkRuntimeAllowError(t, docker, policyValue, command, func(request *RunRequest) {
		request.ContainOnDecoy = contain
		if resource != nil {
			decoyPath := filepath.Join(request.SyntheticHome, ".env")
			if err := os.WriteFile(decoyPath, []byte("GHOST_DECOY=synthetic\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			request.ShadowResources = []ShadowResource{*resource}
		}
	})
	if err != nil {
		t.Fatalf("Run() error = %v, output = %q", err, output)
	}
	return result, output
}

func runNetworkRuntimeAllowError(t *testing.T, docker *DockerRuntime, policyValue ghostnetwork.Policy, command []string, modifiers ...func(*RunRequest)) (RunResult, string, error) {
	t.Helper()
	workspace := t.TempDir()
	sessionDir := filepath.Join(t.TempDir(), "session")
	home := filepath.Join(sessionDir, "shadow-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	request := RunRequest{
		Command: command, Workspace: workspace, SessionID: "test_" + randomSuffix(t),
		SessionDir: sessionDir, SyntheticHome: home, NetworkPolicy: policyValue,
		Stdout: &output, Stderr: &output,
	}
	for _, modify := range modifiers {
		modify(&request)
	}
	result, err := docker.Run(context.Background(), request)
	assertSessionResourcesRemoved(t, request.SessionID)
	return result, output.String(), err
}

func assertSessionResourcesRemoved(t *testing.T, sessionID string) {
	t.Helper()
	for _, command := range [][]string{
		{"ps", "-aq", "--filter", "label=ghost.session=" + sessionID},
		{"network", "ls", "-q", "--filter", "label=ghost.session=" + sessionID},
	} {
		output := strings.TrimSpace(runDockerCommand(t, command...))
		if output != "" {
			t.Fatalf("session resources leaked for %s: %s", sessionID, output)
		}
	}
}

func runDockerCommand(t *testing.T, arguments ...string) string {
	t.Helper()
	output, err := exec.Command("docker", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func waitForFixture(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("docker", "exec", name, "busybox", "wget", "-qO-", "http://127.0.0.1").Run(); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	inspect, _ := exec.Command("docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.Error}}", name).CombinedOutput()
	t.Fatalf("local HTTP fixture did not become ready: state=%s logs=%s", strings.TrimSpace(string(inspect)), strings.TrimSpace(string(logs)))
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	value := make([]byte, 5)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}
