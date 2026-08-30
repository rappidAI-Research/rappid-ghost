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
	runDockerCommand(t, "network", "create", upstreamNetwork)
	t.Cleanup(func() { _, _ = exec.Command("docker", "network", "rm", upstreamNetwork).CombinedOutput() })
	runDockerCommand(t,
		"run", "--detach", "--name", fixtureName, "--network", upstreamNetwork,
		"--network-alias", "allowed.test", DefaultDockerImage,
		"sh", "-c", "printf allowed >/tmp/index.html; exec httpd -f -p 80 -h /tmp",
	)
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", fixtureName).CombinedOutput() })
	waitForFixture(t, fixtureName)
	fixtureIP := strings.TrimSpace(runDockerCommand(t, "inspect", "--format",
		"{{(index .NetworkSettings.Networks \""+upstreamNetwork+"\").IPAddress}}", fixtureName))

	policyValue, err := ghostnetwork.NewPolicy("allowlist", []string{"allowed.test"})
	if err != nil {
		t.Fatal(err)
	}
	docker := &DockerRuntime{binary: "docker", image: DefaultDockerImage, gatewayTestNetwork: upstreamNetwork}

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

	t.Run("decoy access activates containment before the next request", func(t *testing.T) {
		resource := &ShadowResource{DecoyID: "dcy_network", GuestPath: "/home/ghost/.env"}
		command := []string{"sh", "-c",
			"wget -qO /tmp/first http://allowed.test && cat /home/ghost/.env >/dev/null && " +
				"if wget -qO /tmp/second http://allowed.test; then exit 40; fi; cat /tmp/first",
		}
		result, output := runNetworkRuntime(t, docker, policyValue, true, resource, command)
		if result.ExitCode != 0 || !result.Contained || !strings.Contains(output, "allowed") {
			t.Fatalf("result=%#v output=%q", result, output)
		}
		if len(result.Accesses) != 1 || len(result.Network) != 2 ||
			result.Network[0].Decision != policy.Allow || result.Network[1].Decision != policy.Deny ||
			!result.Network[1].Contained ||
			result.Network[0].Sequence >= result.Accesses[0].Sequence ||
			result.Accesses[0].Sequence >= result.Network[1].Sequence {
			t.Fatalf("containment evidence: accesses=%#v network=%#v", result.Accesses, result.Network)
		}
	})

	t.Run("gateway setup failure fails closed", func(t *testing.T) {
		broken := &DockerRuntime{binary: "docker", image: DefaultDockerImage, gatewayTestNetwork: "ghost-missing-network"}
		marker := filepath.Join(t.TempDir(), "host-executed")
		_, _, _ = runNetworkRuntimeAllowError(t, broken, policyValue, []string{"sh", "-c", "touch " + marker})
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("command escaped to host after gateway failure: %v", err)
		}
	})
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
		if err := exec.Command("docker", "exec", name, "wget", "-qO-", "http://127.0.0.1").Run(); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("local HTTP fixture did not become ready")
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	value := make([]byte, 5)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}
