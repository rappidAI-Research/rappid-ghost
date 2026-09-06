package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
)

func TestDockerArgumentsPreserveCommandAndSecurityBoundaries(t *testing.T) {
	t.Parallel()

	docker := &DockerRuntime{binary: "docker", image: DefaultDockerImage}
	command := []string{"printf", "%s %s", "hello world", "$(id)"}
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, projectConfig), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := docker.arguments(workspace, "/tmp/synthetic-home", RunRequest{Command: command}, "1000:1000")

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
	for _, required := range []string{
		"--network none", "--cap-drop ALL", "no-new-privileges", "--read-only",
		"--ipc private", "--cgroupns private", "--pids-limit 256", "--ulimit core=0:0",
		"/tmp:rw,nosuid,nodev,size=64m,mode=1777", "destination=/workspace/.ghost", "tmpfs-size=1048576",
		"dst=/home/ghost,readonly", "dst=/workspace/ghost.yaml,readonly", "HOME=/home/ghost", "--user 1000:1000",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("Docker arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{
		"--privileged", "--network host", "--pid host", "--ipc host", "--userns host",
		"--device", "--use-api-socket", "/var/run/docker.sock",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("Docker arguments contain forbidden value %q: %s", forbidden, joined)
		}
	}
}

func TestDockerOptionsAreExplicitAndDefaultSafely(t *testing.T) {
	t.Parallel()

	defaultRuntime := NewDockerWithOptions(DockerOptions{})
	if defaultRuntime.binary != "docker" || defaultRuntime.image != DefaultDockerImage || defaultRuntime.gatewayUpstreamNetwork != "" {
		t.Fatalf("default Docker options = %#v", defaultRuntime)
	}
	configured := NewDockerWithOptions(DockerOptions{
		Binary: "/controlled/missing-docker", GatewayNetwork: "controlled-upstream",
	})
	if configured.binary != "/controlled/missing-docker" || configured.image != DefaultDockerImage || configured.gatewayUpstreamNetwork != "controlled-upstream" {
		t.Fatalf("configured Docker options = %#v", configured)
	}
}

func TestGuestIdentityRejectsRootAndNonNumericUsers(t *testing.T) {
	tests := []struct {
		uid  string
		gid  string
		want string
	}{
		{uid: "1000", gid: "1000", want: "1000:1000"},
		{uid: "0", gid: "0"},
		{uid: "1000", gid: "0"},
		{uid: "S-1-5-21", gid: "1000"},
		{uid: "1000", gid: "staff"},
	}
	for _, test := range tests {
		got, err := validateGuestIdentity(test.uid, test.gid)
		if test.want == "" {
			if err == nil {
				t.Errorf("validateGuestIdentity(%q, %q) = %q, want error", test.uid, test.gid, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Errorf("validateGuestIdentity(%q, %q) = %q, %v; want %q", test.uid, test.gid, got, err, test.want)
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
		"SSH_AUTH_SOCK", "DATABASE_URL", "ACME_INTERNAL_PASSWORD", "CUSTOM_UNRECOGNIZED_SECRET",
		"LANG", "LC_ALL", "TERM",
	} {
		t.Setenv(name, "HOST_SECRET_SENTINEL")
	}
	args := (&DockerRuntime{image: DefaultDockerImage}).arguments("/tmp/project", "/tmp/home", RunRequest{Command: []string{"env"}}, "1000:1000")
	joined := strings.Join(args, "\n")
	if strings.Contains(joined, "HOST_SECRET_SENTINEL") {
		t.Fatal("Docker arguments contain a host secret value")
	}
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "OPENAI_API_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "DATABASE_URL",
		"ACME_INTERNAL_PASSWORD", "CUSTOM_UNRECOGNIZED_SECRET", "LANG", "LC_ALL", "TERM",
	} {
		if strings.Contains(joined, name) {
			t.Errorf("Docker arguments propagate %s", name)
		}
	}
	for _, required := range []string{"HOME=/home/ghost", "PATH=" + guestPath} {
		if !strings.Contains(joined, required) {
			t.Errorf("Docker arguments omit required environment %q", required)
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
	args := docker.sentinelArguments("ghost-sentinel-safe", "/tmp/home", "/tmp/observation", "/tmp/sentinel-handler", request, "1000:1000")
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--network none", "--cap-drop ALL", "no-new-privileges", "--read-only",
		"--ipc private", "--cgroupns private", "--pids-limit 32", "--ulimit core=0:0",
		"ghost.component=sentinel", "/home/ghost/.aws/credentials:ra", "--user 1000:1000",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("sentinel arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{
		"--privileged", "--network host", "--pid host", "--ipc host", "--userns host", "--device",
		"--use-api-socket", "/var/run/docker.sock", "/workspace", "ghost.db",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("sentinel arguments contain forbidden value %q: %s", forbidden, joined)
		}
	}
}

func TestAllowlistAgentUsesInternalNetworkAndProxyWithoutDNS(t *testing.T) {
	policyValue, err := ghostnetwork.NewPolicy("allowlist", []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	boundary := &networkBoundary{agentNetwork: "ghost-agent-test", gatewayIP: "172.30.0.2"}
	request := RunRequest{SessionID: "safe_session", Command: []string{"wget", "http://example.com"}, NetworkPolicy: policyValue}
	args := (&DockerRuntime{image: DefaultDockerImage}).arguments("/tmp/project", "/tmp/home", request, "1000:1000", boundary)
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--network ghost-agent-test", "--dns 127.0.0.1",
		"HTTP_PROXY=http://172.30.0.2:8080", "HTTPS_PROXY=http://172.30.0.2:8080",
		"NO_PROXY=",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("allowlist arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--network bridge", "--network host", "--privileged", "/var/run/docker.sock"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("allowlist arguments contain %q: %s", forbidden, joined)
		}
	}
}

func TestGatewayArgumentsExposeOnlyMinimumSessionState(t *testing.T) {
	boundary := &networkBoundary{egressNetwork: "ghost-egress-test", gatewayName: "ghost-gateway-test"}
	request := RunRequest{SessionID: "safe_session"}
	args := (&DockerRuntime{image: DefaultDockerImage}).gatewayArguments(
		boundary, request, "/tmp/gateway-handler", "/tmp/allowlist", "/tmp/observation", "1000:1000",
	)
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"--network ghost-egress-test", "--cap-drop ALL", "no-new-privileges",
		"--read-only", "--ipc private", "--cgroupns private", "--pids-limit 64", "--ulimit core=0:0",
		"/tmp:rw,nosuid,nodev,size=16m,mode=1777", "gateway-handler,readonly", "allowlist,readonly",
		"ghost.component=gateway", "--user 1000:1000",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("gateway arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{
		"--privileged", "--network host", "--pid host", "--ipc host", "--userns host", "--device",
		"--use-api-socket", "/var/run/docker.sock", "/workspace", "/home/ghost", "ghost.db",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("gateway arguments contain %q: %s", forbidden, joined)
		}
	}
}

func TestRuntimeHandlersUseValidPOSIXShellSyntax(t *testing.T) {
	for name, script := range map[string]string{"gateway": gatewayHandler, "sentinel": sentinelHandler} {
		command := exec.Command("sh", "-n")
		command.Stdin = strings.NewReader(script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("%s handler syntax: %v: %s", name, err, output)
		}
	}
}

func TestGatewayAddressGuardRejectsNonPublicDestinations(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"93.184.216.34", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"169.254.169.254", false},
		{"192.0.0.1", false},
		{"192.0.2.10", false},
		{"192.88.99.1", false},
		{"198.18.0.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fd00::1", false},
		{"fe80::1", false},
		{"not-an-address", false},
		{"127.1", false},
	}
	for _, test := range tests {
		command := exec.Command("sh", "-c", gatewayAddressGuard+"\nis_public_ipv4 \"$1\"", "ghost-address-test", test.address)
		got := command.Run() == nil
		if got != test.want {
			t.Errorf("is_public_ipv4(%q) = %v, want %v", test.address, got, test.want)
		}
	}
}

func TestGatewayResolutionIsPinnedToValidatedAddress(t *testing.T) {
	for _, required := range []string{
		`nslookup -type=A "$host"`,
		`is_public_ipv4 "$address"`,
		`nc -w 30 "$destination" "$port"`,
	} {
		if !strings.Contains(gatewayHandler, required) {
			t.Errorf("gateway handler missing %q", required)
		}
	}
	if strings.Contains(gatewayHandler, `nc -w 30 "$host" "$port"`) {
		t.Fatal("gateway performs an independent hostname resolution while connecting")
	}
}

func TestContainmentBarrierReplacesTimingDelay(t *testing.T) {
	for _, required := range []string{
		`mktemp /run/ghost-observation/barrier-requests/gateway.XXXXXX`,
		`[ ! -e /run/ghost-observation/contained ] || return 1`,
	} {
		if !strings.Contains(gatewayHandler, required) {
			t.Errorf("gateway containment barrier missing %q", required)
		}
	}
	if strings.Contains(gatewayHandler, "sleep 0.01\n    [ ! -e /run/ghost-observation/contained ]") {
		t.Fatal("gateway still relies on a fixed containment delay")
	}
	marker := strings.Index(sentinelHandler, `: > /run/ghost/contained`)
	evidence := strings.Index(sentinelHandler, `{"kind":"access"`)
	if marker < 0 || evidence < 0 || marker > evidence {
		t.Fatal("sentinel does not publish containment before access evidence")
	}
}

func TestSentinelBarrierAcknowledgementsAreTokenScopedAndRepeatable(t *testing.T) {
	dir := t.TempDir()
	requests := filepath.Join(dir, "requests")
	acks := filepath.Join(dir, "acks")
	for _, path := range []string{requests, acks} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	process := &sentinelProcess{requestDir: requests, ackDir: acks}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			entries, _ := os.ReadDir(requests)
			for _, entry := range entries {
				token := entry.Name()
				_ = os.WriteFile(filepath.Join(acks, token), nil, 0o600)
				_ = os.Remove(filepath.Join(requests, token))
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	for range 20 {
		barrierCtx, barrierCancel := context.WithTimeout(context.Background(), time.Second)
		err := process.barrier(barrierCtx)
		barrierCancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	<-done
	entries, err := os.ReadDir(acks)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("barrier acknowledgements were not consumed: %v", entries)
	}
}

func TestRecoveryOwnershipRequiresExactLabelsAndNames(t *testing.T) {
	const sessionID = "ABC-123"
	for _, test := range []struct {
		component string
		name      string
		want      bool
	}{
		{"agent", "ghost-agent-abc-123", true},
		{"sentinel", "ghost-sentinel-abc-123", true},
		{"gateway", "ghost-gateway-abc-123", true},
		{"agent", "unrelated", false},
		{"benchmark-fixture", "ghost-agent-abc-123", false},
		{"", "ghost-agent-abc-123", false},
	} {
		if got := validContainerOwnership(sessionID, test.component, test.name); got != test.want {
			t.Errorf("validContainerOwnership(%q, %q) = %v, want %v", test.component, test.name, got, test.want)
		}
	}
	for _, test := range []struct {
		name string
		want bool
	}{
		{"ghost-agent-abc-123", true},
		{"ghost-egress-abc-123", true},
		{"ghost-agent-other", false},
		{"unrelated", false},
	} {
		if got := validNetworkOwnership(sessionID, test.name); got != test.want {
			t.Errorf("validNetworkOwnership(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestGatewayResolutionFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "one non-prohibited address",
			output: "Server: 127.0.0.11\nAddress: 127.0.0.11:53\n\nName: allowed.test\nAddress: 93.184.216.34",
			want:   "93.184.216.34",
		},
		{
			name:   "private address",
			output: "Name: allowed.test\nAddress: 10.0.0.8",
		},
		{
			name:   "mixed answer set",
			output: "Name: allowed.test\nAddress 1: 93.184.216.34\nAddress 2: 169.254.169.254",
		},
		{
			name:   "empty answer",
			output: "Server: 127.0.0.11\nAddress: 127.0.0.11:53",
		},
		{
			name:   "malformed answer",
			output: "Name: allowed.test\nAddress: not-an-address",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			script := `nslookup() { printf '%s\n' "$NSLOOKUP_OUTPUT"; }` + "\n" + gatewayAddressGuard +
				`host=allowed.test
resolve_destination || exit 42
printf '%s' "$destination"`
			command := exec.Command("sh", "-c", script)
			command.Env = append(os.Environ(), "NSLOOKUP_OUTPUT="+test.output)
			output, err := command.CombinedOutput()
			if test.want == "" {
				if err == nil {
					t.Fatalf("resolution unexpectedly succeeded with %q", output)
				}
				return
			}
			if err != nil || string(output) != test.want {
				t.Fatalf("resolution = %q, %v; want %q", output, err, test.want)
			}
		})
	}
}

func TestCollectObservationsPreservesOrderAndDropsSensitiveFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	data := strings.Join([]string{
		`{"kind":"network","scheme":"https","host":"Allowed.TEST.","port":443,"method":"CONNECT","decision":"ALLOW","contained":false,"unix":100,"authorization":"Bearer secret","cookie":"secret","body":"secret"}`,
		`{"kind":"access","path":"/home/ghost/.env","events":"r","unix":100}`,
		`{"kind":"network","scheme":"https","host":"allowed.test","port":443,"method":"CONNECT","decision":"DENY","contained":true,"unix":100}`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contained"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	accesses, networkEvents, contained, err := collectObservations(observationPaths{
		dir: dir, events: path, contained: filepath.Join(dir, "contained"),
	}, []ShadowResource{{DecoyID: "dcy", GuestPath: "/home/ghost/.env"}})
	if err != nil {
		t.Fatal(err)
	}
	if !contained || len(accesses) != 1 || len(networkEvents) != 2 {
		t.Fatalf("observations = %#v, %#v, contained=%v", accesses, networkEvents, contained)
	}
	if networkEvents[0].Sequence >= accesses[0].Sequence || accesses[0].Sequence >= networkEvents[1].Sequence {
		t.Fatalf("observation order lost: %#v %#v", accesses, networkEvents)
	}
	if networkEvents[0].Host != "allowed.test" || networkEvents[0].Decision != policy.Allow ||
		networkEvents[1].Decision != policy.Deny || !networkEvents[1].Contained {
		t.Fatalf("network evidence = %#v", networkEvents)
	}
	if !networkEvents[0].DetectedAt.Equal(time.Unix(100, 0).UTC()) {
		t.Fatalf("first timestamp = %v", networkEvents[0].DetectedAt)
	}
	serialized := fmt.Sprintf("%#v", networkEvents)
	for _, secret := range []string{"Bearer secret", "cookie", "body"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("network evidence retained sensitive field %q: %s", secret, serialized)
		}
	}
}

func TestShadowResourceValidationRejectsTraversal(t *testing.T) {
	tests := []string{"/home/ghost", "/home/ghost/../root/secret", "/etc/passwd", "relative", "/home/ghost/bad\"path", "/home/ghost/bad\\path"}
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

	configWorkspace := t.TempDir()
	configTarget := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(configTarget, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(configTarget, filepath.Join(configWorkspace, projectConfig)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := validateWorkspaceExposure(configWorkspace); err == nil || !strings.Contains(err.Error(), "non-regular ghost.yaml") {
		t.Fatalf("symlinked config error = %v, want refusal", err)
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

	configPath := filepath.Join(workspace, projectConfig)
	originalConfig := []byte("version: 1\n")
	if err := os.WriteFile(configPath, originalConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	result, err = NewDocker().Run(context.Background(), RunRequest{
		Workspace: workspace, SyntheticHome: home,
		Command: []string{"sh", "-c", "printf weakened > /workspace/ghost.yaml"}, Stdout: &output, Stderr: &output,
	})
	if err != nil {
		t.Fatalf("policy protection integration: %v", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("guest unexpectedly overwrote project policy: %q", output.String())
	}
	currentConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentConfig, originalConfig) {
		t.Fatalf("guest changed project policy: %q", currentConfig)
	}
}

func TestDockerConfinementIntegration(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 to run Docker integration tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker CLI unavailable: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, output)
	}
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("Ghost correctly refuses Docker execution from a root host identity")
	}

	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "CUSTOM_UNRECOGNIZED_SECRET", "ACME_INTERNAL_PASSWORD", "TERM", "LANG", "LC_ALL",
	} {
		t.Setenv(name, "HOST_ONLY_VALUE")
	}
	workspace := t.TempDir()
	home := t.TempDir()
	hostOnlyDir := t.TempDir()
	hostOnly := filepath.Join(hostOnlyDir, "host-only-fixture")
	if err := os.WriteFile(hostOnly, []byte("host-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionID := "test_" + fmt.Sprintf("%d", time.Now().UnixNano())
	containerName := "ghost-agent-" + sessionID
	release := filepath.Join(workspace, "release")
	script := `while [ ! -e /workspace/release ]; do sleep 0.05; done
set -eu
[ "$(id -u)" = "$1" ]
[ "$(id -g)" = "$2" ]
[ "$HOME" = /home/ghost ]
[ "$PATH" = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ]
[ -z "${AWS_ACCESS_KEY_ID+x}" ]
[ -z "${CUSTOM_UNRECOGNIZED_SECRET+x}" ]
[ -z "${ACME_INTERNAL_PASSWORD+x}" ]
[ -z "${TERM+x}" ]
[ -z "${LANG+x}" ]
[ -z "${LC_ALL+x}" ]
[ ! -e "$3" ]
[ ! -e /var/run/docker.sock ]
[ ! -e /run/docker.sock ]
touch /workspace/agent-write
touch /tmp/agent-write
if touch /etc/ghost-root-write 2>/dev/null; then exit 31; fi
if touch "$HOME/agent-write" 2>/dev/null; then exit 32; fi`

	type outcome struct {
		result RunResult
		err    error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var output bytes.Buffer
	done := make(chan outcome, 1)
	go func() {
		result, err := NewDocker().Run(ctx, RunRequest{
			Workspace: workspace, SyntheticHome: home, SessionID: sessionID,
			Command: []string{"sh", "-c", script, "ghost-confinement", fmt.Sprint(os.Getuid()), fmt.Sprint(os.Getgid()), hostOnly},
			Stdout:  &output, Stderr: &output,
		})
		done <- outcome{result: result, err: err}
	}()
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "--force", containerName).CombinedOutput() })

	var raw []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case value := <-done:
			t.Fatalf("agent exited before inspection: result=%#v error=%v output=%q", value.result, value.err, output.String())
		default:
		}
		value, err := exec.Command("docker", "inspect", containerName).Output()
		if err == nil {
			raw = value
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(raw) == 0 {
		t.Fatal("agent container did not become inspectable")
	}

	var inspected []struct {
		Config struct {
			User string
			Env  []string
		}
		HostConfig struct {
			Privileged     bool
			ReadonlyRootfs bool
			CapDrop        []string
			SecurityOpt    []string
			PidMode        string
			IpcMode        string
			CgroupnsMode   string
			UsernsMode     string
			NetworkMode    string
			PidsLimit      int64
			Devices        []json.RawMessage
			DeviceRequests []json.RawMessage
			Ulimits        []struct {
				Name string
				Soft int64
				Hard int64
			}
		}
		Mounts []struct {
			Type        string
			Source      string
			Destination string
			RW          bool
		}
	}
	if err := json.Unmarshal(raw, &inspected); err != nil || len(inspected) != 1 {
		t.Fatalf("decode Docker inspection: %v", err)
	}
	container := inspected[0]
	if container.Config.User != fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) {
		t.Errorf("container user = %q", container.Config.User)
	}
	if container.HostConfig.Privileged || !container.HostConfig.ReadonlyRootfs || container.HostConfig.PidsLimit != 256 {
		t.Errorf("unsafe host config: privileged=%v readonly=%v pids=%d", container.HostConfig.Privileged, container.HostConfig.ReadonlyRootfs, container.HostConfig.PidsLimit)
	}
	// Docker's isolated PID namespace is represented by an empty PidMode. The
	// CLI supports only host or container:<id> overrides, not a "private" value.
	if container.HostConfig.PidMode != "" || container.HostConfig.IpcMode != "private" || container.HostConfig.CgroupnsMode != "private" {
		t.Errorf("namespace modes: pid=%q ipc=%q cgroup=%q", container.HostConfig.PidMode, container.HostConfig.IpcMode, container.HostConfig.CgroupnsMode)
	}
	if container.HostConfig.UsernsMode == "host" || container.HostConfig.NetworkMode == "host" {
		t.Errorf("host namespace requested: user=%q network=%q", container.HostConfig.UsernsMode, container.HostConfig.NetworkMode)
	}
	if !containsFold(container.HostConfig.CapDrop, "ALL") || !containsPrefixFold(container.HostConfig.SecurityOpt, "no-new-privileges") {
		t.Errorf("capabilities/security options: drop=%v security=%v", container.HostConfig.CapDrop, container.HostConfig.SecurityOpt)
	}
	if len(container.HostConfig.Devices) != 0 || len(container.HostConfig.DeviceRequests) != 0 {
		t.Errorf("unexpected host device exposure: devices=%d requests=%d", len(container.HostConfig.Devices), len(container.HostConfig.DeviceRequests))
	}
	coreDisabled := false
	for _, limit := range container.HostConfig.Ulimits {
		coreDisabled = coreDisabled || (limit.Name == "core" && limit.Soft == 0 && limit.Hard == 0)
	}
	if !coreDisabled {
		t.Errorf("core dump ulimit is not disabled: %v", container.HostConfig.Ulimits)
	}
	for _, mount := range container.Mounts {
		switch mount.Destination {
		case "/workspace":
			if mount.Type != "bind" || mount.Source != workspace || !mount.RW {
				t.Errorf("unexpected workspace mount: %#v", mount)
			}
		case "/workspace/.ghost", "/tmp":
			if mount.Type != "tmpfs" {
				t.Errorf("expected tmpfs mount: %#v", mount)
			}
		case guestHome:
			if mount.Type != "bind" || mount.Source != home || mount.RW {
				t.Errorf("unexpected synthetic-home mount: %#v", mount)
			}
		default:
			t.Errorf("unexpected container mount: %#v", mount)
		}
	}
	for _, forbidden := range []string{
		"AWS_ACCESS_KEY_ID=HOST_ONLY_VALUE", "CUSTOM_UNRECOGNIZED_SECRET=HOST_ONLY_VALUE",
		"ACME_INTERNAL_PASSWORD=HOST_ONLY_VALUE", "TERM=HOST_ONLY_VALUE", "LANG=HOST_ONLY_VALUE", "LC_ALL=HOST_ONLY_VALUE",
	} {
		if containsFold(container.Config.Env, forbidden) {
			t.Errorf("container configuration inherited host environment %q", forbidden)
		}
	}
	for _, variable := range container.Config.Env {
		name, _, _ := strings.Cut(variable, "=")
		if name != "HOME" && name != "PATH" {
			t.Errorf("container configuration contains non-allowlisted environment variable %q", name)
		}
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	value := <-done
	if value.err != nil || value.result.ExitCode != 0 {
		t.Fatalf("confinement command: result=%#v error=%v output=%q", value.result, value.err, output.String())
	}
	if _, err := os.Stat(filepath.Join(workspace, "agent-write")); err != nil {
		t.Fatalf("writable workspace check: %v", err)
	}
	data, err := os.ReadFile(hostOnly)
	if err != nil || string(data) != "host-only" {
		t.Fatalf("host-only fixture changed: %q, %v", data, err)
	}
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func containsPrefixFold(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}
