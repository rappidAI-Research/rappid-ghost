package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	"github.com/rappidAI-research/rappid-ghost/internal/incidents"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/provenance"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

func TestDefaultVersionMatchesDevelopmentCycle(t *testing.T) {
	if Version != "0.3.1-dev" {
		t.Fatalf("default version = %q, want v0.3.1 development version", Version)
	}
}

func TestParseRunArgsPreservesBoundaries(t *testing.T) {
	t.Parallel()

	input := []string{"--", "printf", "%s %s", "hello world", "--flag=value", "$(id)"}
	want := input[1:]
	got, err := parseRunArgs(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
	input[1] = "changed"
	if got[0] != "printf" {
		t.Fatal("parsed command aliases caller input")
	}
	shorthand, err := parseRunArgs([]string{"echo", "hello world", "--flag=value"})
	if err != nil || !reflect.DeepEqual(shorthand, []string{"echo", "hello world", "--flag=value"}) {
		t.Fatalf("shorthand = %#v, %v", shorthand, err)
	}
	for _, input := range [][]string{nil, {"--"}, {"-command"}} {
		if _, err := parseRunArgs(input); err == nil {
			t.Errorf("parseRunArgs(%#v) succeeded", input)
		}
	}
}

func TestParseInspectArgsDefaultsToLatest(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{{nil, "latest"}, {[]string{"latest"}, "latest"}, {[]string{"session-id"}, "session-id"}} {
		got, err := parseInspectArgs(tc.args)
		if err != nil || got != tc.want {
			t.Errorf("parseInspectArgs(%#v) = %q, %v; want %q", tc.args, got, err, tc.want)
		}
	}
	for _, input := range [][]string{{"--json"}, {"latest", "extra"}} {
		if _, err := parseInspectArgs(input); err == nil {
			t.Errorf("parseInspectArgs(%#v) succeeded", input)
		}
	}
}

func TestUnknownCommandSuggestionIsConservative(t *testing.T) {
	for input, want := range map[string]string{"inspec": "inspect", "versoin": "version", "banana": ""} {
		if got := commandSuggestion(input); got != want {
			t.Errorf("commandSuggestion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseGraphArgs(t *testing.T) {
	selector, jsonOutput, err := parseGraphArgs([]string{"latest", "--json"})
	if err != nil || selector != "latest" || !jsonOutput {
		t.Fatalf("parseGraphArgs() = %q, %v, %v", selector, jsonOutput, err)
	}
	selector, jsonOutput, err = parseGraphArgs([]string{"session-id"})
	if err != nil || selector != "session-id" || jsonOutput {
		t.Fatalf("parseGraphArgs() = %q, %v, %v", selector, jsonOutput, err)
	}
	for input, wantJSON := range map[string]bool{"": false, "--json": true} {
		args := strings.Fields(input)
		selector, jsonOutput, err = parseGraphArgs(args)
		if err != nil || selector != "latest" || jsonOutput != wantJSON {
			t.Errorf("parseGraphArgs(%#v) = %q, %v, %v", args, selector, jsonOutput, err)
		}
	}
	for _, input := range [][]string{{"latest", "--yaml"}, {"--json", "latest"}, {"latest", "--json", "extra"}} {
		if _, _, err := parseGraphArgs(input); err == nil {
			t.Errorf("parseGraphArgs(%#v) succeeded", input)
		}
	}
}

func TestParseIncidentsArgs(t *testing.T) {
	selector, jsonOutput, err := parseIncidentsArgs([]string{"latest", "--json"})
	if err != nil || selector != "latest" || !jsonOutput {
		t.Fatalf("parseIncidentsArgs() = %q, %v, %v", selector, jsonOutput, err)
	}
	selector, jsonOutput, err = parseIncidentsArgs([]string{"session-id"})
	if err != nil || selector != "session-id" || jsonOutput {
		t.Fatalf("parseIncidentsArgs() = %q, %v, %v", selector, jsonOutput, err)
	}
	for input, wantJSON := range map[string]bool{"": false, "--json": true} {
		args := strings.Fields(input)
		selector, jsonOutput, err = parseIncidentsArgs(args)
		if err != nil || selector != "latest" || jsonOutput != wantJSON {
			t.Errorf("parseIncidentsArgs(%#v) = %q, %v, %v", args, selector, jsonOutput, err)
		}
	}
	for _, input := range [][]string{{"latest", "--yaml"}, {"--json", "latest"}, {"latest", "--json", "extra"}} {
		if _, _, err := parseIncidentsArgs(input); err == nil {
			t.Errorf("parseIncidentsArgs(%#v) succeeded", input)
		}
	}
}

func TestParseBenchArgs(t *testing.T) {
	options, jsonOutput, err := parseBenchArgs([]string{"--json", "--require-all", "--scenario", "shadow-credentials"})
	if err != nil || options.Scenario != "shadow-credentials" || !options.RequireAll || !jsonOutput {
		t.Fatalf("parseBenchArgs() = %+v, %v, %v", options, jsonOutput, err)
	}
	options, jsonOutput, err = parseBenchArgs([]string{"--scenario=network-deny"})
	if err != nil || options.Scenario != "network-deny" || jsonOutput {
		t.Fatalf("parseBenchArgs() = %+v, %v, %v", options, jsonOutput, err)
	}
	for _, input := range [][]string{{"--scenario"}, {"--scenario", "unknown"}, {"--json", "--json"}, {"--require-all", "--require-all"}, {"extra"}} {
		if _, _, err := parseBenchArgs(input); err == nil {
			t.Errorf("parseBenchArgs(%#v) succeeded", input)
		}
	}
}

func TestGraphSessionRendersStoredEvidenceAsTextAndJSON(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, config.RuntimeDirName, config.DatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	value := session.Session{
		ID: "graph-session", CreatedAt: now, Command: []string{"sh", "DO_NOT_EXPORT_SECRET"},
		Runtime: "docker", Status: session.Completed, NetworkMode: ghostnetwork.Allowlist, SecurityState: policy.StateContained,
	}
	if err := store.CreateSession(ctx, value); err != nil {
		t.Fatal(err)
	}
	shadow := policy.Shadow
	deny := policy.Deny
	decoyPath := deception.GuestHome + "/.aws/credentials"
	for _, event := range []*events.Event{
		{SessionID: value.ID, Timestamp: now, Type: events.ProcessStart, Subject: "sh", Metadata: map[string]any{"argv": value.Command}},
		{SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.DecoyAccess, Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_cli", "marker": "DO_NOT_EXPORT_MARKER"}},
		{SessionID: value.ID, Timestamp: now.Add(2 * time.Millisecond), Type: events.ContainmentActivated, Resource: "network", Decision: &deny},
		{SessionID: value.ID, Timestamp: now.Add(3 * time.Millisecond), Type: events.NetworkRequest, Resource: "example.com:443", Metadata: map[string]any{"host": "example.com", "port": 443, "body": "DO_NOT_EXPORT_BODY"}},
		{SessionID: value.ID, Timestamp: now.Add(4 * time.Millisecond), Type: events.NetworkDeny, Resource: "example.com:443", Decision: &deny, Metadata: map[string]any{"host": "example.com", "port": 443, "contained": true}},
	} {
		if err := store.AddEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var textOutput bytes.Buffer
	if err := graphSession(ctx, root, "latest", false, &textOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Ghost Provenance Graph", "ACCESSED", "CONTAINED", "REQUESTED", "DENIED", "FOLLOWED_BY", "not causality"} {
		if !strings.Contains(textOutput.String(), expected) {
			t.Errorf("text graph missing %q:\n%s", expected, textOutput.String())
		}
	}

	var jsonOutput bytes.Buffer
	if err := graphSession(ctx, root, value.ID, true, &jsonOutput); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Version int `json:"version"`
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(jsonOutput.Bytes(), &document); err != nil {
		t.Fatalf("invalid graph JSON: %v\n%s", err, jsonOutput.String())
	}
	if document.Version != provenance.SchemaVersion || document.Session.ID != value.ID {
		t.Fatalf("graph JSON summary = %+v", document)
	}
	for _, secret := range []string{"DO_NOT_EXPORT_SECRET", "DO_NOT_EXPORT_MARKER", "DO_NOT_EXPORT_BODY"} {
		if strings.Contains(jsonOutput.String(), secret) {
			t.Fatalf("graph JSON leaked %q:\n%s", secret, jsonOutput.String())
		}
	}
}

func TestIncidentsSessionRendersStoredEvidenceAsTextAndJSON(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, config.RuntimeDirName, config.DatabaseName))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	value := session.Session{
		ID: "incident-session", CreatedAt: now, Command: []string{"sh", "DO_NOT_EXPORT_SECRET"},
		Runtime: "docker", Status: session.Completed, NetworkMode: ghostnetwork.Allowlist, SecurityState: policy.StateContained,
	}
	if err := store.CreateSession(ctx, value); err != nil {
		t.Fatal(err)
	}
	shadow := policy.Shadow
	deny := policy.Deny
	decoyPath := deception.GuestHome + "/.aws/credentials"
	for _, event := range []*events.Event{
		{SessionID: value.ID, Timestamp: now, Type: events.PolicyShadow, Subject: "home", Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_cli", "marker": "DO_NOT_EXPORT_MARKER"}},
		{SessionID: value.ID, Timestamp: now.Add(time.Millisecond), Type: events.DecoyAccess, Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_cli"}},
		{SessionID: value.ID, Timestamp: now.Add(2 * time.Millisecond), Type: events.ContainmentActivated, Resource: "network", Decision: &deny},
		{SessionID: value.ID, Timestamp: now.Add(3 * time.Millisecond), Type: events.NetworkRequest, Resource: "example.com:443", Metadata: map[string]any{"host": "example.com", "port": 443, "body": "DO_NOT_EXPORT_BODY"}},
		{SessionID: value.ID, Timestamp: now.Add(4 * time.Millisecond), Type: events.NetworkDeny, Resource: "example.com:443", Decision: &deny, Metadata: map[string]any{"host": "example.com", "port": 443, "contained": true}},
	} {
		if err := store.AddEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var textOutput bytes.Buffer
	if err := incidentsSession(ctx, root, "latest", false, &textOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Ghost Incidents", "DECOY_ACCESS_WITH_NETWORK_ACTIVITY", "SHADOW_EXPOSED", "NETWORK_DENIED", "does not prove causality"} {
		if !strings.Contains(textOutput.String(), expected) {
			t.Errorf("incident text missing %q:\n%s", expected, textOutput.String())
		}
	}

	var jsonOutput bytes.Buffer
	if err := incidentsSession(ctx, root, value.ID, true, &jsonOutput); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Version int `json:"version"`
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
		Incidents []struct {
			Type string `json:"type"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(jsonOutput.Bytes(), &document); err != nil {
		t.Fatalf("invalid incident JSON: %v\n%s", err, jsonOutput.String())
	}
	if document.Version != incidents.SchemaVersion || document.Session.ID != value.ID || len(document.Incidents) != 1 || document.Incidents[0].Type != "DECOY_ACCESS_WITH_NETWORK_ACTIVITY" {
		t.Fatalf("incident JSON summary = %+v", document)
	}
	for _, secret := range []string{"DO_NOT_EXPORT_SECRET", "DO_NOT_EXPORT_MARKER", "DO_NOT_EXPORT_BODY", "dcy_cli"} {
		if strings.Contains(jsonOutput.String(), secret) {
			t.Fatalf("incident JSON leaked %q:\n%s", secret, jsonOutput.String())
		}
	}
}

func TestInspectionShowsNetworkStateWithoutExfiltrationClaim(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 4, 0, 0, time.UTC)
	completed := now.Add(time.Second)
	allow := policy.Allow
	deny := policy.Deny
	value := session.Session{
		ID: "network-session", CreatedAt: now, CompletedAt: &completed,
		Command: []string{"wget"}, Runtime: "docker", Status: session.Completed,
		NetworkMode: ghostnetwork.Allowlist, SecurityState: policy.StateContained,
	}
	shadow := policy.Shadow
	decoyPath := deception.GuestHome + "/.aws/credentials"
	eventValues := []events.Event{
		{ID: 1, SessionID: value.ID, Type: events.NetworkAllow, Timestamp: now, Decision: &allow, Metadata: map[string]any{"host": "allowed.test", "port": 443, "method": "CONNECT"}},
		{ID: 2, SessionID: value.ID, Type: events.DecoyAccess, Timestamp: now.Add(time.Millisecond), Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_inspect"}},
		{ID: 3, SessionID: value.ID, Type: events.ContainmentActivated, Timestamp: now.Add(time.Millisecond), Resource: "network", Decision: &deny},
		{ID: 4, SessionID: value.ID, Type: events.SecurityIncident, Timestamp: now.Add(time.Millisecond), Resource: decoyPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": "dcy_inspect", "severity": "high"}},
		{ID: 5, SessionID: value.ID, Type: events.NetworkRequest, Timestamp: now.Add(2 * time.Millisecond), Resource: "allowed.test:443", Metadata: map[string]any{"host": "allowed.test", "port": 443, "method": "CONNECT"}},
		{ID: 6, SessionID: value.ID, Type: events.NetworkDeny, Timestamp: now.Add(2 * time.Millisecond), Resource: "allowed.test:443", Decision: &deny, Metadata: map[string]any{"host": "allowed.test", "port": 443, "method": "CONNECT", "contained": true}},
	}
	var output bytes.Buffer
	printInspection(&output, value, eventValues, nil)
	for _, expected := range []string{
		"Network:", "ALLOWLIST", "Contained:", "yes", "allowed.test", "443", "ALLOW", "DENY",
		"DECOY_ACCESS_WITH_NETWORK_ACTIVITY", "later contained network activity was denied", "Details: ghost incidents network-session",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("inspection missing %q:\n%s", expected, output.String())
		}
	}
	if strings.Contains(strings.ToLower(output.String()), "credential exfiltration") {
		t.Fatalf("inspection overclaims evidence:\n%s", output.String())
	}
}

func TestSecuritySummaryCountsUniquePromptSources(t *testing.T) {
	eventValues := []events.Event{
		{Type: events.UntrustedContentObserved, Resource: "workspace:README.md"},
		{Type: events.UntrustedContentObserved, Resource: "workspace:README.md"},
		{Type: events.UntrustedContentObserved, Resource: "workspace:AGENTS.md"},
		{Type: events.PromptInjectionSuspected, Resource: "workspace:AGENTS.md"},
		{Type: events.PromptInjectionSuspected, Resource: "workspace:AGENTS.md"},
		{Type: events.PromptInjectionSuspected, Resource: "workspace:README.md"},
		{Type: events.DecoyAccess},
		{Type: events.NetworkDeny},
		{Type: events.ApprovalRequired},
		{Type: events.ApprovalGranted},
		{Type: events.ApprovalRequired},
		{Type: events.ApprovalUnavailable},
	}
	got := summarizeSecurity(session.Session{}, eventValues)
	if got.UntrustedSources != 2 || got.SuspiciousSources != 2 || got.ShadowAccesses != 1 || got.NetworkDenials != 1 || got.ApprovalRequests != 2 || got.ApprovalsGranted != 1 || got.ApprovalsDenied != 1 {
		t.Fatalf("security summary = %+v", got)
	}
}

type cliTestRuntime struct {
	preflightErr error
	preparedErr  error
	result       ghruntime.RunResult
	preflights   int
	preparedRuns int
	directRuns   int
}

type cliTestPreparedRun struct{ runtime *cliTestRuntime }

func (*cliTestRuntime) Name() string { return "docker" }
func (r *cliTestRuntime) Run(context.Context, ghruntime.RunRequest) (ghruntime.RunResult, error) {
	r.directRuns++
	return ghruntime.RunResult{}, errors.New("unexpected direct runtime call")
}
func (r *cliTestRuntime) Preflight(context.Context, ghruntime.RunRequest) (ghruntime.PreparedRun, error) {
	r.preflights++
	if r.preflightErr != nil {
		return nil, r.preflightErr
	}
	return &cliTestPreparedRun{runtime: r}, nil
}
func (p *cliTestPreparedRun) Run(context.Context) (ghruntime.RunResult, error) {
	p.runtime.preparedRuns++
	return p.runtime.result, p.runtime.preparedErr
}

func TestRunCommandSuccessfulPreflightIsConcise(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	var initOutput bytes.Buffer
	if err := initProject(ctx, root, &initOutput); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(initOutput.String(), "Next:   ghost run <agent>") {
		t.Fatalf("init output lacks next step:\n%s", initOutput.String())
	}
	runner := &cliTestRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 0, SecurityState: policy.StateNormal}}
	var stdout, stderr bytes.Buffer
	exitCode := runCommandWithFactory(ctx, root, []string{"echo", "safe"}, strings.NewReader(""), &stdout, &stderr,
		func(string) (ghruntime.Runtime, error) { return runner, nil })
	if exitCode != 0 || runner.preflights != 1 || runner.preparedRuns != 1 || runner.directRuns != 0 {
		t.Fatalf("run result: exit=%d preflight=%d prepared=%d direct=%d stderr=%q", exitCode, runner.preflights, runner.preparedRuns, runner.directRuns, stderr.String())
	}
	for _, want := range []string{"Ghost completed successfully.", "No security actions required."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("run output missing %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "Ghost session ") {
		t.Fatalf("ordinary completion prominently exposed a session UUID: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") || stderr.Len() != 0 {
		t.Fatalf("non-TTY safe run output is noisy: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunCommandPreflightFailureIsActionableAndFailClosed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := initProject(ctx, root, io.Discard); err != nil {
		t.Fatal(err)
	}
	runner := &cliTestRuntime{preflightErr: &ghruntime.PreflightError{
		Area: ghruntime.PreflightDocker, Err: errors.New("controlled daemon outage"),
	}}
	var stdout, stderr bytes.Buffer
	exitCode := runCommandWithFactory(ctx, root, []string{"echo", "must-not-run"}, strings.NewReader(""), &stdout, &stderr,
		func(string) (ghruntime.Runtime, error) { return runner, nil })
	if exitCode != 1 || runner.preflights != 1 || runner.preparedRuns != 0 || runner.directRuns != 0 {
		t.Fatalf("run result: exit=%d preflight=%d prepared=%d direct=%d", exitCode, runner.preflights, runner.preparedRuns, runner.directRuns)
	}
	for _, want := range []string{"Ghost cannot start securely.", "Docker runtime is unavailable.", "The agent was not launched.", "Next:", "controlled daemon outage", "Session:"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("preflight output missing %q:\n%s", want, stderr.String())
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed preflight wrote normal output: %q", stdout.String())
	}
}

func TestDockerPreflightGuidanceDistinguishesMissingCLIAndDaemon(t *testing.T) {
	for _, tc := range []struct {
		detail, guidance string
	}{
		{"Docker CLI not found in PATH", "Install Docker and make sure 'docker' is on PATH"},
		{"Docker daemon is unavailable: controlled outage", "Start Docker and confirm 'docker info' succeeds"},
	} {
		var output bytes.Buffer
		writeRunFailure(&output, session.Session{ID: "session"}, &ghruntime.PreflightError{Area: ghruntime.PreflightDocker, Err: errors.New(tc.detail)})
		if !strings.Contains(output.String(), tc.guidance) || !strings.Contains(output.String(), "The agent was not launched.") {
			t.Errorf("detail=%q output=%q", tc.detail, output.String())
		}
	}
}

func TestDockerPreflightGuidanceExplainsPinnedImageAcquisition(t *testing.T) {
	var output bytes.Buffer
	writeRunFailure(&output, session.Session{}, &ghruntime.PreflightError{
		Area: ghruntime.PreflightDocker, Err: errors.New("obtain pinned runtime image: registry unavailable"),
	})
	message := output.String()
	for _, want := range []string{"registry connectivity", "only use the pinned runtime image", "registry unavailable"} {
		if !strings.Contains(message, want) {
			t.Fatalf("image failure message %q missing %q", message, want)
		}
	}
}

func TestCancellationTakesPrecedenceDuringPreflight(t *testing.T) {
	var output bytes.Buffer
	writeRunFailure(&output, session.Session{ID: "cancelled-preflight"}, &ghruntime.PreflightError{
		Area: ghruntime.PreflightDocker, Err: context.Canceled,
	})
	message := output.String()
	if !strings.Contains(message, "The session was cancelled.") || strings.Contains(message, "Docker runtime is unavailable") {
		t.Fatalf("preflight cancellation was misclassified: %q", message)
	}
}

func TestRunCommandInvalidConfigurationFailsBeforeRuntimeSelection(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, config.FileName), []byte("version: 1\nnetwork:\n  mode: unrestricted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	factoryCalled := false
	var stdout, stderr bytes.Buffer
	exitCode := runCommandWithFactory(context.Background(), root, []string{"echo", "must-not-run"}, strings.NewReader(""), &stdout, &stderr,
		func(string) (ghruntime.Runtime, error) {
			factoryCalled = true
			return nil, errors.New("must not be called")
		})
	if exitCode != 1 || factoryCalled || stdout.Len() != 0 {
		t.Fatalf("invalid config result: exit=%d factory=%v stdout=%q", exitCode, factoryCalled, stdout.String())
	}
	for _, want := range []string{"Ghost cannot start securely.", "Project configuration is invalid.", "Correct ghost.yaml"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("configuration error missing %q:\n%s", want, stderr.String())
		}
	}
	if _, err := os.Stat(filepath.Join(root, config.RuntimeDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid user configuration caused internal state creation: %v", err)
	}
}

func TestRunCommandPropagatesAgentExitCodeAfterSecureLaunch(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := initProject(ctx, root, io.Discard); err != nil {
		t.Fatal(err)
	}
	runner := &cliTestRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 7, SecurityState: policy.StateNormal}}
	var stdout, stderr bytes.Buffer
	exitCode := runCommandWithFactory(ctx, root, []string{"false"}, strings.NewReader(""), &stdout, &stderr,
		func(string) (ghruntime.Runtime, error) { return runner, nil })
	if exitCode != 7 || runner.preparedRuns != 1 || stderr.Len() != 0 {
		t.Fatalf("agent failure result: exit=%d prepared=%d stderr=%q", exitCode, runner.preparedRuns, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Ghost command exited with code 7.") || !strings.Contains(stdout.String(), "No security actions required.") {
		t.Fatalf("agent failure output:\n%s", stdout.String())
	}
}

func TestRunCommandAddsNetworkDenyHintOnlyForLikelyNetworkTools(t *testing.T) {
	for _, tc := range []struct {
		command  []string
		wantHint bool
	}{{[]string{"wget", "https://example.invalid"}, true}, {[]string{"false"}, false}} {
		root := t.TempDir()
		if err := initProject(context.Background(), root, io.Discard); err != nil {
			t.Fatal(err)
		}
		runner := &cliTestRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 1, SecurityState: policy.StateNormal}}
		var stdout, stderr bytes.Buffer
		exitCode := runCommandWithFactory(context.Background(), root, tc.command, strings.NewReader(""), &stdout, &stderr,
			func(string) (ghruntime.Runtime, error) { return runner, nil })
		if exitCode != 1 || strings.Contains(stderr.String(), "blocks network access") != tc.wantHint {
			t.Fatalf("command=%v exit=%d stderr=%q", tc.command, exitCode, stderr.String())
		}
	}
}

func TestRunCommandExplainsUnavailableGuestCommand(t *testing.T) {
	root := t.TempDir()
	if err := initProject(context.Background(), root, io.Discard); err != nil {
		t.Fatal(err)
	}
	runner := &cliTestRuntime{
		result:      ghruntime.RunResult{ExitCode: 127, SecurityState: policy.StateNormal},
		preparedErr: &ghruntime.CommandUnavailableError{Executable: "missing-tool"},
	}
	var stdout, stderr bytes.Buffer
	exitCode := runCommandWithFactory(context.Background(), root, []string{"missing-tool", "DO_NOT_PRINT_ARGUMENT"}, strings.NewReader(""), &stdout, &stderr,
		func(string) (ghruntime.Runtime, error) { return runner, nil })
	if exitCode != 1 || !strings.Contains(stderr.String(), `Command "missing-tool" is not available inside Ghost's pinned isolated runtime.`) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "DO_NOT_PRINT_ARGUMENT") {
		t.Fatalf("failure leaked command arguments: %q", stderr.String())
	}
}

func TestRunCommandExplainsCancellation(t *testing.T) {
	root := t.TempDir()
	if err := initProject(context.Background(), root, io.Discard); err != nil {
		t.Fatal(err)
	}
	runner := &cliTestRuntime{
		result:      ghruntime.RunResult{Started: true, ExitCode: 125, SecurityState: policy.StateNormal},
		preparedErr: context.Canceled,
	}
	var stdout, stderr bytes.Buffer
	exitCode := runCommandWithFactory(context.Background(), root, []string{"sh"}, strings.NewReader(""), &stdout, &stderr,
		func(string) (ghruntime.Runtime, error) { return runner, nil })
	if exitCode != 1 || !strings.Contains(stderr.String(), "The session was cancelled.") || !strings.Contains(stderr.String(), "cleaned up any isolated runtime resources") {
		t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
	}
}

func TestRunFailureExplainsConcurrentProjectRun(t *testing.T) {
	var output bytes.Buffer
	writeRunFailure(&output, session.Session{}, session.ErrProjectBusy)
	message := output.String()
	for _, want := range []string{"already active in this project", "Wait for that run to finish", "Other projects can run independently"} {
		if !strings.Contains(message, want) {
			t.Fatalf("concurrent-run message %q missing %q", message, want)
		}
	}
}

func TestRunFailureExplainsPendingCleanupWithoutClaimingSuccess(t *testing.T) {
	var output bytes.Buffer
	writeRunFailure(&output, session.Session{ID: "cleanup-session"}, &ghruntime.CleanupVerificationError{Err: errors.New("Docker daemon unavailable")})
	message := output.String()
	for _, want := range []string{"could not verify complete cleanup", "remains marked for exact recovery", "unrelated Docker resources will not be removed", "Docker daemon unavailable"} {
		if !strings.Contains(message, want) {
			t.Fatalf("cleanup failure message %q missing %q", message, want)
		}
	}
	if strings.Contains(message, "cleaned up the isolated process tree") {
		t.Fatalf("cleanup failure claimed success: %q", message)
	}
}

func TestRunFailureExplainsTemporaryDatabaseLock(t *testing.T) {
	var output bytes.Buffer
	writeRunFailure(&output, session.Session{}, errors.New("update session: SQLITE_BUSY: database is locked"))
	message := output.String()
	for _, want := range []string{"temporarily busy", "Wait for the other local database operation", "do not delete .ghost"} {
		if !strings.Contains(message, want) {
			t.Fatalf("database-lock message %q missing %q", message, want)
		}
	}
}

func TestRunCommandExplainsMandatoryRuntimeTermination(t *testing.T) {
	for _, tc := range []struct {
		name, kind, problem string
		runErr              error
		limit, observed     int64
	}{
		{"timeout", ghruntime.ResourceTimeout, "configured session time limit", ghruntime.ErrSessionTimeout, 1, 0},
		{"processes", ghruntime.ResourcePIDs, "reached its process boundary", &ghruntime.ResourceLimitError{Kind: ghruntime.ResourcePIDs}, 16, 16},
		{"memory", ghruntime.ResourceOOM, "reached its memory boundary", &ghruntime.ResourceLimitError{Kind: ghruntime.ResourceOOM}, 64 * 1024 * 1024, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := initProject(context.Background(), root, io.Discard); err != nil {
				t.Fatal(err)
			}
			runner := &cliTestRuntime{
				result: ghruntime.RunResult{
					Started: true, ExitCode: 137, SecurityState: policy.StateNormal,
					Resources: []ghruntime.ResourceEvidence{{Kind: tc.kind, DetectedAt: time.Now().UTC(), Limit: tc.limit, Observed: tc.observed}},
				},
				preparedErr: tc.runErr,
			}
			var stdout, stderr bytes.Buffer
			exitCode := runCommandWithFactory(context.Background(), root, []string{"sh"}, strings.NewReader(""), &stdout, &stderr,
				func(string) (ghruntime.Runtime, error) { return runner, nil })
			if exitCode != 1 || !strings.Contains(stderr.String(), tc.problem) || !strings.Contains(stderr.String(), "cleaned up the isolated process tree") {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "Security\n") {
				t.Fatalf("resource evidence summary missing: %q", stdout.String())
			}
		})
	}
}

func TestRunSummaryUsesOnlyStoredEvidenceAndDoesNotClaimCausality(t *testing.T) {
	value := session.Session{ID: "summary-session", Runtime: "docker", SecurityState: policy.StateContained}
	storedEvents := []events.Event{
		{SessionID: value.ID, Type: events.PromptInjectionSuspected, Resource: "workspace:AGENTS.md", Metadata: map[string]any{"excerpt": "DO_NOT_PRINT_SECRET"}},
		{SessionID: value.ID, Type: events.DecoyAccess, Resource: deception.GuestHome + "/.aws/credentials", Metadata: map[string]any{"marker": "DO_NOT_PRINT_MARKER"}},
		{SessionID: value.ID, Type: events.NetworkDeny, Resource: "example.invalid:443", Metadata: map[string]any{"body": "DO_NOT_PRINT_BODY"}},
		{SessionID: value.ID, Type: events.ApprovalRequired},
		{SessionID: value.ID, Type: events.ApprovalUnavailable},
		{SessionID: value.ID, Type: events.ResourceLimitTriggered},
		{SessionID: value.ID, Type: events.PolicyViolation},
		{SessionID: "other-session", Type: events.DecoyAccess},
	}
	var output bytes.Buffer
	writeRunSummary(&output, value, storedEvents)
	for _, want := range []string{
		"Suspicious instruction sources", "SHADOW resources accessed", "Network requests blocked",
		"Approval requests", "0 / 1", "Inspection or resource limits reported", "Policy violations recorded",
		"Session contained", "Host home mounted or host environment inherited: no",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "SHADOW resources accessed  2") {
		t.Fatalf("summary mixed sessions:\n%s", output.String())
	}
	for _, forbidden := range []string{"DO_NOT_PRINT_SECRET", "DO_NOT_PRINT_MARKER", "DO_NOT_PRINT_BODY", "caused", "causal"} {
		if strings.Contains(strings.ToLower(output.String()), strings.ToLower(forbidden)) {
			t.Fatalf("summary contains unsupported or secret text %q:\n%s", forbidden, output.String())
		}
	}
}

func BenchmarkSecuritySummary(b *testing.B) {
	value := session.Session{ID: "benchmark-session", Runtime: "docker", SecurityState: policy.StateContained}
	storedEvents := make([]events.Event, 0, 128)
	for index := 0; index < 32; index++ {
		resource := fmt.Sprintf("workspace:docs/%d.md", index)
		storedEvents = append(storedEvents,
			events.Event{SessionID: value.ID, Type: events.UntrustedContentObserved, Resource: resource},
			events.Event{SessionID: value.ID, Type: events.PromptInjectionSuspected, Resource: resource},
			events.Event{SessionID: value.ID, Type: events.NetworkDeny},
			events.Event{SessionID: value.ID, Type: events.PolicyViolation},
		)
	}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		result := summarizeSecurity(value, storedEvents)
		if result.SuspiciousSources != 32 {
			b.Fatalf("summary = %+v", result)
		}
	}
}

func TestInspectionShowsApprovalSummary(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	completed := now.Add(time.Second)
	ask := policy.Ask
	deny := policy.Deny
	value := session.Session{
		ID: "approval-session", CreatedAt: now, CompletedAt: &completed,
		Command: []string{"wget"}, Runtime: "docker", Status: session.Completed,
		NetworkMode: ghostnetwork.Allowlist, SecurityState: policy.StateNormal,
	}
	eventValues := []events.Event{
		{ID: 1, SessionID: value.ID, Type: events.PolicyAsk, Timestamp: now, Resource: "api.example.com", Decision: &ask},
		{ID: 2, SessionID: value.ID, Type: events.ApprovalRequired, Timestamp: now, Resource: "api.example.com:443", Decision: &ask},
		{ID: 3, SessionID: value.ID, Type: events.ApprovalUnavailable, Timestamp: now, Resource: "api.example.com:443", Decision: &deny},
		{ID: 4, SessionID: value.ID, Type: events.NetworkDeny, Timestamp: now, Resource: "api.example.com:443", Decision: &deny},
	}
	var output bytes.Buffer
	printInspection(&output, value, eventValues, nil)
	for _, expected := range []string{"ASK", "Approval requests:", "Approved / denied:", "0 / 1"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("inspection missing %q:\n%s", expected, output.String())
		}
	}
}

func TestInspectionShowsShadowEvidence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	completed := now.Add(time.Second)
	exitCode := 0
	shadow := policy.Shadow
	value := session.Session{
		ID: "session", CreatedAt: now, CompletedAt: &completed,
		Command: []string{"cat", "/home/ghost/.aws/credentials"}, Runtime: "docker",
		Status: session.Completed, ExitCode: &exitCode,
	}
	decoy := deception.Decoy{
		ID: "dcy", SessionID: value.ID, Type: deception.AWSCredentials,
		GuestPath: deception.GuestHome + "/.aws/credentials", CreatedAt: now,
		Marker: "opaque", Triggered: true, TriggeredAt: &completed,
	}
	eventValues := []events.Event{
		{ID: 1, SessionID: value.ID, Type: events.PolicyShadow, Timestamp: now, Subject: "home", Resource: decoy.GuestPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": decoy.ID}},
		{ID: 2, SessionID: value.ID, Type: events.DecoyAccess, Timestamp: completed, Resource: decoy.GuestPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": decoy.ID}},
		{ID: 3, SessionID: value.ID, Type: events.SecurityIncident, Timestamp: completed, Resource: decoy.GuestPath, Decision: &shadow, Metadata: map[string]any{"decoy_id": decoy.ID, "severity": "high"}},
	}
	var output bytes.Buffer
	printInspection(&output, value, eventValues, []deception.Decoy{decoy})
	for _, expected := range []string{"SHADOW 1", "AWS credentials", "~/.aws/credentials", "TRIGGERED", "Host home mounted:", "HIGH  DECOY_ACCESS"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("inspection missing %q:\n%s", expected, output.String())
		}
	}
}

func TestInitCreatesValidProjectWithoutOverwriting(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	var output bytes.Buffer
	if err := initProject(context.Background(), root, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(filepath.Join(root, config.FileName)); err != nil {
		t.Fatalf("created configuration is invalid: %v", err)
	}
	for _, path := range []string{
		filepath.Join(root, config.RuntimeDirName, config.DatabaseName),
		filepath.Join(root, config.RuntimeDirName, config.SessionsDir),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}

	custom := []byte("version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-only}\nnetwork: {mode: none}\npolicy: {home: deny}\n")
	configPath := filepath.Join(root, config.FileName)
	if err := os.WriteFile(configPath, custom, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initProject(context.Background(), root, &output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, custom) {
		t.Fatalf("second init overwrote configuration:\n%s", got)
	}
}

func TestInitAddsGitIgnoreEntryWithoutRewritingExistingContent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "vendor/\n# project rules"
	ignorePath := filepath.Join(root, ".gitignore")
	if err := os.WriteFile(ignorePath, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := initProject(context.Background(), root, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(ignorePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), original) || strings.Count(string(data), ".ghost/") != 1 {
		t.Fatalf(".gitignore was not safely extended:\n%s", data)
	}
}

func TestInitDoesNotFollowGitIgnoreSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("preserve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".gitignore")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var output bytes.Buffer
	if err := initProject(context.Background(), root, &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preserve\n" || !strings.Contains(output.String(), "add .ghost/ to .gitignore manually") {
		t.Fatalf("target=%q output=%q", data, output.String())
	}
}

func TestRunRecreatesMissingInternalProjectState(t *testing.T) {
	root := t.TempDir()
	if _, err := config.WriteDefault(filepath.Join(root, config.FileName)); err != nil {
		t.Fatal(err)
	}
	run := func() {
		runner := &cliTestRuntime{result: ghruntime.RunResult{Started: true, ExitCode: 0, SecurityState: policy.StateNormal}}
		var stdout, stderr bytes.Buffer
		if exitCode := runCommandWithFactory(context.Background(), root, []string{"true"}, strings.NewReader(""), &stdout, &stderr,
			func(string) (ghruntime.Runtime, error) { return runner, nil }); exitCode != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
		}
	}
	run()
	for _, path := range []string{
		filepath.Join(root, config.RuntimeDirName, config.DatabaseName),
		filepath.Join(root, config.RuntimeDirName, config.SessionsDir),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing recreated state %s: %v", path, err)
		}
	}
	if err := os.RemoveAll(filepath.Join(root, config.RuntimeDirName, config.SessionsDir)); err != nil {
		t.Fatal(err)
	}
	run()
}

func TestInspectRecreatesInternalStateButNotUserConfiguration(t *testing.T) {
	root := t.TempDir()
	if _, err := config.WriteDefault(filepath.Join(root, config.FileName)); err != nil {
		t.Fatal(err)
	}
	err := inspectSession(context.Background(), root, "latest", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no sessions recorded") {
		t.Fatalf("inspect error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, config.RuntimeDirName, config.DatabaseName)); err != nil {
		t.Fatalf("inspect did not reconstruct internal state: %v", err)
	}
}

func TestInitRejectsSymlinkedRuntimeDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, config.RuntimeDirName)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := initProject(context.Background(), root, &bytes.Buffer{}); err == nil {
		t.Fatal("init accepted a symlinked .ghost directory")
	}
}

func TestRuntimeSummaryUsesOperationalEvidenceWithoutSecrets(t *testing.T) {
	value := session.Session{ID: "runtime-summary", Runtime: "docker"}
	var stored []events.Event
	for _, kind := range []string{"session_timeout", "oom_termination", "process_limit_reached"} {
		stored = append(stored, events.Event{SessionID: value.ID, Type: events.ResourceLimitTriggered, Subject: "docker", Metadata: map[string]any{"kind": kind, "secret": "DO_NOT_PRINT", "classification": "operational"}})
	}
	var output bytes.Buffer
	writeRunSummary(&output, value, stored)
	for _, wanted := range []string{"Session time limit reached", "Confirmed container OOM termination", "Process boundary reached"} {
		if !strings.Contains(output.String(), wanted) {
			t.Errorf("missing %s: %s", wanted, output.String())
		}
	}
	for _, forbidden := range []string{"DO_NOT_PRINT", "malicious", "Session contained"} {
		if strings.Contains(output.String(), forbidden) {
			t.Errorf("unsupported output %s", output.String())
		}
	}
}
