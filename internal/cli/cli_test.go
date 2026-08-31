package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"github.com/rappidAI-research/rappid-ghost/internal/deception"
	"github.com/rappidAI-research/rappid-ghost/internal/events"
	ghostnetwork "github.com/rappidAI-research/rappid-ghost/internal/network"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
	"github.com/rappidAI-research/rappid-ghost/internal/storage"
)

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
	if _, err := parseRunArgs([]string{"echo", "hello"}); err == nil {
		t.Fatal("missing -- separator was accepted")
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
	for _, input := range [][]string{nil, {"--json"}, {"latest", "--yaml"}, {"--json", "latest"}, {"latest", "--json", "extra"}} {
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
	for _, input := range [][]string{nil, {"--json"}, {"latest", "--yaml"}, {"--json", "latest"}, {"latest", "--json", "extra"}} {
		if _, _, err := parseIncidentsArgs(input); err == nil {
			t.Errorf("parseIncidentsArgs(%#v) succeeded", input)
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
		Runtime: "docker", Status: session.Completed, NetworkMode: ghostnetwork.Allowlist, Contained: true,
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
	if document.Version != 1 || document.Session.ID != value.ID {
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
		Runtime: "docker", Status: session.Completed, NetworkMode: ghostnetwork.Allowlist, Contained: true,
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
	if document.Version != 1 || document.Session.ID != value.ID || len(document.Incidents) != 1 || document.Incidents[0].Type != "DECOY_ACCESS_WITH_NETWORK_ACTIVITY" {
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
		NetworkMode: ghostnetwork.Allowlist, Contained: true,
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
