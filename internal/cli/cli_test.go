package cli

import (
	"bytes"
	"context"
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
	eventValues := []events.Event{
		{Type: events.NetworkAllow, Timestamp: now, Decision: &allow, Metadata: map[string]any{"host": "allowed.test", "port": 443, "method": "CONNECT"}},
		{Type: events.DecoyAccess, Timestamp: now.Add(time.Millisecond)},
		{Type: events.NetworkRequest, Timestamp: now.Add(2 * time.Millisecond)},
		{Type: events.NetworkDeny, Timestamp: now.Add(2 * time.Millisecond), Decision: &deny, Metadata: map[string]any{"host": "allowed.test", "port": 443, "method": "CONNECT"}},
		{Type: events.SecurityIncident, Timestamp: now.Add(time.Millisecond), Metadata: map[string]any{"severity": "high"}},
	}
	var output bytes.Buffer
	printInspection(&output, value, eventValues, nil)
	for _, expected := range []string{
		"Network:", "ALLOWLIST", "Contained:", "yes", "allowed.test", "443", "ALLOW", "DENY",
		"Outbound network activity occurred after a decoy access in the same session.",
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
		{Type: events.PolicyShadow, Timestamp: now, Decision: &shadow},
		{Type: events.SecurityIncident, Timestamp: completed, Resource: decoy.GuestPath, Decision: &shadow, Metadata: map[string]any{"severity": "high"}},
	}
	var output bytes.Buffer
	printInspection(&output, value, eventValues, []deception.Decoy{decoy})
	for _, expected := range []string{"SHADOW 1", "AWS credentials", "~/.aws/credentials", "TRIGGERED", "Host home mounted:", "HIGH  Shadow resource accessed"} {
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
