package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestScenarioRegistryIsStableAndUnique(t *testing.T) {
	want := []string{
		"host-home-isolation", "shadow-credentials", "deny-sensitive-resource", "network-deny",
		"network-allowlist", "direct-egress-bypass", "dynamic-containment", "session-isolation",
		"fail-closed-runtime", "safe-baseline",
	}
	if got := ScenarioIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ScenarioIDs() = %#v, want %#v", got, want)
	}
	seen := make(map[string]bool)
	for _, id := range ScenarioIDs() {
		if seen[id] {
			t.Fatalf("duplicate scenario %q", id)
		}
		seen[id] = true
	}
}

func TestUnavailableDockerIsSkipAndFailClosedStillRuns(t *testing.T) {
	runner := NewRunner()
	runner.dockerProbe = func(context.Context, string) error { return errors.New("controlled unavailable Docker") }
	report := runner.Run(context.Background(), Options{})
	if report.Version != SchemaVersion || report.Summary.Passed != 1 || report.Summary.Failed != 0 || report.Summary.Skipped != 9 {
		t.Fatalf("report summary = %+v", report.Summary)
	}
	for _, result := range report.Results {
		switch result.Scenario {
		case "fail-closed-runtime":
			if result.Status != Pass || len(result.Evidence) != 1 || result.Evidence[0].SessionID == "" {
				t.Fatalf("fail-closed result = %+v", result)
			}
		default:
			if result.Status != Skip || len(result.Evidence) != 0 {
				t.Fatalf("Docker-dependent result = %+v", result)
			}
		}
	}
}

func TestJSONSchemaIsVersionedAndSecretMinimized(t *testing.T) {
	report := newReport([]Result{{
		Scenario: "safe-baseline", Name: "Safe baseline", Property: "controlled property",
		Status: Pass, Detail: "controlled observation",
		Evidence: []EvidenceBundle{{
			SessionID: "session-1", EventIDs: []int64{1, 2}, IncidentIDs: []string{},
			ProvenanceNodeIDs: []string{"node-1"}, ProvenanceEdgeIDs: []string{"edge-1"},
		}},
	}})
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if document["version"] != float64(1) {
		t.Fatalf("version = %#v", document["version"])
	}
	for _, forbidden := range []string{"credential", "marker", "command_output", "request_body", "headers", "cookies"} {
		if strings.Contains(strings.ToLower(output.String()), `"`+forbidden+`"`) {
			t.Fatalf("benchmark schema exposed forbidden field %q: %s", forbidden, output.String())
		}
	}
}

func TestTextRendererReportsPassFailSkipSeparately(t *testing.T) {
	report := newReport([]Result{
		{Name: "One", Status: Pass},
		{Name: "Two", Status: Fail, Detail: "observed mismatch"},
		{Name: "Three", Status: Skip, Detail: "environment unavailable"},
	})
	var output bytes.Buffer
	WriteText(&output, report)
	for _, expected := range []string{"GhostBench", "One", "PASS", "Two", "FAIL", "Three", "SKIP", "1 passed", "1 failed", "1 skipped"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestTextRendererShowsSelectedScenarioEvidence(t *testing.T) {
	report := newReport([]Result{{
		Name: "Dynamic containment", Property: "controlled transition", Status: Pass,
		Detail: "allow, access, contain, deny observed",
		Evidence: []EvidenceBundle{{
			SessionID: "session-1", EventIDs: []int64{1, 2, 3, 4},
			IncidentIDs: []string{"incident-1"}, ProvenanceNodeIDs: []string{"node-1"},
			ProvenanceEdgeIDs: []string{"edge-1", "edge-2"},
		}},
	}})
	var output bytes.Buffer
	WriteText(&output, report)
	for _, expected := range []string{"Property:", "controlled transition", "Observation:", "Evidence references:", "Session session-1", "4 events", "1 incidents", "2 graph edges"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("selected output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestValidateOptionsRejectsUnknownScenario(t *testing.T) {
	if err := ValidateOptions(Options{Scenario: "does-not-exist"}); err == nil {
		t.Fatal("unknown scenario accepted")
	}
	if err := ValidateOptions(Options{Scenario: "dynamic-containment"}); err != nil {
		t.Fatal(err)
	}
	report := NewRunner().Run(context.Background(), Options{Scenario: "does-not-exist"})
	if report.Summary.Failed != 1 || report.Successful() {
		t.Fatalf("invalid runner report = %+v", report)
	}
}

func TestControlledFixtureArgumentsStayLocalAndConstrained(t *testing.T) {
	fixture := &httpFixture{network: "controlled-network", name: "controlled-fixture"}
	network := strings.Join(fixture.networkArguments(), " ")
	if !strings.Contains(network, "--internal") {
		t.Fatalf("fixture network is not internal: %s", network)
	}
	run := fixture.runArguments("controlled-command")
	joined := strings.Join(run, " ")
	for _, required := range []string{"--cap-drop ALL", "no-new-privileges", "--pids-limit 32", "--read-only", "--network controlled-network"} {
		if !strings.Contains(joined, required) {
			t.Errorf("fixture arguments missing %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--privileged", "--network host", "--publish", "--mount", "/var/run/docker.sock"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("fixture arguments contain %q: %s", forbidden, joined)
		}
	}
}

func TestGhostBenchDockerIntegration(t *testing.T) {
	if os.Getenv("GHOST_DOCKER_INTEGRATION") != "1" {
		t.Skip("set GHOST_DOCKER_INTEGRATION=1 to run GhostBench against Docker")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("Docker CLI unavailable: %v", err)
	}
	report := NewRunner().Run(context.Background(), Options{})
	if report.Summary.Failed != 0 || report.Summary.Skipped != 0 || report.Summary.Passed != len(ScenarioIDs()) {
		for _, result := range report.Results {
			t.Logf("%s: %s: %s", result.Scenario, result.Status, result.Detail)
		}
		t.Fatalf("GhostBench summary = %+v", report.Summary)
	}
	var output bytes.Buffer
	if err := WriteJSON(&output, report); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"aws_secret_access_key", "GHOST_SECRET_", "GHOSTBENCH_CONTROLLED_HOST_AWS_VALUE"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("benchmark JSON leaked %q", forbidden)
		}
	}
}
