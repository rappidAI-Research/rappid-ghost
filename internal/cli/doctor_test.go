package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"gopkg.in/yaml.v3"
)

func TestDoctorArgumentsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		json  bool
		valid bool
	}{
		{nil, false, true},
		{[]string{"--json"}, true, true},
		{[]string{"--json", "extra"}, false, false},
		{[]string{"--repair"}, false, false},
	} {
		got, err := parseDoctorArgs(tc.args)
		if (err == nil) != tc.valid || (err == nil && got != tc.json) {
			t.Fatalf("args=%v got=%v err=%v", tc.args, got, err)
		}
	}
}

func TestDoctorAssessmentsUseOnlyExplicitPolicyAndDoNotReadCredentialValues(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	endpoint := broker.Endpoint{URL: "https://service.example", CredentialEnv: "SYNTHETIC_SHARED_CREDENTIAL"}
	cfg.Broker = broker.Config{Model: &broker.Model{Endpoint: endpoint, Name: "test"}, Application: &endpoint, Tools: []broker.Tool{{Name: "documents.read", Effect: "read", Parameters: map[string]string{"record": "string"}, ResourceArgument: "record", Resources: []string{"synthetic-case"}}}}
	t.Setenv(endpoint.CredentialEnv, "DO_NOT_READ_DIAGNOSTIC_SECRET")
	if _, err := config.Write(filepath.Join(root, config.FileName), cfg); err != nil {
		t.Fatal(err)
	}
	report, err := buildDoctorReport(root, "reachable")
	if err != nil || len(report.Assessments) != 3 || report.RuntimeValidated {
		t.Fatalf("assessments=%+v err=%v", report.Assessments, err)
	}
	encoded, _ := json.Marshal(report)
	for _, denied := range []string{"DO_NOT_READ_DIAGNOSTIC_SECRET", endpoint.CredentialEnv, endpoint.URL, "synthetic-case"} {
		if bytes.Contains(encoded, []byte(denied)) {
			t.Fatalf("policy assessment disclosed %s", denied)
		}
	}
	after, err := config.Load(filepath.Join(root, config.FileName))
	if err != nil || after.Workspace.Mode != cfg.Workspace.Mode || after.Broker.Application.CredentialEnv != endpoint.CredentialEnv {
		t.Fatal("advisory assessment changed explicit policy")
	}
}

func TestDoctorDoesNotMutateConfigOrAssumeCompatibility(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("DO_NOT_READ_SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := buildDoctorReport(root, "unreachable")
	if err != nil {
		t.Fatal(err)
	}
	if report.Configuration != "missing" || report.RuntimeValidated || report.Docker != "unreachable" {
		t.Fatalf("report: %+v", report)
	}
	if _, err := os.Lstat(filepath.Join(root, config.FileName)); !os.IsNotExist(err) {
		t.Fatal("doctor created configuration")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("DO_NOT_READ_SECRET")) {
		t.Fatal("project contents leaked")
	}
	if !strings.Contains(string(encoded), "does not include") {
		t.Fatal("expected image compatibility warning")
	}
}

func TestDoctorReportsValidatedPolicyWithoutWeakeningIt(t *testing.T) {
	root := t.TempDir()
	if _, err := config.WriteDefault(filepath.Join(root, config.FileName)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, config.FileName))
	if err != nil {
		t.Fatal(err)
	}
	report, err := buildDoctorReport(root, "reachable")
	if err != nil {
		t.Fatal(err)
	}
	if report.Configuration != "valid" || report.Policy == nil || report.Policy.Network != "deny" || report.RuntimeValidated {
		t.Fatalf("unexpected policy: %+v", report)
	}
	after, err := os.ReadFile(filepath.Join(root, config.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("doctor changed policy")
	}
}

func TestDoctorInvalidConfigurationStaysInvalid(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, config.FileName)
	if err := os.WriteFile(path, []byte("version: 100\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := buildDoctorReport(root, "missing")
	if err != nil || report.Configuration != "invalid" || report.Policy != nil {
		t.Fatalf("got %+v, %v", report, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "version: 100\n" {
		t.Fatal("invalid config overwritten")
	}
}

func TestDoctorSeparatesCatalogFromHostTools(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Runtime.Environment = "python"
	cfg.Agent.Adapter = "python"
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, config.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := buildDoctorReport(root, "incompatible")
	if err != nil || report.RuntimeValidated || report.Environment != "python" || len(report.HostTools) != 5 || len(report.RuntimeTools) == 0 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if !strings.Contains(strings.Join(report.Recommendations, " "), "mandatory Linux") {
		t.Fatal("missing actionable Docker capability restriction")
	}
	for _, integration := range report.Integrations {
		if strings.Contains(integration.Name, "Codex") && integration.Status != "supported-subset" {
			t.Fatal("claimed unverified integration")
		}
	}
}
