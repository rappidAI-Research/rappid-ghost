package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/advisor"
	"github.com/rappidAI-research/rappid-ghost/internal/compat"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
)

// Doctor is advisory. Neither project detection nor doctor output can modify
// policy, grant a permission, or bypass the runtime's mandatory preflight.
type doctorReport struct {
	Assessments      []doctorAssessment   `json:"policy_assessments"`
	Catalog          []compat.Integration `json:"integration_catalog"`
	BuildKitClient   string               `json:"buildkit_client"`
	Environment      string               `json:"environment"`
	Adapter          string               `json:"adapter"`
	Profile          string               `json:"profile,omitempty"`
	HostTools        []doctorHostTool     `json:"host_tools"`
	RuntimeTools     []string             `json:"runtime_tools"`
	Integrations     []doctorIntegration  `json:"integrations"`
	SchemaVersion    int                  `json:"schema_version"`
	HostPlatform     string               `json:"host_platform"`
	Configuration    string               `json:"configuration"`
	Docker           string               `json:"docker"`
	Policy           *doctorPolicy        `json:"policy,omitempty"`
	Signals          []advisor.Signal     `json:"signals"`
	Recommendations  []string             `json:"recommendations"`
	RuntimeValidated bool                 `json:"runtime_validated"`
}

type doctorAssessment struct {
	ID     string `json:"id"`
	Level  string `json:"level"`
	Basis  string `json:"basis"`
	Action string `json:"suggested_action"`
}

func assessPolicy(cfg config.Config) []doctorAssessment {
	items := make([]doctorAssessment, 0, 4)
	if cfg.Workspace.Mode == "read-write" {
		items = append(items, doctorAssessment{"workspace-write", "review", "The selected policy exposes project files for writing.", "For document-only work, explicitly select a read-only workspace; keep credentials outside the project."})
	}
	if cfg.Broker.Model != nil && cfg.Broker.Application != nil && cfg.Broker.Model.CredentialEnv != "" && cfg.Broker.Model.CredentialEnv == cfg.Broker.Application.CredentialEnv {
		items = append(items, doctorAssessment{"shared-service-credential", "review", "Model and application refer to the same credential variable; values were not read.", "Provision distinct scoped model and employee/application credentials and reference them explicitly."})
	}
	for _, tool := range cfg.Broker.Tools {
		if tool.MaxCalls == 0 || tool.TimeoutMillis == 0 || tool.MaxResultBytes == 0 {
			items = append(items, doctorAssessment{"default-tool-budgets", "review", "At least one read tool inherits a default call, deadline or result-size ceiling.", "Review explicit max_calls, timeout_millis and max_result_bytes for this workflow. Defaults remain finite; doctor changes nothing."})
			break
		}
	}
	if !cfg.Broker.Enabled() {
		items = append(items, doctorAssessment{"legacy-workspace-ipc", "boundary", "This run does not use the broker-mode IPC filter.", "Expose only a dedicated project without live Unix sockets; use an explicitly configured broker for model/read-tool access. See docs/security-model.md."})
	}
	return items
}

type doctorPolicy struct {
	EvidenceBudgetMiB     int    `json:"evidence_database_budget_mib"`
	BrokerContractVersion int    `json:"broker_contract_version"`
	ModelProtocol         string `json:"model_protocol,omitempty"`
	ModelBroker           bool   `json:"model_broker"`
	RegisteredReadTools   int    `json:"registered_read_tools"`
	Workspace             string `json:"workspace"`
	Network               string `json:"network"`
	AllowedDestinations   int    `json:"allowed_destinations"`
	ApprovalDestinations  int    `json:"approval_destinations"`
	Home                  string `json:"home"`
	ContainOnDecoy        bool   `json:"contain_on_decoy"`
}

func parseDoctorArgs(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if len(args) == 1 && args[0] == "--json" {
		return true, nil
	}
	return false, errors.New("usage: ghost doctor [--json]")
}

type doctorHostTool struct {
	Name   string `json:"name"`
	OnPath bool   `json:"on_path"`
}

type doctorIntegration struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Requirement string `json:"requirement"`
}

type doctorOutput struct{ bytes.Buffer }

func (b *doctorOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64*1024 {
		return 0, errors.New("Docker diagnostic exceeds output bound")
	}
	return b.Buffer.Write(p)
}

// dockerStatus checks only CLI presence and daemon responsiveness. It does not
// pull images, run containers, or inspect the host's credentials.
func dockerStatus(ctx context.Context) string {
	if _, err := exec.LookPath("docker"); err != nil {
		return "missing"
	}
	checkCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, "docker", "info", "--format", "{{json .}}")
	var output doctorOutput
	cmd.WaitDelay = time.Second
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &output, io.Discard
	if err := cmd.Run(); err != nil {
		return "unreachable"
	}
	if err := ghruntime.CheckDockerCapabilities(output.Bytes()); err != nil {
		return "incompatible"
	}
	return "reachable"
}

func buildDoctorReport(root, docker string) (doctorReport, error) {
	signals, err := advisor.Detect(root)
	if err != nil {
		return doctorReport{}, err
	}
	report := doctorReport{
		SchemaVersion:  4,
		Assessments:    make([]doctorAssessment, 0),
		Catalog:        compat.IntegrationCatalog(),
		BuildKitClient: "not-checked",
		Environment:    "alpine", Adapter: "command",
		HostTools: make([]doctorHostTool, 0),
		Integrations: []doctorIntegration{
			{Name: "command", Status: "supported", Requirement: "explicit command available in the selected image"},
			{Name: "python", Status: "supported", Requirement: "explicit Python environment and adapter; standard library only"},
			{Name: "node", Status: "supported", Requirement: "explicit Node.js 24.22.3 environment; built-in modules, no npm/yarn installation"},
			{Name: "Codex CLI", Status: "supported-subset", Requirement: "pinned 0.169.0, Linux amd64, explicit model broker, one noninteractive prompt; no account-login or arbitrary CLI flags"},
			{Name: "MCP read tools", Status: "supported-subset", Requirement: "2026-07-28 stateless discovery/list/call; explicit application credential, schema and resource grants"},
			{Name: "OpenAI-compatible model broker", Status: "supported-subset", Requirement: "explicit HTTPS origin/model, exact TLS identity; text-only stateless Responses/chat, no hosted tools"},
			{Name: "LangGraph", Status: "supported-subset", Requirement: "reviewed 1.2.22 wheel bundle, Linux amd64, StateGraph read/model workflow; no arbitrary project dependencies"},
			{Name: "Ollama", Status: "supported-subset", Requirement: "0.40.16-ghost.1 unofficial CPU service, authenticated TLS edge, native nonstreaming text chat only"},
			{Name: "Claude Code / arbitrary LangChain projects / vLLM", Status: "unverified", Requirement: "no independently qualified integration; a model protocol is not universal server compatibility"},
		},
		HostPlatform:     runtime.GOOS + "/" + runtime.GOARCH,
		Configuration:    "missing",
		Docker:           docker,
		Signals:          signals,
		RuntimeValidated: false,
		Recommendations:  make([]string, 0, 8),
	}
	for _, name := range []string{"python3", "node", "go", "claude", "codex"} {
		_, err := exec.LookPath(name)
		report.HostTools = append(report.HostTools, doctorHostTool{Name: name, OnPath: err == nil})
	}
	cfg, err := config.Load(filepath.Join(root, config.FileName))
	switch {
	case err == nil:
		report.Assessments = assessPolicy(cfg)
		report.Configuration = "valid"
		env, _ := compat.ResolveEnvironment(cfg.Runtime.Environment)
		report.Environment, report.Adapter, report.Profile = env.Name, cfg.Agent.Adapter, cfg.Profile
		report.Policy = &doctorPolicy{
			EvidenceBudgetMiB:     cfg.Evidence.MaxDatabaseMiB,
			BrokerContractVersion: 1,
			ModelBroker:           cfg.Broker.Model != nil, RegisteredReadTools: len(cfg.Broker.Tools),
			Workspace:            cfg.Workspace.Mode,
			Network:              cfg.Network.Mode,
			AllowedDestinations:  len(cfg.Network.Allow),
			ApprovalDestinations: len(cfg.Network.Ask),
			Home:                 cfg.Policy.Home,
			ContainOnDecoy:       cfg.OnDecoyAccess.Network == "deny",
		}
		if cfg.Broker.Model != nil {
			report.Policy.ModelProtocol = cfg.Broker.Model.ProtocolName()
		}
	case errors.Is(err, os.ErrNotExist):
		report.Recommendations = append(report.Recommendations, "Run 'ghost init' to create secure defaults. Existing ghost.yaml is never overwritten.")
	default:
		report.Configuration = "invalid"
		report.Recommendations = append(report.Recommendations, "Review and correct ghost.yaml. Ghost refuses to launch with invalid configuration; doctor will not repair it automatically.")
	}
	switch docker {
	case "missing":
		report.Recommendations = append(report.Recommendations, "Install Docker Engine and ensure the docker CLI is on PATH.")
	case "incompatible":
		report.Recommendations = append(report.Recommendations, "Docker responded but mandatory Linux seccomp/cgroup resource capabilities are missing. Run ghost run only after configuring supported Docker Engine isolation; no weaker fallback is offered.")
	case "unreachable":
		report.Recommendations = append(report.Recommendations, "Start Docker and verify that 'docker info' succeeds before attempting Ghost.")
	}
	if report.HostPlatform != "linux/amd64" {
		report.Recommendations = append(report.Recommendations, "Linux amd64 with Docker Engine is the runtime-tested release target; this host platform is not in that gate.")
	}
	environment, _ := compat.ResolveEnvironment(report.Environment)
	report.RuntimeTools = environment.Tools
	if report.Environment == "python" {
		report.Recommendations = append(report.Recommendations, "The explicit Python runtime requires Docker BuildKit and prepares a reviewed image without build network or project context. Python 3.13.18 standard library is included; pip, ensurepip and bundled third-party packages are removed. Doctor does not test a build. No credentials or host software are inherited.")
	}
	if report.Environment == "python-langgraph" {
		report.Recommendations = append(report.Recommendations, "The reviewed LangGraph bundle requires BuildKit and Linux amd64. Dependencies are hash-locked, installed offline during image preparation and read-only at execution; project requirements and pip installs are not accepted.")
	}
	if report.Policy != nil && (report.Policy.ModelBroker || report.Policy.RegisteredReadTools > 0) {
		report.Recommendations = append(report.Recommendations, "Only explicitly configured broker operations can reach their fixed service. Host credentials are checked at run time and never inherited by the agent. Doctor does not read them, resolve endpoints or contact a model. Direct egress remains denied.")
	} else if report.Policy != nil && report.Policy.Network == "deny" {
		report.Recommendations = append(report.Recommendations, "Current network policy blocks direct model APIs and package downloads. An explicitly configured broker.model can mediate a fixed service without granting network access; see docs/integrations.md.")
	}
	if report.Policy != nil && report.Policy.Workspace == "read-only" {
		report.Recommendations = append(report.Recommendations, "The workspace is read-only. Emit results to stdout or bounded /tmp storage; project file writes and build outputs will fail.")
	}
	report.Recommendations = append(report.Recommendations, advisor.Guidance(signals)...)
	report.Recommendations = append(report.Recommendations, "Only 'ghost run' performs the mandatory isolation, image, workspace and resource preflight; doctor is never a security approval.")
	return report, nil
}

func doctorCommand(ctx context.Context, root string, jsonOutput bool, output io.Writer) error {
	report, err := buildDoctorReport(root, dockerStatus(ctx))
	if err != nil {
		return err
	}
	if environment, _ := compat.ResolveEnvironment(report.Environment); environment.BuildRecipe != "" {
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(probeCtx, "docker", "buildx", "version")
		cmd.WaitDelay = time.Second
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		report.BuildKitClient = "client-present-not-build-validated"
		if err := cmd.Run(); err != nil {
			report.BuildKitClient = "unavailable"
			report.Recommendations = append(report.Recommendations, "Install Docker Buildx/BuildKit and verify docker buildx version. Catalog image preparation requires it; no package-manager or host fallback is used.")
		}
		cancel()
	}
	if jsonOutput {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintln(output, "Ghost Doctor (advisory only)")
	fmt.Fprintf(output, "Host: %s\nConfig: %s\nDocker: %s\nRuntime: %s; adapter: %s; profile: %s\nCatalog tools (not probed): %s\n", report.HostPlatform, report.Configuration, report.Docker, report.Environment, report.Adapter, report.Profile, strings.Join(report.RuntimeTools, ", "))
	fmt.Fprintf(output, "BuildKit client: %s (image build is validated only by ghost run)\n", report.BuildKitClient)
	fmt.Fprintln(output, "Host executables (PATH presence only; never run by doctor):")
	for _, tool := range report.HostTools {
		fmt.Fprintf(output, "  - %s: on PATH=%t (does not imply guest availability)\n", tool.Name, tool.OnPath)
	}
	fmt.Fprintln(output, "Integration catalog:")
	for _, integration := range report.Integrations {
		fmt.Fprintf(output, "  - %s: %s; %s\n", integration.Name, integration.Status, integration.Requirement)
	}
	if report.Policy != nil {
		fmt.Fprintf(output, "Current policy: workspace=%s; network=%s (%d allowed, %d ask); home=%s; containment=%t\n",
			report.Policy.Workspace, report.Policy.Network, report.Policy.AllowedDestinations,
			report.Policy.ApprovalDestinations, report.Policy.Home, report.Policy.ContainOnDecoy)
	}
	if len(report.Signals) > 0 {
		fmt.Fprintln(output, "\nProject hints (not proof of installed tools):")
		for _, signal := range report.Signals {
			fmt.Fprintf(output, "  - %s (%s)\n", signal.Name, strings.Join(signal.Evidence, ", "))
		}
	}
	if len(report.Assessments) > 0 {
		fmt.Fprintln(output, "\nConfigured-policy review (advisory; no permission changes):")
		for _, item := range report.Assessments {
			fmt.Fprintf(output, "  - %s: %s %s\n", item.ID, item.Basis, item.Action)
		}
	}
	fmt.Fprintln(output, "\nSuggested next steps:")
	for _, recommendation := range report.Recommendations {
		fmt.Fprintf(output, "  - %s\n", recommendation)
	}
	return nil
}
