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
	BuildKitClient   string              `json:"buildkit_client"`
	Environment      string              `json:"environment"`
	Adapter          string              `json:"adapter"`
	Profile          string              `json:"profile,omitempty"`
	HostTools        []doctorHostTool    `json:"host_tools"`
	RuntimeTools     []string            `json:"runtime_tools"`
	Integrations     []doctorIntegration `json:"integrations"`
	SchemaVersion    int                 `json:"schema_version"`
	HostPlatform     string              `json:"host_platform"`
	Configuration    string              `json:"configuration"`
	Docker           string              `json:"docker"`
	Policy           *doctorPolicy       `json:"policy,omitempty"`
	Signals          []advisor.Signal    `json:"signals"`
	Recommendations  []string            `json:"recommendations"`
	RuntimeValidated bool                `json:"runtime_validated"`
}

type doctorPolicy struct {
	Workspace            string `json:"workspace"`
	Network              string `json:"network"`
	AllowedDestinations  int    `json:"allowed_destinations"`
	ApprovalDestinations int    `json:"approval_destinations"`
	Home                 string `json:"home"`
	ContainOnDecoy       bool   `json:"contain_on_decoy"`
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
		SchemaVersion:  2,
		BuildKitClient: "not-checked",
		Environment:    "alpine", Adapter: "command",
		HostTools: make([]doctorHostTool, 0),
		Integrations: []doctorIntegration{
			{Name: "command", Status: "supported", Requirement: "explicit command available in the selected image"},
			{Name: "python", Status: "supported", Requirement: "explicit Python environment and adapter; standard library only"},
			{Name: "Claude Code / Codex CLI / Node.js / LangChain / LangGraph / MCP / local LLM", Status: "unverified", Requirement: "no bundled integration; do not infer support from marker files"},
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
		report.Configuration = "valid"
		env, _ := compat.ResolveEnvironment(cfg.Runtime.Environment)
		report.Environment, report.Adapter, report.Profile = env.Name, cfg.Agent.Adapter, cfg.Profile
		report.Policy = &doctorPolicy{
			Workspace:            cfg.Workspace.Mode,
			Network:              cfg.Network.Mode,
			AllowedDestinations:  len(cfg.Network.Allow),
			ApprovalDestinations: len(cfg.Network.Ask),
			Home:                 cfg.Policy.Home,
			ContainOnDecoy:       cfg.OnDecoyAccess.Network == "deny",
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
	if report.Policy != nil && report.Policy.Network == "deny" {
		report.Recommendations = append(report.Recommendations, "Current network policy blocks model APIs and package downloads. Offline programs can run; external access requires an explicit reviewed exact-hostname policy and an independent credential design.")
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
	if report.Environment == "python" {
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(probeCtx, "docker", "buildx", "version")
		cmd.WaitDelay = time.Second
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		report.BuildKitClient = "client-present-not-build-validated"
		if err := cmd.Run(); err != nil {
			report.BuildKitClient = "unavailable"
			report.Recommendations = append(report.Recommendations, "Install Docker Buildx/BuildKit and verify docker buildx version. Python image preparation requires it; no package-manager or host fallback is used.")
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
	fmt.Fprintln(output, "\nSuggested next steps:")
	for _, recommendation := range report.Recommendations {
		fmt.Fprintf(output, "  - %s\n", recommendation)
	}
	return nil
}
