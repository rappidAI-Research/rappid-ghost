package cli

import (
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
 "github.com/rappidAI-research/rappid-ghost/internal/config"
)

// Doctor is advisory. Project hints must never modify authorization or
// bypass the mandatory security checks in ghost run.
type doctorReport struct {
 SchemaVersion int `json:"schema_version"`
 HostPlatform string `json:"host_platform"`
 Configuration string `json:"configuration"`
 Docker string `json:"docker"`
 Policy *doctorPolicy `json:"policy,omitempty"`
 Signals []advisor.Signal `json:"signals"`
 Recommendations []string `json:"recommendations"`
 RuntimeValidated bool `json:"runtime_validated"`
}

type doctorPolicy struct {
 Workspace string `json:"workspace"`
 Network string `json:"network"`
 AllowedDestinations int `json:"allowed_destinations"`
 ApprovalDestinations int `json:"approval_destinations"`
 Home string `json:"home"`
 ContainOnDecoy bool `json:"contain_on_decoy"`
}

func parseDoctorArgs(args []string) (bool, error) {
 if len(args) == 0 { return false, nil }
 if len(args) == 1 && args[0] == "--json" { return true, nil }
 return false, errors.New("usage: ghost doctor [--json]")
}

// dockerStatus probes CLI/daemon availability only. It runs no container,
// pulls no image and does not claim the runtime security gate has passed.
func dockerStatus(ctx context.Context) string {
 if _, err := exec.LookPath("docker"); err != nil { return "missing" }
 checkCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
 defer cancel()
 cmd := exec.CommandContext(checkCtx, "docker", "info", "--format", "{{.OSType}}")
 cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
 if err := cmd.Run(); err != nil { return "unreachable" }
 return "reachable"
}

func buildDoctorReport(root, docker string) (doctorReport, error) {
 signals, err := advisor.Detect(root)
 if err != nil { return doctorReport{}, err }
 report := doctorReport{
  SchemaVersion: 1,
  HostPlatform: runtime.GOOS+"/"+runtime.GOARCH,
  Configuration: "missing",
  Docker: docker,
  Signals: signals,
  RuntimeValidated: false,
  Recommendations: make([]string, 0, 8),
 }
 cfg, err := config.Load(filepath.Join(root, config.FileName))
 switch {
 case err == nil:
  report.Configuration = "valid"
  report.Policy = &doctorPolicy{
   Workspace: cfg.Workspace.Mode,
   Network: cfg.Network.Mode,
   AllowedDestinations: len(cfg.Network.Allow),
   ApprovalDestinations: len(cfg.Network.Ask),
   Home: cfg.Policy.Home,
   ContainOnDecoy: cfg.OnDecoyAccess.Network == "deny",
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
 case "unreachable":
  report.Recommendations = append(report.Recommendations, "Start Docker and verify that 'docker info' succeeds before attempting Ghost.")
 }
 if report.HostPlatform != "linux/amd64" {
  report.Recommendations = append(report.Recommendations, "Linux amd64 with Docker Engine is the runtime-tested release target; this host platform is not in that gate.")
 }
 report.Recommendations = append(report.Recommendations, advisor.Guidance(signals)...)
 report.Recommendations = append(report.Recommendations, "Only 'ghost run' performs the mandatory isolation, image, workspace and resource preflight; doctor is never a security approval.")
 return report, nil
}

func doctorCommand(ctx context.Context, root string, jsonOutput bool, output io.Writer) error {
 report, err := buildDoctorReport(root, dockerStatus(ctx))
 if err != nil { return err }
 if jsonOutput {
  encoder := json.NewEncoder(output)
  encoder.SetIndent("", "  ")
  return encoder.Encode(report)
 }
 fmt.Fprintln(output, "Ghost Doctor (advisory only)")
 fmt.Fprintf(output, "Host: %s\nConfig: %s\nDocker: %s\n", report.HostPlatform, report.Configuration, report.Docker)
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
