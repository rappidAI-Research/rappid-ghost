package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
)

const initUsage = "ghost init [--integration command|python|node|codex] [--profile coding|document-processing|restricted|sensitive-enterprise] [--model-url https://host:port --model-name ID [--credential-env NAME] [--certificate-sha256 PIN]]"

// Only explicit trusted CLI selections can create a different policy template.
// File-name heuristics never select runtimes, endpoints or permissions.
func parseInitArgs(args []string) (config.Config, error) {
	cfg := config.Default()
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	integration := flags.String("integration", "command", "")
	profile := flags.String("profile", "", "")
	modelURL := flags.String("model-url", "", "")
	modelName := flags.String("model-name", "", "")
	credential := flags.String("credential-env", "", "")
	pin := flags.String("certificate-sha256", "", "")
	seen := map[string]bool{}
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			key := strings.SplitN(a, "=", 2)[0]
			if seen[key] {
				return cfg, fmt.Errorf("duplicate option %s", key)
			}
			seen[key] = true
		}
	}
	if err := flags.Parse(args); err != nil {
		return cfg, fmt.Errorf("%s: %w", initUsage, err)
	}
	if flags.NArg() != 0 {
		return cfg, errors.New(initUsage)
	}
	switch *integration {
	case "command":
	case "python", "node", "codex":
		cfg.Agent.Adapter = *integration
		cfg.Runtime.Environment = *integration
	default:
		return cfg, fmt.Errorf("unsupported integration %q; use command, python, node or codex", *integration)
	}
	cfg.Profile = *profile
	switch cfg.Profile {
	case "document-processing", "restricted", "sensitive-enterprise":
		cfg.Workspace.Mode = "read-only"
		cfg.Policy.Home = "deny"
	}
	if *modelURL != "" || *modelName != "" || *credential != "" || *pin != "" {
		cfg.Broker.Model = &broker.Model{Endpoint: broker.Endpoint{URL: *modelURL, CredentialEnv: *credential, CertificateSHA256: *pin}, Name: *modelName}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
