package cli

import (
	"bytes"
	"context"
	"github.com/rappidAI-research/rappid-ghost/internal/broker"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitFrameworkAndNativeProtocolTemplates(t *testing.T) {
	cfg, err := parseInitArgs([]string{"--integration", "langgraph", "--profile", "sensitive-enterprise", "--model-protocol", "ollama-chat-v1", "--model-url", "https://127.0.0.1:9443", "--model-name", "local:qualified", "--max-output-tokens", "24", "--credential-env", "EXPLICIT_LOCAL_MODEL_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Adapter != "python" || cfg.Runtime.Environment != "python-langgraph" || cfg.Network.Mode != "deny" || len(cfg.Network.Allow)+len(cfg.Network.Ask) != 0 || cfg.Workspace.Mode != "read-only" || cfg.Policy.Home != "deny" || cfg.Broker.Model.ProtocolName() != broker.ProtocolOllama || cfg.Broker.Model.MaxOutputTokens != 24 {
		t.Fatal("template expanded permissions or selected an implicit service")
	}
	for _, args := range [][]string{
		{"--integration", "python", "--model-url", "https://127.0.0.1:9443", "--model-name", "m", "--model-protocol", "ollama-chat-v1"},
		{"--integration", "codex", "--model-url", "https://127.0.0.1:9443", "--model-name", "m", "--model-protocol", "ollama-chat-v1", "--credential-env", "EXPLICIT_MODEL_KEY"},
		{"--model-protocol", "unknown"},
		{"--model-url", "https://example.test", "--model-name", "m", "--max-output-tokens", "8193"},
	} {
		if _, err := parseInitArgs(args); err == nil {
			t.Fatal("invalid protocol configuration accepted")
		}
	}
}

func TestExplicitInitTemplatesAndNoPolicyOverwrite(t *testing.T) {
	for _, integration := range []string{"python", "node", "codex"} {
		args := []string{"--integration", integration}
		if integration == "codex" {
			args = append(args, "--model-url", "https://api.example.test", "--model-name", "explicit-model", "--credential-env", "EXPLICIT_MODEL_KEY")
		}
		cfg, err := parseInitArgs(args)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Agent.Adapter != integration || cfg.Runtime.Environment != integration || cfg.Network.Mode != "deny" {
			t.Fatalf("unsafe template %+v", cfg)
		}
		root := t.TempDir()
		if err = initProjectWithConfig(context.Background(), root, &bytes.Buffer{}, cfg); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(root, config.FileName))
		if err = initProjectWithConfig(context.Background(), root, &bytes.Buffer{}, config.Default()); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(filepath.Join(root, config.FileName))
		if !bytes.Equal(before, after) {
			t.Fatal("existing policy overwritten")
		}
	}
	for _, args := range [][]string{{"--integration", "codex"}, {"--integration", "host"}, {"--integration", "python", "--integration", "node"}, {"--model-url", "http://127.0.0.1:11434", "--model-name", "local"}, {"--model-url", "https://api.example.test", "--model-name", "m", "--profile", "restricted"}} {
		if _, err := parseInitArgs(args); err == nil {
			t.Fatalf("accepted invalid integration %q", args)
		}
	}
}
