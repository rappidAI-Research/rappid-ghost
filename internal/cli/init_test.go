package cli

import (
	"bytes"
	"context"
	"github.com/rappidAI-research/rappid-ghost/internal/config"
	"os"
	"path/filepath"
	"testing"
)

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
