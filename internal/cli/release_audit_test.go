package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
	ghruntime "github.com/rappidAI-research/rappid-ghost/internal/runtime"
	"gopkg.in/yaml.v3"
)

type auditApprovalRuntime struct{ handlerPresent bool }

func (*auditApprovalRuntime) Name() string { return "docker" }
func (r *auditApprovalRuntime) Run(_ context.Context, request ghruntime.RunRequest) (ghruntime.RunResult, error) {
	r.handlerPresent = request.ApprovalHandler != nil
	return ghruntime.RunResult{}, errors.New("controlled stop")
}
func TestNoninteractiveCLIHasNoTypedNilApprovalHandler(t *testing.T) {
	root := t.TempDir()
	if err := initProject(context.Background(), root, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Network.Mode = "allowlist"
	cfg.Network.Ask = []string{"allowed.test"}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, config.FileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	r := &auditApprovalRuntime{}
	code := runCommandWithFactory(context.Background(), root, []string{"true"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}, func(string) (ghruntime.Runtime, error) { return r, nil })
	if code == 0 || r.handlerPresent {
		t.Fatalf("non-interactive CLI passes a callable nil terminal: code=%d handler=%v", code, r.handlerPresent)
	}
}
