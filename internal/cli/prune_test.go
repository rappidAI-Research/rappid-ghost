package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"github.com/rappidAI-research/rappid-ghost/internal/session"
)

func TestExplicitRetentionCLIUsesPreviewAndRespectsProjectScope(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	if err := initProject(ctx, root, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	s, err := openSessionStore(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	id, err := session.NewID()
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-40 * 24 * time.Hour)
	v := session.Session{ID: id, CreatedAt: old, CompletedAt: &old, Command: []string{"true"}, Runtime: "docker", Status: session.Completed, SecurityState: policy.StateNormal}
	if err = s.CreateSession(ctx, v); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	directory := filepath.Join(root, ".ghost", "sessions", id)
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "log"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	options, err := parsePruneArgs([]string{"--older-than-days", "30", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = pruneCommand(ctx, root, options, &out); err != nil || !strings.Contains(out.String(), "Eligible completed sessions: 1") {
		t.Fatalf("preview %v %s", err, out.String())
	}
	if _, err = os.Stat(directory); err != nil {
		t.Fatal("preview removed files")
	}
	options.dryRun = false
	out.Reset()
	if err = pruneCommand(ctx, root, options, &out); err != nil || !strings.Contains(out.String(), "Removed 1 completed") {
		t.Fatalf("apply %v %s", err, out.String())
	}
	if _, err = os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("explicit CLI retention did not remove owned artifacts")
	}
	for _, args := range [][]string{nil, {"--older-than-days", "0"}, {"--older-than-days", "-1"}, {"--older-than-days", "3651"}, {"--older-than-days", "30", "unexpected"}} {
		if _, err = parsePruneArgs(args); err == nil {
			t.Fatal("ambiguous retention command accepted")
		}
	}
}
