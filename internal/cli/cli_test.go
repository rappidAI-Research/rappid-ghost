package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rappidAI-research/rappid-ghost/internal/config"
)

func TestParseRunArgsPreservesBoundaries(t *testing.T) {
	t.Parallel()

	input := []string{"--", "printf", "%s %s", "hello world", "--flag=value", "$(id)"}
	want := input[1:]
	got, err := parseRunArgs(input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
	input[1] = "changed"
	if got[0] != "printf" {
		t.Fatal("parsed command aliases caller input")
	}
	if _, err := parseRunArgs([]string{"echo", "hello"}); err == nil {
		t.Fatal("missing -- separator was accepted")
	}
}

func TestInitCreatesValidProjectWithoutOverwriting(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	var output bytes.Buffer
	if err := initProject(context.Background(), root, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(filepath.Join(root, config.FileName)); err != nil {
		t.Fatalf("created configuration is invalid: %v", err)
	}
	for _, path := range []string{
		filepath.Join(root, config.RuntimeDirName, config.DatabaseName),
		filepath.Join(root, config.RuntimeDirName, config.SessionsDir),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}

	custom := []byte("version: 1\nruntime: {provider: docker}\nworkspace: {mode: read-only}\nnetwork: {mode: none}\npolicy: {home: deny}\n")
	configPath := filepath.Join(root, config.FileName)
	if err := os.WriteFile(configPath, custom, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initProject(context.Background(), root, &output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, custom) {
		t.Fatalf("second init overwrote configuration:\n%s", got)
	}
}

func TestInitRejectsSymlinkedRuntimeDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, config.RuntimeDirName)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := initProject(context.Background(), root, &bytes.Buffer{}); err == nil {
		t.Fatal("init accepted a symlinked .ghost directory")
	}
}
