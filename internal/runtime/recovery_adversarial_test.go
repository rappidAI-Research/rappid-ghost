package runtime

import (
	"context"
	"github.com/rappidAI-research/rappid-ghost/internal/policy"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryMarkerRejectsAmbiguity(t *testing.T) {
	for _, kind := range []string{"missing", "contained", "symlink", "directory", "nonempty", "observation-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "observation")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "contained")
			var err error
			switch kind {
			case "contained":
				err = os.WriteFile(marker, nil, 0600)
			case "nonempty":
				err = os.WriteFile(marker, []byte("unknown"), 0600)
			case "symlink":
				err = os.Symlink(filepath.Join(root, "absent"), marker)
			case "directory":
				err = os.Mkdir(marker, 0700)
			case "observation-symlink":
				if err = os.Remove(dir); err == nil {
					err = os.Symlink(t.TempDir(), dir)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			state, err := NewDocker().RecoveredSecurityState(context.Background(), root)
			switch kind {
			case "missing":
				if err != nil || state != policy.StateNormal {
					t.Fatalf("%s %v", state, err)
				}
			case "contained":
				if err != nil || !state.IsContained() {
					t.Fatalf("%s %v", state, err)
				}
			default:
				if err == nil {
					t.Fatal("ambiguous recovery accepted")
				}
			}
		})
	}
}
