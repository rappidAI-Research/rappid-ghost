package deception

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratorCreatesSyntheticResources(t *testing.T) {
	root := t.TempDir()
	manifest, err := NewGenerator().Prepare("session_one", root, enabledResources())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(manifest.Decoys) != 3 {
		t.Fatalf("len(Decoys) = %d, want 3", len(manifest.Decoys))
	}

	tests := []struct {
		path     string
		contains []string
	}{
		{path: ".aws/credentials", contains: []string{"GHOST_AWS_", "GHOST_SECRET_"}},
		{path: ".ssh/id_rsa", contains: []string{"BEGIN OPENSSH PRIVATE KEY", "END OPENSSH PRIVATE KEY"}},
		{path: ".env", contains: []string{"ghost://decoy/", "GHOST_API_", "GHOST_TOKEN_"}},
	}
	for _, tt := range tests {
		data, readErr := os.ReadFile(filepath.Join(manifest.SyntheticHome, tt.path))
		if readErr != nil {
			t.Fatalf("read %s: %v", tt.path, readErr)
		}
		for _, value := range tt.contains {
			if !strings.Contains(string(data), value) {
				t.Errorf("%s does not contain %q", tt.path, value)
			}
		}
		info, statErr := os.Stat(filepath.Join(manifest.SyntheticHome, tt.path))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", tt.path, info.Mode().Perm())
		}
	}
}

func TestGeneratorUsesUniqueIDsMarkersAndHomes(t *testing.T) {
	root := t.TempDir()
	first, err := NewGenerator().Prepare("session_one", root, enabledResources())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewGenerator().Prepare("session_two", root, enabledResources())
	if err != nil {
		t.Fatal(err)
	}
	if first.SyntheticHome == second.SyntheticHome {
		t.Fatal("separate sessions share a synthetic home")
	}
	ids := map[string]bool{}
	markers := map[string]bool{}
	for _, manifest := range []Manifest{first, second} {
		for _, decoy := range manifest.Decoys {
			if ids[decoy.ID] {
				t.Fatalf("duplicate decoy ID %q", decoy.ID)
			}
			if markers[decoy.Marker] {
				t.Fatalf("duplicate marker %q", decoy.Marker)
			}
			ids[decoy.ID] = true
			markers[decoy.Marker] = true
		}
	}
}

func TestGeneratorNeverReadsHostCredentials(t *testing.T) {
	hostHome := t.TempDir()
	hostSecret := "REAL_HOST_SECRET_MUST_NOT_APPEAR"
	if err := os.MkdirAll(filepath.Join(hostHome, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostHome, ".aws", "credentials"), []byte(hostSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", hostHome)

	manifest, err := NewGenerator().Prepare("independent", t.TempDir(), enabledResources())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".aws/credentials", ".ssh/id_rsa", ".env"} {
		data, readErr := os.ReadFile(filepath.Join(manifest.SyntheticHome, path))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), hostSecret) {
			t.Fatalf("synthetic %s contains host credential material", path)
		}
	}
}

func TestPrepareWithoutResourcesCreatesEmptySyntheticHome(t *testing.T) {
	manifest, err := NewGenerator().Prepare("deny_session", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(manifest.SyntheticHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || len(manifest.Decoys) != 0 {
		t.Fatalf("deny home is not empty: entries=%d decoys=%d", len(entries), len(manifest.Decoys))
	}
}

func TestPrepareRejectsTraversalAndSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	if _, err := NewGenerator().Prepare("../escape", root, nil); err == nil {
		t.Fatal("Prepare accepted a traversal session ID")
	}
	link := filepath.Join(t.TempDir(), "sessions")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGenerator().Prepare("session", link, nil); err == nil {
		t.Fatal("Prepare accepted a symlinked sessions root")
	}
}

func enabledResources() []Resource {
	resources := KnownResources()
	for index := range resources {
		resources[index].Enabled = true
	}
	return resources
}
