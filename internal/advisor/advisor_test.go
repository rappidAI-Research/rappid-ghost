package advisor

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDetectFixedMarkersSortedAndNoContentRead(t *testing.T) {
	root := t.TempDir()
	for path, value := range map[string]string{
		"AGENTS.md":        "DO_NOT_READ_THIS_SECRET",
		"CLAUDE.md":        "DO_NOT_READ_THIS_SECRET",
		"pyproject.toml":   "DO_NOT_READ_THIS_SECRET",
		"requirements.txt": "DO_NOT_READ_THIS_SECRET",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	signals, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []Signal{
		{Name: "Agent instructions", Evidence: []string{"AGENTS.md"}},
		{Name: "Claude project instructions", Evidence: []string{"CLAUDE.md"}},
		{Name: "Python project", Evidence: []string{"pyproject.toml", "requirements.txt"}},
	}
	if !reflect.DeepEqual(signals, want) {
		t.Fatalf("got %#v; want %#v", signals, want)
	}
	for _, s := range signals {
		if strings.Contains(s.Name+strings.Join(s.Evidence, ""), "SECRET") {
			t.Fatal("project content leaked")
		}
	}
	if !strings.Contains(strings.Join(Guidance(signals), " "), "not proof") {
		t.Fatal("missing limitations")
	}
}

func TestDetectIgnoresSymlinkedMarkersAndParents(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "rules"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "AGENTS.md"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "AGENTS.md"), filepath.Join(root, "AGENTS.md")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".cursor")); err != nil {
		t.Skip(err)
	}
	signals, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Fatalf("symlinked markers must be ignored: %#v", signals)
	}
}

func TestDetectRejectsBadFilesystemShapeWithoutReading(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".github"), []byte("not directory"), 0600); err != nil {
		t.Fatal(err)
	}
	signals, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 0 {
		t.Fatalf("unexpected signals: %#v", signals)
	}
}

func TestEmptyGuidanceDoesNotClaimCompatibility(t *testing.T) {
	got := strings.Join(Guidance(nil), " ")
	if !strings.Contains(got, "No known project indicators") {
		t.Fatal(got)
	}
}

func TestFrameworkHintsDoNotProduceFalseEmptyDiagnosis(t *testing.T) {
	advice := strings.Join(Guidance([]Signal{{Name: "LangGraph configuration", Evidence: []string{"langgraph.json"}}}), " ")
	if strings.Contains(advice, "No known project indicators") || !strings.Contains(advice, "do not establish") {
		t.Fatal(advice)
	}
}
