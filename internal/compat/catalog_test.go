package compat

import (
	"reflect"
	"strings"
	"testing"
)

func TestAdapterPreservesArgvAndRequiresExplicitPython(t *testing.T) {
	command := []string{"tools/agent.py", "hello world", "$(id)", "--flag"}
	got, err := Prepare("python", "python", command)
	want := []string{"/usr/local/bin/python3", "-B", "/workspace/tools/agent.py", "hello world", "$(id)", "--flag"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%q %v", got, err)
	}
	got[3] = "changed"
	if command[1] != "hello world" {
		t.Fatal("caller argv aliased")
	}
	if _, err := Prepare("python", "alpine", command); err == nil {
		t.Fatal("implicitly selected Python image")
	}
	for _, script := range []string{"../escape.py", "/host.py", "-c", ".ghost/agent.py", "agent.py\n", `a\b.py`, "agent.js", ""} {
		if _, err := Prepare("python", "python", []string{script}); err == nil {
			t.Fatalf("accepted %q", script)
		}
	}
	for _, name := range []string{"claude", "codex", "mcp", "langgraph"} {
		if ValidateAdapter(name, "python") == nil {
			t.Fatalf("unsupported adapter %s", name)
		}
	}
	for _, name := range []string{"host", "python:latest", "alpine@sha256:bad"} {
		if _, err := ResolveEnvironment(name); err == nil {
			t.Fatalf("arbitrary runtime %s", name)
		}
	}
	if !strings.Contains(PythonImage, "@sha256:") {
		t.Fatal("unpinned catalog")
	}
}

func TestCodexAdapterKeepsPromptAsDataAndDoesNotExpandPermissions(t *testing.T) {
	prompt := `--trust; $(touch /host/escape) "quoted"`
	argv, err := PrepareWithModel("codex", "codex", []string{prompt}, "explicit-model")
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "/bin/sh" || argv[len(argv)-2] != "--" || argv[len(argv)-1] != prompt {
		t.Fatal("prompt lost argument boundary")
	}
	if strings.Contains(argv[2], prompt) || !strings.Contains(argv[2], `"$@"`) {
		t.Fatal("prompt interpolated into bootstrap")
	}
	for _, arg := range argv[:len(argv)-1] {
		if arg == "--trust" || strings.HasPrefix(arg, "--add-dir") {
			t.Fatal("adapter granted extra access")
		}
	}
	for _, input := range [][]string{nil, {"one", "--trust"}, {""}} {
		if _, err := PrepareWithModel("codex", "codex", input, "model"); err == nil {
			t.Fatal("arbitrary Codex options accepted")
		}
	}
	if _, err = PrepareWithModel("codex", "codex", []string{"task"}, ""); err == nil {
		t.Fatal("missing broker model accepted")
	}
}
