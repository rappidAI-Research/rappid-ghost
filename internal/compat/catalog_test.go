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
