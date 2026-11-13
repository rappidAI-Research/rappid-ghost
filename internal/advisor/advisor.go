// Package advisor recognizes limited, local project signals for non-authoritative
// setup guidance. It never reads project contents or changes security policy.
package advisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Signal struct {
	Name     string   `json:"name"`
	Evidence []string `json:"evidence"`
}

type marker struct {
	path      string
	signal    string
	directory bool
}

// Only fixed, well-known paths are probed. Nothing is recursively scanned,
// executed or interpreted. Presence is a hint, not proof an agent is installed.
var markers = []marker{
	{"AGENTS.md", "Agent instructions", false},
	{"CLAUDE.md", "Claude project instructions", false},
	{"GEMINI.md", "Gemini project instructions", false},
	{".codex", "Codex project settings", true},
	{".cursor/rules", "Cursor project rules", true},
	{".github/copilot-instructions.md", "Copilot project instructions", false},
	{"package.json", "Node.js project", false},
	{"pyproject.toml", "Python project", false},
	{"requirements.txt", "Python project", false},
	{"go.mod", "Go project", false},
	{"Cargo.toml", "Rust project", false},
	{"Dockerfile", "Containerized project", false},
	{"compose.yaml", "Containerized project", false},
	{"docker-compose.yml", "Containerized project", false},
}

// Detect observes only file names and types. Symlinked parents and entries are
// ignored rather than followed, and no project content enters the report.
func Detect(root string) ([]Signal, error) {
	found := make(map[string][]string)
	for _, entry := range markers {
		ok, err := presentWithoutSymlinks(root, entry.path, entry.directory)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", entry.path, err)
		}
		if ok {
			found[entry.signal] = append(found[entry.signal], entry.path)
		}
	}
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Signal, 0, len(names))
	for _, name := range names {
		sort.Strings(found[name])
		out = append(out, Signal{Name: name, Evidence: found[name]})
	}
	return out, nil
}

func presentWithoutSymlinks(root, relative string, wantDir bool) (bool, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	path := root
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false, errors.New("invalid fixed marker path")
		}
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, nil
		}
		if i != len(parts)-1 {
			if !info.IsDir() {
				return false, nil
			}
			continue
		}
		if wantDir {
			return info.IsDir(), nil
		}
		return info.Mode().IsRegular(), nil
	}
	return false, nil
}

// Guidance gives suggestions, never policy decisions. A project hint must
// not be used as permission to launch a detected program or open a network.
func Guidance(signals []Signal) []string {
	result := []string{}
	names := make(map[string]bool)
	for _, s := range signals {
		names[s.Name] = true
	}
	if names["Node.js project"] || names["Python project"] || names["Go project"] || names["Rust project"] {
		result = append(result, "The pinned Alpine runtime does not include your project's language tools automatically. Prepare and validate a compatible isolated runtime before running its agent; do not bypass Ghost on the host.")
	}
	if names["Agent instructions"] || names["Claude project instructions"] || names["Codex project settings"] || names["Cursor project rules"] || names["Gemini project instructions"] || names["Copilot project instructions"] {
		result = append(result, "Agent instruction files were found. They are untrusted project hints, not proof a corresponding executable is installed or supported inside Ghost.")
	}
	if len(result) == 0 {
		result = append(result, "No known project indicators were found. You can still run a command explicitly using 'ghost run <command>'.")
	}
	return result
}
