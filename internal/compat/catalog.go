// Package compat is a closed, source-reviewed compatibility catalog. Project
// discovery must never select entries or expand permissions automatically.
package compat

import (
	"fmt"
	"path"
	"strings"
)

const AlpineImage = "alpine:3.23.8@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2"

const PythonImage = "python:3.13.18-alpine3.23@sha256:bf88c40985006a79ca25458159a4da1dffc457f9ae234e948b2d6df56ca5ebd2"

type Environment struct {
	BuildRecipe string   `json:"-"`
	Name        string   `json:"name"`
	Image       string   `json:"image,omitempty"`
	Tools       []string `json:"tools"`
}

func ResolveEnvironment(name string) (Environment, error) {
	switch name {
	case "", "alpine":
		return Environment{Name: "alpine", Image: AlpineImage, Tools: []string{"sh", "static Linux executables"}}, nil
	case "python":
		return Environment{Name: "python", Image: PythonImage, BuildRecipe: pythonRecipe(), Tools: []string{"sh", "python3 (3.13.18, standard library)"}}, nil
	default:
		return Environment{}, fmt.Errorf("unsupported runtime.environment %q; choose alpine or python (arbitrary images are not accepted)", name)
	}
}

func ValidateAdapter(adapter, environment string) error {
	if _, err := ResolveEnvironment(environment); err != nil {
		return err
	}
	switch adapter {
	case "", "command":
		return nil
	case "python":
		if environment != "python" {
			return fmt.Errorf("agent.adapter python requires explicit runtime.environment: python")
		}
		return nil
	default:
		return fmt.Errorf("unsupported agent.adapter %q; choose command or python; Claude Code, Codex and framework-specific adapters are not verified", adapter)
	}
}

// Prepare only maps argv to a guest command. It does not read scripts, execute
// host programs, install dependencies, supply credentials, or select policy.
func Prepare(adapter, environment string, command []string) ([]string, error) {
	if err := ValidateAdapter(adapter, environment); err != nil {
		return nil, err
	}
	if len(command) == 0 || command[0] == "" {
		return nil, fmt.Errorf("provide an explicit agent command or Python entrypoint")
	}
	if adapter != "python" {
		return append([]string(nil), command...), nil
	}
	script := command[0]
	clean := path.Clean(script)
	if strings.ContainsAny(script, "\\\x00\r\n") || strings.HasPrefix(script, "-") || path.IsAbs(script) || clean == ".." || strings.HasPrefix(clean, "../") || !strings.HasSuffix(clean, ".py") || strings.HasPrefix(clean, ".ghost/") {
		return nil, fmt.Errorf("Python adapter requires a relative .py entrypoint inside the workspace, for example: ghost run agent.py")
	}
	return append([]string{"/usr/local/bin/python3", "-B", "/workspace/" + clean}, command[1:]...), nil
}

// Remove package installers and their vendored libraries: the supported Python
// contract is standard-library execution, never an implicit package manager.
// The build has no project context, network, downloads, or unpinned inputs.
func pythonRecipe() string {
	return "FROM " + PythonImage + "\nARG SOURCE_DATE_EPOCH=0\nRUN rm -rf /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 && mkdir -p /usr/local/lib/python3.13/site-packages\n"
}
