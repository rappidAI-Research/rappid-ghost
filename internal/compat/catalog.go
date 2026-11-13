// Package compat is a closed, source-reviewed compatibility catalog. Project
// discovery must never select entries or expand permissions automatically.
package compat

import (
	"fmt"
	"path"
	"strings"
)

const AlpineImage = "alpine:3.22.5@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

const PythonImage = "python:3.13.18-alpine3.23@sha256:bf88c40985006a79ca25458159a4da1dffc457f9ae234e948b2d6df56ca5ebd2"

type Environment struct {
	Name  string   `json:"name"`
	Image string   `json:"image,omitempty"`
	Tools []string `json:"tools"`
}

func ResolveEnvironment(name string) (Environment, error) {
	switch name {
	case "", "alpine":
		return Environment{Name: "alpine", Image: AlpineImage, Tools: []string{"sh", "static Linux executables"}}, nil
	case "python":
		return Environment{Name: "python", Image: PythonImage, Tools: []string{"sh", "python3 (3.13.18, standard library)"}}, nil
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
