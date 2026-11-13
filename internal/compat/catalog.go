// Package compat is a closed, source-reviewed compatibility catalog. Project
// discovery must never select entries or expand permissions automatically.
package compat

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

const AlpineImage = "alpine:3.23.8@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2"

const PythonImage = "python:3.13.18-alpine3.23@sha256:bf88c40985006a79ca25458159a4da1dffc457f9ae234e948b2d6df56ca5ebd2"

const NodeImage = "node:24.22.3-alpine3.23@sha256:3946fb783fdce8a2812136ea694bc95c698c4f4096f3fd18568dc27a8ac389dc"
const CodexVersion = "0.169.0"
const CodexArchiveSHA256 = "9af4d751fce183faedea629437d5252dbf458eeb04130cf4f97be844621ea985"

type Environment struct {
	SourceEntrypoint []string `json:"-"`
	Architecture     string   `json:"architecture,omitempty"`
	BuildRecipe      string   `json:"-"`
	Name             string   `json:"name"`
	Image            string   `json:"image,omitempty"`
	Tools            []string `json:"tools"`
}

func ResolveEnvironment(name string) (Environment, error) {
	switch name {
	case "", "alpine":
		return Environment{Name: "alpine", Image: AlpineImage, Tools: []string{"sh", "static Linux executables"}}, nil
	case "python":
		return Environment{Name: "python", Image: PythonImage, BuildRecipe: pythonRecipe(), Tools: []string{"sh", "python3 (3.13.18, standard library)"}}, nil
	case "node":
		return Environment{Name: "node", Image: NodeImage, SourceEntrypoint: []string{"docker-entrypoint.sh"}, BuildRecipe: nodeRecipe(), Tools: []string{"sh", "node (24.22.3, built-in modules)"}}, nil
	case "codex":
		return Environment{Name: "codex", Image: AlpineImage, Architecture: "amd64", BuildRecipe: codexRecipe(), Tools: []string{"sh", "codex (0.169.0, noninteractive exec)"}}, nil
	default:
		return Environment{}, fmt.Errorf("unsupported runtime.environment %q; choose alpine, python, node or codex (arbitrary images are not accepted)", name)
	}
}

func ValidateAdapter(adapter, environment string) error {
	if _, err := ResolveEnvironment(environment); err != nil {
		return err
	}
	switch adapter {
	case "", "command":
		return nil
	case "python", "node", "codex":
		if environment != adapter {
			return fmt.Errorf("agent.adapter %s requires explicit runtime.environment: %s", adapter, adapter)
		}
		return nil
	default:
		return fmt.Errorf("unsupported agent.adapter %q; choose command, python, node or codex; Claude Code and framework dependencies are not qualified", adapter)
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
	if adapter == "codex" {
		return nil, fmt.Errorf("Codex requires an explicit model broker configuration")
	}
	if adapter != "python" && adapter != "node" {
		return append([]string(nil), command...), nil
	}
	script := command[0]
	extensions := []string{".py"}
	if adapter == "node" {
		extensions = []string{".js", ".mjs", ".cjs"}
	}
	validExtension := false
	for _, ext := range extensions {
		validExtension = validExtension || strings.HasSuffix(script, ext)
	}
	clean := path.Clean(script)
	if strings.ContainsAny(script, "\\\x00\r\n") || strings.HasPrefix(script, "-") || path.IsAbs(script) || clean == ".." || strings.HasPrefix(clean, "../") || !validExtension || strings.HasPrefix(clean, ".ghost/") {
		return nil, fmt.Errorf("%s adapter requires a relative source entrypoint inside the workspace", adapter)
	}
	if adapter == "node" {
		return append([]string{"/usr/local/bin/node", "--", "/workspace/" + clean}, command[1:]...), nil
	}
	return append([]string{"/usr/local/bin/python3", "-B", "/workspace/" + clean}, command[1:]...), nil
}

// Remove package installers and their vendored libraries: the supported Python
// contract is standard-library execution, never an implicit package manager.
// The build has no project context, network, downloads, or unpinned inputs.
func pythonRecipe() string {
	return "FROM " + PythonImage + "\nARG SOURCE_DATE_EPOCH=0\nRUN rm -rf /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 && mkdir -p /usr/local/lib/python3.13/site-packages\n"
}

// PrepareWithModel keeps all adapter policy in the catalog. Codex accepts one
// prompt (or '-' for stdin), not caller-provided configuration overrides.
func PrepareWithModel(adapter, environment string, command []string, model string) ([]string, error) {
	if adapter != "codex" {
		return Prepare(adapter, environment, command)
	}
	if err := ValidateAdapter(adapter, environment); err != nil {
		return nil, err
	}
	if model == "" || len(command) != 1 || len(command[0]) == 0 || len(command[0]) > 64*1024 {
		return nil, fmt.Errorf("Codex requires broker.model and one prompt, e.g. ghost run 'Review this project' or ghost run -")
	}
	modelJSON, _ := json.Marshal(model)
	return []string{"/bin/sh", "-c", `umask 077; mkdir -p /tmp/ghost-codex || exit 1; export CODEX_HOME=/tmp/ghost-codex; exec /usr/local/bin/codex "$@"`, "ghost-codex", "exec", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--ephemeral", "--color", "never", "--json", "--sandbox", "danger-full-access", "-c", `approval_policy="never"`, "-c", `model_provider="ghost"`, "-c", `model=` + string(modelJSON), "-c", `model_providers.ghost={name="Ghost session broker",base_url="http://127.0.0.1:17871/v1",env_key="OPENAI_API_KEY",wire_api="responses",supports_websockets=false,request_max_retries=0,stream_max_retries=0}`, "--", command[0]}, nil
}
func nodeRecipe() string {
	return "FROM " + NodeImage + "\nARG SOURCE_DATE_EPOCH=0\nRUN rm -rf /usr/local/lib/node_modules /opt/yarn* /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/corepack /usr/local/bin/docker-entrypoint.sh\nENTRYPOINT []\n"
}
func codexRecipe() string {
	return "FROM " + AlpineImage + "\nARG SOURCE_DATE_EPOCH=0\nADD --checksum=sha256:" + CodexArchiveSHA256 + " https://github.com/openai/codex/releases/download/rust-v" + CodexVersion + "/codex-x86_64-unknown-linux-musl.tar.gz /tmp/codex.tar.gz\nRUN test \"$(tar -tzf /tmp/codex.tar.gz)\" = codex-x86_64-unknown-linux-musl && tar -xzf /tmp/codex.tar.gz -C /usr/local/bin && mv /usr/local/bin/codex-x86_64-unknown-linux-musl /usr/local/bin/codex && chmod 0555 /usr/local/bin/codex && rm /tmp/codex.tar.gz\n"
}
