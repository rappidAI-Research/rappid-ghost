package compat

// Integration is static source-reviewed qualification metadata. It is never an
// authorization input, a project-discovery result or proof of this host's state.
type Integration struct {
	ID              string   `json:"id"`
	ContractVersion int      `json:"contract_version"`
	Version         string   `json:"software_version,omitempty"`
	Adapter         string   `json:"adapter,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	Authentication  string   `json:"authentication"`
	DirectNetwork   string   `json:"direct_network"`
	Qualification   string   `json:"qualification"`
	Tested          []string `json:"tested_capabilities"`
	Limits          []string `json:"limits"`
}

const OllamaVersion = "0.40.16"
const OllamaServiceVersion = "0.40.16-ghost.1"
const OllamaImage = "ollama/ollama:0.40.16@sha256:910d0d8107b538fb0894e63163eb195de0cc7aefcbc666dc62d3b18f71124592"

func IntegrationCatalog() []Integration {
	return []Integration{
		{ID: "python", ContractVersion: 1, Version: "3.13.18", Adapter: "python", Environment: "python", Authentication: "none", DirectNetwork: "explicit policy only", Qualification: "qualified-subset", Tested: []string{"stdin/argv/stdout", "Docker confinement", "standard library"}, Limits: []string{"no project dependency installation"}},
		{ID: "node", ContractVersion: 1, Version: "24.22.3", Adapter: "node", Environment: "node", Authentication: "none", DirectNetwork: "explicit policy only", Qualification: "qualified-subset", Tested: []string{"relative source entrypoint", "Docker confinement", "built-in modules"}, Limits: []string{"no npm/yarn installation"}},
		{ID: "codex", ContractVersion: 1, Version: CodexVersion, Adapter: "codex", Environment: "codex", Protocol: "openai-v1", Authentication: "host-only scoped credential", DirectNetwork: "none", Qualification: "qualified-fixture-subset", Tested: []string{"official native binary", "real shell/file tool loop", "argv and stdin"}, Limits: []string{"Responses fixture qualification, no hosted-account certification", "Linux amd64"}},
		{ID: "openai-v1", ContractVersion: 1, Protocol: "openai-v1", Authentication: "TLS identity and optional host bearer credential", DirectNetwork: "none", Qualification: "qualified-subset", Tested: []string{"text Responses/chat", "bounded JSON/SSE", "actual local llama.cpp inference"}, Limits: []string{"no remote media/history/hosted tools", "provider deployments need their own qualification"}},
		{ID: "ollama", ContractVersion: 1, Version: OllamaServiceVersion, Protocol: "ollama-chat-v1", Authentication: "authenticated HTTPS edge with host-only bearer credential", DirectNetwork: "none", Qualification: "pending-qualification", Tested: []string{"strict protocol unit/adversarial tests"}, Limits: []string{"native nonstreaming text /api/chat only", "no cloud/model management/media/tools", "real Docker inference qualification pending"}},
	}
}
