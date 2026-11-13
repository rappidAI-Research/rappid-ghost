# Integrating an agent

Ghost runs the agent in Docker; it never runs an unsupported agent on the host.
Use native Linux amd64 Docker Engine for the qualified v0.5 path. Install the
checksummed release binary or build with `make build` (static Go executable).

## Python and Node.js

In a new project:

```sh
ghost init --integration python
ghost run agent.py
```

For Node.js use `--integration node` and `ghost run agent.mjs` (also `.js`/`.cjs`).
Both adapters preserve arguments, stdin/stdout and subprocess confinement. Python
3.13.18 includes its standard library; Node.js 24.22.3 includes built-in modules.
No pip/npm/yarn install runs automatically. Host-installed dependencies are not
inherited. Framework dependency environments remain unqualified.

`ghost init` never overwrites policy. In an existing project, review and edit both
`agent.adapter` and `runtime.environment` in `ghost.yaml` explicitly. All old
`ghost run [--] <command>` invocations retain their meaning under `command`.

## Native Codex CLI

The catalog contains the official Codex 0.169.0 musl amd64 executable. One
noninteractive prompt or `-` for stdin is accepted; argv prompts do not wait for additional terminal input; arbitrary Codex options,
account login, resumable sessions and remote execution are not exposed.
An operator must first choose a compatible **Responses** model service and a
scoped credential. For example, substituting the service's actual model ID:

```sh
export GHOST_MODEL_KEY='your-scoped-service-key'
ghost init --integration codex --profile coding \
  --model-url https://api.openai.com --model-name YOUR_RESPONSES_MODEL \
  --credential-env GHOST_MODEL_KEY
ghost doctor
ghost run 'Inspect the project and add a small unit test.'
ghost inspect
```

The exact service must implement the tested Responses text/function-tool/SSE
contract. The executable, shell tool loop, output file, credential separation and
lifecycle are tested against a deterministic Responses service in real Docker.
This is a real Codex binary, **not a simulated agent**; the model fixture is not
LLM inference. A paid OpenAI account, a particular hosted model's behavior and
all optional Codex features have not been qualified by that test. Test your
selected model with synthetic data before enabling a project. The separate
local-model example proves actual inference through the same broker transport.

Ghost uses Codex's `danger-full-access` **inside Ghost's constrained Docker
container** and `approval_policy=never`. The outer Docker boundary is the enforced
sandbox: default seccomp, no capabilities, non-root identity, read-only root,
workspace policy, resource limits and no agent network remain mandatory. No
seccomp relaxation, host execution or host-home credential mount occurs. Codex's
separate inner sandbox/approval is not an additional guarantee in this adapter.
Ghost's existing destination approvals are not approvals for individual shell
commands. Keep secrets out of the workspace exposed to any coding agent.

`CODEX_HOME` is a new private directory in the container's bounded `/tmp`, created
by a fixed adapter bootstrap. User config and execpolicy rules are not loaded;
`--ephemeral` avoids session-file retention. Workspace content remains untrusted
agent input and cannot modify Ghost's trusted policy or broker grants.

## A real local model

From the repository after `make build`:

```sh
sh scripts/test-local-model.sh
```

This reproducible example downloads a revision- and SHA-256-pinned 101 MB SmolLM2
GGUF before agent startup and runs the exact pinned official llama.cpp CPU image
on a temporary **internal** Docker network. The service has no published port or
external route. It authenticates a synthetic token and serves TLS with an exact
certificate fingerprint. Ghost's host broker alone can reach that exact private
IP/port. The isolated Python agent uses `OPENAI_BASE_URL`, cannot see the real
token and verifies direct connections to that same model address and an external
address fail. It requires actual generated tokens and prints `LOCAL_INFERENCE_OK`.
Cleanup removes the model service, network and temporary synthetic project.

Requirements: Docker, curl, OpenSSL, Python 3 and the Ghost binary. Model download
and image pull require internet during setup; inference then uses local services.
The tiny base model is a transport qualification, not a useful enterprise model
or a quality evaluation. No real personal data is used. Ollama and vLLM commonly
implement parts of the API, but their specific deployments are not qualified.
Do not open private ranges or replace TLS verification to make them work.

## Tool and MCP integration

See [the broker contract](tool-gateway-design.md) and
[the synthetic application](../examples/enterprise/README.md). A trusted
application supplies a scoped employee/service credential, enforces tenant and
resource authorization on every read, and provisions a reviewed Ghost policy.
The agent never supplies its identity or permissions. Only registered tools,
required scalar schemas, resource grants, an explicit `effect: read`, and a fixed
application HTTPS origin are accepted. Writes and arbitrary MCP forwarding are
unsupported. The official MCP Go SDK example is
[examples/mcp-agent](../examples/mcp-agent/README.md).

Doctor JSON schema 3 separates project markers, host PATH presence, catalog
capabilities and configured permissions. It does not read credential values,
contact model endpoints, install tools or modify permissions. A successful
Doctor process is advisory, not proof that an integration was executed.
