# Runtime and agent compatibility

The release runtime target is **Linux amd64 with Docker Engine**, working cgroup
memory/swap/CPU/PID controls and built-in seccomp. Linux arm64 binaries are built,
but arm64 execution is not covered by the release gate. Docker Desktop, Windows,
macOS, rootless configurations and daemon-level user namespaces need independent
qualification; capability checks are necessary, not a platform certification.

| Path | v0.4 implementation | Qualification / limits |
| --- | --- | --- |
| `command` + `alpine` | Default shell/CLI execution | Existing Docker/GhostBench paths; executable must exist in guest |
| `python` + `python` | Relative `.py` entrypoint, original argument boundaries, stdin/stdout | Python 3.13.18 standard library; real CLI and GhostBench gates required |
| `command` + `python` | Explicit guest command | Catalog image only; application-specific binaries are not bundled |
| Static Go agent | Can use generic command execution | Must be built for guest Linux/architecture; no Go compiler, no blanket Go application guarantee |
| Node.js / Go compiler / Rust toolchain | No catalog environment | Host installation does not add guest tools |
| Claude Code / Codex CLI | No verified dedicated adapter | Not bundled; authentication, dependencies, exact service egress and sandbox nesting remain unresolved |
| LangChain / LangGraph | No bundled integration | Python interpreter support does not establish framework compatibility |
| Ollama / vLLM / local model servers | No broker | Private/loopback destinations stay denied |
| MCP / database / arbitrary tool calls | No mediation | Network destination approval does not authorize individual tool operations |

`ghost doctor --json` schema **2** distinguishes file-name hints, host executable
PATH presence, source-catalog tools and integration status. It never runs detected
software, reads marker bodies, pulls an image or mutates policy. Docker diagnostics
check daemon capabilities only. `runtime_validated: false` is always intentional:
only `ghost run` performs mandatory preflight. Marker presence cannot establish
installed software, framework versions, authentication or successful execution.
Host PATH presence cannot establish a usable program or container compatibility.

## Source-reviewed catalog

`runtime.environment` accepts `alpine` (default) or `python`. Arbitrary image
references, user-defined adapter plugins, host providers, extra mounts and host
environment passthrough are not accepted. The security control plane continues
using Ghost's pinned Alpine image even when the agent uses Python.

Python: `python:3.13.18-alpine3.23` pinned to image-index digest
`sha256:bf88c40985006a79ca25458159a4da1dffc457f9ae234e948b2d6df56ca5ebd2`.
The official [image metadata and build recipe](https://github.com/docker-library/repo-info/blob/master/repos/python/remote/3.13.18-alpine3.23.md)
identify the upstream layers and verified Python source archive. Preflight pulls
only the exact catalog reference when missing, inspects Linux/image metadata,
rejects declared volumes, entrypoints, healthchecks and on-build hooks, and binds
the prepared agent run to its immutable local content ID. Agent arguments never
control Docker options or image selection. Image pinning is not vulnerability
freedom, a publisher signature, or proof of bit-for-bit reproducible rebuilding.
No release claim of reproducible upstream image builds is made. CI/release also run checksum-pinned Trivy 0.76.2 against both catalog images and reject known CRITICAL findings (including unfixed findings), unsupported OS lifetime and scanner failures. The scanner uses its current vulnerability database and disables usage telemetry; an empty scan does not prove freedom from unknown vulnerabilities.

Adding an environment requires a reviewed source entry, immutable upstream
identity, documented build inputs, image-side behavior review and tests covering
the production orchestration, resource limits, networking, SHADOW and recovery.
Adding an adapter requires a pure guest argv mapping and its own integration
qualification. Neither extension may grant permissions or read host credentials.

Official interfaces reviewed for future work:
[Codex noninteractive execution](https://developers.openai.com/codex/noninteractive),
[Claude Code programmatic execution](https://code.claude.com/docs/en/headless).
These interfaces alone do not establish a working Ghost integration. Cloud model
access also needs a separately designed credential boundary. Do not mount user
homes or forward host environments to work around missing authentication.
