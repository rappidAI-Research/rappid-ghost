# Runtime and integration compatibility

The qualified execution target is **native Linux amd64, Docker Engine with
working seccomp and memory/swap/CPU/PID cgroups**, under a non-root host UID/GID.
Arm64 binaries are cross-built/checksummed only. Linux arm64 execution, Docker
Desktop on macOS, WSL2/Windows, rootless Docker, UID remapping and remote daemons
are not independently qualified. A compiled binary or responsive daemon does not
establish equivalent filesystem/Unix-socket/security behavior.

| Integration | Implemented path | Qualification and limits |
| --- | --- | --- |
| Generic CLI/static Go | `command` + catalog environment | Existing Docker/GhostBench; executable must be available in guest; no Go compiler |
| Python | `python` + `python` | Python 3.13.18 standard library, relative `.py`, stdin/stdout/argv, real Docker boundaries |
| Node.js | `node` + `node` | Node 24.22.3 built-in modules, `.js`/`.mjs`/`.cjs`, real Docker boundary test and GhostBench |
| OpenAI Codex CLI | `codex` + `codex` + model broker | Official 0.169.0 native musl amd64; noninteractive real shell-tool loop against deterministic Responses fixture; account/hosted inference not certified |
| Local model | Python + exact HTTPS model broker | Actual llama.cpp CPU/SmolLM2 inference example; direct service/external bypass denied; text-only chat |
| MCP read tools | Broker `/mcp` | Restricted 2026-07-28 stateless discovery/list/call, official Go SDK 1.8.0 interoperability, guest Docker client and negative scope tests |
| Application read tools | Broker `/ghost/tools/call` | Explicit required scalar schema/resource/effect grants; application authorization/revocation required |
| Claude Code | No qualified adapter | Official noninteractive interface reviewed; native packaging, provider/auth semantics and full workflow not independently tested |
| LangChain/LangGraph/dependency bundles | No qualified environment | Bare interpreter support does not qualify frameworks or dependency installation |
| Ollama/vLLM-specific integration | No separate qualified adapter | Protocol similarity alone is not a deployment guarantee; HTTPS service identity is mandatory |
| MCP sessions/notifications/writes/arbitrary servers | Unsupported | No legacy fallback, blind forwarding, subscriptions, MRTR, server sampling or transaction mediation |

See [working integration instructions](integrations.md) and
[release audit](release-audit-v0.5.md) for the evidence and its limits.

## Closed catalog and supply chain

Arbitrary images, dynamic adapter plugins, host environment forwarding, extra
mount flags and host execution are rejected. Adapters are pure guest argv
mappings and fixed bootstraps. The security core does not receive a different
permission policy because a particular agent needs it. Broker-enabled sessions
require network deny and cannot combine direct allowlist/ASK egress with mediation.

| Environment | Immutable upstream input | Preparation |
| --- | --- | --- |
| Alpine/control roles | `alpine:3.23.8@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2` | Minimal default |
| Python | `python:3.13.18-alpine3.23@sha256:bf88c40985006a79ca25458159a4da1dffc457f9ae234e948b2d6df56ca5ebd2` | Removes site-packages, pip and ensurepip |
| Node.js | `node:24.22.3-alpine3.23@sha256:3946fb783fdce8a2812136ea694bc95c698c4f4096f3fd18568dc27a8ac389dc` | Removes npm/npx/yarn/corepack and the reviewed source entrypoint; final image has no entrypoint |
| Codex | Alpine above + official `rust-v0.169.0` musl amd64 archive | `ADD --checksum`, SHA-256 `9af4d751fce183faedea629437d5252dbf458eeb04130cf4f97be844621ea985`; fixed archive member, no install script |

Docker BuildKit consumes only reviewed stdin Dockerfiles, no workspace context,
no RUN network and no arbitrary arguments; `SOURCE_DATE_EPOCH=0` is fixed. Codex's
checksum-constrained archive download happens during image preparation, never
inside the untrusted agent. Source and final images are inspected for immutable
identity, Linux platform, volumes/hooks/healthchecks/entrypoint behavior; actual
execution binds the final inspected content ID. Only the exact reviewed Node
source entrypoint is accepted before its removal. All final environments plus
the pinned external local-model demonstration service are scanned by
checksum-pinned Trivy 0.76.2, including unfixed HIGH/CRITICAL findings and EOL.
Go modules are version- and sum-pinned and checked for reachable vulnerabilities.
Pinning/scanning is not publisher-signature verification, unknown-vulnerability
freedom or proof of bit-identical builds across BuildKit versions.

The local model service is an external application dependency, not another
accepted `runtime.environment`. Its image, upstream source revision and model
SHA/revision are fixed in `scripts/test-local-model.sh`.

Doctor schema **3** reports hints and static integration requirements separately
from host executable presence and configured permissions. `runtime_validated`
remains false: only a real `ghost run` exercises mandatory runtime preflight and
execution. Discovery never reads marker contents, selects an adapter, reads a
credential, contacts an endpoint or changes policy.
