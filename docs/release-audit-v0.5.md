# Ghost v0.5 engineering audit

Reviewed 2026-11-13. This is source review and reproducible engineering evidence,
not an independent penetration test, certification or proof of complete security.
**Release gate is pending until the final exact-commit CI below is recorded.**

## Verified baseline

Remote main and stable v0.4.0 both targeted
`d7e7cdee8fc22c6628d1dc515a4d10db3b1c0550`; its release and Go/Docker CI were
successful. PRs #16/#17 were merged and no newer work had to be overwritten.
The implementation continues on [PR #18](https://github.com/rappidAI-Research/rappid-ghost/pull/18).
The published catalog, Python adapter, Docker/gateway/approval/sentinel boundaries,
profiles, doctor, persistence/recovery and 26 GhostBench properties were inspected.

v0.4's fixed runtime catalog and no-private-egress policy were deliberate security
boundaries, not bugs to bypass. Missing authenticated service mediation and agent
packaging were actual integration gaps. The v0.5 solution retains the deterministic
core and adds a session-only Unix broker, exact TLS destinations and pure adapter
bootstraps; it does not grant direct/private agent networking.

## Review and corrections

| Area | Disposition |
| --- | --- |
| Runtime images | Closed pinned Node/Codex inputs; checksum-constrained official archive; BuildKit without project context/RUN network; source hooks rejected, exact reviewed Node entrypoint removed; final content ID inspected/scanned |
| Broker isolation | UID-private session socket/helper, no host TCP listener, actual network=none and read-only/nonrecursive mounts checked before guest exec; direct destination gateway combination rejected |
| Credentials/SSRF | Only explicit host variable references; no credential or arbitrary header forwarding to guest; exact TLS origin/name/cert/port and session-bound numeric address; proxies, redirects and remote model references denied |
| Model protocol | Text/stateless subset, output budget, no hosted tools; local client tool schemas distinguished from remote media; Codex cache/client metadata stripped; unknown fields fail closed |
| Tools/MCP | Explicit read-effect contract, required scalar schema/resource ceiling, atomic bounded replay state, current application authorization on every read; official MCP SDK independently validates restricted 2026-07-28 protocol |
| Race/lifecycle | Snapshot caller grants, serialize sentinel barriers, monotonic containment/expiry cancellation; join handlers before sentinel finalization; helper/socket cleanup included in owned crash recovery |
| Resource exhaustion | Bounded connections/concurrency/rate/request history/body sizes/depth/time/tokens; audit-before-effect fails closed; retained failure state is bounded rather than appending errors indefinitely |
| Data minimization | Correlated host-generated admission/denial/completion IDs in existing SQLite events; no prompts, credential values, arguments/resource IDs or document bodies added to audit |
| UX/profiles | Explicit integration templates preserve existing policy; Doctor schema 3 is advisory and does not read credentials/contact services; blocked broker actions appear in the normal summary; restricted profile forbids brokers |
| Tests | Original properties retained, real Node scenario added (27 total); native Codex/actual local inference/MCP/tenant/revocation/crash/parallel/resource checks use production execution paths |

The application implements read effects and its own employee/tenant permissions;
Ghost cannot infer either from an agent/tool name. Cancellation cannot undo bytes
or effects already accepted. Container escape, host/Docker compromise, workspace
secrets, aggregate host/disk quotas, data retention and model output quality remain
outside these claims. No known issue is hidden by a SKIP-to-PASS conversion.

## Validation evidence and resolved qualification failures

Local Go tests/race validation use Go 1.26.11. This editing environment has no
Docker daemon; native runtime evidence comes from GitHub Actions.

Early Docker runs exposed real integration assumptions: Codex needs an existing,
writable private state directory; its current wire metadata differs from older
documentation; local-only tool discovery differs from hosted tools. These were
fixed at the adapter/protocol boundary, without relaxing Docker/remote-tool policy.
The model demo now obtains Docker's own unused private address before generating
its TLS certificate; it publishes no port or external route. A recovery test was
corrected to distinguish the existing `.run.lock` file from session directories.
The old concurrent approval checks remain enabled; Docker package scheduling is
serialized to avoid unrelated compiler/model stress invalidating their deadlines.

On [CI 43494194577](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43494194577),
Go integrity/vet/vulnerability/unit/race/build checks and the image gate passed.
Actual local llama.cpp inference produced 24 generated tokens, direct same-service
and external connections were denied, MCP/enterprise tests and socket crash
recovery passed. That overall run **failed** because Codex qualification was still
incomplete. It is not release approval.

Final complete gate: **pending**. Required: all Go checks, native Docker with zero
skips, 27/0/0 GhostBench, all declared integration paths, five image scans,
normal/documented workflows, repeated OOM and checksummed release artifacts.

## Performance method

Required Docker measurements compare a warmed standard-library Python task with
and without one broker request: one warmup plus three samples per mode. Logs retain
wall duration, host process-tree CPU/wait4 RSS (includes waited Docker CLI children,
excludes guest cgroups/model inference) and guest-to-broker TLS roundtrip. Separate
Docker cgroup snapshots report the idle-after-request guest/helper footprint.
These are controlled observations on a shared runner, not hard real-time SLAs,
aggregate RSS or a model throughput comparison. Final measured values: **pending**.

## Explicitly deferred to v0.6

Claude Code and independently tested hosted-account flows; controlled dependency
bundles/LangChain/LangGraph; Ollama/vLLM-specific qualification; general MCP/remote
transactions/write approvals; authenticated multi-user control plane; workspace
and evidence quotas/retention and aggregate admission; rootless/arm64/Desktop/WSL
execution qualification; signed attestations/SBOM and independent security review.
