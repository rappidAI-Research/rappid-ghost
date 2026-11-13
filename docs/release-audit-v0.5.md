# Ghost v0.5 engineering audit

Reviewed 2026-11-13. This is source review and reproducible engineering evidence,
not an independent penetration test, certification or proof of complete security.
The complete implementation and IPC hardening gates passed on the final source
head. Publication additionally requires successful CI on the exact merged main
commit and the independent release workflow. The tag/release is authoritative
for publication status.

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
| Host IPC bypass | [Complete IPC CI 43498902304](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43498902304) for `df0d627aa2dade785b190ab8e6ca93aa83ac21cc` passed Go, Docker, native Codex, model/MCP/enterprise/recovery and all 27 GhostBench properties after the additional filter. Final review found that live workspace Unix sockets can cross an IP-only network boundary. Broker agents now inherit a synchronized socket/ptrace/FD/io_uring seccomp filter; anonymous connected stream pairs remain for internal signaling, bridge dumpability is disabled; a real host-listener adversarial Docker test is required. The private IPC root/session trees are excluded as workspaces for every adapter, preventing legacy broad-workspace cross-session access; other non-broker workspace semantics remain explicitly documented |
| Broker isolation | UID-private session socket/helper, no host TCP listener, actual network=none and read-only/nonrecursive mounts checked before guest exec; direct destination gateway combination rejected |
| Credentials/SSRF | Only explicit host variable references; no credential or arbitrary header forwarding to guest; exact TLS origin/name/cert/port and session-bound numeric address; proxies, redirects and remote model references denied |
| Model protocol | Final input review additionally rejects mixed Chat/Responses representations and null/remote content; a text alias cannot bypass strict content validation. Text/stateless subset, output budget, no hosted tools; local client tool schemas distinguished from remote media; Codex cache/client metadata stripped; unknown fields fail closed |
| Tools/MCP | Explicit read-effect contract, required scalar schema/resource ceiling, atomic bounded replay state, current application authorization on every read; official MCP SDK independently validates restricted 2026-07-28 protocol |
| Race/lifecycle | Snapshot caller grants, serialize sentinel barriers, monotonic containment/expiry cancellation; join handlers before sentinel finalization; helper/socket cleanup included in owned crash recovery |
| Resource exhaustion | Bounded connections/concurrency/rate/request history/body sizes/depth/time/tokens; audit-before-effect fails closed; retained failure state is bounded rather than appending errors indefinitely |
| Data minimization | Correlated host-generated admission/denial/completion IDs in existing SQLite events; no prompts, credential values, arguments/resource IDs or document bodies added to audit |
| UX/profiles | Explicit integration templates preserve existing policy; Doctor schema 3 is advisory and does not read credentials/contact services; blocked broker actions appear in the normal summary; restricted profile forbids brokers |
| Tests | Original properties retained, real Node scenario added (27 total); native Codex/actual local inference/MCP/tenant/revocation/crash/parallel/resource checks use production execution paths |

The final integration runner was Ubuntu 24.04.5 LTS, Linux x86_64 kernel
7.0.0-1017-azure, Docker Engine 28.0.4 with cgroup v2, four CPUs and approximately
15.6 GiB host RAM. This records the tested functional environment; it does not
certify every daemon/kernel version or replace operators' host patch management.

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
its TLS certificate; it publishes no port or external route. An idle-terminal Codex regression verifies argv prompts finish without requiring stdin EOF, while the explicit stdin path preserves its prompt. A recovery test was
corrected to distinguish the existing `.run.lock` file from session directories.
The old concurrent approval checks remain enabled; Docker package scheduling is
serialized to avoid unrelated compiler/model stress invalidating their deadlines.

On [CI 43494194577](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43494194577),
Go integrity/vet/vulnerability/unit/race/build checks and the image gate passed.
Actual local llama.cpp inference produced 24 generated tokens, direct same-service
and external connections were denied, MCP/enterprise tests and socket crash
recovery passed. That overall run **failed** because Codex qualification was still
incomplete. It is not release approval.

Final implementation commit `7a207d15cf4360e885d537765afd7c505f1fa7a1` passed
[complete push CI 43502042105](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43502042105)
and [complete PR CI 43502050942](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43502050942):

| Gate | Verified result |
| --- | --- |
| Go integrity, tidy, format, vet, govulncheck | PASS; no reachable reported vulnerabilities |
| Unit and race tests | PASS |
| Docker integration | PASS; 76 selected Go test results including parent/subtests, 0 FAIL / 0 SKIP |
| GhostBench ordinary/JSON/strict | **27 PASS / 0 FAIL / 0 SKIP**; original 26 retained |
| Native Codex | Official binary; argv with a deliberately open idle stdin and explicit stdin prompt both passed; two model requests, real shell/file execution and tool-result roundtrip per path |
| Local inference | Real pinned llama.cpp/SmolLM2, 24 generated tokens; direct same-service/external connections denied |
| Tool/MCP/application | Official SDK guest, malformed/scope/replay cases, application employee/tenant authorization and revocation passed |
| Recovery and concurrency | Forced-controller crash socket/helper reconciliation, concurrent session credentials/resource isolation, and reachable-host-IPC positive control followed by enforced denial passed |
| Image supply chain | All four final runtime/control images and pinned external model service passed current HIGH/CRITICAL/EOL scan gate |
| Ordinary/documented workflows | Shorthand/legacy CLI, Python stdin example and ten rapid-child OOM repetitions passed |
| Artifacts | Static linux amd64/arm64 cross-builds and checksums passed; arm64 execution remains unqualified |

Local release preparation also passed full unit/race/vet/integrity/tidy/govulncheck,
static builds and checksum verification. Final documentation and source preparation repeat CI; the release workflow requires successful CI
on the exact merged main commit and independently repeats all runtime gates.
No independent human penetration test or hosted OpenAI-account qualification is
claimed. No known critical finding remains from this engineering review.

## Performance method

Required Docker measurements compare a warmed standard-library Python task with
and without one broker request: one warmup plus three samples per mode. Logs retain
wall duration, host process-tree CPU/wait4 RSS (includes waited Docker CLI children,
excludes guest cgroups/model inference) and guest-to-broker TLS roundtrip. Separate
Docker cgroup snapshots report the idle-after-request guest/helper footprint.
These are controlled observations on a shared runner, not hard real-time SLAs,
aggregate RSS or a model throughput comparison. From the final successful push CI above, with the inherited IPC filter enabled:

| Measurement | Python baseline | Python plus one broker request |
| --- | --- | --- |
| Warm end-to-end wall time, median of 3 | 978.461 ms | 1093.729 ms |
| Host process-tree CPU, median | 531.576 ms | 562.419 ms |
| Guest cgroup memory, idle-after-request snapshot | 11.49 MiB | 16.24 MiB |
| Guest process/thread count at that snapshot | 3 | 11 |
| Guest-to-broker/upstream roundtrip, median | n/a | 26.547 ms |

The measured full-workflow difference is about **115 ms** in this small task,
including the actual additional TLS request and helper lifecycle, not pure proxy
latency. The guest snapshot difference is about **4.75 MiB**; idle CPU was 0.00% at
both snapshots, not a total CPU overhead estimate. Wait4 host-tree peak RSS was
approximately 51 MiB in both modes and is not combined guest/model memory. Native Codex's first argv workflow took about six seconds. Catalog images had
already been prepared by the scan gate; this is not a fresh-registry cold-start
measurement. No speculative performance optimization or broad speed claim is made.

## Explicitly deferred to v0.6

Claude Code and independently tested hosted-account flows; controlled dependency
bundles/LangChain/LangGraph; Ollama/vLLM-specific qualification; general MCP/remote
transactions/write approvals; authenticated multi-user control plane; workspace
and evidence quotas/retention and aggregate admission; rootless/arm64/Desktop/WSL
execution qualification; signed attestations/SBOM and independent security review.
