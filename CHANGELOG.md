# Changelog

All notable changes to Ghost will be documented in this file.

## v0.5.0 — 2026-11-13

- Add pinned Node.js and native Codex runtimes/adapters without host execution or automatic dependency installation.
- Add per-session Unix model/read-tool mediation with exact TLS service identity, host-only explicit credentials, bounded/replay-safe operations, containment fencing and durable correlated decisions.
- Implement a restricted current MCP read-tool subset and official SDK qualification; provide actual local inference and synthetic application authorization examples.
- Add explicit integration setup, Doctor schema 3, sensitive-enterprise constraints and clear broker denial summaries.
- Retain all previous security scenarios and add Node boundaries (27 GhostBench properties), integration/recovery/parallel/resource tests and a five-image vulnerability gate.
- Keep unsupported agents/frameworks/platforms explicit. See docs/release-audit-v0.5.md for final validation status; a changelog entry does not publish a release.


## v0.4.0 — 2026-11-13

- Add a checksum-pinned Trivy runtime-image gate that rejects known HIGH/CRITICAL findings (including unfixed entries), scanner failures and end-of-life OS versions.
- Add explicit Alpine/Python runtime catalog, immutable agent-image validation and independent control sidecars.
- Add a Python entrypoint adapter with real CLI/Docker tests and an offline standard-library example.
- Expand Doctor with descriptor-safe project hints, host-tool presence, Docker capability checks and honest compatibility boundaries (JSON schema 2).
- Add explicit restrictive profile validation without automatic permission changes.
- Bound configuration/approval reads, reject substituted symlinks/FIFOs, limit approval request concurrency/history and exclude nested workspace mounts.
- Inspect mandatory container privilege/capability/namespace/device/logging boundaries before agent execution.
- Retain the 25 original GhostBench scenarios and add Python isolation/SHADOW/containment validation (26 total).
- Document compatibility, configuration, enterprise boundaries and a future tool/model gateway contract; MCP/local model support remains deferred.

### Included unreleased v0.3.1 work

### Build security

- Raise the source-build minimum and pinned CI/release toolchain to Go 1.26.11, the supported-series patch released on 10 November 2026. This resolves the standard-library findings reported by the current vulnerability gate, including GO-2026-6859. Existing v0.3.0 release artifacts remain the original builds; this entry describes unreleased source changes.

### Usability and reliability

- Accept `ghost run <command>` while retaining exact compatibility with `ghost run -- <command>`; keep executable names beginning with `-` behind the explicit separator.
- Default `ghost inspect`, `ghost graph`, and `ghost incidents` to the latest session, including `--json` for the latter two, while preserving explicit selectors.
- Recreate missing Ghost-owned `.ghost/`, session-directory, and database state from a valid `ghost.yaml`; never replace or repair invalid user policy.
- Append `.ghost/` to a local Git working tree's `.gitignore` during initialization without rewriting existing rules, and keep repeated initialization idempotent.
- Add concise typo suggestions, calmer completion output, actionable Docker/runtime/guest-command failures, bounded network-deny hints, and terminal `yes`/`no` approval aliases without changing ASK scope or fail-closed behavior.
- Add user-journey regression coverage for shorthand and legacy syntax, latest-session defaults, state recreation, repeated initialization, failure explanations, cancellation, resource termination, approval aliases, and secret-minimized output.
- Journal Docker cleanup responsibility before runtime creation and retry exact, positively identified cleanup even when the prior session already reached a terminal state; daemon loss or ambiguous ownership remains fail closed.
- Commit terminal session state and its single `SESSION_END` event atomically, make identical finalization retries idempotent, reject terminal-state rewrites, and bound SQLite lock waits.
- Prepare the exact digest-pinned runtime image during preflight with one bounded Docker pull when absent; cancellation remains cancellation and registry failure never selects a different image or host fallback.
- Keep Ctrl+C during approval or preflight bounded, classify concurrent same-project runs clearly, and preserve independent-project operation.

## v0.3.0 — 2026-09-21

### Final release audit

- Fix noninteractive CLI ASK handler wiring, recheck containment after DNS and CONNECT headers, reject contradictory approval replies, and fail closed on gateway decision-log write failure.
- Preserve HTTP headers/bodies through explicit producer stdin and forward only one framed operation per approval; deny ambiguous framing and pipelining beyond the first request.
- Verify approval-channel readiness before launch and reject stale SQLite updates that would reset containment.
- Preserve trusted containment through evidence collection/validation failures and reject ambiguous live markers using the same reader as recovery; incomplete logs never invent decoy-access events.
- Bound directory discovery and observation collection before allocation; prevent replaced sources/FIFOs from escaping or blocking prompt inspection.
- Require confirming runtime evidence for derived process/exposure provenance; omit command arguments from new durable history and from inspection of older sessions.
- Pin Go 1.26.8 for CI/release builds, retaining the same supported Go series with its security and correctness fixes.
- Reproduce rapid-child OOM evidence loss during containerd cgroup removal. Keep the agent cgroup alive until a trusted kernel counter is collected; retain all hard boundaries, original execution identity/argv, bounded graceful/forced cleanup, and strict repeated regressions on stock Docker.

### Adversarial validation

- Expand GhostBench from the v0.2 release's 15 to 25 required scenarios with cached-approval containment precedence, concurrent ALLOW_ONCE isolation and integrated cross-session isolation; extend the prompt/SHADOW chain through network denial.
- Add 18 prompt/benign regression cases, exact-scope and cancellation tests, malformed approval protocol, required evidence-write failure, pending-approval containment races and real CLI crash/summary/resource chains.
- Fix recovery losing uncommitted runtime containment after a Ghost crash; preserve the trusted marker with explicitly recovered evidence after owned-resource cleanup.
- Keep guest stderr out of persisted Docker attachment errors; preserve live command output.
- Require CLI Docker adversarial tests in CI and the release gate, with zero required skips.


### Architecture

- Add one structured security-signal ingestion path that validates observations before converting them into the existing persisted event source of truth.
- Replace parallel Go containment booleans with a typed, monotonic `NORMAL`/`CONTAINED` session security state while retaining the compatible SQLite containment column.
- Add a contextual policy evaluation seam where authoritative containment deterministically overrides network `ALLOW` with `DENY` and unknown state fails closed.
- Reserve a small event vocabulary for trust, prompt-injection, sensitive-resource, policy-violation, and resource-limit observations.
- Extend provenance to represent those future structured signals without exporting arbitrary signal metadata.

### Prompt-Injection Guard

- Automatically inspect selected agent instruction, repository documentation, `.github`, and script surfaces before `PROCESS_START`, with fixed file, byte, entry, and line bounds.
- Add deterministic named rules for instruction override, security bypass, sensitive access, transmission, environment exposure, security-setting changes, authority impersonation, concealment, Unicode/control obfuscation, and conservative one-level Base64 decoding.
- Persist one content-minimized `PROMPT_INJECTION_SUSPECTED` event per source with location, rule/category identifiers, deterministic severity, and SHA-256 fingerprint—never the document body.
- Integrate prompt findings into policy context, provenance, incidents, `ghost inspect`, and concise normal-run output without making policy more permissive or terminating solely on a heuristic match.
- Record scan-bound activation as `RESOURCE_LIMIT_TRIGGERED`; skip binaries, oversized files, excluded build/dependency trees, and symlinks rather than following them outside the workspace.
- Add false-positive controls for defensive documentation while documenting that both false positives and false negatives remain possible.

### Validation

- Add adversarial and defensive corpora, symlink/binary/oversize/obfuscation tests, fail-closed scanner tests, session-isolation checks, provenance/incident privacy tests, and a scanner benchmark.
- Add GhostBench coverage for explicit prompt detection, defensive-document false-positive control, benign untrusted-exposure provenance, and prompt-plus-Shadow temporal reconstruction.

### Trust context and provenance

- Add deterministic `TRUSTED`, `UNTRUSTED`, `SENSITIVE`, and `SHADOW` resource classes plus monotonic, session-local exposure context available to policy evaluation without loosening base decisions.
- Persist one content-minimized `UNTRUSTED_CONTENT_OBSERVED` event per selected analyzed workspace source; benign untrusted content does not create a suspicious finding or incident.
- Record a derived `SENSITIVE_RESOURCE_REQUESTED` signal only after genuine matching `DECOY_ACCESS` evidence, retaining the source event ID and never inspecting a host credential source.
- Upgrade provenance JSON to schema v2 with trust-labelled nodes and evidence-backed `EXPOSED_TO`/sensitive `REQUESTED` edges. `EXPOSED_TO` means workspace availability, not a file read or causal influence.
- Enrich incidents with source observation and derived command-scope exposure while preserving session isolation, evidence references, content minimization, and explicitly non-causal wording.

### Context-aware policy and approval

- Add canonical `ASK` only for exact HTTP/HTTPS destinations deliberately listed under `network.ask`; static `ALLOW`, automatic `DENY`, and home `SHADOW` behavior remain unchanged.
- Add a session-local, concurrency-safe approval controller supporting `ALLOW_ONCE`, exact scheme/host/port/method `ALLOW_SESSION`, and `DENY` without editing persistent project policy.
- Route interactive input through one terminal multiplexer so approval responses cannot race Docker's stdin reader. Non-interactive input, cancellation, timeout, malformed response, and broker/protocol failure deny the operation.
- Preserve hard precedence: containment, raw-IP/local/private/metadata address checks, unsupported ports/protocols, host-resource denial, and runtime confinement are never approvable.
- Link request-specific `APPROVAL_REQUIRED`, `APPROVAL_GRANTED`, `APPROVAL_DENIED`, `APPROVAL_UNAVAILABLE`, and `APPROVAL_EXPIRED` evidence into SQLite, inspection, provenance schema v3, and incident schema v2 without attributing user decisions to the agent.
- Add GhostBench coverage for non-interactive ASK failure closure and proof that `ALLOW_ONCE` cannot authorize the next matching request.

### Correctness

- Fail a session when a runtime reports decoy-access evidence but does not report the containment state required by configured policy.
- Clamp valid whole-second sidecar evidence timestamps to `PROCESS_START`, preserving stable runtime sequence/ID ordering instead of allowing coarse timestamps to sort activity before the process that produced it.
- Add an integrated Docker preflight that reuses runtime validation, returns a single-use prepared execution, and prevents mandatory static failures from producing `PROCESS_START` or invoking the agent path.
- Replace terse setup failures with categorized plain-language explanations while retaining technical causes and session IDs for debugging.
- Add an automatic completion summary derived only from persisted events and session state; uneventful runs remain concise and security-relevant runs report observed actions without copying secret-bearing metadata or asserting causality.
- Keep the v0.2 CLI/configuration flow and all existing runtime behavior compatible; `ghost init` now points directly to `ghost run -- <agent>`, with no new command, wizard, or feature toggle.

### Integrated runtime resource protection

- Add mandatory per-container RAM/swap and CPU ceilings, preserve PID confinement, explicitly bound shared memory, and retain bounded tmpfs plus a read-only root for agent and sidecars.
- Validate daemon resource capabilities and the built-in seccomp profile, snapshot strict optional runtime limits during preflight, and verify the created agent's actual Docker configuration before starting it. Rootless operation requires supported cgroup v2/systemd delegation; no weaker fallback is provided.
- Bound the prepared runtime, including setup, to a default one-hour deadline with TERM, five-second grace, forced termination, and cleanup by immutable container ID. Keep recovery and cleanup ownership checks fail closed, including name conflicts.
- Read trusted kernel OOM counters before teardown, with bounded positive daemon state/history evidence where available. Persist confirmed OOM, observed process saturation, and timeout as operational `RESOURCE_LIMIT_TRIGGERED` observations through the existing pipeline and provenance. Preserve authoritative containment state without inventing hostile incidents. ASK cannot override limits.
- Include resource evidence in summaries for failed sessions, exclude guest stderr from retained runtime errors, and disable Docker log-file accumulation for Ghost-owned containers.
- Publish gateway approval requests using a same-filesystem atomic rename, and make broker fixtures follow that protocol; avoid partial reads from cross-filesystem copies or direct writes discovered during the complete CI gate.
- Add deterministic validation/lifecycle tests and bounded Docker fixtures for descendant cgroups, PID exhaustion, child OOM, forced timeout, tmpfs, and unrelated-resource preservation. Add a GhostBench timeout/process-tree/session-isolation scenario; the final 25-scenario release gate requires zero failures and zero skips.
- Document workspace/evidence-disk, aggregate-host, daemon-availability, and sampled PID-observation limitations.

## v0.2.0 — 2026-09-06

### Security hardening

- Reject local-use and single-label allowlist names, including localhost-style, Docker host/gateway, and common metadata hostnames.
- Resolve approved names inside the gateway, reject the complete answer set when any returned IPv4 address is loopback, private, link-local, shared, benchmark, multicast, reserved, or otherwise prohibited, and connect only to the validated numeric address.
- Keep IPv6 and raw-IP upstream destinations denied in this release rather than accepting an address family that is not yet validated end to end.
- Move local Docker test fixtures onto a fixed, isolated public-unicast-shaped subnet so the tests exercise the production validator without permitting private gateway access or using the public Internet.
- Keep Docker's isolated PID namespace and request explicit private IPC and cgroup namespaces for every Ghost-owned container while retaining the existing non-root identity, capability drop, `no-new-privileges`, read-only root, and PID limits.
- Disable container core dumps, bound the private `.ghost` mask, and keep writable mounts limited to the configured workspace plus explicit per-container temporary or observation paths.
- Confirm the guest environment uses a positive allowlist: Ghost supplies only fixed `HOME`/`PATH` values and, for allowlist sessions, its own proxy variables. Arbitrary host variables are not forwarded.
- Replace the timing-based containment recheck with a unique token/ack fence through the sentinel's ordered inotify queue; publish containment before access evidence and deny when the fence cannot be completed.
- Serialize runs within each project and recover interrupted sessions on the next run by removing only Docker resources with matching durable session identity, Ghost component labels, and exact expected names. Recovery ambiguity and cleanup failure remain fail-closed.
- Treat an allowlist gateway that terminates before the agent completes as a visible runtime failure; the internal agent network continues to deny direct fallback egress.
- Preserve Docker cleanup failures alongside existing setup or runtime failures instead of hiding stale-resource evidence.
- Pin Alpine 3.22.5 to its immutable multi-platform index digest across the runtime, integration fixtures, and GhostBench.
- Pin GitHub Actions to full commit SHAs, use explicit Ubuntu and Go patch versions, retain read-only default workflow permissions, and verify the Go module checksum/tidy state in CI.
- Add a main- and tag-verified release workflow, triggerable manually or by an exact-main `release/vX.Y.Z` branch, that reruns the complete security gate, creates an annotated tag only after success, and publishes deterministic Linux artifact names with a verified SHA256 manifest.

### Validation

- Add unit coverage for prohibited address classes, fail-closed DNS parsing, local-use hostnames, fixed ports, and the absence of a second hostname resolution during connection.
- Add Docker integration coverage proving that an exact allowlisted hostname resolving to an RFC1918 address is denied.
- Add Docker integration coverage confirming that the agent has no usable external DNS resolver in the allowlist topology.
- Add Docker inspection coverage for namespace, privilege, mount, device, filesystem, PID, core-dump, identity, and environment isolation properties.
- Add repeated immediate-containment, token-barrier, interrupted-session, project-lock, ownership-validation, and Docker stale-resource recovery coverage.
- Expand GhostBench from ten to fifteen scenarios with live RFC1918-resolution denial, unknown-environment exclusion, guest-visible confinement, concurrent post-decoy containment, and interrupted contained-session recovery.
- Serialize stdout/stderr delivery when callers share one writer, preventing first-pull Docker diagnostics from corrupting guest output.

## v0.1.0 — 2026-08-31

### Added

- Docker-isolated command execution with no host fallback, host-home mount, Docker socket, privileged mode, or host network.
- Deterministic `ALLOW`, `DENY`, and active Shadow Home `SHADOW` policy for synthetic AWS, SSH, and `.env` resources.
- Inotify-based decoy-access evidence, per-session containment, and exact-host HTTP/HTTPS egress allowlists without TLS interception.
- SQLite sessions, events, decoys, migrations, inspection, provenance graphs, and deterministic incident reconstruction.
- GhostBench with ten local `PASS`/`FAIL`/`SKIP` security-property scenarios and a strict release gate.

### Security hardening

- Masked `.ghost` and protected `ghost.yaml` inside writable workspaces.
- Explicit minimal guest environment and secret-minimized network, provenance, incident, and benchmark output.
- Read-only container roots, dropped capabilities, `no-new-privileges`, PID limits, private per-session resources, and fail-closed gateway/sentinel startup.
- Refusal to execute Docker workloads as host root or without a numeric unprivileged UID/GID.
- Base-image selection narrowed from a moving minor tag to the exact `alpine:3.22.5` patch tag; digest pinning remains future hardening.

### Validation

- GitHub Actions ran the normal Go checks, Docker integration suite, and strict GhostBench release gate successfully.
- GhostBench result: `PASS: 10`, `FAIL: 0`, `SKIP: 0`.
