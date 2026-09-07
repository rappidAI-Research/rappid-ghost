# Changelog

All notable changes to Ghost will be documented in this file.

## Unreleased — v0.3 development

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
- Expand the v0.3 GhostBench development gate from fifteen to nineteen scenarios with explicit prompt detection, defensive-document false-positive control, benign untrusted-exposure provenance, and prompt-plus-Shadow temporal reconstruction.

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
- Expand GhostBench from nineteen to twenty-one scenarios with non-interactive ASK failure closure and proof that `ALLOW_ONCE` cannot authorize the next matching request.

### Correctness

- Fail a session when a runtime reports decoy-access evidence but does not report the containment state required by configured policy.
- Clamp valid whole-second sidecar evidence timestamps to `PROCESS_START`, preserving stable runtime sequence/ID ordering instead of allowing coarse timestamps to sort activity before the process that produced it.
- Keep the v0.2 CLI/configuration flow and all existing runtime behavior unchanged; no new command or feature toggle is required.

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
