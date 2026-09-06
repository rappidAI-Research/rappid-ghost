# Changelog

All notable changes to Ghost will be documented in this file.

## Unreleased — v0.2.0

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
- Pin Alpine 3.22.5 to its immutable multi-platform index digest across the runtime, integration fixtures, and GhostBench.
- Pin GitHub Actions to full commit SHAs, use explicit Ubuntu and Go patch versions, retain read-only default workflow permissions, and verify the Go module checksum/tidy state in CI.
- Add a manual, tag-verified release workflow that reruns the complete security gate and publishes deterministic Linux artifact names with a verified SHA256 manifest.

### Validation

- Add unit coverage for prohibited address classes, fail-closed DNS parsing, local-use hostnames, fixed ports, and the absence of a second hostname resolution during connection.
- Add Docker integration coverage proving that an exact allowlisted hostname resolving to an RFC1918 address is denied.
- Add Docker inspection coverage for namespace, privilege, mount, device, filesystem, PID, core-dump, identity, and environment isolation properties.
- Add repeated immediate-containment, token-barrier, interrupted-session, project-lock, ownership-validation, and Docker stale-resource recovery coverage.
- Expand GhostBench from ten to fifteen scenarios with live RFC1918-resolution denial, unknown-environment exclusion, guest-visible confinement, concurrent post-decoy containment, and interrupted contained-session recovery.

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
