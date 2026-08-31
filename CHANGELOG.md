# Changelog

All notable changes to Ghost will be documented in this file.

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
