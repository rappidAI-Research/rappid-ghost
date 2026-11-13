# Ghost v0.4 audit and validation record

Audit date: 2026-11-13. This is an engineering review with regression evidence,
not an independent penetration test, certification or proof of complete security.

## Verified starting point

- Remote main: `bc2ce21d473515cf6f58341e800bcb3952764c33` (0.3.1-dev).
- Latest published release/tag: v0.3.0. No v0.3.1 release/tag existed at inspection.
- PR #16: open draft, head `bea4681de339a8aeea13e25bba561f5f258f087b`, clean base.
  Its latest [CI](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43433019350)
  included successful Go, Docker integration, strict 25-scenario GhostBench,
  normal CLI and repeated rapid-child OOM jobs. Earlier failed runs were not
  substituted for the latest results.
- PRs #13–15 were already merged. The new work continues PR #16, preserving those
  changes rather than reimplementing the previous milestones.
- Repository ruleset collection was empty. Reading main branch protection returned
  integration permission 403; no protection was removed or bypassed. Merge must
  still honor GitHub's own review/check enforcement.

## Review scope and findings

| Area | Inspection / disposition |
| --- | --- |
| Module boundaries | Keep deterministic policy/session/event pipeline. Add small closed compatibility catalog and pure argv adapter; no plugin loader, duplicate policy engine or host runtime |
| PR #16 paths | Sequential Lstat could traverse a substituted parent. Fixed with descriptor-relative no-follow metadata lookups; concurrent parent-replacement regression |
| Configuration | Lstat then unbounded ReadFile could follow replacement/FIFO or grow without bound. Fixed single-FD no-follow/nonblocking regular read, 64 KiB cap, existing strict YAML validation retained |
| Approval | Existing controller serializes exact scoped grants; containment remains authoritative. Bound host workers to 32 and session request history to 512; bounded directory enumeration and 4 KiB artifact reads; protocol errors cancel in-flight resolution |
| Isolation | Existing capabilities/seccomp/namespaces/read-only root/non-root identity preserved. Inspect retained capabilities/privileges/namespaces/devices/logging/core dumps before untrusted execution; reject image volumes/hooks and unsafe metadata |
| Workspace | Default recursive bind could expose existing nested mounts; disable recursive inclusion for workspace and synthetic home, independent of read-only kernel support |
| Network | Existing exact-host gateway, numeric checked IPv4 upstream, private/link-local/raw-IP/IPv6/unsupported-port denial retained. Python requires the same ordered containment sequence; no private model-network exception |
| SHADOW | Same three synthetic resources and separate Alpine sentinel. Distinct Python image must produce real access and containment evidence; no intent/exfiltration claim |
| Prompt guard | Bounded heuristic selected-text startup scan retained; false-positive/adversarial tests retained. No new semantic safety claim or automatic permission decision |
| Persistence/recovery | Existing private SQLite state, per-project run lock, terminal/event transaction and cleanup-pending journal retained; exact ownership recovery and containment monotonicity regressions remain mandatory |
| Resources | Per-container memory/swap/CPU/PID/tmpfs/deadline constraints unchanged for Python; child-process/deadline and cleanup regression added. No workspace/evidence disk or aggregate-host quota claim |
| Data minimization | Doctor exposes fixed marker names, host tool presence and policy summaries, never marker bodies/paths to binaries. New durable history stores executable only; older database arguments may remain. Protocol bodies/credentials not added to exports |
| Runtime supply chain | Python official immutable image-index identity is source-reviewed, inspected and bound to local content ID. A checksum-pinned Trivy 0.76.2 gate scans both exact catalog images for known CRITICAL findings, including unfixed entries; scan/DB errors fail. Upstream bit-reproducibility, signatures and vulnerability freedom are not claimed |
| Product/release | Compatibility matrix, profile/config reference, runnable Python example, troubleshooting and explicit future gateway contract added; strict SKIP rejection and exact-main release gate retained |

These fixes address concrete filesystem-race, resource-exhaustion and runtime
boundary risks. Privileged/malicious host actors, Docker daemon/kernel compromise,
container escape, workspace secrets intentionally supplied by operators and
application/tenant authorization remain outside the runtime guarantee.

## Validation

The implementation is not releasable while any required Docker scenario fails.
The first feature CI passed Go/vet/race/vulnerability/build checks and all 25 old
GhostBench scenarios. The new Python tests correctly exposed a test assumption:
Python 3.13 raises PermissionError when probing Ghost's inaccessible state mask.
The assertion was corrected to require an actual open to fail with absence or
permission denial; no filesystem permission or security gate was loosened.

Local Go 1.26.11: all package tests, race suite, vet, module verification/tidy and
govulncheck passed on the first complete feature implementation. Docker is absent
locally; Docker execution evidence must come from GitHub Actions, not local SKIPs.
A later contended local run exceeded an existing shutdown timing assertion once;
that assertion was retained and repeated in isolation before final validation.
The second Docker run also exposed an exact fixture-body assertion mismatch (`allowed` versus the fixture's `allowed\n`). The assertion now matches the existing fixture body; no boundary was relaxed. Final complete-gate results are recorded below after they finish.

## Measured performance

Fixed-marker metadata discovery benchmark, Go 1.26.11 Linux amd64, same host,
three samples; intentionally no timing regression threshold from this noisy
shared runner. Base PR #16: 59–118 microseconds/op, about 5.65 KiB and 70
allocations. New descriptor implementation with more fixed markers: 93–347
microseconds/op, 1,688 bytes and 63 allocations. Lower allocated bytes are measured;
no speedup is claimed. Doctor runs on explicit request, not as a second recursive
scan in every agent execution. CI records this microbenchmark separately from
security tests. No speculative runtime performance optimization was introduced.

## v0.5 priorities

1. Authenticated per-session tool/model broker with application-bound capability,
   replay/expiry/revocation and tenant authorization gates; no broad private egress.
2. Credential design plus separately qualified Node and authentic Claude/Codex
   workflows; do not relabel Python interpreter support as framework support.
3. Workspace/evidence quotas, retention and aggregate admission control.
4. Independent security assessment, SBOM/signatures/attestations and more platform
   qualification, including rootless Docker and arm64 execution.

The [gateway design](tool-gateway-design.md) gives concrete trust and acceptance
requirements. Sensitive enterprise data is not an appropriate first deployment
without those application controls and an independent review.

## Verified complete implementation gate

Implementation commit `030e36aa3924daa6ceef4d3297985d9a9c14e6b0` passed
[complete CI](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/43439888916):
Go integrity/tidy/format/vet/govulncheck, unit/race, binary/cross-build/checksums,
real Docker integration without skipped tests, ordinary/JSON/strict GhostBench
**26 PASS / 0 FAIL / 0 SKIP**, normal shorthand/legacy user journeys, the documented
Python stdin example and ten rapid-child OOM repetitions. The two new Python
Docker tests passed. No failing check was disabled or converted to a pass.

Final local non-Docker suite: **396 passing test/subtest entries**, **19 explicitly
skipped Docker entries**, zero failing entries. Those local skips are not runtime
evidence; the Docker CI above supplies it. The final race suite also passed.
Local timing failures occurred while running competing full suites/builds and
were retained in the audit; isolated unchanged timing tests passed three times,
and complete serial unit checks and stock GitHub checks passed afterward.

A subsequent release-preparation commit adds the checksum-pinned image scan and
release metadata. Its own exact-commit CI and main/release gates must also pass
before publication; the earlier result alone cannot authorize release.
