# Ghost v0.6 engineering audit — development

Reviewed baseline 2026-11-16. This is engineering review, not an independent
penetration test or a production-data certification. v0.6 is not released.

## Verified starting point

Remote `main` and annotated stable v0.5.0 target
`970631de9872e2eedcc3523318103d100a4b70fc`. PRs #18/#19 are merged; no open PR
or newer main work existed. Main CI 43507846873 and Release 43508905601 passed,
including Docker and all 27 GhostBench properties. Baseline local Go 1.26.11
unit tests pass; Docker is unavailable in the editing environment and must run in CI.
No branch protection or ruleset was configured at inspection; existing review
and protection requirements must still be checked at integration time.

The runtime catalog, adapter preparation, model/read-tool broker, guest IPC
filter, sentinel/containment lifecycle, application authorization example,
recovery, persistence, Doctor and release workflow were reviewed against the
published architecture/security/threat/compatibility documentation.

## Architecture assessment

The closed catalog and pure argv adapters are useful boundaries, not defects.
Adapters are prepared before session persistence: Codex prompts are arguments to
a fixed bootstrap and do not replace the persisted executable identity. Model
and tool credentials remain host-side; authorization and minimal broker audit
share the existing lifecycle. No replacement security core is needed.

Actual extension gaps are an implicit OpenAI-only wire contract, no independently
qualified native Ollama path, no reviewed dependency environment, coarse shared
rather than per-tool budgets, unbounded retained project history, and incomplete
qualification metadata. Heuristic project hints must never fill these gaps by
opening permissions. Multi-user identity and tenant authorization belong to the
trusted application; tools remain read-only until remote write invariants exist.

## v0.6 implementation boundaries

1. Versioned closed model-protocol contracts: backward-compatible OpenAI v1 and
   narrowly validated native Ollama chat, reusing exact TLS destination binding,
   host credentials, cancellation, audit and resource enforcement.
2. Real pinned Ollama CPU/model demonstration behind an authenticated TLS edge,
   no published model port, no cloud model pull, no direct agent network. Native
   model-management, media, remote tools and unbounded generation stay denied.
3. Explicit per-tool budgets, deadlines and result-size ceilings; atomic replay
   and admission under concurrency. No arbitrary tools or write capabilities.
4. A reviewed hash-locked binary-wheel LangGraph environment if it passes actual
   framework, inference and supply-chain qualification. No live pip/npm installs.
5. Improve operator diagnosis, evidence-backed reporting and storage lifecycle
   without a second event store or automatic privilege expansion.
6. Recheck the whole change independently in a second critical engineering pass;
   retain all 27 existing benchmark properties and require final-commit CI.

Claude/provider-account qualification, vLLM, general writes/MCP transactions,
full multi-user control plane and additional host platforms are not claimed by
this development document. Only completed real tests may change their status.

## Validation ledger

- Baseline local `go test ./...`: PASS (Docker tests not executed locally).
- New implementation gates: pending. No pending test is release approval.

## First implementation checks and supply-chain finding

First implementation commit 7d843d8 passed Go CI (full tests/race/vet/module and
artifact checks), but CI 43882238301 **failed** the unchanged image gate on the
original official Ollama 0.40.16. Findings: CVE-2026-109518 in apt/libapt (HIGH)
and CVE-2026-78661 in x/net 0.61.0 (HIGH). This is not qualification.

A candidate unofficial CPU service now rebuilds the same checksum-pinned source
using Go 1.26.11 and x/net 0.62.0, actually removes apt/libapt offline and drops
unused GPU payloads. Both source and remaining distro/Go inventories are retained.
The candidate binary compiles locally and records x/net 0.62.0. Only a fresh
complete final-image scan and real Docker inference can qualify this change.

The new shared broker tests pass locally with race detection: strict native
Ollama text/model/options and response validation, protocol/management-route
separation, per-tool atomic parallel admission/deadline/result ceilings, and
revocation during completion audit before buffered result release. TLS-edge
unit tests also pass for authentication, fixed target/model, token separation,
unknown/media inputs and redirect rejection. Native runtime tests remain pending.

The patched CPU service passed the complete unchanged HIGH/CRITICAL scan in
CI 43885661826, including its real Ubuntu/Go inventory (no findings). That overall
CI still **failed** native inference with HTTP 502; it is not release approval.
Source inspection found the current native response includes the documented
`prompt_eval_cached_count` metric. The strict parser now accepts only that
additional bounded scalar; unknown/remote/tool fields remain denied. Better
closed broker-error diagnostics and bounded synthetic service logs support the
next real qualification. The runtime tests must prove the fix.

A candidate LangGraph 1.2.22 closure contains 38 versioned binary wheels (14.8 MB),
each independently matched to PyPI's SHA-256/URL and inspected for unsafe archive
paths and `.pth` hooks (none). The compiled catalog embeds this manifest. BuildKit
fetches checksum-constrained artifacts, offline pip verifies all hashes and
requirements, then pip/ensurepip are removed. No project lock, sdist or build hook
is accepted. Local catalog/config/CLI race tests pass; actual framework/model,
root-filesystem, credential, tool-budget and IPC-filter Docker tests are pending.
