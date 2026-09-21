# v0.3 release audit — 2026-09-21

Status: **AUDIT COMPLETE; final release gate required**. This document records
verified fixes and validation, not a security certification. Publication is
controlled by the exact-main CI, version, artifact and annotated-tag checks.

## Verified starting repository state

- Starting remote main: `5a76ccf758d5693140cd635748a237b30d703e5b`.
- Public releases/tags: v0.1.0 and v0.2.0. The intended next feature release is
  **v0.3.0**, not v0.3.1. The release preparation sets metadata to `0.3.0`.
- PR #6 was already merged; original UX commit `4e351602b3e33bd4ba9a33095530bb9b4904642e`
  is an ancestor of main. PR #7 contains actual runtime resource enforcement.
- PR #8 was still open. Its exact head `089b58f86ed5f6703ba786647046f5880706a4cf`
  passed both CI jobs and was merged as `d9de8d940cec9cdefc4c995f5e55ad00f57d431b`.
  Main CI for that merge passed. Earlier development branches were checked against
  current implementation; older prompt/chronology and signal-state commits are
  represented by their integrated successors, not missing milestones.

## Findings and permanent regressions

| Finding | Correction / objective regression |
|---|---|
| Noninteractive CLI passed a typed-nil terminal handler | Pass a genuinely nil interface; CLI wiring test plus real Docker ASK test require unavailable/deny evidence and no grant |
| Static ALLOW could use pre-DNS containment state | Final sentinel fence and marker check after resolution/approval and CONNECT headers; actual gateway-script regression transitions state inside controlled resolution |
| HTTP producer inherited closed stdin and lost request headers/body | Preserve explicit stdin and forward only one Content-Length-framed request; reject ambiguous/unsupported framing before ASK; actual script and Docker POST regressions |
| Contradictory scope/source protocol values could grant | Reject automatic grants and invalid session/one-use combinations; table of malformed responses must produce unavailable evidence |
| Gateway could continue after decision-log write failure | Required ALLOW/approval evidence writes must succeed; broken-log fixture denies without opening transport |
| Broker readiness was asynchronous | Verify fresh real directories and response write/cleanup before returning a broker; missing-channel startup tests fail synchronously |
| Stale session update could clear persisted containment | Atomic SQL predicate rejects CONTAINED-to-NORMAL updates; regression verifies retained state and later failed-session finalization |
| Failed observation collection/finalization could lose live containment | Reuse the trusted recovery marker reader after all sidecars stop, including failure exits; retain containment before validating other evidence, reject ambiguous markers, persist failed CONTAINED sessions without inventing access events |
| Directory discovery allocated whole listings before checking bounds | Root-confined bounded listings; oversized directory is reported as truncated, never an arbitrary partial selection |
| Replaced special source could block startup inspection | Nonblocking opens with type/inode checks; symlink and FIFO regressions |
| Launch request alone invented process/exposure provenance after setup failure | Require subsequent same-session runtime proof; STARTED is DERIVED, exposure cites observation, launch request and confirmation; foreign evidence cannot confirm it |
| Command arguments could contain secrets in durable history | Preserve original execution argv but persist only executable and argument count; inspection omits historical arguments; synthetic-token regression |
| Observation/history bounds were checked after allocation or absent | Bound observation collection to 16 MiB / 10,000 records and OOM output to 64 KiB during collection; original evidence retained on failure |
| Noncanonical zero and overflowing identities passed helper validation | Parse unsigned 32-bit IDs and reject numerical zero; UID/GID regressions |
| Build toolchain missed supported-series fixes | Pin Go 1.26.8 and govulncheck v1.8.0; same Go series, no application dependency redesign |
| Release workflow did not require existing exact-main CI | Require both mandatory jobs for the exact main SHA, matching source version/changelog, complete security gate and checksums before annotated tag creation |

These are fixes to existing paths. No scanner command, second runtime, new policy
authority, benchmark score, or mandatory user workflow was added. The detector
corpus remains the curated supported-pattern/benign-control corpus; no universal
accuracy rate is claimed. GhostBench remains exactly **25 scenarios**.

## Architecture and boundary review

CLI/configuration, manager/locking, policy/trust/signals, approval, Docker agent and
sidecars, SHADOW/inotify, resources, cleanup/recovery, SQLite, provenance/incidents,
summary, benchmark harness and release workflows were reviewed together. The
live sentinel marker and terminal SQLite state have an explicit handoff. Events
remain the durable source for derived views; operational limits do not establish
malicious intent or change containment by themselves.

Existing enforcement remains: Docker only; non-root UID/GID; no host home/socket
or host environment; all capabilities dropped; no-new-privileges; read-only root;
private PID/IPC/cgroup namespaces; synthetic per-session SHADOW material; deny
network by default; exact destination and pinned validated IPv4 connection for
allowlist/ASK; forbidden private/raw/metadata destinations cannot be approved.
Already-authorized connections are not atomically revoked by later containment.

Defaults remain 2048 MiB RAM, no additional swap, one CPU quota, 256 processes /
threads, 3600-second prepared-execution deadline, five-second TERM grace and
64-MiB `/tmp`. The kernel boundary covers descendants. Forced termination and
owned-resource cleanup remain part of the same runtime lifecycle. Default Docker
seccomp is required; AppArmor remains optional host hardening. Unsupported
resource capabilities fail closed, including unsupported rootless configurations.

## Rapid child OOM: reproduced cause and lifecycle correction

The original strict test observed a killed child followed immediately by a
successful parent exit, but no OOM evidence in Docker state or event history.
Exit 137 alone was never treated as proof of OOM.

The failing environment used Docker 28.0.4, cgroup v2/systemd, containerd 2.3.4
(commit `db8809540e1a7a9da5d518876894933ff55692ab`) and runc 1.5.1. The
[instrumented reproduction](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/35643946615)
recorded the actual watcher read: it parsed `oom_kill:1`, then returned ENODEV
as the empty cgroup disappeared. The watcher discarded the parsed value on that
read error and published no `/tasks/oom`. Independent kernel parent counters
increased, and both containerd's event stream and Docker history lacked OOM.
Instrumentation only logged the original upstream code; it is not a user runtime
requirement or part of release validation.

Ghost now keeps the existing agent container alive with a distinct non-root
keeper and executes the agent inside that same container/resource boundary.
Before launching, a trusted probe requires a fresh readable kernel OOM counter.
After execution, Ghost reads the cumulative counter before stopping/removing the
container. Probe/keeper and agent identities differ; the read-only image and
kernel mount prevent guest-authored output from serving as resource evidence.
Docker state/history remain supplementary evidence if the final probe fails;
missing evidence remains a visible failure, never an assumed zero.

Docker's own CLI transport retains context/TLS/rootless connection handling.
The agent keeps its original argv, non-root UID/GID, workspace, allowlisted
environment and all existing confinement. Docker exec inspection, rather than
launch intent or guest exit text, supplies actual start/exit evidence. Shutdown
attempts TERM for agent descendants before bounded forced whole-container
cleanup. No patched Docker, host cgroup writes, new capability or user workflow
is introduced.

The unchanged rapid-exit fixture remains strict. Separate branch validation ran
100 repetitions on stock Docker, and normal CI/release gates retain ten repetitions
(three finite 64-MiB container cases per invocation). New tests cover kernel
counter validation, failure before launch, missing daemon notification, stream
framing/privacy, stdin/exit/start semantics, keeper protection, and graceful as
well as forced shutdown. Temporary diagnostic scripts were removed after reproduction; the linked
commit/run retains them for traceability. Passing retries alone is not the fix.

## Validation and release conditions

Local checks use Go 1.26.8: formatting, vet, unit tests, race tests, both build
commands, module verification, vulnerability checking and checksummed Linux
amd64/arm64 release-shaped artifacts. Local Docker is unavailable; actual Docker
and full benchmark results must come from the exact GitHub Actions commit.
Final counts and run links are recorded in the audit PR and completion report.
The normal CI gate also runs init, a harmless workspace-writing command, inspect,
graph and incidents. No approval prompt belongs in that baseline.

The OOM fix is merged as `2ab74e8ef74d1a81ddb89180c927299cfea06271` (PR #11).
Its final [branch CI](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/35647133276)
and [PR CI](https://github.com/rappidAI-Research/rappid-ghost/actions/runs/35647137256)
passed both mandatory jobs. The Docker gate records **56 PASS / 0 FAIL / 0 SKIP**
test/subtest results, including unit cases selected by the Docker gate's name
filter. GhostBench records exactly **25 PASS / 0 FAIL / 0 SKIP** in ordinary,
JSON and strict modes. The normal init/run/inspect/graph/incidents workflow and
ten additional strict child-OOM repetitions passed. Focused stock-Docker
validation also passed 100 repetitions (300 finite container cases).

The release preparation changes version metadata and documentation only. The
release workflow must find successful CI on the exact final main commit, rerun
the complete Go/Docker/GhostBench gate, verify Linux amd64/arm64 artifacts and
SHA256SUMS, and verify main has not advanced before creating the annotated
`v0.3.0` tag. The tag and release's workflow run identify the final audited SHA.
No v0.3.1 is appropriate because no earlier v0.3.0 exists.

## Known limits

Workspace and retained evidence have no byte quota; read bounds are not disk
quotas. Limits are per container, not aggregate host admission control. Hard host
crashes can interrupt evidence import and userspace deadlines. Recovery preserves
known containment but does not invent missing activity. Docker/kernel/image trust,
startup-only heuristic prompt detection, false positives/negatives, no semantic
causality/exfiltration proof, and no reliable individual child PID attribution
remain documented limits.

New history excludes command arguments; older SQLite rows may still contain them
and are not silently rewritten. Live program stdout/stderr remains program output,
not a sanitized security summary. Filenames, executable paths and necessary
operational errors can still identify local resources; source bodies, raw approval
input, request bodies and decoy values are excluded from reconstructed exports.

The next action is closure of the OOM evidence blocker and a repeated v0.3 release
gate. No v0.4 work is part of this audit.
