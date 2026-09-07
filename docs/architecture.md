# Architecture

Ghost is a local command-line application with small package boundaries, deterministic filesystem and network policy, read-only provenance and incident views over stored evidence, and an evidence-backed benchmark orchestrator. Version 0.2 added boundary, recovery, and supply-chain hardening. The v0.3 development line adds a shared security-signal ingestion path, typed monotonic session state and trust context, a contextual policy seam, and an integrated bounded Prompt-Injection Guard without changing the v0.2 enforcement boundary.

```text
                         Ghost CLI
                             |
                       configuration
                             |
                       Session Manager
                   /          |          \
          Policy Context  Security State  Deception
       ALLOW/DENY/SHADOW/ASK NORMAL/CONTAINED Generator
                   \          |          /
                       Docker Runtime
                  /          |          \
       inotify Sentinel   Agent command   Egress Gateway
                  \          |          /
                    structured signals
                             |
                    validated Event Store
                         /          \
                   SQLite       Provenance Builder
                                 /            \
                         Graph view   Incident Reconstructor
                                            |
                                       Incident view
```

GhostBench enters through the CLI, invokes the same session manager and Docker runtime, and evaluates its named assertions from the resulting SQLite events, reconstructed graph, and incidents. Its local HTTP fixture is setup infrastructure, not another enforcement implementation.

## Components

- **CLI:** validates command shape, selects the configured runtime, and presents stored results. It does not construct decoy values, SQL, or Docker arguments.
- **Config:** strictly decodes `ghost.yaml`, rejects unknown fields and unsupported values, applies safe defaults to older schema-version-1 files, and prevents destructive initialization.
- **Session manager:** owns status transitions, policy evaluation, synthetic-home preparation, runtime invocation, and routing runtime evidence through the security-signal pipeline. A per-project process lock prevents a live session from being mistaken for interrupted recovery work. Incidents are reconstructed later and are not separately persisted.
- **Policy:** defines canonical `ALLOW`, `DENY`, `SHADOW`, and `ASK` values plus the small `NORMAL`/`CONTAINED` session state and contextual evaluation seam. Evaluation receives resource trust and monotonic session-local exposure facts, but those facts cannot make a forbidden operation approvable or a base decision more permissive. The implemented Shadow Home evaluator remains automatic. A contained network context always evaluates to `DENY`; invalid context fails closed.
- **Approval:** owns one in-memory controller per run. It serializes decisions, consumes `ALLOW_ONCE` once, and keys `ALLOW_SESSION` by exact scheme/host/port/method. The terminal multiplexer is Ghost's single stdin reader while a prompt is active. Missing interaction, timeout, malformed response, cancellation, or broker failure is fail closed.
- **Trust context:** defines the closed `TRUSTED`/`UNTRUSTED`/`SENSITIVE`/`SHADOW` vocabulary and a small per-run context for untrusted observation, highest prompt severity, and Shadow access. It stores no content and has no independent database.
- **Prompt-Injection Guard:** before runtime launch, selects bounded agent-facing workspace text without following symlinks outside the workspace, applies named deterministic rules, and emits content-minimized findings. It does not inspect the agent's reasoning or declare unmatched content safe.
- **Security signals and events:** a signal is the validated pre-persistence representation of a security-relevant observation. It is immediately converted to the existing event model and stored in SQLite. There is no second signal database or asynchronous policy bus. `PROMPT_INJECTION_SUSPECTED` is now emitted by the integrated guard; other reserved types remain extension points.
- **Deception:** defines decoys and manifests and generates independent, session-specific material with `crypto/rand`. It never queries a host credential source.
- **Runtime:** exposes a minimal `Run` operation plus an optional fail-closed recovery capability. Docker remains the only production implementation. A shared confinement profile supplies the non-root identity, Docker's isolated PID namespace, explicit private IPC/cgroup namespaces, capability drop, `no-new-privileges`, core-dump prohibition, read-only root, and per-role PID limit to the agent and both sidecars. The result can carry access evidence for explicit Shadow resources.
- **Sentinel:** runs BusyBox `inotifyd` in a separate, constrained container and watches only the decoy files. It has no network and no access to the workspace, database, Docker socket, or host home.
- **Network policy:** normalizes and validates exact ASCII hostnames, rejects raw IPs and wildcards, and evaluates `DENY`, exact `ALLOW`, or exact configured `ASK` within the two network modes `DENY` and `ALLOWLIST`.
- **Egress gateway:** is a per-session, constrained sidecar. It validates HTTP absolute-form destinations and HTTPS `CONNECT` authorities, checks live containment state, resolves permitted/approvable hostnames, rejects prohibited IPv4 answer sets, requests host approval only where policy returned `ASK`, connects to the selected validated numeric address, and records only destination/approval metadata and decisions.
- **Storage:** persists sessions, JSON-compatible events, and decoy trigger state in SQLite. The existing `contained` column stores the typed session state's durable representation, so this refactor needs no migration. Presentation logic consumes domain values rather than database rows.
- **Provenance:** deterministically reconstructs a versioned graph from one persisted session and its events. Trust-labelled resources and derived exposure/request relationships require explicit event evidence. It is downstream of storage and has no role in policy or runtime enforcement.
- **Incidents:** deterministically groups supported untrusted-observation, prompt, decoy, containment, and network-denial evidence into concise session-local reports. Every statement retains event IDs and graph references; reconstruction is downstream of provenance and has no enforcement role.
- **GhostBench:** orchestrates controlled fixtures and actual session/runtime paths, then checks named properties against session status, events, decoys, provenance, and incidents. It neither implements a second runtime nor participates in enforcement.

## Session lifecycle

1. Load and validate `ghost.yaml`, acquire the private project run lock, and reconcile any non-terminal session left by a previous Ghost process. Recovery validates the session ID, labels, component, and exact Docker object name before removing an object; ambiguity or Docker failure aborts the new run.
2. Create a persisted session and record `SESSION_START`.
3. Inspect selected workspace instruction surfaces within fixed file, byte, entry, and line limits; persist one `UNTRUSTED` source observation per analyzed file plus any prompt finding or scan-limit evidence.
4. Record the workspace `ALLOW` and the configured network `DENY`, exact `ALLOW`, and/or exact `ASK` policy.
5. Evaluate each supported home resource as `SHADOW` or `DENY`, with the structured security context available but unable to loosen the base decision.
6. Create a private per-session synthetic home. Persist each generated decoy and record `DECOY_CREATED` plus `POLICY_SHADOW`; record `POLICY_DENY` for absent resources.
7. Record `PROCESS_START`, making command-scope exposure to the mounted selected workspace sources derivable without claiming a file read, and ask the Docker runtime to execute.
8. If decoys exist, start the sentinel and wait for a token/ack barrier proving its watches are active.
9. For an allowlist session, start the session-local approval controller when an ASK list exists, create private agent and egress networks, start the gateway, attach it to both networks, and confirm it is listening. For each request the gateway validates the exact host and fixed port, resolves and validates the complete IPv4 answer set, and either applies static `ALLOW`, obtains the exact request's approval, or denies.
10. Start the ephemeral agent container with the shared confinement profile, fixed allowlisted environment values, and the synthetic home mounted read-only at `/home/ghost`. Deny sessions use network `none`; allowlist sessions join only the internal agent network.
11. An ASK request crosses only a session-private file protocol between the constrained gateway and host broker. The broker verifies the request is within the configured ASK policy before invoking the terminal handler. The gateway records the scoped outcome and rechecks containment before connecting by the already validated numeric address. Any protocol uncertainty denies the request and fails the session where evidence is incomplete.
12. On a decoy open/access event, the sentinel first creates the containment marker and then appends evidence. Before each allow/ask decision in a containment-enabled session, the gateway sends a unique barrier token through the sentinel's ordered inotify queue, waits for its matching acknowledgement, and rechecks the marker. A missing acknowledgement denies the request. Containment always precedes approval.
13. After agent exit, flush the sentinel, stop sidecars and the approval broker, collect ordered `DECOY_ACCESS`, `APPROVAL_*`, and `NETWORK_*` evidence, and remove the per-session networks.
14. Record `PROCESS_EXIT`, terminal session status, and `SESSION_END`.

All manager-produced evidence, including trust observations and prompt findings, follows the same `Signal -> validated Event -> SQLite` path. A verified decoy access additionally creates a derived `SENSITIVE_RESOURCE_REQUESTED` event referencing that access ID. Runtime adapters return a typed security-state snapshot with their evidence. When configured containment is required, decoy-access evidence without a `CONTAINED` result fails the session rather than accepting contradictory state.

The BusyBox sidecars report whole-second Unix timestamps. Before persistence, the manager clamps a valid sidecar timestamp that predates `PROCESS_START` to the process-start time; the runtime sequence and stable event IDs then preserve ordering among observations sharing that timestamp. This prevents clock precision from presenting in-container activity before the process while retaining the sidecars' actual time resolution.

Failures after session creation still transition the session to `failed` and leave an event trail. Final-state persistence uses a short context detached from command cancellation, so an interrupted agent does not normally leave its session marked `running`. The runtime verifies that an allowlist gateway is still running before accepting an otherwise completed run. If Ghost itself terminates before finalization, the next run removes only positively identified resources for that recorded session, retains its containment flag, marks it `failed`, and adds a recovery `SESSION_END`. Docker, sentinel, network, gateway, or recovery failure never invokes the command on the host.

## Security-state authority and handoff

Ghost has one logical session security state: `NORMAL` or `CONTAINED`. The only permitted escalation is `NORMAL -> CONTAINED`; de-escalation within a session is rejected.

During Docker execution, the session-private containment marker is the live enforcement authority shared by the sentinel and gateway. Publishing that marker precedes access evidence, and the gateway fences its decision through the sentinel queue before allowing a request. At runtime completion, the adapter converts the marker into the typed state returned with evidence. The session manager validates that snapshot, applies the monotonic transition, and persists it in the existing SQLite containment column. After execution or recovery, SQLite is the durable authority.

These are lifecycle representations of the same state, not independently mutable policy stores. Ghost does not claim to revoke traffic that was already established before containment. See [security signals and state](security-signals.md).

## Sentinel readiness and evidence ordering

Decoys are fully written before `inotifyd` starts, avoiding initialization events. The sentinel watches a private barrier-request directory and the explicit decoy files in one inotify instance. Ghost creates unique request tokens until the sentinel creates a matching acknowledgement. Because `inotifyd` installs all requested watches before its event loop handles that request event, the agent starts only after monitoring is ready.

BusyBox `inotifyd` waits for each handler to finish before dispatching the next queued event. The same token/ack barrier is therefore also an enforcement fence: a decoy event already queued before a gateway check publishes `contained` before that check is acknowledged. After the agent container exits, Ghost signals another barrier so prior access records are visible before evidence collection. Ghost recognizes only exact manifest paths and de-duplicates repeated open/access notifications.

The agent receives neither handler nor the observation directory, so it cannot write Ghost's evidence through a mounted path. Sentinel and gateway append small structured records to one session-private log so their relative order is preserved. The retained raw log aids diagnosis; SQLite remains the stable inspection interface.

## Synthetic-home layout

```text
.ghost/sessions/<session-id>/
├── shadow-home/
│   ├── .aws/credentials
│   ├── .ssh/id_rsa
│   └── .env
├── sentinel-handler
├── observation/
│   ├── barrier-requests/
│   ├── barrier-acks/
│   ├── events.jsonl
│   ├── approval-requests/
│   ├── approval-responses/
│   └── contained
└── network/
    ├── gateway-handler
    ├── allowlist
    └── asklist
```

Only `shadow-home` is mounted in the agent container. When policy is `deny` or deception is disabled, that directory exists but contains no protected resources. Session material is retained locally so inspection can explain the run; it is excluded from Git.

## Why Docker first

Docker provides a mature, widely available isolation primitive and lets Ghost make launch controls explicit without prematurely implementing a platform-specific kernel sandbox. Alpine also provides the small BusyBox `inotifyd` primitive needed for explicit file observation, avoiding another runtime or a broad tracing framework.

Docker is not treated as a perfect boundary. Ghost inherits the isolation properties and vulnerabilities of the Docker engine, host kernel, selected image, bind-mount configuration, and invoking local user.

## Storage evolution

Schema changes use numbered transactions in `schema_migrations`:

- migration 1: `sessions` and extensible `events`;
- migration 2: `decoys`, with a foreign key to `sessions`, unique session/path identity, marker provenance, and first-trigger timestamps.
- migration 3: per-session `network_mode` and `contained` state with safe defaults for old rows.

Opening an earlier schema-version-1 database applies later migrations without recreating existing tables or deleting history. Future incidents or policy snapshots can receive dedicated migrations when their behavior requires them.

No schema migration is required for recovery. Non-terminal `created`/`running` rows are the durable recovery journal; terminal recovery preserves the recorded containment bit and adds evidence through the existing event schema.

Security signals, trust context, approval evidence, typed session state, provenance graphs, incident reports, and benchmark results require no database migration. Trust observations, ASK policy, and approval outcomes become existing event rows immediately; live approval grants are intentionally session-local and nonpersistent. Typed containment state uses the existing column, graphs and incidents are rebuilt from SQLite evidence, and benchmark reports refer to controlled-run artifacts without becoming a second truth source.

## Build and release inputs

All Ghost-owned Docker roles and benchmark fixtures use the same human-readable Alpine patch tag plus immutable multi-platform index digest. The Go module graph remains defined by `go.mod` and authenticated by `go.sum`; CI runs both module verification and a tidy-diff check. CI and the release workflow pin their two reusable GitHub Actions to full commit SHAs and request read-only repository contents except for the narrowly scoped release-creation step.

Release artifacts are Linux amd64/arm64 binaries built with `CGO_ENABLED=0`, `-trimpath`, a requested semantic version, deterministic names, and a `SHA256SUMS` manifest. The release workflow can be dispatched manually or by a `release/vX.Y.Z` branch whose commit must exactly match the current `main`. It reruns unit, race, Docker integration, and strict GhostBench checks, then creates or verifies an annotated tag for that exact commit before publishing. These controls improve input and artifact integrity; they are not reproducible-build proof or cryptographic publisher identity.
