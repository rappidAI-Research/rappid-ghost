# Architecture

Ghost is a local command-line application with small package boundaries, deterministic filesystem and network policy, read-only provenance and incident views over stored evidence, and an evidence-backed benchmark orchestrator. The current main branch adds v0.2 boundary, recovery, and supply-chain hardening over the released v0.1 architecture.

```text
                         Ghost CLI
                             |
                       configuration
                             |
                       Session Manager
                      /               \
             Policy Engine       Deception Engine
                  |               /             \
          ALLOW/DENY/SHADOW   Generator       Manifest
                      \               /
                       Docker Runtime
                  /          |          \
       inotify Sentinel   Agent command   Egress Gateway
                  \          |          /
                     ordered evidence
                             |
                         Event Store
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
- **Session manager:** owns status transitions, policy evaluation, synthetic-home preparation, runtime invocation, and conversion of runtime evidence into persistent events. A per-project process lock prevents a live session from being mistaken for interrupted recovery work. Incidents are reconstructed later and are not separately persisted.
- **Policy:** defines the canonical `ALLOW`, `DENY`, and `SHADOW` values. The implemented Shadow Home evaluator returns `SHADOW` only when the home mode, deception switch, and individual resource switch all enable it; every other supported combination returns `DENY`.
- **Deception:** defines decoys and manifests and generates session-independent material with `crypto/rand`. It never queries a host credential source.
- **Runtime:** exposes a minimal `Run` operation plus an optional fail-closed recovery capability. Docker remains the only production implementation. A shared confinement profile supplies the non-root identity, Docker's isolated PID namespace, explicit private IPC/cgroup namespaces, capability drop, `no-new-privileges`, core-dump prohibition, read-only root, and per-role PID limit to the agent and both sidecars. The result can carry access evidence for explicit Shadow resources.
- **Sentinel:** runs BusyBox `inotifyd` in a separate, constrained container and watches only the decoy files. It has no network and no access to the workspace, database, Docker socket, or host home.
- **Network policy:** normalizes and validates exact ASCII hostnames, rejects raw IPs and wildcards, and evaluates the two implemented modes: `DENY` and `ALLOWLIST`.
- **Egress gateway:** is a per-session, constrained sidecar. It validates HTTP absolute-form destinations and HTTPS `CONNECT` authorities, checks live containment state, resolves approved hostnames, rejects prohibited IPv4 answer sets, connects to the selected validated numeric address, and records only destination metadata and decisions.
- **Storage:** persists sessions, JSON-compatible events, and decoy trigger state in SQLite. Presentation logic consumes domain values rather than database rows.
- **Provenance:** deterministically reconstructs a versioned graph from one persisted session and its events. It is downstream of storage and has no role in policy or runtime enforcement.
- **Incidents:** deterministically groups supported decoy, containment, and network-denial evidence into concise session-local reports. Every statement retains event IDs and graph references; reconstruction is downstream of provenance and has no enforcement role.
- **GhostBench:** orchestrates controlled fixtures and actual session/runtime paths, then checks named properties against session status, events, decoys, provenance, and incidents. It neither implements a second runtime nor participates in enforcement.

## Session lifecycle

1. Load and validate `ghost.yaml`, acquire the private project run lock, and reconcile any non-terminal session left by a previous Ghost process. Recovery validates the session ID, labels, component, and exact Docker object name before removing an object; ambiguity or Docker failure aborts the new run.
2. Create a persisted session and record `SESSION_START`.
3. Record the workspace `ALLOW` and the configured network `DENY` or exact `ALLOWLIST` policy.
4. Evaluate each supported home resource as `SHADOW` or `DENY`.
5. Create a private per-session synthetic home. Persist each generated decoy and record `DECOY_CREATED` plus `POLICY_SHADOW`; record `POLICY_DENY` for absent resources.
6. Record `PROCESS_START` and ask the Docker runtime to execute.
7. If decoys exist, start the sentinel and wait for a token/ack barrier proving its watches are active.
8. For an allowlist session, create private agent and egress networks, start the gateway, attach it to both networks, and confirm it is listening. For each request the gateway validates the exact host and fixed port, resolves and validates the complete IPv4 answer set, then connects to a selected validated address without a second hostname lookup.
9. Start the ephemeral agent container with the shared confinement profile, fixed allowlisted environment values, and the synthetic home mounted read-only at `/home/ghost`. Deny sessions use network `none`; allowlist sessions join only the internal agent network.
10. On a decoy open/access event, the sentinel first creates the containment marker and then appends evidence. Before each allowlist decision in a containment-enabled session, the gateway sends a unique barrier token through the sentinel's ordered inotify queue, waits for its matching acknowledgement, and rechecks the marker. A missing acknowledgement denies the request.
11. After agent exit, flush the sentinel, stop sidecars, collect ordered `DECOY_ACCESS` and `NETWORK_*` evidence, and remove the per-session networks.
12. Record `PROCESS_EXIT`, terminal session status, and `SESSION_END`.

Failures after session creation still transition the session to `failed` and leave an event trail. Final-state persistence uses a short context detached from command cancellation, so an interrupted agent does not normally leave its session marked `running`. The runtime verifies that an allowlist gateway is still running before accepting an otherwise completed run. If Ghost itself terminates before finalization, the next run removes only positively identified resources for that recorded session, retains its containment flag, marks it `failed`, and adds a recovery `SESSION_END`. Docker, sentinel, network, gateway, or recovery failure never invokes the command on the host.

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
│   └── contained
└── network/
    ├── gateway-handler
    └── allowlist
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

Provenance graphs, incident reports, and benchmark results require no database migration. Graphs and incidents are rebuilt from SQLite evidence; benchmark reports refer to controlled-run artifacts without becoming a second truth source.

## Build and release inputs

All Ghost-owned Docker roles and benchmark fixtures use the same human-readable Alpine patch tag plus immutable multi-platform index digest. The Go module graph remains defined by `go.mod` and authenticated by `go.sum`; CI runs both module verification and a tidy-diff check. CI and the manual release workflow pin their two reusable GitHub Actions to full commit SHAs and request read-only repository contents except for the narrowly scoped release-creation step.

Release artifacts are Linux amd64/arm64 binaries built with `CGO_ENABLED=0`, `-trimpath`, a tag-derived version, deterministic names, and a `SHA256SUMS` manifest. Before release creation, the workflow requires an existing annotated semantic-version tag, proves that its commit is the checkout, and reruns unit, race, Docker integration, and strict GhostBench checks. These controls improve input and artifact integrity; they are not reproducible-build proof or cryptographic publisher identity.
