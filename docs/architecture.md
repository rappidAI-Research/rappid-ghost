# Architecture

Ghost v0.1 is a local command-line application with small package boundaries, deterministic filesystem and network policy, read-only provenance and incident views over stored evidence, and an evidence-backed benchmark orchestrator.

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
- **Session manager:** owns status transitions, policy evaluation, synthetic-home preparation, runtime invocation, and conversion of runtime evidence into persistent events. Incidents are reconstructed later and are not separately persisted.
- **Policy:** defines the canonical `ALLOW`, `DENY`, and `SHADOW` values. The implemented Shadow Home evaluator returns `SHADOW` only when the home mode, deception switch, and individual resource switch all enable it; every other supported combination returns `DENY`.
- **Deception:** defines decoys and manifests and generates session-independent material with `crypto/rand`. It never queries a host credential source.
- **Runtime:** exposes one minimal `Run` operation. Docker remains the only production implementation. The result can carry access evidence for explicit Shadow resources.
- **Sentinel:** runs BusyBox `inotifyd` in a separate, constrained container and watches only the decoy files. It has no network and no access to the workspace, database, Docker socket, or host home.
- **Network policy:** normalizes and validates exact ASCII hostnames, rejects raw IPs and wildcards, and evaluates the two implemented modes: `DENY` and `ALLOWLIST`.
- **Egress gateway:** is a per-session, constrained sidecar. It validates HTTP absolute-form destinations and HTTPS `CONNECT` authorities, checks live containment state, and records only destination metadata and decisions.
- **Storage:** persists sessions, JSON-compatible events, and decoy trigger state in SQLite. Presentation logic consumes domain values rather than database rows.
- **Provenance:** deterministically reconstructs a versioned graph from one persisted session and its events. It is downstream of storage and has no role in policy or runtime enforcement.
- **Incidents:** deterministically groups supported decoy, containment, and network-denial evidence into concise session-local reports. Every statement retains event IDs and graph references; reconstruction is downstream of provenance and has no enforcement role.
- **GhostBench:** orchestrates controlled fixtures and actual session/runtime paths, then checks named properties against session status, events, decoys, provenance, and incidents. It neither implements a second runtime nor participates in enforcement.

## Session lifecycle

1. Load and validate `ghost.yaml`.
2. Create a persisted session and record `SESSION_START`.
3. Record the workspace `ALLOW` and the configured network `DENY` or exact `ALLOWLIST` policy.
4. Evaluate each supported home resource as `SHADOW` or `DENY`.
5. Create a private per-session synthetic home. Persist each generated decoy and record `DECOY_CREATED` plus `POLICY_SHADOW`; record `POLICY_DENY` for absent resources.
6. Record `PROCESS_START` and ask the Docker runtime to execute.
7. If decoys exist, start the sentinel and wait for a control-file barrier proving its watches are active.
8. For an allowlist session, create private agent and egress networks, start the gateway, attach it to both networks, and confirm it is listening.
9. Start the ephemeral agent container with the synthetic home mounted read-only at `/home/ghost`. Deny sessions use network `none`; allowlist sessions join only the internal agent network.
10. A decoy access is appended to the ordered observation log. When configured, the sentinel immediately creates the containment marker checked by every gateway request.
11. After agent exit, flush the sentinel, stop sidecars, collect ordered `DECOY_ACCESS` and `NETWORK_*` evidence, and remove the per-session networks.
12. Record `PROCESS_EXIT`, terminal session status, and `SESSION_END`.

Failures after session creation still transition the session to `failed` and leave an event trail. Final-state persistence uses a short context detached from command cancellation, so an interrupted agent does not normally leave its session marked `running`. Docker, sentinel, network, or gateway failure never invokes the command on the host.

## Sentinel readiness and evidence ordering

Decoys are fully written before `inotifyd` starts, avoiding initialization events. The sentinel watches a private control file and the explicit decoy files in one inotify instance. Ghost repeatedly modifies the control file until the sentinel emits a structured barrier record. Because `inotifyd` installs all requested watches before its event loop handles that record, the agent starts only after monitoring is ready.

After the agent container exits, Ghost signals another barrier. The handler processes inotify events serially, so access records already queued for the watched files precede the final barrier in the append-only session log. Ghost recognizes only exact manifest paths and de-duplicates repeated open/access notifications.

The agent receives neither handler nor the control/event directory, so it cannot write Ghost's evidence through a mounted path. Sentinel and gateway append small structured records to one session-private log so their relative order is preserved. The retained raw log aids diagnosis; SQLite remains the stable inspection interface.

## Synthetic-home layout

```text
.ghost/sessions/<session-id>/
├── shadow-home/
│   ├── .aws/credentials
│   ├── .ssh/id_rsa
│   └── .env
├── sentinel-handler
├── observation/
│   ├── control
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

Provenance graphs, incident reports, and benchmark results require no database migration. Graphs and incidents are rebuilt from SQLite evidence; benchmark reports refer to controlled-run artifacts without becoming a second truth source.
