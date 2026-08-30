# Architecture

Ghost v0.2 is a local command-line application with small package boundaries and deterministic resource policy.

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
                      /              \
              inotify Sentinel     Agent command
                      \              /
                      observed events
                             |
                         Event Store
                             |
                           SQLite
```

## Components

- **CLI:** validates command shape, selects the configured runtime, and presents stored results. It does not construct decoy values, SQL, or Docker arguments.
- **Config:** strictly decodes `ghost.yaml`, rejects unknown fields and unsupported values, applies safe defaults to older schema-version-1 files, and prevents destructive initialization.
- **Session manager:** owns status transitions, policy evaluation, synthetic-home preparation, runtime invocation, and conversion of runtime evidence into persistent events and incidents.
- **Policy:** defines the canonical `ALLOW`, `DENY`, and `SHADOW` values. The implemented Shadow Home evaluator returns `SHADOW` only when the home mode, deception switch, and individual resource switch all enable it; every other supported combination returns `DENY`.
- **Deception:** defines decoys and manifests and generates session-independent material with `crypto/rand`. It never queries a host credential source.
- **Runtime:** exposes one minimal `Run` operation. Docker remains the only production implementation. The result can carry access evidence for explicit Shadow resources.
- **Sentinel:** runs BusyBox `inotifyd` in a separate, constrained container and watches only the decoy files. It has no network and no access to the workspace, database, Docker socket, or host home.
- **Storage:** persists sessions, JSON-compatible events, and decoy trigger state in SQLite. Presentation logic consumes domain values rather than database rows.

## Session lifecycle

1. Load and validate `ghost.yaml`.
2. Create a persisted session and record `SESSION_START`.
3. Record the workspace `ALLOW` and network `DENY` decisions.
4. Evaluate each supported home resource as `SHADOW` or `DENY`.
5. Create a private per-session synthetic home. Persist each generated decoy and record `DECOY_CREATED` plus `POLICY_SHADOW`; record `POLICY_DENY` for absent resources.
6. Record `PROCESS_START` and ask the Docker runtime to execute.
7. If decoys exist, start the sentinel and wait for a control-file barrier proving its watches are active.
8. Start the ephemeral agent container with the synthetic home mounted read-only at `/home/ghost`.
9. After agent exit, issue a second barrier. Convert observed, exact-path open/access events into `DECOY_ACCESS`; optionally record `SECURITY_INCIDENT`.
10. Record `PROCESS_EXIT`, terminal session status, and `SESSION_END`.

Failures after session creation still transition the session to `failed` and leave an event trail. Docker or sentinel failure never invokes the command on the host.

## Sentinel readiness and evidence ordering

Decoys are fully written before `inotifyd` starts, avoiding initialization events. The sentinel watches a private control file and the explicit decoy files in one inotify instance. Ghost repeatedly modifies the control file until the sentinel emits a structured barrier record. Because `inotifyd` installs all requested watches before its event loop handles that record, the agent starts only after monitoring is ready.

After the agent container exits, Ghost signals another barrier. The handler processes inotify events serially, so access records already queued for the watched files precede the final barrier in the append-only session log. Ghost recognizes only exact manifest paths and de-duplicates repeated open/access notifications.

The agent receives neither the handler nor the control/event directory, so it cannot write Ghost's sentinel evidence through a mounted path. The retained raw log aids diagnosis; SQLite remains the stable inspection interface.

## Synthetic-home layout

```text
.ghost/sessions/<session-id>/
├── shadow-home/
│   ├── .aws/credentials
│   ├── .ssh/id_rsa
│   └── .env
└── sentinel/
    ├── handler
    ├── control
    └── events.jsonl
```

Only `shadow-home` is mounted in the agent container. When policy is `deny` or deception is disabled, that directory exists but contains no protected resources. Session material is retained locally so inspection can explain the run; it is excluded from Git.

## Why Docker first

Docker provides a mature, widely available isolation primitive and lets Ghost make launch controls explicit without prematurely implementing a platform-specific kernel sandbox. Alpine also provides the small BusyBox `inotifyd` primitive needed for explicit file observation, avoiding another runtime or a broad tracing framework.

Docker is not treated as a perfect boundary. Ghost inherits the isolation properties and vulnerabilities of the Docker engine, host kernel, selected image, bind-mount configuration, and invoking local user.

## Storage evolution

Schema changes use numbered transactions in `schema_migrations`:

- migration 1: `sessions` and extensible `events`;
- migration 2: `decoys`, with a foreign key to `sessions`, unique session/path identity, marker provenance, and first-trigger timestamps.

Opening a v0.1 database applies migration 2 without recreating existing tables or deleting history. Future incidents or policy snapshots can receive dedicated migrations when their behavior requires them.
