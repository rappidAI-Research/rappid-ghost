# Architecture

Ghost v0.1 is a local command-line application with deliberately small package boundaries.

```text
CLI
  -> Config
  -> Session Manager
  -> Runtime interface
  -> Docker runtime
  -> Event Store
  -> SQLite
```

## Components

- **CLI:** validates command shape, finds the current project, selects the configured runtime, and presents results. It does not contain database queries or Docker argument construction.
- **Config:** strictly decodes `ghost.yaml`, rejects unknown fields and unsupported values, and prevents destructive initialization.
- **Session manager:** owns the lifecycle from `created` through `running` to `completed` or `failed`. It records events before and after isolated execution.
- **Runtime:** exposes one minimal `Run` operation. Docker is the only implementation, but session logic does not depend on Docker command details.
- **Event store:** persists sessions and JSON-compatible event metadata in SQLite. Integer nanosecond timestamps and stable row IDs give deterministic ordering.
- **Policy types:** define the canonical `ALLOW`, `DENY`, and `SHADOW` outcomes. The v0.1 runtime enforces its fixed exposure rules directly; a general policy evaluator is a later milestone.

## Execution lifecycle

1. Load and validate `ghost.yaml`.
2. Create a persisted session with status `created`.
3. record `SESSION_START`, set status `running`, and record `PROCESS_START`.
4. Verify Docker and run an ephemeral container.
5. Record `PROCESS_EXIT` when a container process started.
6. Persist the terminal session status and record `SESSION_END`.

A Docker availability failure still leaves a failed session and event trail. Ghost never substitutes host execution.

## Why Docker first

Docker provides a mature, widely available isolation primitive and lets Ghost establish its control flow without prematurely building a kernel sandbox. It also makes security-relevant launch options explicit and testable.

Docker is not treated as a perfect security boundary. Ghost inherits the isolation properties and vulnerabilities of the local Docker engine, host kernel, container image, and configuration. A custom sandbox would add substantial platform-specific attack surface before the policy and evidence model is proven.

## Storage evolution

Schema changes are versioned in `schema_migrations`. The current schema contains only `sessions` and `events`. Later milestones can add decoys, incidents, and policies without overloading the event table or changing the event taxonomy for every new event type.
