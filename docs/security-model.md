# Security model

Ghost v0.1 is an experimental local wrapper around an explicitly constrained Docker execution. Its guarantees are conditional on the command being launched through Ghost and on Docker and the host operating as intended.

## Current guarantees

For `ghost run -- <command>` with a valid v0.1 configuration, Ghost constructs a Docker invocation with these properties:

- The current project is mounted at `/workspace`, read-write by default or read-only when configured.
- A workspace that contains the user's whole home directory or a known active Docker socket is rejected.
- The container working directory is `/workspace`.
- The host home directory is not mounted by Ghost.
- The Docker socket is not mounted by Ghost.
- `.ghost` is masked by an in-container `tmpfs`, so the host database and session directory are not visible at their workspace path.
- Networking uses Docker's `none` network mode.
- The container is ephemeral and removed after execution.
- The root filesystem is read-only, with a bounded writable `tmpfs` at `/tmp`.
- All Linux capabilities are dropped and `no-new-privileges` is enabled.
- Privileged mode and host networking are never requested.
- Command arguments are passed directly to Docker without joining them into a shell command.
- If the Docker CLI or daemon is unavailable, Ghost fails and records the failed session. It never runs the requested command on the host as a fallback.

The container uses the invoking user's numeric UID and GID when they are available from the host. This avoids creating root-owned workspace files in typical Unix environments. It does not create an identity or authorization boundary by itself.

## Persistence and evidence

SQLite stores sessions and lifecycle events locally under `.ghost/ghost.db`. Migrations run transactionally. Event ordering is `timestamp_ns` followed by the stable autoincrement event ID; newest-session selection uses creation time followed by insertion sequence.

Ghost currently observes its own session and process lifecycle only. It does not observe individual file reads, writes, subprocess system calls, network attempts, or prompt content. No such events are claimed or synthesized.

## Policy outcomes

`ALLOW`, `DENY`, and `SHADOW` are canonical serialized domain values. In v0.1, fixed configuration validation and Docker launch constraints provide the implemented exposure policy. A general resource policy engine and actual synthetic `SHADOW` resources do not yet exist.

## Dependency boundary

Docker supplies the isolation boundary; Ghost does not strengthen Docker against runtime or kernel vulnerabilities. Anyone evaluating Ghost must also evaluate Docker daemon configuration, image provenance, host kernel security, and local user permissions. Access to a Docker daemon is itself security-sensitive on many installations.

The Alpine base image contains only basic utilities. A missing command fails clearly and is not executed elsewhere.

## Important limitations

- Read-write mode deliberately permits an untrusted process to alter project files.
- Docker may pull the base image through the daemon before execution; network isolation applies to the guest container, not image acquisition by the daemon.
- CPU, memory, storage, and wall-clock limits are not yet configurable.
- The base image is currently fixed by the implementation.
- There is no deception, honeytoken, proxy, or content-inspection behavior yet.
- There is no authentication, cloud service, telemetry, or remote policy source.

Ghost v0.1 should not be treated as a complete defense against hostile code or as a replacement for hardened sandbox infrastructure.
