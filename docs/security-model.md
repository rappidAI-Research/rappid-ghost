# Security model

Ghost v0.2 is an experimental, local security runtime. Its guarantees apply only to commands launched through `ghost run` and depend on Docker and the host behaving as configured.

## Three separate properties

### Isolation

Isolation prevents Ghost from exposing a real host resource. The agent receives the project workspace and a session-specific synthetic home. Ghost does not mount or inspect the host home, Docker socket, or SQLite database. A protected home resource remains absent even when deception is disabled.

### Deception

Deception provides a controlled synthetic alternative. With `policy.home: shadow`, enabled known-sensitive paths receive fresh Ghost-generated content. AWS-like values contain Ghost prefixes, the SSH file is deliberately nonfunctional, and `.env` values use non-real Ghost forms. Generation uses `crypto/rand` and never consults a real credential source. The opaque marker provides provenance, not an authentication secret or security boundary.

### Detection

Detection records evidence that a synthetic resource received a Linux inotify open/access event after the watcher readiness barrier. It does not infer access from session start, exit status, modification time, or access-time metadata. It does not claim that the data was understood, copied, transmitted, or used successfully.

## Docker launch guarantees requested by Ghost

The agent container has:

- `/workspace` as its working directory and configured project mount;
- a read-only synthetic-home bind mount at `/home/ghost`;
- `HOME=/home/ghost` and an explicit standard `PATH`;
- no wholesale host environment inheritance;
- Docker network mode `none`;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- a read-only root filesystem and bounded writable `/tmp` tmpfs;
- a PID limit;
- `.ghost` masked by a private tmpfs at its workspace path;
- no privileged mode, host networking, host home, or Docker socket; and
- direct argv forwarding without an implicit shell or host fallback.

The invoking numeric UID/GID is used when available. In the normal non-root developer workflow, this runs the agent as that unprivileged account and avoids root-owned workspace artifacts. If Ghost itself is invoked as host root, the current implementation uses UID 0 in the container; capabilities and privilege escalation remain disabled, but this is a known hardening limitation.

## Sentinel boundary

The sentinel is a separate per-session Alpine container. It receives only:

- the synthetic home, read-only; and
- a private session sentinel directory for its handler, barrier file, and structured event log.

It receives no network, workspace, database, Docker socket, host home, or Linux capabilities. The agent does not receive the sentinel directory. Ghost will not start the agent until a barrier confirms the watch set is active, and it will fail the session rather than run unmonitored when sentinel startup fails.

Creation cannot trigger a decoy because all decoy files are closed before the watcher exists. A final barrier after agent exit orders queued open/access records before evidence collection. Repeated events for the same manifest path become one first-trigger record in SQLite.

## Guest environment

Ghost provides exactly these variables through Docker arguments:

```text
HOME=/home/ghost
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Docker does not inherit the launching process environment unless variables are explicitly supplied. Ghost does not supply AWS, model-provider, GitHub, SSH-agent, database, or other host secret variables.

## Persistence and evidence

SQLite stores session lifecycle, JSON-compatible events, decoy identity, type, guest path, opaque marker, creation time, and first-trigger state. It does not store decoy contents or any real credential. Migrations are transactional and idempotent. Events order by nanosecond timestamp and stable row ID.

Session directories retain the synthetic home and sentinel log locally for auditability. They use private directory permissions and are not mounted into later sessions. Normal cleanup forcibly removes the ephemeral sentinel container; a hard host or Ghost process crash can leave a labeled sentinel container requiring operator cleanup.

## Dependency boundary and limitations

Docker supplies the isolation boundary; Ghost does not protect against a compromised daemon, image, kernel, or container escape. Docker may pull Alpine through the daemon before execution, while the guest itself remains network-disabled.

Other important limitations:

- Shadow Home covers exactly three known paths, not arbitrary filesystem virtualization.
- Inotify evidence is file-event evidence, not semantic intent, process attribution, provenance, or exfiltration proof.
- Read-write workspace mode intentionally permits modification of project files.
- The base image and resource limits are not yet configurable beyond the implemented flags.
- A hard crash may leave a labeled sentinel container, although it has no network and restricted mounts.
- There is no LLM detection, MCP handling, network interception, telemetry, or remote policy source.

Ghost v0.2 should not be treated as complete protection against hostile code or as a replacement for a hardened sandbox.
