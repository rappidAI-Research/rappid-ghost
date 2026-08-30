# Security model

Ghost v0.3 is an experimental, local security runtime. Its guarantees apply only to commands launched through `ghost run` and depend on Docker and the host behaving as configured.

## Four separate properties

### Isolation

Isolation prevents Ghost from exposing a real host resource. The agent receives the project workspace and a session-specific synthetic home. Ghost does not mount or inspect the host home, Docker socket, or SQLite database. A protected home resource remains absent even when deception is disabled.

### Deception

Deception provides a controlled synthetic alternative. With `policy.home: shadow`, enabled known-sensitive paths receive fresh Ghost-generated content. AWS-like values contain Ghost prefixes, the SSH file is deliberately nonfunctional, and `.env` values use non-real Ghost forms. Generation uses `crypto/rand` and never consults a real credential source. The opaque marker provides provenance, not an authentication secret or security boundary.

### Detection

Detection records evidence that a synthetic resource received a Linux inotify open/access event after the watcher readiness barrier. It does not infer access from session start, exit status, modification time, or access-time metadata. It does not claim that the data was understood, copied, transmitted, or used successfully.

### Network restriction

Network restriction either gives the agent no network or limits HTTP/HTTPS destinations through a session-specific gateway. It is enforced by Docker topology plus exact-hostname gateway policy, not by trusting proxy environment variables. It does not inspect encrypted content or prove that restricted egress prevents every side channel.

## Docker launch guarantees requested by Ghost

The agent container has:

- `/workspace` as its working directory and configured project mount;
- a read-only synthetic-home bind mount at `/home/ghost`;
- `HOME=/home/ghost` and an explicit standard `PATH`;
- no wholesale host environment inheritance;
- Docker network mode `none` for deny sessions, or only a per-session `--internal` network for allowlist sessions;
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

## Gateway boundary

The gateway is a separate per-session Alpine container attached to the internal agent network and a distinct egress network. It receives a read-only handler and normalized allowlist plus the small observation directory needed to read containment state and append network decisions. It has no workspace, synthetic home, host home, database, Docker socket, host environment, published host port, or Linux capabilities.

The gateway supports HTTP proxy requests on port 80 and HTTPS `CONNECT` to port 443. It does not perform TLS interception. The agent's DNS points to an unused loopback resolver; the gateway resolves only an exact hostname already approved by policy. See [network security](network-security.md) for matching, failure behavior, containment ordering, and limitations.

## Guest environment

Ghost provides exactly these variables through Docker arguments:

```text
HOME=/home/ghost
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Allowlist sessions additionally receive uppercase and lowercase HTTP/HTTPS proxy variables containing a session-private gateway IP and empty `NO_PROXY` values. Those variables are not the enforcement boundary; direct traffic still lacks an external route.

Docker does not inherit the launching process environment unless variables are explicitly supplied. Ghost does not supply AWS, model-provider, GitHub, SSH-agent, database, or other host secret variables.

## Persistence and evidence

SQLite stores session lifecycle, network mode, containment state, JSON-compatible events, decoy identity, type, guest path, opaque marker, creation time, and first-trigger state. Network events contain destination metadata and decisions, never headers, cookies, proxy credentials, bodies, URL paths, query strings, or tunneled bytes. SQLite does not store decoy contents or any real credential. Migrations are transactional and idempotent.

Session directories retain the synthetic home and structured observation log locally for auditability. They use private directory permissions and are not mounted into later sessions. Normal cleanup forcibly removes the agent and sidecars plus both temporary networks. A hard host, daemon, or Ghost process crash can leave labeled Docker objects requiring operator cleanup.

## Dependency boundary and limitations

Docker supplies the isolation boundary; Ghost does not protect against a compromised daemon, image, kernel, or container escape. Docker may pull Alpine through the daemon before execution. A deny guest remains network-disabled; an allowlist guest receives only the internal gateway path described above.

Other important limitations:

- Shadow Home covers exactly three known paths, not arbitrary filesystem virtualization.
- Inotify evidence is file-event evidence, not semantic intent, process attribution, provenance, or exfiltration proof.
- Read-write workspace mode intentionally permits modification of project files.
- The base image and resource limits are not yet configurable beyond the implemented flags.
- A hard crash may leave labeled agent, gateway, sentinel, or network objects.
- DNS rebinding, approved-host relays, content inspection, and information-flow proof are not implemented.
- Only HTTP port 80 and HTTPS `CONNECT` port 443 are supported; arbitrary TCP and UDP remain denied.
- There is no LLM detection, MCP handling, TLS interception, telemetry, or remote policy source.

Ghost v0.3 should not be treated as complete protection against hostile code, guaranteed exfiltration prevention, or a replacement for a hardened sandbox.
