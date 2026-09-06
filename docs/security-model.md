# Security model

Ghost v0.1 is an experimental, local security runtime. Its guarantees apply only to commands launched through `ghost run` and depend on Docker and the host behaving as configured.

## Seven separate properties

### Isolation

Isolation prevents Ghost from exposing a real host resource. The agent receives the project workspace and a session-specific synthetic home. Ghost does not mount or inspect the host home, Docker socket, or SQLite database. A protected home resource remains absent even when deception is disabled.

### Deception

Deception provides a controlled synthetic alternative. With `policy.home: shadow`, enabled known-sensitive paths receive fresh Ghost-generated content. AWS-like values contain Ghost prefixes, the SSH file is deliberately nonfunctional, and `.env` values use non-real Ghost forms. Generation uses `crypto/rand` and never consults a real credential source. The opaque marker provides provenance, not an authentication secret or security boundary.

### Detection

Detection records evidence that a synthetic resource received a Linux inotify open/access event after the watcher readiness barrier. It does not infer access from session start, exit status, modification time, or access-time metadata. It does not claim that the data was understood, copied, transmitted, or used successfully.

### Network restriction

Network restriction either gives the agent no network or limits HTTP/HTTPS destinations through a session-specific gateway. It is enforced by Docker topology, exact-hostname policy, and resolved IPv4 address validation, not by trusting proxy environment variables. It does not inspect encrypted content or prove that restricted egress prevents every side channel.

### Provenance reconstruction

Provenance is a read-only interpretation of stored session events. Observed edges link directly to supporting event IDs; derived edges represent temporal order. The builder cannot alter policy, containment, decoy state, sessions, or events. It is not part of the security boundary and does not establish causality, intent, semantic influence, or data flow.

### Incident reconstruction

Incident reconstruction is a second read-only interpretation over the same evidence and provenance graph. It groups repeated access evidence for one decoy, attaches supported containment evidence, and can attach later denied network requests in that contained session. Each timeline statement cites event IDs. The grouping is deterministic, but temporal association is not causal attribution and does not prove that decoy content entered a request.

### Benchmark validation

GhostBench executes controlled scenarios through the production session manager and Docker runtime, then evaluates explicit assertions against the resulting evidence. `PASS` means every assertion for that named scenario was observed. `FAIL` means a required assertion failed or a runnable environment failed unexpectedly. `SKIP` means the required environment, currently Docker, was unavailable and the property was not tested. A result is not a proof beyond its stated fixture, topology, platform, and execution.

## Docker launch guarantees requested by Ghost

The agent container has:

- `/workspace` as its working directory and configured project mount;
- a read-only synthetic-home bind mount at `/home/ghost`;
- `HOME=/home/ghost` and an explicit standard `PATH`;
- no wholesale host environment inheritance;
- Docker network mode `none` for deny sessions, or only a per-session `--internal` network for allowlist sessions;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- Docker's isolated PID namespace and explicit private IPC and cgroup namespaces;
- a read-only root filesystem and bounded writable `/tmp` tmpfs;
- a PID limit;
- core dumps disabled with a zero soft and hard `core` ulimit;
- `.ghost` masked by a bounded, private tmpfs at its workspace path;
- `ghost.yaml` over-mounted read-only so a writable guest cannot weaken policy for a later session;
- no privileged mode, host networking, host home, or Docker socket; and
- direct argv forwarding without an implicit shell or host fallback.

The invoking numeric UID/GID is used for the agent and sidecars. Ghost refuses Docker execution when either host ID is root or either ID cannot be represented numerically. This keeps the guest unprivileged and avoids root-owned workspace artifacts; it also means native Windows identities are not currently supported.

Ghost does not pass `--userns=host`, but Docker exposes no per-container option that creates a new user namespace; its only explicit `--userns` value disables daemon-level remapping. A distinct user namespace therefore requires a rootless Docker daemon or daemon-wide `userns-remap`. Ghost preserves either deployment mode and documents the absence of it as part of the Docker trusted-computing-base limitation rather than pretending to enforce it from the container command.

Ghost adds no host devices or device requests. Standard virtual devices supplied by the OCI runtime, such as null, zero, random, and terminal devices, remain available because basic command execution requires them. The Docker daemon and its default seccomp/device policy remain trusted.

## Sentinel boundary

The sentinel is a separate per-session Alpine container. It receives only:

- the synthetic home, read-only; and
- a private session sentinel directory for its handler, barrier file, and structured event log.

It receives no network, workspace, database, Docker socket, host home, or Linux capabilities. The agent does not receive the sentinel directory. Ghost will not start the agent until a token-specific acknowledgement confirms the watch set is active, and it will fail the session rather than run unmonitored when sentinel startup fails.

The observation directory is the sentinel's only writable host bind. It is required to append access/barrier evidence and create the containment marker. Its root filesystem and synthetic-home mount remain read-only.

Creation cannot trigger a decoy because all decoy files are closed before the watcher exists. On access, containment state is published before evidence. A final token/ack barrier after agent exit orders queued open/access records before evidence collection. Repeated events for the same manifest path become one first-trigger record in SQLite.

## Gateway boundary

The gateway is a separate per-session Alpine container attached to the internal agent network and a distinct egress network. It receives a read-only handler and normalized allowlist plus the small observation directory needed to read containment state and append network decisions. It has no workspace, synthetic home, host home, database, Docker socket, host environment, published host port, or Linux capabilities.

The gateway's writable paths are a bounded `/tmp` tmpfs, used for its request FIFO, and the observation bind required for network evidence and containment state. Other image paths are read-only.

The gateway supports HTTP proxy requests on port 80 and HTTPS `CONNECT` to port 443. It does not perform TLS interception. The agent's DNS points to an unused loopback resolver. For each exact hostname already approved by policy, the gateway performs one A-record lookup, validates every answer, and connects to a validated numeric IPv4 address. Resolution and validation failure deny the request; IPv6 upstream egress is currently unsupported and therefore fail-closed. See [network security](network-security.md) for matching, prohibited ranges, containment ordering, and limitations.

## Guest environment

The agent receives exactly these base variables through Ghost's Docker arguments:

```text
HOME=/home/ghost
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Allowlist sessions additionally receive uppercase and lowercase HTTP/HTTPS proxy variables containing a session-private gateway IP and empty `NO_PROXY` values. Those variables are not the enforcement boundary; direct traffic still lacks an external route. The sentinel receives fixed `HOME` and `PATH`; the gateway receives only fixed `PATH`.

Docker does not inherit the launching process environment unless variables are explicitly supplied. Ghost uses no name-based secret filter: it never iterates or forwards `os.Environ`. Known credentials, arbitrary custom secrets, locale values, and terminal settings are all excluded by default. Docker, the selected image, and an invoked shell may synthesize container-local values such as `HOSTNAME`, `PWD`, or `SHLVL`; those are not copied from the host.

## Persistence and evidence

SQLite stores session lifecycle, network mode, containment state, JSON-compatible events, decoy identity, type, guest path, opaque marker, creation time, and first-trigger state. The database and its parent runtime directory are secured before SQLite opens them; symlinked database/configuration paths are rejected. Network events contain destination metadata and decisions, never headers, cookies, proxy credentials, bodies, URL paths, query strings, or tunneled bytes. SQLite does not store decoy contents or read credentials from a host credential source. Migrations are transactional and idempotent.

Ghost does persist the requested command and argument vector as session evidence. Secrets supplied directly as command-line arguments can therefore enter local session storage; callers should pass such values through a future explicit secret-injection mechanism rather than argv. Ghost does not currently provide that mechanism.

The provenance and incident JSON exports deliberately exclude the session argument vector, arbitrary event metadata, raw decoy IDs and markers, headers, bodies, cookies, and credential material. They include only minimal session fields, normalized labels, relationships or summaries, and evidence IDs/timestamps. This limits export exposure but does not sanitize the underlying SQLite database.

Session directories retain the synthetic home and structured observation log locally for auditability. They use private directory permissions and are not mounted into later sessions. Normal cleanup forcibly removes the agent and sidecars plus both temporary networks. A per-project advisory lock prevents concurrent `ghost run` processes from confusing live and interrupted state. After a Ghost process crash, the next run queries durable non-terminal session rows and removes only Docker objects whose session label, component label, and exact expected name agree. It then preserves any containment bit, marks the interrupted session `failed`, and records a recovery `SESSION_END`. Ambiguous ownership, unavailable Docker, or cleanup failure aborts the new run. A host or daemon crash can still leave objects until such a recovery succeeds.

## Dependency boundary and limitations

Docker supplies the isolation boundary; Ghost does not protect against a compromised daemon, image, kernel, or container escape. Docker may pull the source-pinned Alpine image through the daemon before execution. A deny guest remains network-disabled; an allowlist guest receives only the internal gateway path described above.

The runtime and benchmark containers use `alpine:3.22.5` together with an immutable multi-platform image-index digest. CI actions are pinned to reviewed commit SHAs and workflow permissions default to read-only. CI also verifies `go.sum`, rejects a `go mod tidy` diff, and builds checksummed release-shaped artifacts. The manual release job grants `contents: write` only while creating a release from an already existing annotated tag whose commit matches the checkout.

Other important limitations:

- Shadow Home covers exactly three known paths, not arbitrary filesystem virtualization.
- Inotify evidence is file-event evidence, not semantic intent, exact process attribution, data flow, or exfiltration proof.
- The provenance process node represents the recorded command scope. Current instrumentation does not provide reliable guest PID, parent/child identity, or exact process attribution for file/network events.
- Arbitrary workspace reads are not observed, so no workspace `READ` edge is generated from current evidence.
- Incident grouping is session-local and temporal; it does not establish motive, causal influence, or semantic data flow.
- Read-write workspace mode intentionally permits modification of project files.
- The base image and resource limits are not yet configurable beyond the implemented flags.
- Image and action digests prevent silent tag movement but do not prove upstream source integrity, image freedom from vulnerabilities, or runner integrity. Ghost does not yet publish signatures, provenance attestations, or an SBOM.
- A hard crash may leave labeled agent, gateway, sentinel, or network objects until the next successful project recovery; Ghost neither scans nor deletes objects it cannot tie to an incomplete session in that project's database.
- Ghost serializes `ghost run` within one project so a live session is never recovered as interrupted. Separate projects and their session state remain independent.
- A separate user namespace depends on rootless Docker or daemon-level `userns-remap`; Ghost cannot enable one per container without changing daemon configuration.
- The OCI runtime's standard virtual devices and Docker's default seccomp/device policy remain part of the trusted computing base.
- DNS changes between separate requests, approved-host relays, content inspection, DNSSEC validation, and information-flow proof are not prevented.
- IPv6 upstream egress is not implemented; IPv6-only destinations are denied.
- Only HTTP port 80 and HTTPS `CONNECT` port 443 are supported; arbitrary TCP and UDP remain denied.
- There is no LLM detection, MCP handling, TLS interception, telemetry, or remote policy source.

Ghost v0.1 should not be treated as complete protection against hostile code, guaranteed exfiltration prevention, or a replacement for a hardened sandbox. GhostBench validates only its documented scenarios; it does not prove Docker, Ghost, or autonomous agents generally secure.
