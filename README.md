# Ghost

> A deception-aware security runtime for autonomous AI agents.

Ghost controls what autonomous AI agents can access — and, eventually, what they believe they accessed.

Ghost v0.2.0 is the current stable release. The `main` branch is the experimental v0.3 development line. It retains the v0.2 security boundary and adds a bounded Prompt-Injection Guard, deterministic trust context, and narrow human approval inside the integrated policy pipeline. These observations enrich policy context and evidence; they are not model-based authorization or replacements for isolation. Ghost is not a general firewall, complete attack detector, or hardened replacement for Docker.

## Start in two commands

From the project you want the agent to work in:

```sh
ghost init
ghost run -- echo "hello from ghost"
```

Replace the example command with an agent command available in the runtime image. `ghost init` writes one secure default configuration without a setup wizard. On every run, Ghost automatically validates configuration, project state, Docker availability, the non-root identity, the workspace boundary, and session-owned runtime state before handing execution to Docker. It then applies workspace inspection, isolation, SHADOW, network policy, containment, approvals where explicitly configured, evidence persistence, and a short evidence-based result summary. If a mandatory boundary cannot be established, Ghost stops without launching the agent; it never falls back to host execution or weaker Docker settings.

An uneventful run ends quietly with `No security actions required.` Security-relevant runs summarize only observed actions such as suspicious instruction sources, SHADOW access, blocked network requests, approval outcomes, protection limits, or containment. Full evidence remains available through `ghost inspect`, `ghost graph`, and `ghost incidents`.

## Why SHADOW?

Traditional resource policy usually reduces to two outcomes:

- `ALLOW` — expose the permitted real resource.
- `DENY` — refuse access.

Ghost adds a third deterministic outcome:

- `SHADOW` — expose a controlled synthetic resource while the corresponding real resource remains isolated.

The v0.3 development line also supports `ASK` for explicitly configured, approvable operations. `ASK` pauses one exact operation for `ALLOW_ONCE`, exact `ALLOW_SESSION`, or `DENY`; it cannot override containment or make forbidden host/private destinations approvable. If interaction or the approval path is unavailable, `ASK` becomes `DENY`.

The distinction matters when refusal alone provides little evidence about an autonomous process's behavior. A Shadow resource can be safe to expose and observable when opened. The marker and generated values are synthetic; they are not derived from host credentials and cannot authenticate to a real service.

## Current capabilities

Current `main` can (while retaining the v0.2.0 boundary):

- initialize a project with a small, strictly validated `ghost.yaml`;
- automatically preflight the mandatory Docker, identity, workspace, policy, and session-state prerequisites without a separate diagnostic command;
- execute a command in an ephemeral Docker container;
- mount the project at `/workspace` in read-write or read-only mode;
- give each session a private synthetic home at `/home/ghost`;
- generate synthetic AWS credentials, an intentionally nonfunctional SSH private-key-shaped file, and a generic `.env` file;
- deterministically apply `SHADOW` or `DENY` to those supported home resources;
- observe open/access events for explicit decoy files with a minimal inotify sentinel;
- record `DECOY_CREATED`, `POLICY_SHADOW`, `DECOY_ACCESS`, and evidence-based `SECURITY_INCIDENT` events;
- deny networking by default or restrict HTTP/HTTPS proxy destinations to exact hostnames;
- reject local-use allowlist names and require every resolved IPv4 address to pass destination validation before the gateway connects to the selected numeric address;
- prevent proxy-variable bypass by placing the agent on a Docker `--internal` network with no direct external route;
- enforce HTTPS destinations with HTTP `CONNECT`, without TLS interception;
- record `NETWORK_REQUEST`, `NETWORK_ALLOW`, and `NETWORK_DENY` without headers or bodies;
- deterministically publish per-session network containment after a decoy access and fence subsequent allow decisions through the sentinel's ordered event queue;
- reconcile interrupted sessions and remove only positively identified Ghost-owned Docker resources before the next run in that project;
- avoid host-home, Docker-socket, and Ghost-database exposure;
- run every Ghost-owned container as the invoking numeric non-root UID/GID with all capabilities dropped, `no-new-privileges`, isolated PID/IPC/cgroup namespaces, a read-only root filesystem, disabled core dumps, and bounded process counts;
- pass a fixed allowlist of Ghost-owned environment values instead of forwarding the host environment;
- keep `ghost.yaml` read-only inside a writable guest workspace so a run cannot weaken policy for later sessions;
- persist sessions, events, and decoy state in SQLite;
- inspect the newest or a specific session;
- reconstruct a versioned session provenance graph from persisted events;
- render that graph as terminal text or stable JSON without exporting decoy contents or arbitrary event metadata;
- deterministically group related decoy, containment, and denied-network evidence into concise incidents;
- render incident reports as terminal text or versioned, secret-minimized JSON;
- automatically inspect selected workspace instruction surfaces before the container starts, recording bounded rule/category/hash evidence without document contents;
- classify selected workspace sources as `UNTRUSTED`, synthetic decoys as `SHADOW`, and protected credential-path classes as `SENSITIVE` without inspecting a real credential source;
- reconstruct derived command-scope exposure and sensitive-path-request relationships from explicit event IDs while never inventing a workspace `READ` or causal edge;
- correlate suspicious-instruction signals with later security activity as temporal, not causal, context;
- request narrow approval for exact configured HTTP/HTTPS destinations, with non-interactive, timeout, malformed-response, and broker-failure paths failing closed;
- keep `ALLOW_ONCE` consumable once and `ALLOW_SESSION` scoped to the exact scheme, hostname, port, method, and live session;
- record approval requirements and outcomes in the existing event, provenance, incident, inspection, and security-summary paths without attributing a user decision to the agent;
- summarize completed sessions from persisted evidence while keeping uneventful runs concise; and
- run twenty-one explicit GhostBench scenarios on the v0.3 development line with `PASS`, `FAIL`, or honest environment-dependent `SKIP` results and evidence references.

Ghost does **not** detect every prompt injection, observe arbitrary workspace reads, understand model intent, rescan arbitrary content created during a session, virtualize arbitrary filesystem paths, inspect TLS or request content, proxy general TCP/UDP, intercept MCP, perform byte-level taint tracking, prove causal influence or credential exfiltration, assign model-based risk, or provide a web interface. Approval does not revoke existing connections, persist into configuration, or override hard runtime boundaries. Prompt findings may be false positive or false negative. Enforcement never calls an LLM or cloud control plane.

## Requirements

- Linux with Docker Engine is the release-qualified target. Docker Desktop on macOS may work but is not currently covered by the release gate; native Windows execution is unsupported.
- Go 1.26 or newer to build from source.
- A working local Docker CLI and daemon to execute commands and run Docker-backed benchmarks.
- A non-root host account with non-zero numeric UID and GID. Ghost refuses Docker execution if either host ID is root rather than launching a guest with root identity.

The default image is `alpine:3.22.5` pinned to the immutable multi-platform index digest `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`. Docker may need to pull it once. Commands missing from that minimal image fail clearly; Ghost never falls back to host execution. Updating the image requires an explicit source change and the complete Docker/GhostBench gate.

## Build

```sh
make build
./bin/ghost version
```

Native Go commands work as well:

```sh
go build -o bin/ghost ./cmd/ghost
```

## Explore SHADOW and evidence

Initialization creates `ghost.yaml`, `.ghost/ghost.db`, and `.ghost/sessions/`. Re-running `ghost init` never overwrites an existing configuration. Commit `ghost.yaml` if it represents project policy; do not commit `.ghost/`. The v0.3 development build automatically inspects selected agent-facing workspace text during `ghost run`; suspicious content produces one concise notice and never disables deterministic controls. See the [Prompt-Injection Guard model](docs/prompt-injection-guard.md).

Exercise the first Shadow resource:

```sh
ghost run -- sh -c 'cat ~/.aws/credentials'
```

The returned file is generated by Ghost for that session. Ghost does not inspect, copy, compare, or mount the host user's AWS credentials.

Inspect the evidence:

```sh
ghost inspect latest
```

The report shows decision counts, decoys and trigger state, security incidents, and the complete event timeline. A specific session can be selected by ID:

```sh
ghost inspect 12345678-1234-4234-8234-123456789abc
```

Reconstruct observed session relationships:

```sh
ghost graph latest
ghost graph latest --json
```

The graph links nodes and edges to stored event IDs. `OBSERVED` relationships come directly from a supported event. `DERIVED` relationships combine explicit evidence: `FOLLOWED_BY` is chronology, while `EXPOSED_TO` means selected untrusted content was observed before the command scope received the workspace. Neither is a file-read or causal claim.

For example, a contained Shadow session can produce relationships equivalent to:

```text
[process] command scope: sh --ACCESSED--> [decoy] shadow:~/.aws/credentials
[session] session 91af... --CONTAINED--> [policy_decision] network containment DENY
[process] command scope: sh --REQUESTED--> [network_destination] network:example.com:443
[network_destination] network:example.com:443 --DENIED--> [policy_decision] network DENY
```

Ghost does not currently observe arbitrary workspace reads or reliable per-process PIDs. The command node covers the top-level command and children as one runtime scope, so the graph does not invent per-process propagation or `READ` relationships.

When an exact configured destination requires approval, the graph distinguishes the agent request, automatic `ASK` decision, and `USER_DECISION`. The user decision is never attributed to the agent.

Reconstruct security-relevant sequences:

```sh
ghost incidents latest
ghost incidents latest --json
```

For a contained Shadow session, Ghost may report that a synthetic resource was exposed, the command scope accessed it, containment was activated, and a later outbound request was denied. Each statement includes its supporting event IDs. “Later” describes temporal order only; it does not establish that decoy content entered the request or explain why the process acted.

## GhostBench

Run the complete local security-property suite:

```sh
ghost bench
ghost bench --json
ghost bench --require-all
```

Run one scenario:

```sh
ghost bench --scenario shadow-credentials
```

The stable v0.2.0 suite checks fifteen separately reported properties. The v0.3 development suite adds six focused cases: four prompt/trust cases plus non-interactive approval failure closure and one-use approval scope. It does not collapse these observations into an arbitrary score.

The current development gate requires all twenty-one scenarios to execute successfully: `PASS: 21`, `FAIL: 0`, `SKIP: 0`.

Docker-dependent scenarios are `SKIP`, never `PASS`, when Docker is unavailable. The fail-closed scenario remains runnable because it deliberately points the production Docker runtime at an unavailable executable and verifies that the controlled command was not executed on the host. `--require-all` is the release/CI gate: it returns nonzero for either `FAIL` or `SKIP`. See [benchmark methodology](docs/benchmarks.md).

The canonical end-to-end demonstration is:

```sh
ghost bench --scenario dynamic-containment
```

It uses a harmless HTTP fixture on a temporary local Docker network. The scenario demonstrates an allowed request, synthetic AWS credential access, containment, a later denied request, and the corresponding event/provenance/incident evidence. It does not send data to an external service or claim credential exfiltration.

The `--` separator for `run` is required and preserves command argument boundaries.

### Exit status

- `0` means Ghost securely launched the command and the command succeeded.
- `2` means the Ghost command line itself was invalid.
- `1` means configuration, preflight, recovery, runtime-security setup, or another Ghost-controlled operation failed. Ghost does not launch on a failed mandatory preflight.
- Once the isolated command runs, its non-zero exit status is propagated when no Ghost runtime failure supersedes it.

Because an agent may itself exit with `1` or `2`, scripts that need the reason should use the accompanying plain-language output and recorded session evidence. Non-interactive approval always fails closed to `DENY`; it never waits indefinitely or silently permits the request.

## Configuration

The default configuration is:

```yaml
version: 1

runtime:
  provider: docker

workspace:
  mode: read-write

network:
  mode: deny

policy:
  home: shadow

deception:
  enabled: true
  resources:
    aws_credentials: true
    ssh_private_key: true
    env_file: true

on_decoy_access:
  severity: high
  record_incident: true
  network: deny
```

`network.mode: deny` is the default. To enable limited egress, use:

```yaml
network:
  mode: allowlist
  allow:
    - github.com
    - api.github.com
```

To require an interactive decision for selected exact destinations, place them in `ask` instead of `allow`:

```yaml
network:
  mode: allowlist
  allow:
    - github.com
  ask:
    - api.example.com
```

On an interactive terminal, an `ask` request offers allow once, allow for this session, or deny. Session approval is exact to scheme, hostname, port, and HTTP method and is held only in memory for that run. Ghost never edits `ghost.yaml`. In CI, redirected/stdin-less execution, on timeout, or after malformed input, the request is denied. `ask` cannot include raw IP, local/private/metadata destinations and cannot override containment. See [human approval](docs/approvals.md).

Matching is exact after lowercase and trailing-root-dot normalization: `github.com` does not include `api.github.com`. Raw IPs, wildcard entries, HTTP ports other than 80, HTTPS `CONNECT` ports other than 443, and arbitrary TCP/UDP remain denied. The legacy `network.mode: none` spelling is accepted as `deny`, so earlier schema-version-1 configurations stay fail closed.

Single-label and local-use names such as `localhost`, `*.localhost`, `*.local`, `*.internal`, and `host.docker.internal` are rejected. After an exact hostname match, the gateway performs one IPv4 lookup, validates every returned address against prohibited loopback, private, link-local, shared, benchmark, reserved, multicast, and metadata-relevant ranges, and connects to the already validated numeric address. Resolution failure, malformed answers, mixed safe/prohibited answers, raw IPs, and IPv6-only destinations fail closed. Ghost does not claim to eliminate every form of DNS rebinding or approved-endpoint relay; see [network security](docs/network-security.md).

`policy.home: deny` creates an empty synthetic home and exposes no decoys. Likewise, `deception.enabled: false` means no decoy is exposed; it never means “mount the real home.” See [`ghost.example.yaml`](ghost.example.yaml) for comments and [network security](docs/network-security.md) for the precise boundary.

## How access detection works

For a Shadow session, Ghost creates decoy files before monitoring starts. It then launches a separate, network-disabled Alpine container running BusyBox `inotifyd` over only the explicit decoy paths. A token-specific barrier acknowledgement proves that every watch is installed before the agent container can start. After the agent exits, another ordered barrier flushes prior events before Ghost interprets the structured sentinel log.

The sentinel does not scan the workspace, read decoy contents, use a network, or share its evidence directory with the agent. File creation is complete before the watches exist, so creation is not reported as access. Detection means an inotify open/access event was observed for the decoy inode; it does not establish semantic data flow or exfiltration.

When `on_decoy_access.network: deny`, the live sentinel creates a session-private containment marker before recording access evidence. Before allowing a new request, the gateway obtains a matching acknowledgement through the same ordered inotify queue and rechecks that marker. Failure to complete the check denies the request. This does not revoke an already-established connection, and the observation “network activity occurred after a decoy access in the same session” remains an ordering fact rather than proof that decoy contents flowed into the request.

## Repository structure

```text
cmd/ghost/          CLI entry point
internal/cli/       command parsing and presentation
internal/bench/     GhostBench scenarios, evidence checks, and renderers
internal/config/    YAML schema and validation
internal/deception/ synthetic resource domain and generators
internal/events/    event domain types and taxonomy
internal/network/   exact-hostname destination policy
internal/policy/    deterministic ALLOW / DENY / SHADOW / ASK evaluation
internal/approval/  narrow interactive decisions and session-local grants
internal/promptguard/ bounded workspace selection and deterministic instruction rules
internal/provenance/ deterministic graph reconstruction and rendering
internal/incidents/ deterministic incident reconstruction and rendering
internal/runtime/   Docker agent, sentinel, gateway, and network lifecycle
internal/session/   session orchestration and evidence lifecycle
internal/storage/   SQLite schema, migrations, and queries
internal/trust/     trust classes and monotonic session-local exposure context
examples/           reproducible local demonstrations
docs/               architecture and security documentation
```

The v0.3 development architecture routes runtime observations through one validated signal-to-event pipeline. The Prompt-Injection Guard, trust classifier, and approval evidence use that path; they do not create another database or policy authority. SQLite events remain the sole evidence source for provenance and incidents. Session security state is the small monotonic `NORMAL`/`CONTAINED` model; containment and hard destination protections override approval. The primary workflow remains `ghost init` followed by `ghost run -- <agent>`, with `inspect`, `graph`, and `incidents` available for detailed evidence. See [security signals and state](docs/security-signals.md), [trust context](docs/trust-context.md), [Prompt-Injection Guard](docs/prompt-injection-guard.md), and [human approval](docs/approvals.md).

## Security model

In deny mode Ghost asks Docker for no guest network. In allowlist mode it creates a per-session internal agent network and a separate egress network. The agent can reach only the gateway address; direct connections remain on the internal network, and guest DNS points to an unused loopback resolver. The gateway receives only its handler, normalized allow/ask lists, and a small observation directory. It resolves a permitted or approvable hostname once per request, rejects prohibited addresses before asking, and connects by the validated IPv4 address instead of resolving the hostname again. The host-side approval broker sees only normalized request identity and destination metadata. Neither component receives the workspace, synthetic home, host home, Docker socket, database, host environment, request headers, or bodies.

All agent and sidecar containers drop Linux capabilities, enable `no-new-privileges`, retain Docker's isolated PID namespace, request private IPC and cgroup namespaces, disable core dumps, use read-only root filesystems, and are removed after execution. The project and the session's read-only synthetic home are the agent's only host bind mounts; `.ghost` is masked by a bounded private tmpfs and `ghost.yaml` is over-mounted read-only within `/workspace`. The sentinel receives only the synthetic home and its private observation directory. Ghost adds no host devices.

The agent receives fixed `HOME` and `PATH` values. Allowlist sessions additionally receive only Ghost's proxy variables. Host variables—including unrecognized custom variables—are not forwarded. Docker and the invoked program may create their own runtime variables such as a container hostname; these are not inherited host values.

Ghost never requests `--userns=host`. Docker does not offer a per-container flag that creates a fresh user namespace: user-namespace remapping or rootless operation must be configured at the daemon level. Without that deployment hardening, Docker and the host UID namespace remain part of the trusted computing base.

These are Docker configuration properties, not a claim that containers are unbreakable. Ghost inherits Docker, daemon, image, host-kernel, and local-user risks. In read-write workspace mode, the guest is intentionally allowed to modify project files. Commands run outside Ghost are outside its control.

Read the [security model](docs/security-model.md) and [threat model](docs/threat-model.md) before relying on this release.

## Development

```sh
make fmt
make test
make race
make vet
make bench
make bench-release
```

Create release-shaped Linux artifacts and their checksum manifest locally with:

```sh
make dist VERSION=0.2.0
(cd dist && sha256sum --check SHA256SUMS)
```

CI uses immutable action commit SHAs, an explicit Ubuntu runner release and an exact Go patch release. It verifies the module checksum set and that `go mod tidy` produces no diff. The release workflow accepts either a manual semantic version or a `release/vX.Y.Z` branch that points exactly to the current `main`. It reruns the complete Go/Docker/GhostBench gate, builds deterministic artifact names, verifies `SHA256SUMS`, and only then creates or verifies the annotated tag and publishes the GitHub Release. A retry may reuse only an annotated tag that already targets the same checked commit. Its write permission is scoped to that release job. Checksums detect artifact corruption; Ghost does not yet publish signed binaries, attestations, or an SBOM.

Docker integration is opt-in locally and skips cleanly without Docker:

```sh
GHOST_DOCKER_INTEGRATION=1 go test ./internal/bench ./internal/runtime ./internal/session -run Docker -v
```

The integration suite demonstrates Shadow access, host-secret isolation, allowed and denied requests, raw-IP and proxy-variable bypass attempts, child-process isolation, live containment, failure closure, cleanup, and integrated prompt-signal handling with local Docker fixtures. Provenance and incident unit/CLI tests reconstruct those event forms without changing enforcement state. GhostBench reuses those production paths as an opt-in integration regression suite. See the [GhostBench demo](examples/ghostbench/), [Shadow credentials example](examples/shadow-credentials/), [network containment example](examples/network-containment/), [Prompt-Injection Guard](docs/prompt-injection-guard.md), [provenance model](docs/provenance.md), and [incident reconstruction model](docs/incidents.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow, [SECURITY.md](SECURITY.md) for private vulnerability reporting, and [CHANGELOG.md](CHANGELOG.md) for release status.
