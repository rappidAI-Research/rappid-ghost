# Design principles

## Deterministic enforcement

Security decisions are produced by code and explicit policy, never by an LLM. Shadow Home evaluation is a small truth table: a resource is `SHADOW` only when home policy, deception, and that resource are enabled; otherwise it is `DENY`.

Network evaluation is similarly deterministic: the base mode is `DENY` or an exact `ALLOWLIST`, and session containment overrides every prior allow decision with `DENY`.

## Deny host access by default

Only deliberate mounts cross the host boundary. Disabling deception removes synthetic resources and never exposes their real counterparts. The host home, Docker socket, host environment secrets, and Ghost metadata remain unavailable to the agent.

Networking is denied unless an allowlist is deliberately configured. An old `network.mode: none` configuration is interpreted as `deny`, never unrestricted access.

## Deception complements isolation

Isolation keeps the real resource away. Deception provides a controlled alternative. Detection records interaction with that alternative. None of those properties substitutes for the others.

## Evidence over claims

Ghost records only what it can observe. A `DECOY_ACCESS` requires an inotify event after watcher readiness; file creation, session start, process exit, and unreliable `atime` do not count. A network decision records a destination attempt and policy result, not connection success or request content. Same-session ordering proves neither intent nor exfiltration.

Provenance preserves this distinction. `OBSERVED` graph edges require a supporting stored event. `DERIVED` `FOLLOWED_BY` edges encode event order only. Missing PID, workspace-read, parent-process, or data-flow evidence results in an absent relationship rather than a guessed one.

## Local first

Configuration, generated material, decisions, sessions, and evidence remain on the developer's machine. The core requires no account, cloud service, external API, telemetry endpoint, or real credential registration.

## No model dependency

Ghost remains operational when no AI model is available. Models may provide future signals, but they cannot become the enforcement authority.

## Generic core

Codex is the first use case, not a hard-coded dependency. Runtime requests describe commands, resources, and evidence rather than agent-provider APIs.

## Minimal first version

The deception boundary covers three explicit synthetic-home paths. The first network boundary covers exact hostnames for HTTP/HTTPS only. Ghost does not introduce a policy language, arbitrary filesystem virtualization, TLS interception, general proxying, broad tracing, or external infrastructure before those capabilities are required.
