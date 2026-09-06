# Design principles

## Deterministic enforcement

Security decisions are produced by code and explicit policy, never by an LLM. Shadow Home evaluation is a small truth table: a resource is `SHADOW` only when home policy, deception, and that resource are enabled; otherwise it is `DENY`.

Network evaluation is similarly deterministic: the base mode is `DENY` or an exact `ALLOWLIST`, resolved destination addresses must pass an explicit prohibited-range check, and session containment overrides every prior allow decision with `DENY`.

## Deny host access by default

Only deliberate mounts cross the host boundary. Disabling deception removes synthetic resources and never exposes their real counterparts. The host home, Docker socket, host environment secrets, and Ghost metadata remain unavailable to the agent.

Networking is denied unless an allowlist is deliberately configured. An old `network.mode: none` configuration is interpreted as `deny`, never unrestricted access.

Environment exposure also uses a positive allowlist. Ghost supplies fixed values required by the runtime and never forwards the launching process environment wholesale. Adding a new host-to-guest variable requires an explicit design and test rather than a secret-name blocklist.

## Deception complements isolation

Isolation keeps the real resource away. Deception provides a controlled alternative. Detection records interaction with that alternative. None of those properties substitutes for the others.

## Evidence over claims

Ghost records only what it can observe. A `DECOY_ACCESS` requires an inotify event after watcher readiness; file creation, session start, process exit, and unreliable `atime` do not count. A network decision records a destination attempt and policy result, not connection success or request content. Same-session ordering proves neither intent nor exfiltration.

Provenance preserves this distinction. `OBSERVED` graph edges require a supporting stored event. `DERIVED` `FOLLOWED_BY` edges encode event order only. Missing PID, workspace-read, parent-process, or data-flow evidence results in an absent relationship rather than a guessed one.

Incident reconstruction follows the same rule. Every timeline statement cites stored event IDs, unrelated events remain outside the incident, and incomplete history produces a smaller report. A later network denial may be temporally associated with containment; Ghost does not relabel that sequence as exfiltration or intent.

GhostBench follows the same rule: each scenario names one property and passes only when all required observations are present. An unavailable runtime produces `SKIP`; there is no overall security score, LLM judge, or substitution of process exit for security evidence.

## Local first

Configuration, generated material, decisions, sessions, and evidence remain on the developer's machine. The core requires no account, cloud service, external API, telemetry endpoint, or real credential registration.

## No model dependency

Ghost remains operational when no AI model is available. Models may provide future structured signals, but they cannot become the enforcement authority. Signals enter the same validated event pipeline and deterministic policy context as runtime observations; they never create an unrestricted-access fallback.

## Generic core

Codex is the first use case, not a hard-coded dependency. Runtime requests describe commands, resources, and evidence rather than agent-provider APIs.

## Minimal first version

The deception boundary covers three explicit synthetic-home paths. The first network boundary covers exact hostnames for HTTP/HTTPS only. Ghost does not introduce a policy language, arbitrary filesystem virtualization, TLS interception, general proxying, broad tracing, or external infrastructure before those capabilities are required.

## Complexity stays internal

The normal product contract remains `ghost init` followed by `ghost run -- <agent>`. Security observation, policy, persistence, provenance, incidents, and containment compose behind that flow. Advanced evidence commands remain available, but contributors should not turn each future detector or signal into a separate user-facing product or mandatory configuration switch.
