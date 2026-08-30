# Design principles

## Deterministic enforcement

Security decisions must be produced by code and explicit policy, never by an LLM. A model may eventually provide signals, but it cannot be the enforcement authority.

## Deny host access by default

Ghost exposes only configured resources. The current project workspace is the sole host bind mount in v0.1. The host home directory, Docker socket, and Ghost database are not exposed by Ghost.

## Deception complements isolation

`SHADOW` is a first-class policy outcome because controlled synthetic resources can complement denial and containment. It is represented in domain types now, but synthetic resources are not implemented in v0.1.

## Evidence over claims

Documentation and event records must describe only what Ghost can observe and enforce. For example, v0.1 records process lifecycle events but does not claim filesystem-level monitoring.

## Local first

Configuration, decisions, sessions, and events live on the developer's machine. The core requires no account, cloud service, external API, or telemetry endpoint.

## No model dependency

Ghost must remain operational when no AI model is available. Model-specific integrations belong outside the enforcement core.

## Generic core

Codex is the first use case, not a hard-coded dependency. Runtime requests are commands and workspace paths rather than agent-specific objects.

## Minimal first version

Every abstraction must support an implemented behavior or a concrete test seam. New interception layers, policy languages, or services should be added only when their milestone requires them.
