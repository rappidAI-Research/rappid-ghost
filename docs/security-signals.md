# Security signals and session state

The v0.3 development architecture gives security-relevant observations one internal route:

```text
runtime observation
        |
        v
structured Signal
        |
   validation
        |
        v
persisted Event
        |
        +-- provenance
        +-- incidents
        +-- inspection
```

`Signal` is a pre-persistence envelope, not a second event system. It uses the existing event fields: timestamp, type, subject, resource, action, optional deterministic policy decision, and JSON-compatible metadata. The pipeline validates required identity, time, type, and policy-decision values before writing the existing SQLite event row. SQLite events remain the sole durable evidence source.

## Current and reserved observations

Current enforcement already emits lifecycle, policy, Shadow, network, containment, and incident events. Existing `DECOY_ACCESS` represents an observed Shadow-resource access, and `NETWORK_REQUEST` represents an observed destination request.

The event vocabulary now reserves these structured integration points:

- `UNTRUSTED_CONTENT_OBSERVED`
- `PROMPT_INJECTION_SUSPECTED`
- `SENSITIVE_RESOURCE_REQUESTED`
- `POLICY_VIOLATION`
- `RESOURCE_LIMIT_TRIGGERED`

No new detector emits these events yet. Reserving their shape does not claim prompt-injection detection, trust classification, taint tracking, resource-limit enforcement, or model reasoning access.

Provenance can represent a persisted reserved signal as a `SECURITY_SIGNAL` node with an observed `SIGNALED` edge and its event ID. It deliberately excludes arbitrary signal metadata from JSON exports. Missing events produce no graph relationship.

## Authoritative state

The logical session state is deliberately small:

- `NORMAL`
- `CONTAINED`

It is monotonic. `NORMAL` may transition to `CONTAINED`; `CONTAINED` cannot transition back during that session. Contextual network policy turns an otherwise valid `ALLOW` into `DENY` while contained. Invalid or unavailable state does not produce an allow decision.

The live Docker boundary and durable session record use one explicit handoff:

1. During execution, the session-private containment marker is authoritative for the sentinel and gateway.
2. The runtime returns the marker-derived typed state together with ordered evidence.
3. The session manager rejects invalid state, contradictory containment evidence, or required containment that was not reported.
4. The manager applies the monotonic state transition and persists it using the existing SQLite containment column.
5. SQLite is authoritative for completed and recovered session history.

This avoids independently mutable state in the manager, gateway, and event database while respecting the process boundary between the Go host and constrained sidecars.

## Policy integration

The policy package accepts a deterministic base decision and structured context containing resource kind and session state. Current behavior remains narrow: containment overrides network access; existing home policy still evaluates `SHADOW` or `DENY`; workspace behavior is unchanged.

Future trust or semantic signals may inform explicit policy, but they must not disable Docker isolation, network restrictions, Shadow behavior, environment isolation, or containment. An analyzer declaring content “safe” can never be an unrestricted-access fallback.

`ASK` is not implemented or added to the canonical decision type in this milestone.

## User experience and configuration

No new command or configuration flag is required. The primary workflow remains:

```sh
ghost init
ghost run -- <agent>
```

Normal output stays concise. Detailed evidence remains available through `ghost inspect`, `ghost graph`, and `ghost incidents`. Future integrated security signals should follow the same rule: brief action-oriented output during normal use and complete evidence in the existing advanced views.
