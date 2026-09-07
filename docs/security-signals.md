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

The integrated Prompt-Injection Guard emits one `UNTRUSTED_CONTENT_OBSERVED` event for each selected source successfully analyzed during bounded startup inspection, and emits `PROMPT_INJECTION_SUSPECTED` when deterministic rules match. It may emit `RESOURCE_LIMIT_TRIGGERED` when a scan bound prevents complete analysis. A genuine Shadow open/access also produces a `SENSITIVE_RESOURCE_REQUESTED` signal that references the source `DECOY_ACCESS` event; this is a derived resource-class statement, not evidence that Ghost inspected a real secret. The remaining vocabulary does not imply byte-level taint tracking, general resource-limit enforcement, or model reasoning access.

Provenance can represent a persisted signal as a `SECURITY_SIGNAL` node with an observed `SIGNALED` edge and its event ID. Selected workspace-resource nodes carry `UNTRUSTED`, decoy nodes carry `SHADOW`, and protected resource-class nodes carry `SENSITIVE`. Derived `EXPOSED_TO` and sensitive `REQUESTED` edges require their complete source event set. Arbitrary signal metadata is excluded from JSON exports; missing or contradictory evidence produces no relationship.

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

The policy package accepts a deterministic base decision and structured context containing resource kind, session state, and validated security-signal kinds. Current behavior remains narrow: containment overrides network access; existing home policy still evaluates `SHADOW` or `DENY`; prompt findings are available as context but do not terminate a session or loosen a decision. Workspace behavior is unchanged.

Trust context now carries session-local untrusted-input observation, highest prompt-finding severity, and Shadow-access state into the existing policy seam. It is monotonic and cannot loosen a base decision. Future semantic signals may inform explicit policy, but they must not disable Docker isolation, network restrictions, Shadow behavior, environment isolation, or containment. An analyzer declaring content “safe” can never be an unrestricted-access fallback.

`ASK` is not implemented or added to the canonical decision type in this milestone.

## User experience and configuration

No new command or configuration flag is required. The primary workflow remains:

```sh
ghost init
ghost run -- <agent>
```

Normal output stays concise. A prompt finding produces one pre-run notice and a compact completion count. Detailed evidence remains available through `ghost inspect`, `ghost graph`, and `ghost incidents`. Integrated security signals follow the same rule: brief action-oriented output during normal use and content-minimized evidence in the existing advanced views.

See [trust context](trust-context.md) for classification and exposure semantics, and [Prompt-Injection Guard](prompt-injection-guard.md) for source selection, normalization, severity, limits, and false-positive/false-negative boundaries.
