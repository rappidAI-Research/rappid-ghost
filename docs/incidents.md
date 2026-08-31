# Incident reconstruction

Ghost v0.1 reconstructs concise incidents from one persisted session's events and provenance graph:

```text
SQLite session + events
          |
          v
  Provenance Builder
          |
          v
 Incident Reconstructor
       /        \
 terminal      JSON v1
```

The event store remains the source of truth. Incident reconstruction is read-only, creates no database rows, changes no containment state, and has no role in Docker or policy enforcement.

## Evidence model

Every timeline statement carries one or more SQLite event IDs. Incidents also list the provenance node and edge IDs supported entirely by their evidence set.

- `OBSERVED` means a supported stored event directly describes the statement, such as `DECOY_ACCESS`, `CONTAINMENT_ACTIVATED`, or a `NETWORK_DENY` decision.
- `DERIVED` means Ghost combined stored facts deterministically. For example, a containment event followed by a denied network request supports the statement that the denial occurred later in the contained session.

Temporal order is not causality. The report does not claim that reading a decoy caused a network request, that the request contained decoy data, or that the process intended exfiltration.

## Incident types and grouping

The initial taxonomy is deliberately small:

- `DECOY_ACCESS`: one or more access events for the same provenance decoy node.
- `DECOY_ACCESS_WITH_NETWORK_ACTIVITY`: a decoy-access incident that owns session containment and has a later denied outbound request.
- `NETWORK_POLICY_VIOLATION`: an independently denied outbound request not linked to an active containment chain.
- `CONTAINMENT_ACTIVATED`: containment evidence for which the available history has no preceding decoy-access evidence.

Grouping is deterministic:

1. Repeated access evidence for the same decoy node is grouped into one incident. Different decoy nodes remain separate.
2. The first containment activation is attached to the most recently observed decoy-access incident. Repeated containment evidence does not create another incident.
3. Denied network requests after that activation are attached to the contained incident for the rest of the session.
4. A denied request outside a supported containment chain becomes its own network-policy incident.
5. Duplicate copies of the same SQLite event ID are ignored. Distinct network decision event IDs remain distinct observed requests.
6. Events belonging to another session, events without stable positive IDs, and malformed resource identities are excluded.

The reconstructor does not fill missing gaps. A partial historical session may therefore produce a smaller incident, an independent network-policy incident, an orphan-containment incident, or no incident.

## Severity

Severity is deterministic security significance, not a compromise probability:

- Decoy access defaults to `HIGH`.
- A valid severity in a `SECURITY_INCIDENT` event (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`) controls the decoy incident. Current `ghost.yaml` generation permits `LOW`, `MEDIUM`, or `HIGH`; `CRITICAL` is reserved for compatible historical or future evidence.
- Later denied network activity after containment raises a decoy incident to at least `HIGH`.
- Independent network-policy denials are `MEDIUM`.
- Orphan containment evidence is `MEDIUM`.

No probability, model score, fuzzy classification, or LLM output is used.

## CLI and JSON

```sh
ghost incidents latest
ghost incidents latest --json
ghost incidents <session-id>
ghost incidents <session-id> --json
```

The JSON schema version is `1` and has stable top-level fields:

```json
{
  "version": 1,
  "session": {},
  "incidents": []
}
```

Each incident contains its deterministic ID, type, severity and severity evidence, start/end timestamps, summary, evidence-backed timeline, evidence event IDs, relevant provenance node/edge IDs, and optional containment action.

The export uses only allowlisted, normalized labels from the provenance graph. It excludes command arguments, raw decoy IDs, markers, decoy contents, arbitrary event metadata, HTTP headers, cookies, request bodies, query strings, and tunneled content. The underlying SQLite event store remains local evidence and may contain operational error text or other metadata not present in this export.

## Limitations

- No causal inference, intent attribution, reasoning reconstruction, or chain-of-thought access.
- No semantic data flow or proof that decoy content entered a network request.
- No exact guest PID or child-process attribution beyond the current command scope.
- No arbitrary workspace-read reconstruction.
- No cross-session grouping or behavioral profiling.
- No persisted incident table; reports are reconstructed from current evidence each time.
