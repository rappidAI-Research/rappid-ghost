# Provenance

Ghost v0.4 reconstructs a session graph from the session row and its ordered SQLite events:

```text
SQLite session + events
          |
          v
  Provenance Builder
       /        \
 terminal      JSON v1
```

The event store remains the source of truth. Graph generation is read-only and is not part of policy evaluation, Docker enforcement, decoy detection, or containment.

## Evidence language

Ghost distinguishes two evidence levels:

- `OBSERVED`: a supported stored event directly describes the relationship. Examples include a runtime-scope decoy access, a network destination request, or a policy decision.
- `DERIVED`: the relationship is deterministically reconstructed from multiple stored facts. In v0.4 this is used for `FOLLOWED_BY` between chronologically ordered security events.

`FOLLOWED_BY` means event ordering only. It does not mean caused, influenced, intended, transmitted, or exfiltrated.

## Graph model

The JSON schema version is `1`. Its node types are:

- `SESSION`
- `PROCESS`
- `RESOURCE`
- `DECOY`
- `NETWORK_DESTINATION`
- `POLICY_DECISION`
- `INCIDENT`

The compact edge vocabulary is:

- `STARTED`
- `READ`
- `ACCESSED`
- `REQUESTED`
- `ALLOWED`
- `DENIED`
- `SHADOWED`
- `TRIGGERED`
- `CONTAINED`
- `FOLLOWED_BY`

`READ` is reserved for future evidence that identifies an actual resource read. Current Ghost instrumentation does not emit arbitrary workspace-read evidence, so the builder does not create `READ` edges today.

Every node or edge includes supporting SQLite event IDs where available. The top-level `evidence` array provides only event ID, event type, and timestamp. It deliberately excludes arbitrary metadata.

## Process and resource identity

The current `PROCESS` node represents the recorded top-level command scope. Ghost does not yet receive a reliable guest PID, parent PID, or process tree from Docker/inotify/network evidence. An `ACCESSED` or `REQUESTED` edge therefore means the access occurred within that command's runtime scope, not that Ghost identified the exact child process responsible.

Resource labels use explicit namespaces where supported:

```text
workspace:/workspace
shadow:~/.aws/credentials
network:example.com:443
```

No secret or decoy content is included. Unsupported or malformed identities are omitted rather than guessed.

## CLI

```sh
ghost graph latest
ghost graph latest --json
ghost graph <session-id>
ghost graph <session-id> --json
```

The text renderer separates observed relationships from derived temporal relationships and states the non-causality limitation. JSON has stable top-level fields:

```json
{
  "version": 1,
  "session": {},
  "nodes": [],
  "edges": [],
  "evidence": []
}
```

The export omits session argv, raw decoy IDs, arbitrary event metadata, decoy markers and contents, HTTP headers, cookies, bodies, query strings, and tunneled bytes. The process label contains only a sanitized executable basename.

## Limitations

- No reasoning reconstruction, chain-of-thought access, or causal inference.
- No arbitrary filesystem-read observation.
- No exact PID or parent/child attribution.
- No semantic data flow, taint tracking, or proof of exfiltration.
- No cross-session graph or behavioral profiling.
- Historical or malformed evidence degrades to fewer nodes and edges; the builder does not fill gaps with assumptions.
