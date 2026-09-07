# Provenance

Ghost reconstructs a session graph from the session row and its ordered SQLite events:

```text
SQLite session + events
          |
          v
  Provenance Builder
       /        \
 terminal      JSON v2
```

The event store remains the source of truth. Graph generation is read-only and is not part of policy evaluation, Docker enforcement, decoy detection, or containment.

## Evidence language

Ghost distinguishes two evidence levels:

- `OBSERVED`: a supported stored event directly describes the relationship. Examples include a runtime-scope decoy access, a network destination request, or a policy decision.
- `DERIVED`: the relationship is deterministically reconstructed from multiple stored facts. This includes `FOLLOWED_BY` chronology, command-scope `EXPOSED_TO` availability, and a sensitive-path `REQUESTED` classification backed by a matching Shadow-access event.

`FOLLOWED_BY` means event ordering only. `EXPOSED_TO` means selected content was observed before the process received the workspace mount, not that the file was read. Neither relationship means caused, influenced, intended, transmitted, or exfiltrated.

## Graph model

The JSON schema version is `2`. Its node types are:

- `SESSION`
- `PROCESS`
- `RESOURCE`
- `DECOY`
- `NETWORK_DESTINATION`
- `POLICY_DECISION`
- `INCIDENT`
- `SECURITY_SIGNAL`

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
- `SIGNALED`
- `EXPOSED_TO`

`READ` is reserved for future evidence that identifies an actual resource read. Current Ghost instrumentation does not emit arbitrary workspace-read evidence, so the builder does not create `READ` edges today. A process node represents the entire top-level command scope, including child activity that Ghost cannot attribute to a reliable individual PID.

`SECURITY_SIGNAL` and `SIGNALED` provide a secret-minimized representation for the v0.3 structured-signal vocabulary. They are present only when a corresponding stored event exists. Startup observations link their normalized `workspace:<path>` resource to the signal. After `PROCESS_START`, the builder can derive `process --EXPOSED_TO--> resource` from both event IDs; it does not invent a process read. A `SENSITIVE_RESOURCE_REQUESTED` signal creates a derived command-scope `REQUESTED` edge only when it references a matching, earlier `DECOY_ACCESS` event for the same protected path.

Resource/decoy nodes may carry one of the deterministic trust classes `UNTRUSTED`, `SENSITIVE`, or `SHADOW`. `SHADOW` and `SENSITIVE` remain separate identities: the former is the synthetic decoy actually exposed, while the latter denotes the protected real-resource class/path that Ghost did not expose or inspect. Arbitrary event metadata, including source content, is not copied into the graph.

Every node or edge includes supporting SQLite event IDs where available. The top-level `evidence` array provides only event ID, event type, and timestamp. It deliberately excludes arbitrary metadata.

## Process and resource identity

The current `PROCESS` node represents the recorded top-level command scope. Ghost does not yet receive a reliable guest PID, parent PID, or process tree from Docker/inotify/network evidence. An `ACCESSED` or `REQUESTED` edge therefore means the access occurred within that command's runtime scope, not that Ghost identified the exact child process responsible.

Resource labels use explicit namespaces where supported:

```text
workspace:/workspace
workspace:AGENTS.md
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
- No byte-level or semantic data flow, arbitrary propagation, or proof of exfiltration.
- No cross-session graph or behavioral profiling.
- Historical or malformed evidence degrades to fewer nodes and edges; the builder does not fill gaps with assumptions.

The incident reconstructor consumes this graph together with the same ordered events to produce a smaller security-relevant sequence. It stores no separate truth and never changes the graph or enforcement state. See [incident reconstruction](incidents.md).
