# Trust context

Ghost v0.3 attaches a small deterministic trust vocabulary to evidence that already exists in the normal `ghost run` lifecycle:

- `TRUSTED`: Ghost-owned policy or runtime control data, when represented.
- `UNTRUSTED`: selected user/repository workspace content. Local origin does not make content trusted.
- `SENSITIVE`: a protected real-resource class or path. This label does not mean Ghost read or found a real secret.
- `SHADOW`: a Ghost-generated synthetic substitute. Shadow values are independent of real host credentials.

The classes are descriptive security context, not permission decisions. `ALLOW`, `DENY`, `SHADOW`, and narrow configured `ASK` remain deterministic policy outcomes.

## Startup observation and exposure

The Prompt-Injection Guard already opens selected bounded workspace text before the container starts. Each successfully analyzed source now produces a content-minimized `UNTRUSTED_CONTENT_OBSERVED` event with its normalized workspace path, source kind, and SHA-256 fingerprint. Benign content is still `UNTRUSTED`; that classification does not mean malicious or suspicious and does not create an incident by itself.

When a later `PROCESS_START` proves that Ghost launched the command with the workspace, provenance may derive:

```text
[process] command scope --EXPOSED_TO--> [resource] workspace:AGENTS.md (UNTRUSTED)
```

`EXPOSED_TO` means that selected content was observed before the command scope received the workspace mount. It does **not** mean Ghost observed a file read, that a model parsed the file, or that the content influenced behavior. Current instrumentation therefore continues to emit no workspace `READ` edge.

The process node is one command scope. Child processes share that runtime scope, but Ghost does not currently identify individual guest PIDs or infer separate child propagation.

## Monotonic session-local context

During one run Ghost maintains a small context containing:

- whether selected untrusted input was observed;
- the highest deterministic Prompt-Injection Guard severity, if any; and
- whether a Shadow resource was accessed.

Facts can be added or severity can increase; they are not cleared during the session. A fresh context is created for every run, so exposure cannot cross session boundaries. This active value is not a second durable truth source: every update corresponds to an event, and completed-session provenance/incidents are rebuilt from SQLite events.

The context is passed to the existing policy evaluator together with the authoritative `NORMAL`/`CONTAINED` security state and resource trust class. Trust context cannot make a base decision more permissive. Suspicious-instruction severity may appear in the explanation for an otherwise approvable exact destination, but it cannot make a forbidden operation approvable or prove causality. Ordinary actions are not interrupted solely because a repository contains untrusted text.

## Sensitive requests and Shadow access

When the sentinel reports a genuine open/access event for a known Shadow path, Ghost records the existing `DECOY_ACCESS` event. It then records `SENSITIVE_RESOURCE_REQUESTED` for the protected resource class, referencing the exact `DECOY_ACCESS` event ID from which the classification was derived.

Provenance keeps two identities:

```text
[decoy]   shadow:~/.aws/credentials   (SHADOW)
[resource] resource:~/.aws/credentials (SENSITIVE)
```

The command-scope `ACCESSED` edge to the decoy is `OBSERVED`. The `REQUESTED` edge to the sensitive resource class is `DERIVED` and requires the matching access event plus the derived signal event. Ghost never reads or constructs a node from a host credential file.

## Persistence and privacy

Trust evidence uses the existing events table. Ghost stores normalized paths, source kind, deterministic category/severity, fingerprints, trust class, and evidence event references. It does not persist source bodies or prompts for trust tracking. Provenance and incident JSON continue to omit arbitrary event metadata and decoy contents.

## Limitations

- No arbitrary workspace-read observation or proof that content was consumed.
- No byte-level taint, semantic propagation through files/IPC/network, or model-memory tracking.
- No exact PID or parent/child attribution; the current process identity is a command scope.
- No causal inference, intent attribution, or proof that earlier content influenced later activity.
- Startup-selected content only; files created or changed during execution are not rescanned.
- `SENSITIVE` identifies a protected class/path, not the existence or contents of a real host secret.
