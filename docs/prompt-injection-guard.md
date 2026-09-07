# Prompt-Injection Guard

Ghost's Prompt-Injection Guard is a deterministic startup inspection of selected workspace text. It runs automatically during `ghost run`, after the session has been durably created and before `PROCESS_START` or container launch. It is an additional source of evidence, not an isolation boundary and not a declaration that content is safe.

## Scope and limits

The guard prioritizes agent-control and repository instruction surfaces:

- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot instruction files, Cursor rules, and similar recognized instruction files at any workspace depth;
- root README, CONTRIBUTING, SECURITY, prompt, and instruction documents;
- supported text formats under `docs/` and `.github/`; and
- supported text/script formats under `scripts/`.

It skips `.git`, `.ghost`, dependency/build outputs, test fixtures, symlinks, non-regular files, binary or invalid UTF-8 files, and unrecognized source files. Files are opened relative to an `os.Root`, so a symlink swap cannot make an accepted path escape the workspace. The default bounds are 256 KiB per file, 4 MiB total analyzed text, 256 candidate files, 20,000 discovered entries, and 4,096 analyzed lines per file. Recognized agent-instruction files are considered before lower-priority documentation or scripts. For a line-heavy file, only bounded leading and trailing regions are analyzed. Limit activation is recorded as `RESOURCE_LIMIT_TRIGGERED`; it is not silently presented as a complete scan.

This first implementation inspects the workspace at session startup. Ghost does not yet observe arbitrary workspace reads or rescan files created or changed while the agent is running.

## Detection rules

The detector lowercases text, collapses whitespace, normalizes full-width ASCII, removes selected zero-width and bidirectional formatting characters, and rejoins simple letter-spaced words. It keeps Markdown list items, headings, and fenced blocks as separate logical units, then evaluates bounded six-unit windows using named rules for:

- previous/system/developer instruction override;
- Ghost, sandbox, policy, or security bypass;
- credential, token, secret-file, or environment access;
- network transmission paired with sensitive access;
- security-setting alteration;
- system/developer/tool impersonation;
- concealment from the user; and
- Unicode/control obfuscation or a conservatively decoded Base64 instruction token.

Base64 is decoded once, only for bounded printable UTF-8 tokens, and produces a finding only when the decoded text contains a high-risk instruction combination. Ghost is not a general decoder or malware unpacker.

One highest-severity finding is emitted per source file. A finding stores the normalized workspace path, source kind, named category and rule identifiers, the start line of the matching analysis window, severity, and SHA-256 content fingerprint. It does not store an excerpt or document body.

## Deterministic severity

| Severity | Rule meaning |
|---|---|
| `LOW` | A weak structural signal such as standalone authority impersonation or obfuscation with a recognized instruction indicator. |
| `MEDIUM` | An explicit override, security bypass, credential/environment request, security-setting change, or supported compound impersonation pattern. |
| `HIGH` | Multiple reinforcing actions, such as sensitive access plus transmission, override plus sensitive/bypass/concealment language, or bypass plus concealment. |
| `CRITICAL` | Sensitive access plus transmission combined with override, bypass, concealment, or encoded-instruction evidence. |

Explicitly defensive context in repository documentation suppresses a medium-only match and can cap an otherwise high rule combination at `MEDIUM`. A security-themed filename alone is not trusted; the text must contain multiple defensive markers or an explicit protection/negative-exposure statement. Dedicated agent instruction surfaces do not receive that treatment. This is deterministic false-positive control, not semantic understanding, and both false positives and false negatives remain possible.

## Evidence and policy integration

Each selected source successfully analyzed becomes an `UNTRUSTED_CONTENT_OBSERVED` event containing only normalized path, source kind, trust class, and fingerprint. Each finding becomes a `PROMPT_INJECTION_SUSPECTED` event through the same signal pipeline and SQLite event store. Provenance links the workspace resource to signal evidence and may derive command-scope `EXPOSED_TO` availability after `PROCESS_START`; this is not evidence that the process read the file. Incident reconstruction can show that suspicious instructions were observed before later Shadow or denied-network activity, but labels that relationship `DERIVED` temporal context—not causality.

The policy evaluation context can carry `PROMPT_INJECTION_SUSPECTED`, but this milestone does not terminate a run solely because text matched. The signal cannot make an `ALLOW`, `DENY`, or `SHADOW` decision more permissive. Docker isolation, network policy, environment isolation, Shadow resources, and containment remain authoritative even when the guard misses a prompt injection. If the inspector itself cannot initialize or complete safely, Ghost records a failed session and does not start the runtime.

See [trust context](trust-context.md) for resource classes, session-local exposure semantics, and the boundary between observed and derived relationships.

## User experience

No scanner command or feature flag is required. A normal run remains:

```sh
ghost run -- <agent>
```

When findings exist, Ghost prints one concise pre-run notice and a compact completion count. `ghost inspect`, `ghost graph`, and `ghost incidents` provide detailed, evidence-linked views without exposing the matched document contents.
