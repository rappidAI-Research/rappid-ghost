# v0.3 adversarial validation

The normal workflow remains `ghost init` and `ghost run -- <agent>`. These
fixtures exercise production orchestration with scripted, harmless commands.
No model participates: suspicious content preceding an action is temporal
context, never proof that the content influenced an agent.

## Attack-chain matrix

| Chain | Objective assertions | Executable coverage |
|---|---|---|
| Suspicious source → SHADOW → containment → network | Finding precedes launch; observed decoy access precedes contained DENY; temporal incident and graph references; markers absent from exports | `prompt-shadow-context`, CLI Docker summary/privacy test; existing host-home and SHADOW benchmarks verify host credential isolation |
| Suspicious source → ASK → cached grant → SHADOW → concurrent egress | Context shown to handler; exact session grant reused; four later requests denied; USER_DECISION remains distinct from agent | `approval-containment-precedence` |
| Concurrent ASK → one approval | Four unique request IDs; one successful request, three denials; no grant reuse | `concurrent-approval-once`; 16-request controller regression |
| Pending ASK → decoy → late approval | File handshake triggers access while decision is pending; actual containment marker gates response; final request is denied | Docker pending-decision test, three repetitions without timing sleeps to hide races |
| Prompt/network policy interaction | Suspicious context does not widen the network allowlist; raw/private/metadata addresses stay forbidden; ASK handler cannot authorize a private resolved address | Integrated chains plus gateway address-guard and real private-ASK tests |
| Session A → session B → session C | Fresh decoy markers; no inherited grants, findings, trust sources, containment, resource evidence or foreign references; next explicit allowlist works | `cross-session-security-isolation`, `session-timeout`, existing `session-isolation` |
| Resource limit → termination → next session | Real bounded PID/OOM fixtures; descendants share cgroups; TERM-ignoring tree removed; operational evidence, no invented hostile intent | Docker resource tests, `session-timeout`, CLI SHADOW-plus-timeout summary test |
| Live containment → host SIGKILL → recovery | Kill only a test-owned Ghost subprocess after marker exists; old row initially NORMAL; recovery preserves actual CONTAINED state and finalizes failed; unrelated network survives; next run clean | CLI Docker crash test; existing ownership ambiguity tests and `interrupted-session-recovery` |
| Required dependency/evidence failure → launch prevention | No host/egress fallback; no automatic approval; failed state visible where storage works | Missing Docker, unsafe identity/config, gateway/sentinel setup, malformed broker, required event-write failure and inconsistent runtime-state tests |

Every benchmark has one registered property, explicit assertions and evidence
references. Existing 22 scenarios remain; three integrated scenarios bring the
exact total to **25**. Any assertion mismatch is FAIL. Only unavailable execution
dependencies justify SKIP; `--require-all` rejects both FAIL and SKIP. Docker
integration CI rejects skipped tests, including the CLI crash and summary tests.

## Prompt corpus

`internal/promptguard/adversarial_test.go` adds 18 labeled regression cases:
override, fake system/developer roles, credential access/transmission, disabling
security, concealment, case/whitespace, zero-width/fullwidth/bidi/control variants,
spaced letters and one supported base64 layer, alongside academic, quoted attack,
defensive credential and comment-in-document controls. A separate scanner test
shows ordinary source-code comments are outside the selected startup sources.
Benign examples must not escalate to HIGH/CRITICAL; explicit defensive credential
text must produce no finding. Quoted attack discussions may produce MEDIUM.

This is a curated English-language regression corpus, not a statistically
representative accuracy study. The bounded startup scanner does not inspect all
files, later tool output, all encodings, every Unicode trick or model reasoning.
No detection percentage or universal attack-prevention claim follows from it.

## Evidence and reproduced defects

- Interrupted runtime containment previously could be lost when SQLite still
  contained NORMAL. After positively identified resources are stopped, recovery
  now consults the trusted sentinel marker and monotonically preserves CONTAINED.
  A recovered containment event is timestamped at recovery and marked as such.
  It does not invent a missing decoy read, approval or precise transition time.
- A failed Docker attachment previously copied the last guest stderr line into
  the returned error, which could also reach persisted failure metadata. The
  error now retains the attachment failure without copying untrusted output.
  Live guest stdout/stderr remains the command's output stream, not a sanitized
  security report.

Graph edges remain FOLLOWED_BY with derived evidence, never CAUSED_BY. Production
exports and automatic summaries are checked against actual synthetic markers.
User decisions have USER_DECISION attribution. Operational timeouts and OOMs do
not themselves prove hostile behavior. After a hard host crash, detailed events
not yet imported into SQLite can remain only in the private observation log;
recovery does not manufacture complete incident history from incomplete evidence.

## Limits of this gate

CI validates the configured Linux/Docker environment, not every kernel, rootless
host, AppArmor deployment or developer toolchain. Memory/PID fixtures are capped
inside containers, never host exhaustion tests. Workspace and evidence storage
remain without a robust byte quota. A killed Ghost process cannot keep its
userspace deadline running; cgroup ceilings remain subject to Docker/kernel
health until recovery. Existing open connections are not proof of exfiltration.
A final v0.3 security/quality audit and release-readiness gate remains separate.
