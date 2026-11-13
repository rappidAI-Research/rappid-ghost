# Tool gateway and local model access — proposed v0.5 contract

**Design only. Ghost v0.4 does not implement this gateway, mount a broker socket,
mediate MCP, connect to a database or grant local model access.** Private network
ranges remain blocked. The existing HTTPS CONNECT gateway authorizes a destination,
not application operations or data access inside an encrypted connection.

## Trust and invocation contract

A trusted application authenticates the user and derives tenant/resource scopes
from its own authorization store. It creates a short-lived, session-bound capability
outside the agent. A broker validates application identity using authenticated IPC
or mutually authenticated transport; subject/tenant strings supplied by an agent
are never an authority. The agent receives an opaque capability handle, not a
service credential or database password.

A versioned invocation envelope contains only:

```json
{"schema_version":1,"request_id":"opaque-unique-id","session_id":"bound-session",
 "capability":"opaque-handle","tool":"documents.summarize.v1",
 "arguments":{"document_id":"untrusted-resource-selector"},
 "idempotency_key":"opaque-id"}
```

This example is not an accepted v0.4 API. The broker resolves the tool ID against
a source-reviewed registry. The capability binds identity, tenant, tool/schema
version, resource selectors, effect class, expiry, nonce, per-call size limits,
request budget and policy version. No arbitrary URL, shell command, SQL or
filesystem path becomes a trusted destination through tool arguments.

Validation order: authenticate application/session; enforce bounded framing and
strict schema; resolve/revalidate capability and application authorization;
validate arguments; consult authoritative containment; obtain exact human approval
where configured; recheck capability expiry/revocation, authorization and
containment immediately before the effect; commit with idempotency and a bounded
transaction. Unknown tools, session mismatch, cancellation, replay, missing state,
invalid authorization and unavailable audit persistence deny. Approval cannot
broaden tenant permissions or survive containment. Destructive multi-step actions
need application transactions/compensation; a generic proxy cannot undo effects.

## Transport and credentials

Prefer a dedicated per-session IPC endpoint exposed only to that workload. An
implementation must verify endpoint ownership and stale-socket cleanup and ensure
no arbitrary host directory/socket can be mounted. A trusted broker owns upstream
credentials. A narrowly scoped model service connector pins the exact configured
service identity/address and port, validates responses, forbids redirects to other
destinations and never turns all RFC1918/loopback addresses into an allowlist.
Raw agent sockets remain contained. Avoid forwarding client bearer tokens to other
servers, sharing authorization sessions between tenants or trusting MCP tool
annotations as authorization. MCP protocol/version and transport behavior require
separate tests; protocol support is not application authorization.

Model prompts, documents and tool arguments are sensitive. Persist minimal tool
identity, decision, request ID, timestamps and bounded outcome codes rather than
bodies, credentials, prompts or document text. Content retention requires a separate
explicit application policy. Limit tokens, bytes, concurrent calls, duration,
retries and aggregate spend independently of container resource ceilings.

## Child and youth services example

The application authorizes a staff member for selected records, stages only those
inputs into an isolated per-task workspace and starts Ghost with read-only/deny
policy. v0.4 can run an offline Python transformation and produce stdout; it cannot
supply an LLM, enforce caseworker/tenant permissions or authorize a production
record update. A future broker would separately authorize a narrowly named record
operation and model request. The trusted application validates outputs and controls
storage and release of generated results. Privacy compliance, consent, retention,
legal basis, human review and incident response remain application/operator duties.

## Required implementation gates

Cross-tenant/resource substitution; revocation during approval; replay/expiry;
malicious schemas/tool metadata; SSRF/DNS/redirects; broker crash and stale IPC;
credential exclusion; bounded malformed frames; log exhaustion; concurrent
containment; idempotent effects; upstream timeouts; per-tenant and aggregate
budgets. Deploy no sensitive-data pilot before these gates and independent review.

References reviewed 2026-11-13:
[MCP security](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices),
[OWASP agent security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html),
[OWASP authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
