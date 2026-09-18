# Human approval

The v0.3 development line adds `ASK` to Ghost's deterministic policy vocabulary. Approval is integrated into `ghost run`; it is not a separate scanner, command, or persistent policy editor.

## Supported policy

Approval is deliberately narrow in this milestone. Only exact HTTP/HTTPS destinations listed under `network.ask` are approvable:

```yaml
network:
  mode: allowlist
  allow:
    - github.com
  ask:
    - api.example.com
```

`allow` and `ask` entries cannot overlap. Both use the same exact ASCII hostname normalization. Raw IPs, wildcards, single-label/local-use names, prohibited resolved addresses, nonstandard ports, arbitrary TCP/UDP, and destinations omitted from both lists remain non-approvable. HTTP is scoped to port 80 and its exact method; HTTPS is scoped to `CONNECT` on port 443.

## Precedence and failure behavior

Hard controls precede approval:

1. validate request shape, exact configured hostname, and fixed port;
2. check authoritative session containment;
3. resolve the hostname once and reject the complete answer set if any address is prohibited;
4. only then request a narrow user decision;
5. recheck containment through the sentinel barrier before connecting to the already validated numeric address.

A contained session receives `DENY`, never `ASK`. Approval cannot expose the host home, Docker socket, privileged execution, private/local/metadata destinations, raw IPs, or a direct external route. It cannot weaken Docker confinement, environment isolation, Shadow policy, or recovery rules.

Approval is fail closed. A missing handler, non-interactive stdin, EOF, cancellation, timeout, malformed response, invalid request identity, broker failure, or containment uncertainty becomes `DENY`. Ghost does not retry with weaker Docker or network settings and never executes the command on the host.

## Scopes

- `ALLOW_ONCE` permits only the one request that owns the unique request ID.
- `ALLOW_SESSION` is held in memory for the live session and matches exact scheme, normalized hostname, port, and HTTP method. A later exact request still passes destination resolution and containment checks.
- `DENY` rejects the request.

There are no wildcards or persistent grants. Session approvals are not written to `ghost.yaml`, do not survive the run, and cannot cross-authorize another session or a simultaneous request with a different identity or scope.

## Terminal behavior

When stdin and the diagnostic output are terminal character devices, Ghost is the sole reader of stdin. It normally forwards bytes to the agent container. While one approval is pending, it temporarily consumes one bounded response line and serializes other approval prompts:

```text
Ghost paused a sensitive request.
Destination: api.example.com:443
Reason: destination requires explicit session approval
Security context: Suspicious repository instructions were observed earlier in this session.
[A] Allow once  [S] Allow for this session  [D] Deny
Default: Deny (timeout 30s)
```

Most runs display no prompt. In CI, redirected input, and other non-interactive execution, ASK fails closed without waiting for terminal input. Prompt-Injection Guard context can make the explanation more informative, but it never makes a forbidden action approvable or proves that workspace content caused the request.

## Evidence

Approval uses the existing event store:

- `POLICY_ASK`
- `APPROVAL_REQUIRED`
- `APPROVAL_GRANTED`
- `APPROVAL_DENIED`
- `APPROVAL_UNAVAILABLE`
- `APPROVAL_EXPIRED`

Each runtime request has a unique session-private ID that links its request, outcome, and final network decision. Events record destination/action scope, decision source, and bounded security context—not prompt text, request headers, cookies, request bodies, decoy contents, or tunneled bytes.

The gateway can publish request artifacts but sees the host-owned response directory through a read-only nested mount. A broker protocol or filesystem failure cancels the session approval channel; pending and later operations fail closed instead of continuing through partially valid approval state.

Provenance schema v3 adds `USER_DECISION`, `REQUIRED_APPROVAL`, and `GRANTED`. Automatic policy and fail-closed outcomes remain policy-decision nodes. Incident schema v2 can attach approval evidence to a matching denied network request. It says “the user granted/denied” only for an actual `USER_DECISION`; malformed or unavailable input is described as automatic failure closure. Neither layer attributes the user's decision to the agent or claims causality.

## Limitations

- Approval currently covers only configured HTTP/HTTPS destinations, not filesystem or arbitrary process operations.
- Ghost does not persist grants, support broad patterns, or provide remote/multi-user approval.
- Approval cannot retract an already established HTTP response or HTTPS tunnel.
- Terminal multiplexing is line-based during a prompt and is not a full TUI/job-control implementation.
- Requests are serialized for user decisions. A handler that ignores cancellation can leave its own goroutine blocked, although the operation still times out and is denied.
- Approval says a scoped operation was permitted; it does not prove the upstream connection succeeded, infer user intent beyond the selected scope, or prove why the agent requested it.
