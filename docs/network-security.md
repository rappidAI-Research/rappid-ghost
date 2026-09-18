# Network security

Ghost v0.1 introduced narrow destination control for outbound HTTP and HTTPS. Version 0.2 hardens resolved-address validation. It does not claim to be a general network firewall or content-loss-prevention system.

## Modes and matching

`network.mode: deny` is the safe default. The agent container uses Docker network mode `none`.

`network.mode: allowlist` requires one or more exact ASCII hostnames split between static `allow` and/or interactive `ask`:

```yaml
network:
  mode: allowlist
  allow:
    - github.com
  ask:
    - api.github.com
```

An `allow` entry is automatic. An `ask` entry is eligible for one exact user decision after all hard destination checks pass. Entries cannot overlap. If interaction or the approval path is unavailable, ASK becomes DENY. See [human approval](approvals.md).

Configuration and request hostnames are lowercased and a single final DNS root dot is removed. Labels are validated, duplicates are rejected after normalization, and raw IPv4, IPv6, numeric-IP-like, wildcard, URL, and host-with-port entries are rejected. Single-label names and local-use suffixes such as `.localhost`, `.local`, `.localdomain`, `.internal`, `.lan`, and `.home.arpa` are rejected, covering common Docker host/gateway and metadata aliases. An entry for `github.com` does not authorize any subdomain.

Only HTTP on destination port 80 and HTTPS `CONNECT` on destination port 443 are supported. Ports are not configurable in this milestone.

## Per-session topology

Allowlist sessions use two fresh Docker bridge networks:

- an `--internal` agent network, which does not provide direct external egress;
- a separate egress network used by one session-specific gateway.

The gateway joins both. The agent joins only the internal network and receives the gateway's internal IP in `HTTP_PROXY`, `HTTPS_PROXY`, and lowercase equivalents. Guest DNS is set to an unused loopback resolver because the agent does not need DNS to reach that numeric proxy address.

The proxy variables are routing hints, not the security boundary. Unsetting them causes direct requests to fail on the internal network. The agent does not receive the egress network, host networking, the Docker socket, or gateway observation files.

The gateway receives only:

- read-only exact-hostname allow and ask lists;
- a read-only request handler;
- a session-private observation directory used for decision events and containment state.

It receives no workspace, synthetic home, host home, Ghost database, Docker socket, host environment, or published host port. Agent, gateway, and sentinel containers drop every Linux capability, use `no-new-privileges`, and have read-only root filesystems.

## HTTP and HTTPS

For HTTP, the gateway validates the absolute-form proxy request target and forwards it in origin form only after the hostname, port, and resolved destination addresses are allowed.

For HTTPS, the gateway validates the `CONNECT host:443` authority and then creates a byte tunnel. Ghost does not generate a root certificate, intercept TLS, decrypt traffic, inspect application content, or verify that tunneled bytes are actually TLS.

After the exact hostname decision, the gateway makes one IPv4 DNS query. Every A record in the answer set must pass validation. This validation occurs before an ASK prompt, so a user cannot approve a prohibited resolution. Ghost denies the request if resolution fails, the answer is empty or malformed, or any returned address is prohibited. After an approval, the connection uses the selected validated numeric address, so the connect operation cannot perform a second independent hostname lookup.

The prohibited classes include IPv4 unspecified/current-network, loopback, RFC1918 private, shared-address space, link-local (including `169.254.169.254`), protocol-assignment, benchmarking, multicast, reserved, and future-use ranges. Docker's normal bridge gateways are private IPv4 and are therefore denied. Raw IP requests remain denied before resolution. IPv6 upstream connections are not supported in this release: raw IPv6 is rejected and an IPv6-only DNS answer fails closed, covering IPv6 loopback, unique-local, and link-local destinations by non-support rather than partial validation.

The gateway records only the scheme, normalized destination host, port, method, request identity, policy/approval decision, containment flag, and coarse event time. It does not record resolved addresses, headers, cookies, proxy credentials, bodies, URL paths, query strings, or tunneled bytes. `NETWORK_ALLOW` means hostname, port, containment, resolution, address policy, and any required approval allowed the attempt; it does not prove that the upstream connection succeeded.

## Dynamic containment

With:

```yaml
on_decoy_access:
  severity: high
  record_incident: true
  network: deny
```

the sentinel creates a session-private containment marker before it appends concrete `DECOY_ACCESS` evidence. The gateway checks that marker before each new request. In a containment-enabled session it then creates a unique file in the sentinel's barrier-request directory, waits for the matching acknowledgement, and checks the marker again before allowing. BusyBox `inotifyd` processes its queued events serially and waits for each handler, so an access event queued before that gateway barrier publishes containment first. A missing or timed-out acknowledgement fails closed. A contained request receives `DENY` even if its hostname was originally allowlisted or had a prior session approval; it never reaches ASK. The marker is private to the session and cannot transition back to normal during that run.

The fence orders new request decisions against decoy events already present in the sentinel's inotify queue; it is not packet-level atomic revocation. A request whose barrier event is ordered before the decoy event can still be allowed, and Ghost cannot terminate an HTTP response or HTTPS tunnel that was already allowed and established. The repeated Docker integration case exercises immediate requests after access without an agent-side delay.

`on_decoy_access.network: unchanged` deliberately disables this response. It does not change the base destination allowlist.

## DNS and remaining limitations

The agent cannot use Ghost's gateway as an arbitrary DNS resolver and is configured without a usable guest resolver. The gateway performs ordinary DNS resolution only for an already approved exact hostname. Resolution validation and connection are coupled within the same request by connecting to the checked numeric address.

Known limitations include:

- DNS answers can change between separate requests; each request is resolved and validated again, but Ghost does not maintain DNSSEC state, TTL pinning, or a session-wide resolution cache and therefore does not claim to eliminate every DNS-rebinding technique;
- an approved server can redirect or relay data, although a redirect to a different hostname receives a new policy decision;
- IPv6 upstream egress is not implemented; a hostname with no acceptable IPv4 answer is denied;
- a `CONNECT` tunnel to an approved host on port 443 can carry non-TLS bytes;
- approval is limited to exact HTTP/HTTPS destinations and does not revoke a connection already established before containment;
- Docker's internal bridge remains reachable as a local link, so services deliberately bound to that per-session bridge are in the agent's reachable set;
- the gateway supports neither arbitrary TCP nor UDP, and Ghost does not inspect DNS content or detect DNS tunneling;
- abrupt host or daemon termination can temporarily leave labeled Docker objects. The next run in that project reconciles non-terminal database sessions and removes only objects whose session label, component label, and exact name all match; ambiguous ownership or cleanup failure aborts the new run.

These limitations are why Ghost claims destination and resolved-address restriction for its HTTP/HTTPS gateway, not generalized exfiltration prevention.

## Boundary security review

The review checks the explicit bypass and isolation surfaces:

| Surface | Implemented control or documented residual |
| --- | --- |
| Direct and proxy-variable bypass | Agent joins only the internal network; tests unset proxy variables and use a child process. |
| Gateway escape | Read-only root, all capabilities dropped, `no-new-privileges`, bounded PIDs/tmpfs, no sensitive mounts. Container/runtime escapes remain in Docker's trusted computing base. |
| Host networking | No container uses host networking and the proxy publishes no host port. The internal bridge-link limitation is documented above. |
| DNS paths | Agent resolver is unusable loopback; only the gateway resolves an already-approved hostname. All returned A records are validated and connection uses the selected numeric address. Changes between separate requests remain documented. |
| Allowlist parsing and hostname normalization | Strict YAML fields, exact normalized ASCII labels, no wildcard or implicit subdomain semantics. |
| Port validation | HTTP is fixed to 80 and HTTPS `CONNECT` to 443. |
| Approval precedence | Hard hostname/address/port checks and containment run before ASK; a grant is exact and containment is rechecked before connection. Non-interactive or failed approval is DENY. |
| IPv4, IPv6, and raw-IP bypass | Configuration rejects IP and numeric-IP-like entries; the gateway denies raw-IP requests; direct raw-IP traffic lacks egress. IPv6 upstream egress is fail-closed until implemented end to end. |
| Stale resources | Normal exit removes named containers and labeled networks. A project run lock distinguishes live work from interrupted sessions; next-run recovery requires matching database identity, labels, component, and exact object name and otherwise fails closed. |
| Decoy-to-containment race | The sentinel publishes the marker before evidence; every candidate allow is fenced through the same ordered inotify queue and rechecks authoritative session state. Already-authorized traffic and events ordered after the fence remain documented limitations. |
| Cross-session leakage | Networks, gateway, observation directory, marker, and persisted state are session-specific; unit tests run contained and normal sessions consecutively. |
| Sensitive request logging | Gateway log schema contains destination/method/decision fields only; unit tests inject ignored sensitive fields and verify they do not enter runtime evidence. |
| Fail-open gateway behavior | Agent has no alternate external route, so gateway startup or runtime failure fails closed. |
| Environment-secret propagation | Agent and gateway receive explicit variables only; existing isolation tests set representative host secrets. |
| Docker socket exposure | Workspace validation rejects known socket paths; agent and sidecars receive no socket mount. |
| Gateway privilege escalation | Gateway drops all capabilities, enables `no-new-privileges`, and runs as the invoking non-zero numeric UID/GID. Ghost refuses Docker execution when either host ID is root. |

## Evidence language

Ghost may establish this ordered evidence within one session:

1. a decoy file produced an open/access event;
2. containment was activated;
3. a later outbound destination request received `DENY`.

The supported conclusion is: “Outbound network activity occurred after a decoy access in the same session.”

Ghost does not trace information flow and must not describe that sequence as detected credential exfiltration.
