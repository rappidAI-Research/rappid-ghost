# Network security

Ghost's network boundary, introduced in v0.3 and unchanged in v0.5, implements narrow destination control for outbound HTTP and HTTPS. It does not claim to be a general network firewall or content-loss-prevention system.

## Modes and matching

`network.mode: deny` is the safe default. The agent container uses Docker network mode `none`.

`network.mode: allowlist` requires one or more exact ASCII hostnames:

```yaml
network:
  mode: allowlist
  allow:
    - github.com
    - api.github.com
```

Configuration and request hostnames are lowercased and a single final DNS root dot is removed. Labels are validated, duplicates are rejected after normalization, and raw IPv4, IPv6, numeric-IP-like, wildcard, URL, and host-with-port entries are rejected. An entry for `github.com` does not authorize any subdomain.

Only HTTP on destination port 80 and HTTPS `CONNECT` on destination port 443 are supported. Ports are not configurable in this milestone.

## Per-session topology

Allowlist sessions use two fresh Docker bridge networks:

- an `--internal` agent network, which does not provide direct external egress;
- a separate egress network used by one session-specific gateway.

The gateway joins both. The agent joins only the internal network and receives the gateway's internal IP in `HTTP_PROXY`, `HTTPS_PROXY`, and lowercase equivalents. Guest DNS is set to an unused loopback resolver because the agent does not need DNS to reach that numeric proxy address.

The proxy variables are routing hints, not the security boundary. Unsetting them causes direct requests to fail on the internal network. The agent does not receive the egress network, host networking, the Docker socket, or gateway control files.

The gateway receives only:

- a read-only exact-hostname allowlist;
- a read-only request handler;
- a session-private observation directory used for decision events and containment state.

It receives no workspace, synthetic home, host home, Ghost database, Docker socket, host environment, or published host port. Agent, gateway, and sentinel containers drop every Linux capability, use `no-new-privileges`, and have read-only root filesystems.

## HTTP and HTTPS

For HTTP, the gateway validates the absolute-form proxy request target and forwards it in origin form only after the hostname and port are allowed.

For HTTPS, the gateway validates the `CONNECT host:443` authority and then creates a byte tunnel. Ghost does not generate a root certificate, intercept TLS, decrypt traffic, inspect application content, or verify that tunneled bytes are actually TLS.

The gateway records only the scheme, normalized destination host, port, method, policy decision, containment flag, and coarse event time. It does not record headers, cookies, proxy credentials, bodies, URL paths, query strings, or tunneled bytes. `NETWORK_ALLOW` means the destination policy allowed the attempt; it does not prove that DNS resolution or the upstream connection succeeded.

## Dynamic containment

With:

```yaml
on_decoy_access:
  severity: high
  record_incident: true
  network: deny
```

the sentinel appends concrete `DECOY_ACCESS` evidence and immediately creates a session-private containment marker. The gateway checks that marker before each new request and, in a containment-enabled decoy session, performs a brief local recheck before allowing. A contained request receives `DENY` even if its hostname was originally allowlisted. The marker is private to the session and remains effective until that session ends.

The residual race is the interval between the kernel queuing the inotify event and the sentinel handler creating the marker. Ghost minimizes it by keeping enforcement local and checking shared state in the gateway for every request, but it does not claim a zero-width race. The Docker integration suite exercises an immediate request after access without an intentional delay.

`on_decoy_access.network: unchanged` deliberately disables this response. It does not change the base destination allowlist.

## DNS and remaining limitations

The agent cannot use Ghost's gateway as an arbitrary DNS resolver and is configured without a usable guest resolver. The gateway performs ordinary DNS resolution only for an already approved exact hostname.

Known limitations include:

- DNS rebinding and changes between repeated resolutions are not prevented;
- an approved hostname can resolve to loopback, private, or otherwise sensitive addresses from the gateway's perspective;
- an approved server can redirect or relay data, although a redirect to a different hostname receives a new policy decision;
- a `CONNECT` tunnel to an approved host on port 443 can carry non-TLS bytes;
- Docker's internal bridge remains reachable as a local link, so services deliberately bound to that per-session bridge are in the agent's reachable set;
- the gateway supports neither arbitrary TCP nor UDP, and Ghost does not inspect DNS content or detect DNS tunneling;
- abrupt host or daemon termination can leave labeled Docker objects, although normal errors, cancellation, and command exit remove agent, gateway, and network objects.

These limitations are why v0.3 claims destination restriction for outbound HTTP/HTTPS, not generalized exfiltration prevention.

## Milestone security review

The v0.3 review checked the explicit bypass and isolation surfaces:

| Surface | Implemented control or documented residual |
| --- | --- |
| Direct and proxy-variable bypass | Agent joins only the internal network; tests unset proxy variables and use a child process. |
| Gateway escape | Read-only root, all capabilities dropped, `no-new-privileges`, bounded PIDs/tmpfs, no sensitive mounts. Container/runtime escapes remain in Docker's trusted computing base. |
| Host networking | No container uses host networking and the proxy publishes no host port. The internal bridge-link limitation is documented above. |
| DNS paths | Agent resolver is unusable loopback; only the gateway resolves an already-approved hostname. Rebinding remains documented. |
| Allowlist parsing and hostname normalization | Strict YAML fields, exact normalized ASCII labels, no wildcard or implicit subdomain semantics. |
| Port validation | HTTP is fixed to 80 and HTTPS `CONNECT` to 443. |
| IPv4, IPv6, and raw-IP bypass | Configuration rejects IP and numeric-IP-like entries; the gateway denies raw-IP requests; direct raw-IP traffic lacks egress. |
| Stale resources | Normal exit, startup failure, cancellation, and gateway failure remove named containers and labeled networks. Abrupt-process residue remains documented. |
| Decoy-to-containment race | Live shared marker is checked for every request; the bounded but nonzero inotify-handler race is documented and exercised without an agent-side test delay. |
| Cross-session leakage | Networks, gateway, observation directory, marker, and persisted state are session-specific; unit tests run contained and normal sessions consecutively. |
| Sensitive request logging | Gateway log schema contains destination/method/decision fields only; unit tests inject ignored sensitive fields and verify they do not enter runtime evidence. |
| Fail-open gateway behavior | Agent has no alternate external route, so gateway startup or runtime failure fails closed. |
| Environment-secret propagation | Agent and gateway receive explicit variables only; existing isolation tests set representative host secrets. |
| Docker socket exposure | Workspace validation rejects known socket paths; agent and sidecars receive no socket mount. |
| Gateway privilege escalation | Gateway drops all capabilities and enables `no-new-privileges`. Invoking Ghost as host root retains the numeric-UID limitation described in the security model. |

## Evidence language

Ghost may establish this ordered evidence within one session:

1. a decoy file produced an open/access event;
2. containment was activated;
3. a later outbound destination request received `DENY`.

The supported conclusion is: “Outbound network activity occurred after a decoy access in the same session.”

Ghost does not trace information flow and must not describe that sequence as detected credential exfiltration.
