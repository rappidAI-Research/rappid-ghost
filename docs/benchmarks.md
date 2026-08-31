# GhostBench

GhostBench is Ghost's local, deterministic security-property validation suite. It answers which concrete controls were observed in a controlled run. It does not calculate a security score and does not use an LLM or external judging service.

## Running the suite

Build Ghost, then run:

```sh
ghost bench
ghost bench --json
ghost bench --scenario shadow-credentials
```

The complete suite requires a working Docker CLI and daemon and may pull `alpine:3.22` once. It needs no account, real credential, paid API, public test target, or attacker infrastructure. Docker-dependent scenarios report `SKIP` when Docker is unavailable. The fail-closed scenario is deliberately runnable without Docker.

## Result semantics

| Status | Meaning |
|---|---|
| `PASS` | Every documented assertion for that scenario was actually observed. |
| `FAIL` | A required assertion failed, or an environment that passed preflight failed while executing the scenario. |
| `SKIP` | A required execution dependency was unavailable; the property was not tested. |

The process exits nonzero when any scenario is `FAIL`. `SKIP` does not silently become success and is counted separately. There is intentionally no aggregate security score.

The JSON format is versioned at `1`. Each result includes the scenario identity, expected property, status, evidence-based detail, and zero or more evidence bundles. Evidence bundles contain session IDs, event IDs, incident IDs, and provenance node/edge IDs. They never contain captured command output, decoy markers, credential values, request headers, cookies, or bodies.

## Scenarios

| Scenario | Required observation |
|---|---|
| `host-home-isolation` | A controlled host-only file outside the workspace exists on the host, is absent at the same path in the guest, and remains unchanged. |
| `shadow-credentials` | `~/.aws/credentials` returns independently generated Ghost material; the controlled host fixture is absent from output; the decoy is triggered and has event, provenance, and incident evidence. |
| `deny-sensitive-resource` | Under home `DENY`, the AWS path is absent, no decoy is created, and `POLICY_DENY` is stored. |
| `network-deny` | A controlled local HTTP fixture is unreachable from a guest launched with network `DENY`. The command also verifies that `wget` exists before testing the connection. |
| `network-allowlist` | `allowed.test` succeeds through the gateway and `denied.test` receives `DENY`; both decisions are stored. Matching is exact. |
| `direct-egress-bypass` | A child process unsets all proxy variables and attempts the fixture's raw IP. It cannot reach the fixture or the gateway. |
| `dynamic-containment` | An initial allowlisted request succeeds, AWS decoy access is observed, containment activates, and a later request to the same allowlisted host receives a contained `DENY`. Provenance and incident relationships must exist. |
| `session-isolation` | One of two sessions is contained. The other remains uncontained, reaches the allowed fixture, has an untouched independently generated decoy, and contains no incidents or foreign events. |
| `fail-closed-runtime` | The production Docker runtime is pointed at a deliberately missing executable. A host marker command is not executed, the session is persisted as failed, and invalid network policy is rejected. |
| `safe-baseline` | `echo hello` succeeds while its prepared decoy remains untouched and no decoy access, containment, security incident, or reconstructed incident appears. |

## Local network fixture

Network scenarios create a short-lived Alpine HTTP fixture on a randomly named internal Docker bridge with no external route. Only the Ghost egress gateway is attached to that fixture network. The agent stays on its own per-session `--internal` network and cannot join the fixture network directly. The fixture publishes no host port, mounts no host files, drops all Linux capabilities, enables `no-new-privileges`, applies a PID limit, and uses a read-only root filesystem with a small `/tmp` tmpfs.

The gateway test attachment is an explicit runtime option used only by the benchmark and Docker integration harness. It attaches the gateway, never the untrusted agent. Normal `ghost run` behavior is unchanged.

Benchmark projects, synthetic homes, SQLite databases, and controlled host fixtures are created in private temporary directories and removed after the result is assembled. Fixture containers and networks are also removed. A hard process or Docker-daemon crash can still leave labeled Docker objects, matching the runtime's documented crash limitation.

## Canonical demonstration

Run:

```sh
ghost bench --scenario dynamic-containment
```

The scenario executes this evidence sequence through the actual Ghost runtime:

1. request `allowed.test` through the gateway;
2. open the synthetic AWS credential file;
3. observe `DECOY_ACCESS` and activate session containment;
4. attempt `allowed.test` again;
5. observe a contained `NETWORK_DENY`;
6. reconstruct provenance and an incident from the stored events.

The output reports only whether these observations occurred. It does not claim that credential content entered the second request, that the process intended exfiltration, or that the temporal sequence proves causality.

## Regression use

The production scenarios are also used by an opt-in integration test:

```sh
GHOST_DOCKER_INTEGRATION=1 go test ./internal/bench -run TestGhostBenchDockerIntegration -v
```

Normal CI remains reliable without Docker: the integration test skips unless explicitly enabled, while unit tests exercise schema stability, status accounting, CLI parsing, failure closure, and secret-minimized output.

## What GhostBench does not prove

GhostBench does not prove that Ghost is unbreakable, Docker cannot be escaped, every prompt injection is stopped, all exfiltration is detected, arbitrary malware is contained, every AI agent is safe, or causal intent has been reconstructed. It does not test arbitrary TCP/UDP, TLS content, DNS tunneling, kernel vulnerabilities, side channels, or future resource policies. Its claims are limited to the scenario, fixture, platform, runtime version, and evidence recorded during that run.
