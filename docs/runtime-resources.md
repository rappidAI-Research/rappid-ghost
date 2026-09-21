# Integrated runtime resources (unreleased v0.3)

The workflow remains `ghost init`, then `ghost run -- <agent>`. Limits are mandatory Docker/cgroup boundaries below ALLOW/DENY/SHADOW/ASK. They never ask permission to continue, retry with larger limits, or fall back to the host.

## Defaults and scope

| Boundary | Agent | Sentinel | Gateway |
| --- | --- | --- | --- |
| RAM | 2048 MiB | 128 MiB | 128 MiB |
| Additional swap | 0 | 0 | 0 |
| CPU quota | 1 CPU | 0.25 CPU | 0.25 CPU |
| Processes/threads | 256 | 32 | 64 |
| `/tmp` tmpfs | 64 MiB | no writable `/tmp` | 16 MiB |
| Private shared memory | 16 MiB | 16 MiB | 16 MiB |
| Root filesystem | read-only | read-only | read-only |

The agent also retains the existing 1-MiB private `.ghost` tmpfs mask. Tmpfs consumes the container's memory budget. CPU quotas throttle continuously, include descendants, and are ceilings rather than reserved host capacity. PID cgroups count threads as well as processes. Children cannot obtain another resource boundary through fork/exec. Docker logging is disabled for these ephemeral containers; attached output still works. Ghost retains at most 64 KiB of agent stderr for error diagnostics.

The prepared runtime has a **3600-second** deadline, including image/container/network/sidecar setup. On cancellation or a terminal resource observation, Ghost addresses the agent's immutable Docker ID, requests SIGTERM, allows **5 seconds** of grace, and lets Docker force SIGKILL. A failed stop has an explicit KILL fallback; final force removal covers the whole container tree. Sidecars, approval broker, and session networks are cleaned using existing lifecycle paths. Cleanup and evidence operations use separate bounded contexts so cancellation does not suppress cleanup or final persistence. These operations add bounded time after the execution deadline; the CLI is not promised to return at exactly second 3600.

## Optional configuration

Older version-1 configurations need no edits. Omitted fields receive defaults. Explicit zero, negative, overflowing, unknown, or out-of-range values fail validation.

```yaml
runtime:
  provider: docker
  limits:
    memory_mib: 2048
    cpu_millis: 1000
    pids: 256
    timeout_seconds: 3600
    grace_seconds: 5
    tmp_mib: 64
```

Allowed inclusive ranges: memory 64–65536 MiB; CPU 100–8000 milli-CPUs; PIDs 16–4096; runtime 1–86400 seconds; grace 1–30 seconds; `/tmp` 1–1024 MiB and no larger than memory. Operators choosing larger settings must provision suitable host capacity. Sidecar limits remain fixed. Configuration is trusted project policy, masked read-only from the guest; the agent cannot edit limits for the next run.

## Docker and host compatibility

Preflight requires Docker to report Linux memory, swap, CPU-period/quota, and PID-limit support. The created agent's HostConfig must retain the requested limits, read-only root, and enabled OOM killer before its command starts. Sidecar configurations are checked before agent launch too. Missing or ignored capabilities fail closed. Rootless Docker additionally requires cgroup v2 and the systemd cgroup driver with controllers delegated to Docker; Ghost never adds privileges or drops limits to accommodate an unsupported host.

Ghost requires Docker to report its built-in default seccomp profile. It does not install a bespoke profile or use `seccomp=unconfined`. Docker's maintained default supports ordinary shell/developer workloads without adding a second profile maintenance burden. The base image still supplies only its existing Alpine tools; this milestone does not add package managers, compilers, or arbitrary agents to that image. AppArmor is optional daemon/host hardening: Ghost neither requires it nor disables it. Docker, its runtime, and the host kernel remain trusted.

See Docker's [resource constraints](https://docs.docker.com/engine/containers/resource_constraints/), [default seccomp profile](https://docs.docker.com/engine/security/seccomp/), and [rootless resource-limit requirements](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources).

## Evidence and policy precedence

The existing `RESOURCE_LIMIT_TRIGGERED` event is used with subject `docker`, `classification: operational`, and one observed kind:

| Kind | Evidence | Numeric limit unit |
| --- | --- | --- |
| `session_timeout` | Ghost's configured runtime deadline expired | seconds |
| `oom_termination` | Docker reports `State.OOMKilled` or an exact-container `oom` event | bytes |
| `process_limit_reached` | Docker's sampled process/thread count is at or above the configured PID ceiling | processes/threads |

A plain exit 137 is not OOM evidence. CPU throttling and tmpfs ENOSPC are enforced but do not generate invented events. Kernel PID enforcement applies continuously; Docker process-count sampling can miss a brief rejected fork and is not a complete count of fork failures. A reported sustained saturation is terminated; any observation failure during live execution also stops the session rather than disabling the check. Sidecar health failures remain setup/runtime failures rather than fabricated agent OOM evidence.

Resource observations go through the existing validated signal/event/SQLite pipeline and appear as evidence-linked provenance signals and in the automatic summary, including unsuccessful runs. The session fails; existing containment state remains monotonic and is not changed solely by an operational limit. Incidents do not infer hostile intent from timeout/OOM. ASK cannot change or override these controls. The same event type still reports bounded Prompt-Injection Guard inspection separately.

## Known limits

- Bind-mounted workspace bytes, retained SQLite/observation data, and aggregate host disk usage have **no reliable byte quota** in the current architecture. Docker tmpfs limits are not a workspace quota. No promise of universal disk-abuse prevention is made.
- Limits are per container/session; independent projects can run concurrently. There is no host-wide admission control, aggregate memory reservation, or guarantee that other host processes remain responsive.
- Docker or host failure can prevent timely termination/removal. Ghost reports cleanup failure without claiming success; hard cgroup ceilings still apply while the daemon/kernel enforce them. Existing recovery handles recorded interrupted sessions. SIGKILL of Ghost or a host crash cannot guarantee its userspace deadline continues running.
- Docker PID/OOM observations are operational evidence, not proof of model intent, prompt injection, or a complete attack detector. An OOM observation does not prove that only this container caused host memory pressure.
- Read-only roots, seccomp, cgroups, and non-root identities reduce exposure; they are not perfect container isolation or protection against daemon/kernel vulnerabilities.

Adversarial CLI integration also combines a SHADOW-triggered containment event
with a mandatory timeout and verifies both survive in the failed session summary.
Runtime limits remain outside ASK. A separate real Ghost-process crash test
checks owned-resource cleanup and recovery of uncommitted containment; see the
[validation matrix](adversarial-validation.md).
