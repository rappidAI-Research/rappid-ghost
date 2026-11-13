# Configuration reference

`ghost.yaml` is explicitly trusted local policy, never an agent instruction.
`ghost init` creates defaults only when absent. YAML uses version 1, rejects unknown
keys, duplicate/multiple documents and invalid values. Reads require a regular,
non-symlink file, use one nonblocking descriptor and stop at 64 KiB. Existing valid
v0.3 configurations keep their behavior; new fields default to Alpine/command and
no named profile.

| Field | Accepted values / default |
| --- | --- |
| `version` | `1` |
| `profile` | Omitted, `coding`, `document-processing`, `restricted`; [constraints](profiles.md) |
| `agent.adapter` | `command` (default), `python` |
| `runtime.provider` | `docker` only |
| `runtime.environment` | `alpine` (default), `python`; no arbitrary image URLs |
| `workspace.mode` | `read-write` (default), `read-only`; whole workspace, no per-file selectors |
| `network.mode` | `deny` (default), `allowlist`; legacy `none` means deny |
| `network.allow` / `network.ask` | Explicit exact hostnames; empty by default; no overlapping entries, wildcards, private destinations or arbitrary ports |
| `policy.home` | `shadow` (default), `deny`; no host-home access |
| `deception.enabled` | `true` by default |
| `deception.resources.aws_credentials` / `ssh_private_key` / `env_file` | `true` by default; synthetic resources only |
| `on_decoy_access.severity` | `low`, `medium`, `high` (default) |
| `on_decoy_access.record_incident` | `true` by default |
| `on_decoy_access.network` | `deny` (default), `unchanged`; profile may require deny |

| `runtime.limits` field | Default | Accepted inclusive range |
| --- | --- | --- |
| `memory_mib` | 2048 | 64–65536 |
| `cpu_millis` | 1000 | 100–8000 |
| `pids` | 256 | 16–4096 |
| `timeout_seconds` | 3600 | 1–86400 |
| `grace_seconds` | 5 | 1–30 |
| `tmp_mib` | 64 | 1–1024, no greater than memory |

Limits include descendants and remain mandatory for every catalog environment.
There is no host environment passthrough, secret injection, image override,
post-detection permission grant, dynamic adapter loader or host fallback.

## Troubleshooting

- **Docker missing/unreachable:** install/start supported Linux Docker Engine and
  verify `docker info`. Do not run the same agent unsandboxed as a workaround.
- **Docker incompatible:** configure memory/swap/CPU/PID cgroups and built-in seccomp.
  Rootless Docker needs cgroup v2/systemd delegation. No unlimited fallback exists.
- **Command unavailable:** host tools are not guest tools. For a `.py` entrypoint,
  explicitly set both Python environment and adapter; Node/Go/Rust toolchains are
  not included. `command` means a guest executable, not a host executable.
- **Invalid profile:** set each required restrictive field explicitly. The error
  names the required constraints; Ghost does not auto-rewrite permissions.
- **Read-only write failure:** emit to stdout or bounded temporary storage, or
  explicitly choose a reviewed writable-workspace policy outside read-only profiles.
- **Model API / package download blocked:** network deny is intentional. Approving
  an exact hostname does not provision credentials or authorize tool operations.
- **Local LLM unavailable:** loopback/private access is unsupported in v0.4. Do not
  broaden ranges; see the [future broker design](tool-gateway-design.md).
- **Recovery/cleanup pending:** restore Docker availability and rerun. Ghost retries
  only exactly owned resources; do not remove private session state to hide a failure.

Doctor output is advisory and returns success when it could produce a report,
even when that report lists missing prerequisites. Automation must inspect JSON
fields; a successful doctor process is not permission to execute an agent.
