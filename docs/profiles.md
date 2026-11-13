# Explicit security profiles

Profiles are deterministic validation constraints over trusted `ghost.yaml`.
They do not infer intent, change settings, grant network access or authenticate
users. Omit `profile` to retain existing explicit policy semantics.

| Profile | Required constraints |
| --- | --- |
| `coding` | SHADOW with deception enabled requires decoy-triggered network denial; workspace and exact egress remain explicitly configured |
| `document-processing` | Read-only workspace, network deny with empty allow/ask, home deny |
| `sensitive-enterprise` | Read-only workspace, direct network deny, home deny; only separately configured model/read-tool capabilities; application identity/tenant checks remain external |
| `restricted` | No broker communication; same restrictions plus memory/CPU/PIDs/timeout/tmpfs ceilings no greater than defaults |

An inconsistent configuration fails before agent launch. Merely adding a profile
name does not silently rewrite a writable workspace or an allowlist. All general
configuration checks continue to apply. Profiles have no per-file selectors,
application identity, tenant scope, row-level authorization or confidentiality
classification. Read-only still allows reading **all** files exposed in the
workspace and writing ephemeral `/tmp` data or stdout. Choose an already
permission-filtered staging directory; do not mount an entire tenant database.

Python example:

```yaml
version: 1
profile: document-processing
agent:
  adapter: python
runtime:
  provider: docker
  environment: python
workspace:
  mode: read-only
network:
  mode: deny
policy:
  home: deny
```

Run `ghost init` to prepare private state without replacing existing policy,
then `ghost run agent.py`. The Python adapter accepts a relative `.py` entrypoint,
constructs a guest path beneath `/workspace` and preserves subsequent argv values.
It does not execute the entrypoint on the host. Default `command` preserves
`ghost run [--] <command> [arguments...]` unchanged.

An explicitly selected document-processing or sensitive-enterprise profile may
use a configured broker without receiving direct networking. These profiles do
not prove data locality, safe model behavior, confidentiality, user authorization
or legal compliance. The fixed service and each resource grant still require
operator review. The restricted profile forbids broker communication entirely.
