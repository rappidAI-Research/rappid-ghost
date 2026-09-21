# Security policy

Ghost is experimental security software and is not a guarantee that autonomous agents, Docker, or the host are secure.

## Reporting a vulnerability

Use GitHub's private **Report a vulnerability** flow for this repository when available. Include the affected commit or version, platform and Docker versions, configuration, reproduction steps, observed impact, and whether the issue creates a fail-open path or exposes host data.

Do not include exploit details, credentials, decoy markers, or sensitive logs in a public issue. If private vulnerability reporting is unavailable, open a minimal public issue requesting a private maintainer contact without disclosing the vulnerability.

Maintainers should acknowledge a private report before discussing disclosure timing. No response-time or remediation guarantee is made for this experimental project.

## Supported versions

The latest public release is `v0.2.0`. Reports should identify the exact affected tag or commit. No response-time or remediation guarantee is made for this experimental project.

## Scope reminders

Reports about host-resource exposure, host execution fallback, Docker/network boundary bypass, cross-session trust/state/approval leakage, approval scope widening or fail-open interaction, evidence forgery, unsupported causal claims, secret-bearing exports, workspace-inspection path escape, unsafe Prompt-Injection Guard failure, dependency substitution, or release-artifact integrity are particularly relevant. Container escapes, Docker daemon vulnerabilities, and host-kernel flaws should also be reported to the responsible upstream project when Ghost is not the vulnerable component.

Development `main` includes mandatory per-container runtime limits. Report ignored limits, unsafe timeout/cleanup behavior, or ASK overriding a runtime boundary as security defects. These limits do not byte-limit bind-mounted workspaces or retained evidence and do not guarantee host availability; see [runtime resource scope](docs/runtime-resources.md).

The v0.3 [adversarial validation matrix](docs/adversarial-validation.md) documents
controlled multi-control chains, benign prompt controls and evidence limits.
Passing the 25-scenario suite is not proof of model intent, exfiltration,
universal prompt detection or freedom from Docker/kernel vulnerabilities.
Recovery preserves observed runtime containment even when a hard process crash
preceded SQLite finalization; detailed unimported evidence can remain incomplete.

The [v0.3 release audit](docs/release-audit-v0.3.md) records fixes, the reproduced rapid-child OOM evidence loss, and its lifecycle correction. v0.3 remains unreleased. New session evidence omits command arguments; older local databases may still retain historical arguments and are not rewritten. Attached program output is not a sanitized security report.
