# Security policy

Ghost is experimental security software and is not a guarantee that autonomous agents, Docker, or the host are secure.

## Reporting a vulnerability

Use GitHub's private **Report a vulnerability** flow for this repository when available. Include the affected commit or version, platform and Docker versions, configuration, reproduction steps, observed impact, and whether the issue creates a fail-open path or exposes host data.

Do not include exploit details, credentials, decoy markers, or sensitive logs in a public issue. If private vulnerability reporting is unavailable, open a minimal public issue requesting a private maintainer contact without disclosing the vulnerability.

Maintainers should acknowledge a private report before discussing disclosure timing. No response-time or remediation guarantee is made while the project is pre-release.

## Supported versions

Security fixes for the first public release target the latest `v0.1.0` maintenance commit on `main`. No response-time or remediation guarantee is made for this experimental project.

## Scope reminders

Reports about host-resource exposure, host execution fallback, Docker/network boundary bypass, cross-session leakage, evidence forgery, or secret-bearing exports are particularly relevant. Container escapes, Docker daemon vulnerabilities, and host-kernel flaws should also be reported to the responsible upstream project when Ghost is not the vulnerable component.
