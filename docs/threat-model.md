# Threat model

This document describes the v0.1 threat model, not the complete Ghost vision.

## Protected environment

A developer runs an autonomous coding agent in a project containing source code and potentially untrusted content. That content may try to influence the agent into reading host data, contacting remote systems, or executing destructive commands outside the intended workspace.

The developer and local Ghost configuration are trusted. The command executed through Ghost, its arguments, project content, and processes created inside the container are untrusted. Docker, its configured daemon, the host kernel, and the selected base image are dependencies in the trusted computing base for this milestone.

## Assets

- Files outside the configured project workspace, especially the host home directory.
- Local credentials and service sockets not deliberately exposed.
- Ghost's session database and evidence trail.
- Network-accessible systems that an untrusted process might contact.
- Integrity of project files when the workspace is configured read-only.

## Threats mitigated in v0.1

When commands are launched through `ghost run`, Ghost reduces exposure by:

- mounting only the current project at `/workspace`;
- not mounting the host home directory or Docker socket;
- disabling container networking;
- dropping Linux capabilities and enabling `no-new-privileges`;
- using a read-only container root filesystem;
- masking `.ghost` inside the workspace mount with a private `tmpfs`;
- optionally mounting the project read-only;
- refusing execution when Docker is unavailable instead of falling back to the host; and
- persisting an execution lifecycle for later inspection.

These controls apply only to commands actually started through Ghost.

## Planned threats, not yet mitigated

- Prompt injection or malicious instructions in files, tool output, issues, or web content.
- Attempts that should receive synthetic `SHADOW` resources rather than denial.
- Fine-grained filesystem policy inside the exposed workspace.
- Semantic data-flow and provenance tracking.
- MCP, HTTP, or other agent-tool interception.
- Policy decisions based on process ancestry, content sensitivity, or resource semantics.
- Detection and correlation of higher-level security incidents.

## Outside scope

- A compromised Docker daemon, container runtime, or host kernel.
- Docker/container escape vulnerabilities.
- Protection for commands the developer or agent runs outside Ghost.
- Denial of service against CPU, memory, disk, or the Docker daemon; v0.1 sets a PID limit but no complete resource budget.
- Malicious modification of project files when `workspace.mode` is `read-write`.
- Supply-chain trust of commands, dependencies, or the base image.
- Multi-user authorization, remote execution, cloud isolation, and hosted service security.
