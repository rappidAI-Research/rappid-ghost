# Threat model

This document describes Ghost v0.3, not the complete Ghost vision.

## Protected environment

A developer runs an autonomous coding agent in a project containing source code and potentially untrusted content. That content may influence the agent to request credentials or other data outside the intended workspace.

The developer and local Ghost configuration are trusted. The command, project content, and processes inside the agent container are untrusted. Docker, its daemon, the host kernel, the Alpine image, and the invoking local account remain part of the trusted computing base.

## Assets

- Host files outside the configured project, especially real AWS credentials, SSH keys, and home-directory secret files.
- Service sockets and environment credentials not deliberately exposed.
- Ghost's database, session directories, policy record, and evidence trail.
- Project-file integrity when the workspace is configured read-only.
- The outbound network boundary and its per-session policy and containment state.

## Threats mitigated in v0.3

When a command is launched through `ghost run`, Ghost:

- mounts the project and a dedicated synthetic home, not the host home;
- refuses project roots that contain the host home or a known Docker socket;
- does not mount the Docker socket or Ghost database;
- masks `.ghost` and over-mounts `ghost.yaml` read-only in the guest, preventing ordinary in-container policy changes for later runs;
- passes an explicit guest environment containing only `HOME` and `PATH` rather than forwarding the host environment;
- denies networking by default;
- when explicitly enabled, places the agent on an internal network and restricts HTTP/HTTPS destinations through an exact-hostname gateway;
- prevents unsetting proxy variables, raw-IP attempts, and child processes from gaining a direct external route;
- drops Linux capabilities, requests `no-new-privileges`, and uses a read-only container root;
- never falls back to host execution when Docker or the sentinel is unavailable;
- exposes selected synthetic AWS, SSH, and `.env` resources under `SHADOW` policy;
- leaves those resources absent under `DENY` or when deception is disabled; and
- records evidence when the sentinel observes an open/access event for an explicit decoy file;
- records destination-policy decisions without request secrets; and
- can deterministically change that session's network state to `CONTAINED` after a decoy access.

Example: an agent requests `~/.aws/credentials`. Ghost does not check whether the host file exists. With `policy.home: deny`, the guest path is absent. With `policy.home: shadow`, the guest receives a newly generated, nonfunctional Ghost file and an observed access can trigger an incident.

Isolation, deception, and detection are distinct: the mount design prevents Ghost from exposing the corresponding real source; the decoy supplies a controlled alternative; the sentinel supplies evidence that the alternative was opened or accessed.

## Threats not yet mitigated

- Prompt injection or malicious instructions in files, tool output, issues, or web content.
- Fine-grained policy for arbitrary workspace or home paths.
- Semantic data-flow, taint, causal provenance, or proof that decoy content was exfiltrated.
- TLS interception, request-content inspection, arbitrary TCP/UDP, DNS tunneling detection, and advanced DNS rebinding defenses.
- MCP servers and future non-HTTP network paths.
- Malicious dependencies or tools operating inside the explicitly mounted workspace.
- Cross-event causality beyond events occurring in the same session.

## Outside scope

- Container escapes, Docker daemon vulnerabilities, and host-kernel vulnerabilities.
- Attacks through project content intentionally exposed in read-write mode.
- Side channels and denial of service against CPU, memory, disk, or the Docker daemon.
- Commands launched outside Ghost.
- Host resources explicitly exposed by future policy.
- Supply-chain trust of the base image or binaries executed in it.
- Multi-user authorization, cloud isolation, authentication, telemetry, and hosted services.

The sentinel observes inotify events for known files; it does not identify semantic intent or prove which high-level agent instruction caused the access. A privileged host actor remains capable of affecting local runtime state and is not an adversary this milestone contains.

An approved hostname can resolve to a private destination or operate as a relay. A same-session `DECOY_ACCESS` followed by `NETWORK_DENY` establishes event ordering and enforcement, not causal data flow or credential exfiltration.
