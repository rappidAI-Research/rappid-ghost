# Reviewed Ollama CPU service build

This is an **unofficial source build** of upstream Ollama 0.40.16, versioned
`0.40.16-ghost.1`. It is external model infrastructure, not an allowed Ghost
agent image or a claim about every Ollama installation.

The first full CI correctly rejected the original pinned official image for
CVE-2026-109518 (apt/libapt) and CVE-2026-78661 (`golang.org/x/net` 0.61.0).
The source graph changes only x/net to fixed 0.62.0, with checked-in module sums.
The Go application is rebuilt with fixed Go 1.26.11; original CPU inference
backends come from the exact source image digest. Apt and its library are
actually purged offline, unused GPU payloads removed, and the final image retains
the real distro/Go package inventory for the unchanged vulnerability gate.
No VEX/ignore entry, severity override or scanner-metadata deletion is used.

`sh scripts/build-ollama-service.sh` uses a temporary context containing only
this reviewed Dockerfile and two lock files. Source archive and compiler/service
images are digest-pinned. Only Go dependency retrieval has a build network;
compilation and package removal are offline. No project install/build script or
agent runs during preparation. The helper prints an inspected linux/amd64 image
content ID, which both the scanner and demo bind directly. Source/module/image
pinning and scanning do not prove absence of malicious upstream code or unknown
vulnerabilities. Docker/BuildKit and the host remain trusted.

The final service exposes no port unless an operator explicitly configures one;
the qualification script publishes none, disables cloud features, uses an
internal network, and applies non-root/read-only/capability/resource constraints.
Use a trusted TLS/authentication edge and never grant an agent raw port 11434.
