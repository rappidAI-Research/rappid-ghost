# Native local Ollama qualification (development)

After `make build`, run `sh scripts/test-ollama.sh` from the repository root.
Requires native Linux amd64 Docker Engine/BuildKit, Go 1.26.11, GNU timeout,
Python 3, curl and OpenSSL. This candidate is not qualified until its full gate passes.

The script builds a checksum-pinned Ollama 0.40.16 source with Go 1.26.11 and
`golang.org/x/net` 0.62.0. The known-vulnerable apt package manager and library
are actually purged and unused GPU backends omitted from the final CPU service.
The resulting **unofficial** version is `0.40.16-ghost.1`, not an upstream release.
All module versions/sums are reviewed in `services/ollama`; no project code is
used as build context. Final image scanning remains mandatory with no exclusions.

A revision/SHA-pinned 101 MB SmolLM2 GGUF is imported offline. The model service
has a private internal Docker network, no published port, no cloud route and
bounded CPU/RAM/PIDs/tmp storage. Its plaintext port is reachable only by trusted
setup/edge infrastructure, not by the Ghost agent. The trusted loopback TLS edge
requires a synthetic bearer credential, binds one numeric local upstream and
one model, and permits finite native text chat only. It is an example service
front, not employee/tenant authentication or a general proxy.

Ghost's existing host broker authenticates that exact TLS origin/certificate,
keeps its credential out of the guest and forwards native `/api/chat` only.
The agent has `network=none`, tests direct model/external denial and rejects
model-management/foreign-model calls before requiring real generated tokens.
`OLLAMA_INFERENCE_OK` and exit success prove this fixture, not model usefulness.
The script verifies cleanup; forced process death can leave external demo Docker
objects labeled `ghost.demo=ollama-v06`, which are outside Ghost session recovery.

Do not use real personal data. A production application must own identities,
authorization, model deployment/retention and its TLS edge. `keep_alive=0` requests
unloading; it does not prove memory erasure or prevent service-side retention.
