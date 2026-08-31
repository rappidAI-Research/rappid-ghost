# Contributing to Ghost

Ghost is security-sensitive software. Keep changes small, deterministic, and evidence-backed. Enforcement must not depend on an LLM, external API, or implicit host fallback.

## Development setup

Use Go 1.26 or newer. Linux with Docker Engine is the release-qualified development target; run Ghost as a non-root user with a numeric UID/GID.

```sh
make check-fmt
make vet
make test
make race
make build
```

Run the Docker-backed security checks separately:

```sh
GHOST_DOCKER_INTEGRATION=1 go test ./internal/bench ./internal/runtime ./internal/session -run Docker -v
make bench-release
```

`make bench-release` fails on both `FAIL` and `SKIP`. Do not report an unavailable Docker scenario as passed.

## Pull requests

- Add regression tests for changes to policy, isolation, deception, networking, persistence, evidence, or cleanup.
- Document the exact security property demonstrated and any remaining limitation.
- Keep JSON formats versioned and free of command output, decoy contents, headers, cookies, bodies, and credential material.
- Preserve existing migrations; never recreate a user's database destructively.
- Do not commit real secrets or credentials, even as test fixtures.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue with exploit details.
