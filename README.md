# Ghost

> A deception-aware security runtime for autonomous AI agents.

Ghost controls what autonomous AI agents can access — and, eventually, what they believe they accessed.

Ghost is currently experimental. Milestone 1 establishes a deterministic, local execution lifecycle around Docker with YAML configuration and SQLite evidence. It does not yet implement active deception or content-aware threat detection.

## Why Ghost

Autonomous coding agents act on files, commands, and tool output that may contain untrusted instructions. A useful security layer must enforce resource exposure independently of the model and leave evidence of what it actually did.

Ghost models three canonical policy outcomes:

- `ALLOW` — expose the real permitted resource.
- `DENY` — refuse access.
- `SHADOW` — expose a controlled synthetic resource instead of the real resource.

`SHADOW` is represented in the domain and event model, but synthetic resources are **not implemented in v0.1**.

## Current capabilities

Ghost v0.1 can:

- initialize a project with a small, strictly validated `ghost.yaml`;
- execute a command in an ephemeral Docker container;
- mount the current project at `/workspace` in read-write or read-only mode;
- reject project roots that would expose the user's whole home directory or a known Docker socket;
- disable guest networking and avoid host-home or Docker-socket mounts;
- mask host-side `.ghost` data from the guest container;
- persist session and process lifecycle events in SQLite; and
- inspect the newest or a specific persisted session.

Ghost v0.1 does **not** inspect prompt content, detect prompt injection, monitor filesystem operations, intercept MCP or HTTP traffic, assign dynamic risk, create decoys, or provide a web interface. It never calls an LLM or external API.

## Requirements

- Go 1.26 or newer to build from source.
- A working local Docker CLI and daemon to execute commands.

The default image is `alpine:3.22`. Docker may need to pull it once. Commands unavailable in that minimal image fail clearly; Ghost does not fall back to host execution.

## Build

```sh
make build
./bin/ghost version
```

Native Go commands work as well:

```sh
go build -o bin/ghost ./cmd/ghost
```

## Quick start

Initialize Ghost in the project you want to expose:

```sh
ghost init
```

This creates `ghost.yaml`, `.ghost/ghost.db`, and `.ghost/sessions/`. Re-running `ghost init` never overwrites an existing configuration. Commit `ghost.yaml` if it is project policy; do not commit `.ghost/`.

Run a command. The `--` separator is required and preserves argument boundaries:

```sh
ghost run -- echo "hello from ghost"
```

Inspect the newest session or address one by ID:

```sh
ghost inspect latest
ghost inspect 12345678-1234-4234-8234-123456789abc
```

The default configuration is:

```yaml
version: 1
runtime:
  provider: docker
workspace:
  mode: read-write
network:
  mode: none
policy:
  home: deny
```

Only values implemented by the current release are accepted. See `ghost.example.yaml` for comments.

## Repository structure

```text
cmd/ghost/          CLI entry point
internal/cli/       command parsing and presentation
internal/config/    YAML schema and validation
internal/events/    event domain types and taxonomy
internal/policy/    ALLOW / DENY / SHADOW values
internal/runtime/   runtime interface and Docker implementation
internal/session/   session domain and lifecycle manager
internal/storage/   SQLite schema, migrations, and queries
docs/               architecture and security documentation
```

## Security model

Ghost asks Docker for no guest network, no Linux capabilities, `no-new-privileges`, a read-only root filesystem, an ephemeral container, and no mounts other than the project workspace. `.ghost` is hidden inside the guest with a nested `tmpfs` mount. The invoking numeric UID/GID is used when available.

These are Docker configuration properties, not a claim that containers are unbreakable. Ghost inherits Docker, image, daemon, host-kernel, and local-user risks. In read-write mode, the guest is intentionally allowed to change project files. Commands run outside Ghost are outside its control.

Read [the security model](docs/security-model.md) and [threat model](docs/threat-model.md) before relying on this milestone.

## Development

```sh
make fmt
make test
make vet
```

Docker integration is opt-in so normal tests and CI remain reliable:

```sh
GHOST_DOCKER_INTEGRATION=1 go test ./internal/runtime -run TestDockerIntegration -v
```

See [architecture](docs/architecture.md) and [design principles](docs/design-principles.md) for the intended evolution of the core.

## License

Apache License 2.0. See [LICENSE](LICENSE).
