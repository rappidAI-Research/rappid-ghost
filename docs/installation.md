# Install, update and verify

The execution-qualified target is a **non-root native Linux amd64** operator with
Docker Engine and mandatory seccomp/cgroup capabilities. Python 3 is required only
for the optional installer; Go 1.26.11 is required to build from source. Arm64
binaries are cross-built but execution is unqualified. Docker Desktop, Windows,
WSL2 and rootless deployments need their own execution qualification.

## Official fixed release

Obtain and review `scripts/install.py` from the versioned official source tree
(or the release's `install.py` asset). Run it explicitly, without sudo:

```sh
python3 scripts/install.py --version v0.6.0
export PATH="$HOME/.local/bin:$PATH"
ghost version
```

The installer fetches only the fixed official release's expected amd64 asset and
checksum manifest, with HTTPS verification, restricted GitHub redirect origins,
no inherited proxy credentials and bounded downloads. It selects exactly that
asset's single SHA-256 entry; it never executes paths from the manifest. Verified
bytes replace the binary atomically. Symlink/non-regular targets and symlinked
prefix components are refused. `--prefix /absolute/real/directory` selects another
operator-owned prefix. Existing project policy/history is not modified.

SHA-256 from the same release detects corruption; it is not an independent
publisher identity. v0.6 release artifacts additionally have signed GitHub build
provenance. With the official GitHub CLI available, require it during install:

```sh
python3 scripts/install.py --version v0.6.0 --verify-attestation
```

Verification binds the bytes to this repository's release workflow and denies
self-hosted signers. It does not prove the code or GitHub runner is secure.
Alternatively download a release binary and `SHA256SUMS`, select/check the exact
asset and verify before installing:

```sh
gh attestation verify ghost_0.6.0_linux_amd64 \
  --repo rappidAI-Research/rappid-ghost \
  --signer-workflow rappidAI-Research/rappid-ghost/.github/workflows/release.yml \
  --deny-self-hosted-runners
```

No `curl | sh` step or automatic floating-version update is required. The same
installer handles an **explicit version** update, preserving the previous binary
on download/checksum/attestation failure. Review the new release's migration and
security notes first; the installer does not choose an update policy for you.

## Existing v0.5 projects

Stop active runs, back up `ghost.yaml` and the entire `.ghost` directory together,
then install v0.6. `ghost doctor --json` reports policy and catalog capabilities
without widening access. Existing YAML remains untouched; omitted evidence budget
defaults to 128 MiB. The next run migrates schema 4 to 5. The release gate builds
the exact released v0.5 source and runs a real old-to-new Docker workflow, checking
historical identity/events, original policy and completed cleanup. Downgrade to
v0.5 requires a consistent pre-upgrade backup: v0.5 refuses schema 5.
See [retention](evidence-retention.md) for exhausted storage and explicit cleanup.

## Build and inventory

```sh
make build
./bin/ghost version
```

Builds use `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` and Go 1.26.11. Release
assets include per-binary SPDX inventories derived from actual embedded Go build
information and `runtime-sboms.tar.gz` with seven CycloneDX image inventories plus
their exact source-pinned references/content IDs. The compiled module inventory
is not a file-level license audit; the image inventories describe the scanned
prepared images, not arbitrary future application dependencies. Source manifests
in `internal/compat/bundles` and `services/ollama` record reviewed artifact/module
hashes. No SBOM is a security certification. Full image scanning still rejects
HIGH/CRITICAL or EOL findings without exclusions.
