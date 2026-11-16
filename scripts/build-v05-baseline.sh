#!/bin/sh
# Compile the independently released source, never a simulated old-code path.
set -eu
baseline_sha=970631de9872e2eedcc3523318103d100a4b70fc
case "${1:-}" in /*) baseline_binary=$1;; *) echo 'Supply an absolute output path' >&2; exit 1;; esac
if ! git show-ref --verify --quiet refs/tags/v0.5.0; then
 git fetch --no-tags origin refs/tags/v0.5.0
 baseline_tag=$(git rev-parse --verify 'FETCH_HEAD^{commit}')
else
 baseline_tag=$(git rev-parse --verify 'refs/tags/v0.5.0^{commit}')
fi
test "$baseline_tag" = "$baseline_sha"
baseline_source=$(mktemp -d)
trap 'rm -rf -- "$baseline_source"' EXIT HUP INT TERM
git archive "$baseline_sha" | tar -xf - -C "$baseline_source"
(cd "$baseline_source" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$baseline_binary" ./cmd/ghost)
test "$("$baseline_binary" version)" = 'ghost 0.5.0'
