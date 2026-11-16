#!/bin/sh
# Emit exactly one inspected content ID, never accept a user-selected image.
set -eu
umask 077
test "$#" = 0
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
cp "$repo_dir/services/ollama/Dockerfile" "$build_dir/Dockerfile"
cp "$repo_dir/services/ollama/go.mod.lock" "$build_dir/go.mod.lock"
cp "$repo_dir/services/ollama/go.sum.lock" "$build_dir/go.sum.lock"
timeout 12m docker buildx build --load --progress=plain --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=0 --iidfile "$build_dir/image-id" "$build_dir" >&2
image_id=$(cat "$build_dir/image-id")
printf '%s\n' "$image_id" | grep -Eq '^sha256:[a-f0-9]{64}$'
test "$(docker image inspect --format '{{.Id}} {{.Os}} {{.Architecture}} {{index .Config.Labels "org.opencontainers.image.version"}}' "$image_id")" = "$image_id linux amd64 0.40.16-ghost.1"
printf '%s\n' "$image_id"
