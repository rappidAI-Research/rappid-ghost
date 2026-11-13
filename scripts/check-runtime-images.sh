#!/bin/sh
# Source-pinned scanner and image catalog; no ignored/unfixed HIGH or CRITICAL findings.
set -eu
scan_dir=$(mktemp -d)
trap 'rm -rf "$scan_dir"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --retry 2 --max-time 120 \
  https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz \
  --output "$scan_dir/trivy.tar.gz"
printf '%s  %s\n' bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf "$scan_dir/trivy.tar.gz" | sha256sum --check --status
tar -xzf "$scan_dir/trivy.tar.gz" -C "$scan_dir" trivy
go run ./internal/compat/cmd/images > "$scan_dir/images"
# Also qualify the externally operated local-model demo service, not an agent runtime.
printf '%s\n' 'ghcr.io/ggml-org/llama.cpp:server@sha256:e3032ea0712da96dec820c770626385de4322dd06619fb5829256a504bbc9375' >> "$scan_dir/images"
while IFS= read -r image; do
  test -n "$image"
  "$scan_dir/trivy" --config /dev/null --cache-dir "$scan_dir/cache" image \
    --no-progress --disable-telemetry --exit-on-eol 1 --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed=false \
    --ignorefile /dev/null --timeout 3m "$image"
done < "$scan_dir/images"
