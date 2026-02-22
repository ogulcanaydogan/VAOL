#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

to_minor() {
  awk -F. '{print $1 "." $2}' <<<"$1"
}

mapfile -t workflow_go_versions < <(
  grep -hE 'go-version:[[:space:]]*"[^"]+"' \
    "$ROOT_DIR/.github/workflows"/*.yml 2>/dev/null |
    sed -E 's/.*"([^"]+)"/\1/' |
    sort -u
)

if ((${#workflow_go_versions[@]} == 0)); then
  echo "ERROR: no go-version declarations found in workflow files" >&2
  exit 1
fi

if ((${#workflow_go_versions[@]} != 1)); then
  echo "ERROR: multiple go-version values declared in workflows: ${workflow_go_versions[*]}" >&2
  exit 1
fi

workflow_go_version="${workflow_go_versions[0]}"
workflow_go_minor="$(to_minor "$workflow_go_version")"

mapfile -t docker_builder_versions < <(
  grep -hE '^FROM[[:space:]]+golang:[0-9]+\.[0-9]+(\.[0-9]+)?' \
    "$ROOT_DIR/deploy/docker"/Dockerfile* 2>/dev/null |
    sed -E 's/^FROM[[:space:]]+golang:([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/' |
    sort -u
)

if ((${#docker_builder_versions[@]} == 0)); then
  echo "ERROR: no golang builder images found in deploy/docker/Dockerfile*" >&2
  exit 1
fi

for docker_version in "${docker_builder_versions[@]}"; do
  docker_minor="$(to_minor "$docker_version")"
  if [[ "$docker_minor" != "$workflow_go_minor" ]]; then
    echo "ERROR: Go toolchain drift detected. workflows=$workflow_go_version docker=$docker_version" >&2
    exit 1
  fi
done

echo "Go toolchain alignment OK: workflows=$workflow_go_version docker=${docker_builder_versions[*]}"
