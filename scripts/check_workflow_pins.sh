#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_DIR="${1:-${ROOT_DIR}/.github/workflows}"

if [[ ! -d "${WORKFLOW_DIR}" ]]; then
  echo "workflow directory not found: ${WORKFLOW_DIR}" >&2
  exit 2
fi

violations=0

check_policy() {
  local pattern="$1"
  local message="$2"
  local matches
  matches="$(rg -n --glob '*.yml' "${pattern}" "${WORKFLOW_DIR}" || true)"
  if [[ -n "${matches}" ]]; then
    echo "policy violation: ${message}" >&2
    echo "${matches}" >&2
    echo >&2
    violations=1
  fi
}

check_policy 'runs-on:\s*ubuntu-latest\b' "use pinned runner image (ubuntu-24.04), not ubuntu-latest"
check_policy 'uses:\s*[^[:space:]]+@master\b' "do not reference @master in workflow actions"
check_policy '(^|[[:space:]])version:\s*latest\b' "do not use version: latest in workflow configuration"
check_policy 'go install [^[:space:]]+@latest\b' "do not install Go tools using @latest"

if [[ "${violations}" -ne 0 ]]; then
  echo "workflow pin policy check failed" >&2
  exit 1
fi

echo "workflow pin policy check passed (${WORKFLOW_DIR})"
