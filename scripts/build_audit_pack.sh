#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-${ROOT_DIR}/tmp/audit-pack/${RUN_ID}}"
DOCS_DIR="${OUT_DIR}/docs"
ARTIFACT_DIR="${OUT_DIR}/artifacts"
META_DIR="${OUT_DIR}/meta"
RUN_MATRIX="${VAOL_AUDIT_RUN_MATRIX:-0}"

mkdir -p "${DOCS_DIR}" "${ARTIFACT_DIR}" "${META_DIR}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "${src}" ]]; then
    cp "${src}" "${dst}"
  else
    echo "missing expected file: ${src}" >&2
  fi
}

run_cmd() {
  local name="$1"
  shift
  echo "[audit-pack] running: ${name}"
  (
    cd "${ROOT_DIR}"
    "$@"
  ) >"${ARTIFACT_DIR}/${name}.log" 2>&1
}

require_cmd git
require_cmd tar

cat >"${META_DIR}/manifest.txt" <<EOF
run_id=${RUN_ID}
generated_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
git_branch=$(git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD)
git_commit=$(git -C "${ROOT_DIR}" rev-parse HEAD)
EOF

copy_if_exists "${ROOT_DIR}/CHANGELOG.md" "${DOCS_DIR}/CHANGELOG.md"
copy_if_exists "${ROOT_DIR}/README.md" "${DOCS_DIR}/README.md"
copy_if_exists "${ROOT_DIR}/docs/architecture.md" "${DOCS_DIR}/architecture.md"
copy_if_exists "${ROOT_DIR}/docs/threat-model.md" "${DOCS_DIR}/threat-model.md"
copy_if_exists "${ROOT_DIR}/docs/crypto-design.md" "${DOCS_DIR}/crypto-design.md"
copy_if_exists "${ROOT_DIR}/docs/api-reference.md" "${DOCS_DIR}/api-reference.md"
copy_if_exists "${ROOT_DIR}/docs/external-audit-readiness.md" "${DOCS_DIR}/external-audit-readiness.md"
copy_if_exists "${ROOT_DIR}/docs/ha-sequencing-model.md" "${DOCS_DIR}/ha-sequencing-model.md"
copy_if_exists "${ROOT_DIR}/docs/dr-playbook.md" "${DOCS_DIR}/dr-playbook.md"
copy_if_exists "${ROOT_DIR}/docs/compliance-operations.md" "${DOCS_DIR}/compliance-operations.md"
copy_if_exists "${ROOT_DIR}/docs/auditor-guide.md" "${DOCS_DIR}/auditor-guide.md"
copy_if_exists "${ROOT_DIR}/docs/audit/rfp-shortlist.md" "${DOCS_DIR}/audit-rfp-shortlist.md"
copy_if_exists "${ROOT_DIR}/docs/audit/sow.md" "${DOCS_DIR}/audit-sow.md"
copy_if_exists "${ROOT_DIR}/docs/audit/control-matrix.md" "${DOCS_DIR}/audit-control-matrix.md"
copy_if_exists "${ROOT_DIR}/docs/audit/remediation-report-template.md" "${DOCS_DIR}/audit-remediation-template.md"

if [[ "${RUN_MATRIX}" == "1" ]]; then
  require_cmd go
  require_cmd docker
  require_cmd jq

  run_cmd "go-test-all" go test ./...
  run_cmd "go-test-race-e2e-tamper" go test -race ./tests/e2e ./tests/tamper -v
  run_cmd "python-checks" /bin/zsh -lc "cd sdk/python && ruff check vaol/ && mypy vaol/ && pytest tests/ -v"
  run_cmd "typescript-checks" /bin/zsh -lc "cd sdk/typescript && npm ci && npm run lint && npm test"
  run_cmd "startup-restore-benchmark" ./scripts/check_startup_restore_bench.sh "${ARTIFACT_DIR}/startup-restore-bench.txt"
  run_cmd "demo-auditor" ./scripts/demo_auditor.sh
  run_cmd "docker-build-server" docker build -f deploy/docker/Dockerfile.server -t vaol-server:ci .
  run_cmd "docker-build-proxy" docker build -f deploy/docker/Dockerfile.proxy -t vaol-proxy:ci .
fi

if command -v shasum >/dev/null 2>&1; then
  (cd "${OUT_DIR}" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) >"${META_DIR}/SHA256SUMS"
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "${OUT_DIR}" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"${META_DIR}/SHA256SUMS"
fi

PACK_DIR="$(dirname "${OUT_DIR}")"
PACK_NAME="$(basename "${OUT_DIR}")"
tar -C "${PACK_DIR}" -czf "${OUT_DIR}.tar.gz" "${PACK_NAME}"

echo "[audit-pack] generated: ${OUT_DIR}"
echo "[audit-pack] archive:   ${OUT_DIR}.tar.gz"
