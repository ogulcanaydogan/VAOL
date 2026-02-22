#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${VAOL_DEMO_BIN_DIR:-${ROOT_DIR}/bin}"
COMPOSE_FILE="${ROOT_DIR}/deploy/docker/docker-compose.yml"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${ROOT_DIR}/tmp/demo-auditor/${RUN_ID}"
KEY_DIR="${RUN_DIR}/keys"
LOG_DIR="${RUN_DIR}/logs"
ARTIFACT_DIR="${RUN_DIR}/artifacts"

SERVER_ADDR="${VAOL_DEMO_ADDR:-127.0.0.1:18080}"
SERVER_URL="http://${SERVER_ADDR}"
TENANT_ID="${VAOL_DEMO_TENANT:-acme-health-${RUN_ID}}"
OPA_POLICY="${VAOL_DEMO_OPA_POLICY:-v1/data/vaol/mandatory_citations}"
KEEP_STACK="${VAOL_DEMO_KEEP_STACK:-0}"
RESET_STATE="${VAOL_DEMO_RESET_STATE:-1}"
SKIP_BUILD="${VAOL_DEMO_SKIP_BUILD:-0}"
DSN="${VAOL_DEMO_DSN:-postgres://vaol:vaol@localhost:5432/vaol?sslmode=disable}"

mkdir -p "${KEY_DIR}" "${LOG_DIR}" "${ARTIFACT_DIR}"

SERVER_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

ensure_docker_ready() {
  if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is not ready. Start or unpause Docker Desktop and retry." >&2
    exit 1
  fi
}

print_server_log_tail() {
  if [[ -f "${LOG_DIR}/vaol-server.log" ]]; then
    echo "--- vaol-server.log (last 120 lines) ---" >&2
    tail -n 120 "${LOG_DIR}/vaol-server.log" >&2 || true
    echo "--- end vaol-server.log ---" >&2
  fi
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_STACK}" != "1" ]]; then
    docker compose -f "${COMPOSE_FILE}" down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd curl
require_cmd jq
require_cmd docker
if [[ "${SKIP_BUILD}" != "1" ]]; then
  require_cmd go
fi
ensure_docker_ready

if [[ "${SKIP_BUILD}" == "1" ]]; then
  if [[ ! -x "${BIN_DIR}/vaol-server" ]] || [[ ! -x "${BIN_DIR}/vaol" ]]; then
    echo "VAOL_DEMO_SKIP_BUILD=1 requires executable binaries at ${BIN_DIR}/vaol-server and ${BIN_DIR}/vaol" >&2
    exit 1
  fi
else
  echo "[demo] building vaol binaries..."
  (cd "${ROOT_DIR}" && go build -o "${BIN_DIR}/vaol-server" ./cmd/vaol-server && go build -o "${BIN_DIR}/vaol" ./cmd/vaol-cli)
fi

echo "[demo] generating signing key pair..."
"${BIN_DIR}/vaol" keys generate --output "${KEY_DIR}" >"${LOG_DIR}/keygen.log" 2>&1

echo "[demo] starting postgres + opa dependencies..."
if [[ "${RESET_STATE}" == "1" ]]; then
  docker compose -f "${COMPOSE_FILE}" down -v >/dev/null 2>&1 || true
fi
docker compose -f "${COMPOSE_FILE}" up -d postgres opa >/dev/null

echo "[demo] waiting for postgres..."
for _ in $(seq 1 30); do
  if docker compose -f "${COMPOSE_FILE}" exec -T postgres pg_isready -U vaol >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[demo] starting vaol-server locally..."
"${BIN_DIR}/vaol-server" \
  --addr "${SERVER_ADDR}" \
  --dsn "${DSN}" \
  --key "${KEY_DIR}/vaol-signing.pem" \
  --opa-url "http://localhost:8181" \
  --opa-policy "${OPA_POLICY}" \
  --policy-mode fail-closed \
  --auth-mode disabled \
  >"${LOG_DIR}/vaol-server.log" 2>&1 &
SERVER_PID=$!

echo "[demo] waiting for vaol-server health..."
HEALTH_READY=0
for _ in $(seq 1 40); do
  if curl -fsS "${SERVER_URL}/v1/health" >/dev/null 2>&1; then
    HEALTH_READY=1
    break
  fi
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    echo "vaol-server exited unexpectedly. See ${LOG_DIR}/vaol-server.log" >&2
    print_server_log_tail
    exit 1
  fi
  sleep 1
done

if [[ "${HEALTH_READY}" != "1" ]]; then
  echo "timed out waiting for vaol-server health endpoint (${SERVER_URL}/v1/health)" >&2
  print_server_log_tail
  exit 1
fi

COMPLIANT_REQ="${ARTIFACT_DIR}/request-compliant.json"
DENIED_REQ="${ARTIFACT_DIR}/request-denied.json"
COMPLIANT_RESP="${ARTIFACT_DIR}/response-compliant.json"
DENIED_RESP="${ARTIFACT_DIR}/response-denied.json"
BUNDLE_JSON="${ARTIFACT_DIR}/audit-bundle.json"
TAMPERED_BUNDLE_JSON="${ARTIFACT_DIR}/audit-bundle-tampered.json"
VERIFY_PASS_LOG="${ARTIFACT_DIR}/verify-pass.log"
VERIFY_FAIL_LOG="${ARTIFACT_DIR}/verify-fail.log"
REPORT_MD="${ARTIFACT_DIR}/auditor-report.md"
VERIFY_TRANSCRIPT_JSON="${ARTIFACT_DIR}/verify-transcript.json"
VERIFY_REPORT_JSON="${ARTIFACT_DIR}/verify-report.json"
VERIFY_REPORT_MD="${ARTIFACT_DIR}/verify-report.md"

cat >"${COMPLIANT_REQ}" <<EOF
{
  "identity": {
    "tenant_id": "${TENANT_ID}",
    "subject": "service:demo"
  },
  "model": {
    "provider": "openai",
    "name": "gpt-4o"
  },
  "parameters": {
    "temperature": 0.1
  },
  "prompt_context": {
    "user_prompt_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "policy_context": {
    "policy_decision": "allow"
  },
  "rag_context": {
    "connector_ids": ["ehr-db"],
    "document_ids": ["doc-001"],
    "chunk_hashes": ["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    "citation_hashes": ["sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]
  },
  "output": {
    "output_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "mode": "hash_only"
  },
  "trace": {
    "otel_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "otel_span_id": "00f067aa0ba902b7"
  }
}
EOF

cat >"${DENIED_REQ}" <<EOF
{
  "identity": {
    "tenant_id": "${TENANT_ID}",
    "subject": "service:demo"
  },
  "model": {
    "provider": "openai",
    "name": "gpt-4o"
  },
  "parameters": {
    "temperature": 0.1
  },
  "prompt_context": {
    "user_prompt_hash": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  },
  "policy_context": {
    "policy_decision": "allow"
  },
  "rag_context": {
    "connector_ids": ["ehr-db"],
    "document_ids": ["doc-002"],
    "chunk_hashes": ["sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
    "citation_hashes": []
  },
  "output": {
    "output_hash": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
    "mode": "hash_only"
  },
  "trace": {
    "otel_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "otel_span_id": "00f067aa0ba902b8"
  }
}
EOF

echo "[demo] submitting compliant request..."
COMPLIANT_HTTP_CODE="$(curl -sS -o "${COMPLIANT_RESP}" -w "%{http_code}" \
  -X POST "${SERVER_URL}/v1/records" \
  -H "Content-Type: application/json" \
  -H "X-VAOL-Tenant-ID: ${TENANT_ID}" \
  --data-binary @"${COMPLIANT_REQ}")"
if [[ "${COMPLIANT_HTTP_CODE}" != "201" ]]; then
  echo "expected compliant request to return 201, got ${COMPLIANT_HTTP_CODE}" >&2
  cat "${COMPLIANT_RESP}" >&2
  exit 1
fi

echo "[demo] submitting non-compliant request (missing citations)..."
DENIED_HTTP_CODE="$(curl -sS -o "${DENIED_RESP}" -w "%{http_code}" \
  -X POST "${SERVER_URL}/v1/records" \
  -H "Content-Type: application/json" \
  -H "X-VAOL-Tenant-ID: ${TENANT_ID}" \
  --data-binary @"${DENIED_REQ}")"
if [[ "${DENIED_HTTP_CODE}" != "403" ]]; then
  echo "expected non-compliant request to return 403, got ${DENIED_HTTP_CODE}" >&2
  cat "${DENIED_RESP}" >&2
  exit 1
fi

if ! jq -e '.decision.rule_ids // [] | index("rag_missing_citations") != null' "${DENIED_RESP}" >/dev/null; then
  echo "deny response missing expected rule_id rag_missing_citations" >&2
  cat "${DENIED_RESP}" >&2
  exit 1
fi

echo "[demo] exporting auditor bundle..."
curl -sS \
  -X POST "${SERVER_URL}/v1/export" \
  -H "Content-Type: application/json" \
  -H "X-VAOL-Tenant-ID: ${TENANT_ID}" \
  --data-binary "{\"tenant_id\":\"${TENANT_ID}\",\"limit\":1000}" \
  >"${BUNDLE_JSON}"

RECORD_COUNT="$(jq '.records | length' "${BUNDLE_JSON}")"
if [[ "${RECORD_COUNT}" -lt 1 ]]; then
  echo "exported bundle has no records" >&2
  cat "${BUNDLE_JSON}" >&2
  exit 1
fi

echo "[demo] verifying bundle (expected pass)..."
"${BIN_DIR}/vaol" verify bundle "${BUNDLE_JSON}" \
  --public-key "${KEY_DIR}/vaol-signing.pub" \
  --transcript-json "${VERIFY_TRANSCRIPT_JSON}" \
  --report-json "${VERIFY_REPORT_JSON}" \
  --report-markdown "${VERIFY_REPORT_MD}" \
  >"${VERIFY_PASS_LOG}" 2>&1

if [[ ! -s "${VERIFY_TRANSCRIPT_JSON}" ]] || [[ ! -s "${VERIFY_REPORT_JSON}" ]] || [[ ! -s "${VERIFY_REPORT_MD}" ]]; then
  echo "verifier artifacts were not generated as expected" >&2
  exit 1
fi

echo "[demo] tampering bundle signature and verifying (expected fail)..."
jq '.records[0].dsse_envelope.signatures[0].sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"' \
  "${BUNDLE_JSON}" >"${TAMPERED_BUNDLE_JSON}"

if "${BIN_DIR}/vaol" verify bundle "${TAMPERED_BUNDLE_JSON}" --public-key "${KEY_DIR}/vaol-signing.pub" >"${VERIFY_FAIL_LOG}" 2>&1; then
  echo "tampered bundle unexpectedly verified successfully" >&2
  exit 1
fi

COMPLIANT_REQUEST_ID="$(jq -r '.request_id' "${COMPLIANT_RESP}")"

cat >"${REPORT_MD}" <<EOF
# VAOL Auditor Demo Report

- Run ID: \`${RUN_ID}\`
- Timestamp (UTC): \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`
- Tenant: \`${TENANT_ID}\`
- OPA Policy Path: \`${OPA_POLICY}\`
- Server URL: \`${SERVER_URL}\`

## Scenario Results

1. Compliant RAG request submitted with citation hashes: **HTTP ${COMPLIANT_HTTP_CODE}**
2. Non-compliant RAG request without citations: **HTTP ${DENIED_HTTP_CODE}**
3. Offline bundle verification: **PASS**
4. Tampered bundle verification: **FAIL (expected)**

## Evidence

- Compliant request: \`${COMPLIANT_REQ}\`
- Compliant response (record receipt): \`${COMPLIANT_RESP}\`
- Denied request: \`${DENIED_REQ}\`
- Denied response: \`${DENIED_RESP}\`
- Exported bundle: \`${BUNDLE_JSON}\`
- Tampered bundle: \`${TAMPERED_BUNDLE_JSON}\`
- Verify pass log: \`${VERIFY_PASS_LOG}\`
- Verify fail log: \`${VERIFY_FAIL_LOG}\`
- Verify transcript JSON: \`${VERIFY_TRANSCRIPT_JSON}\`
- Verify report JSON: \`${VERIFY_REPORT_JSON}\`
- Verify report Markdown: \`${VERIFY_REPORT_MD}\`
- VAOL server log: \`${LOG_DIR}/vaol-server.log\`

## Key Record

- Compliant record request_id: \`${COMPLIANT_REQUEST_ID}\`
EOF

echo "[demo] complete"
echo "Artifacts:"
echo "  ${ARTIFACT_DIR}"
echo "Report:"
echo "  ${REPORT_MD}"
