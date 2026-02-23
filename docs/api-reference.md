# VAOL REST API Reference

**Version:** 0.2.24
**Base URL:** `http://<host>:8080`
**Content-Type:** `application/json`

---

## Table of Contents

- [Overview](#overview)
- [gRPC API](#grpc-api)
- [Authentication](#authentication)
- [Common Response Headers](#common-response-headers)
- [Error Format](#error-format)
- [Endpoints](#endpoints)
  - [POST /v1/records](#post-v1records)
  - [GET /v1/records/{id}](#get-v1recordsid)
  - [GET /v1/records](#get-v1records)
  - [GET /v1/records/{id}/proof](#get-v1recordsidproof)
  - [GET /v1/proofs/{id}](#get-v1proofsid)
  - [POST /v1/verify](#post-v1verify)
  - [POST /v1/verify/record](#post-v1verifyrecord)
  - [POST /v1/verify/bundle](#post-v1verifybundle)
  - [GET /v1/ledger/checkpoint](#get-v1ledgercheckpoint)
  - [GET /v1/ledger/checkpoints/latest](#get-v1ledgercheckpointslatest)
  - [GET /v1/ledger/consistency](#get-v1ledgerconsistency)
  - [POST /v1/export](#post-v1export)
  - [GET /v1/health](#get-v1health)
- [Data Types](#data-types)

---

## Overview

The VAOL REST API provides an append-only ledger for cryptographically verifiable AI decision records. Every record appended to the ledger receives a DSSE (Dead Simple Signing Envelope) signature, is linked into a SHA-256 hash chain, and is anchored in a Merkle tree with verifiable inclusion proofs.

All timestamps use RFC 3339 format in UTC. All cryptographic hashes use the `sha256:<hex>` prefix format.

## gRPC API

VAOL also provides a gRPC surface (`VAOLLedger`) defined in `proto/vaol/v1/ledger.proto`.

Enable it by starting the server with:

```bash
./bin/vaol-server --grpc-addr :9090
```

gRPC metadata contract:

- `authorization: Bearer <JWT>` for authenticated calls (required when `--auth-mode=required`)
- `x-vaol-tenant-id` preferred tenant context key
- `x-tenant-id` legacy tenant key (supported only when equal to `x-vaol-tenant-id`)

Tenant precedence and enforcement:

1. If JWT has `tenant_id` claim, that tenant is authoritative.
2. If both claim tenant and metadata tenant are present, they must match.
3. If claim tenant is absent, metadata tenant is required for tenant-scoped RPCs.
4. `ListRecords` and `ExportBundle` force empty tenant filters to caller tenant.
5. Cross-tenant access attempts return deterministic `PermissionDenied` (`tenant mismatch`).

`Health` is intentionally unauthenticated. All other RPCs run auth verification according to configured auth mode.

Available RPCs:

- `Health`
- `AppendRecord`
- `GetRecord`
- `ListRecords` (server stream)
- `GetInclusionProof`
- `GetProofByID`
- `GetConsistencyProof`
- `GetCheckpoint`
- `VerifyRecord`
- `ExportBundle` (server stream)

Common gRPC status mapping:

| Status | Meaning |
|---|---|
| `Unauthenticated` | Missing/invalid bearer token when auth is required, or invalid token in optional mode |
| `PermissionDenied` | Tenant mismatch, subject mismatch, or missing tenant context for tenant-scoped operations |
| `NotFound` | Record/proof/checkpoint target does not exist |

---

## Authentication

VAOL supports three server-side auth modes:

- `disabled`: no JWT verification (local development only)
- `optional`: verifies `Authorization: Bearer <JWT>` when present
- `required`: rejects requests without a valid JWT (default in `vaol-server`)

JWT verification supports `HS256`, `RS256`, and `ES256`, with keys from `--jwks-file`, `--jwks-url`, or `--jwt-hs256-secret`.

When JWT validation succeeds on REST, the server injects trusted identity context (`X-VAOL-Tenant-ID`, `X-Auth-Issuer`, `X-Auth-Subject`, `X-Auth-Token-Hash`) and strips the original `Authorization` header before handler processing. On gRPC, equivalent trusted claim binding is applied directly in handler logic.

`/v1/health` and `/ui/*` bypass authentication.

For tenant-scoped reads and export (`GET /v1/records`, `GET /v1/records/{id}`, `GET /v1/records/{id}/proof`, `GET /v1/proofs/{id}`, `POST /v1/export`), the effective tenant context must be present via:

- `X-VAOL-Tenant-ID` (preferred), or
- `X-Tenant-ID`

If tenant context is missing or mismatched with query/body/stored data, VAOL returns `403` with deterministic deny metadata (`decision_reason_code=missing_tenant_context|tenant_mismatch`).

---

## Common Response Headers

Every response includes the following headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Request-ID` | Unique identifier for the request. Echoes the client-supplied `X-Request-ID` header if present; otherwise auto-generated. | `vaol-1708300000000000000` |
| `X-VAOL-Version` | Server version string. | `0.2.24` |
| `X-VAOL-Record-ID` | The `request_id` (UUID) of the appended record. Present only on `POST /v1/records` responses. | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| `X-VAOL-Sequence` | The assigned sequence number in the ledger. Present only on `POST /v1/records` responses. | `42` |
| `Content-Type` | Always `application/json`. | `application/json` |
| `Access-Control-Allow-Origin` | CORS header. Set to `*` by default. | `*` |

---

## Error Format

All error responses return a JSON object with an `error` field:

```json
{
  "error": "human-readable error description"
}
```

Policy denial responses (403) include additional detail:

```json
{
  "error": "request denied by policy",
  "decision": {
    "decision": "deny",
    "allow": false,
    "rule_ids": ["require-pii-redaction", "block-phi-in-plaintext"]
  }
}
```

---

## Endpoints

### POST /v1/records

Append a new DecisionRecord to the ledger. The server computes the record hash, links it into the hash chain, signs the record in a DSSE envelope, appends the leaf to the Merkle tree, and returns a receipt.

**Request Body:** DecisionRecord JSON

Fields `schema_version`, `request_id`, and `timestamp` are auto-populated if omitted. The `integrity` block is computed server-side and should not be set by the client.

```json
{
  "identity": {
    "tenant_id": "acme-corp",
    "subject": "hmac:user:8f14e45f",
    "subject_type": "user"
  },
  "model": {
    "provider": "openai",
    "name": "gpt-4o",
    "version": "2024-08-06",
    "endpoint": "https://api.openai.com/v1/chat/completions"
  },
  "parameters": {
    "temperature": 0.7,
    "max_tokens": 2048,
    "top_p": 0.95
  },
  "prompt_context": {
    "system_prompt_hash": "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "user_prompt_hash": "sha256:f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
    "message_count": 3,
    "total_input_tokens": 1250
  },
  "policy_context": {
    "policy_decision": "allow"
  },
  "output": {
    "output_hash": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "mode": "hash_only",
    "output_tokens": 512,
    "finish_reason": "stop",
    "latency_ms": 1430.5
  },
  "trace": {
    "otel_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "otel_span_id": "00f067aa0ba902b7",
    "session_id": "sess-abc-123"
  }
}
```

**Response:** `201 Created`

```json
{
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "sequence_number": 42,
  "record_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "merkle_root": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "merkle_tree_size": 42,
  "inclusion_proof_ref": "/v1/proofs/proof:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "inclusion_proof": {
    "leaf_index": 41,
    "hashes": [
      "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      "sha256:789def012345789def012345789def012345789def012345789def012345789d"
    ]
  },
  "timestamp": "2025-01-15T10:30:00Z"
}
```

**Response Headers (in addition to common headers):**

```
X-VAOL-Record-ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
X-VAOL-Sequence: 42
```

**Error Responses:**

| Status | Condition | Example |
|--------|-----------|---------|
| `400 Bad Request` | Malformed JSON, missing required fields, invalid schema | `{"error": "invalid request body: ..."}` |
| `401 Unauthorized` | Auth mode is `required`/`optional` and JWT verification fails | `{"error": "authentication failed: ..."}` |
| `403 Forbidden` | Policy engine denied the request | `{"error": "request denied by policy", "decision": {...}}` |
| `409 Conflict` | A record with the same `request_id` already exists | `{"error": "duplicate request_id"}` |

---

### GET /v1/records/{id}

Retrieve a single stored record by its `request_id`.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID string | The `request_id` of the record to retrieve. |

**Request Example:**

```
GET /v1/records/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Response:** `200 OK`

```json
{
  "sequence_number": 42,
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "tenant_id": "acme-corp",
  "timestamp": "2025-01-15T10:30:00Z",
  "record_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "previous_record_hash": "sha256:e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
  "dsse_envelope": {
    "payloadType": "application/vnd.vaol.decision-record.v1+json",
    "payload": "<base64url-encoded DecisionRecord JSON>",
    "signatures": [
      {
        "keyid": "vaol-ed25519-001",
        "sig": "<base64url-encoded signature>",
        "timestamp": "2025-01-15T10:30:00Z"
      }
    ]
  },
  "merkle_leaf_index": 41,
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Invalid UUID format in path. |
| `404 Not Found` | No record exists with the given `request_id`. |
| `401 Unauthorized` | Auth mode is `required`/`optional` and JWT verification fails. |
| `403 Forbidden` | Missing tenant context header or cross-tenant access attempt. |

---

### GET /v1/records

List records with optional filtering and cursor-based pagination.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tenant_id` | string | _(none)_ | Optional explicit tenant filter. If provided, it must match tenant context header. If omitted, tenant context header is applied automatically. |
| `after` | RFC 3339 datetime | _(none)_ | Return records created after this timestamp (inclusive). |
| `before` | RFC 3339 datetime | _(none)_ | Return records created before this timestamp (inclusive). |
| `limit` | integer | `100` | Maximum number of records to return. |
| `cursor` | integer | _(none)_ | Sequence number to start after (for pagination). |

**Request Example:**

```
GET /v1/records?tenant_id=acme-corp&after=2025-01-01T00:00:00Z&limit=10
```

**Response:** `200 OK`

```json
{
  "records": [
    {
      "sequence_number": 1,
      "request_id": "d1e2f3a4-b5c6-7890-1234-567890abcdef",
      "tenant_id": "acme-corp",
      "timestamp": "2025-01-02T08:00:00Z",
      "record_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      "previous_record_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "dsse_envelope": { "..." : "..." },
      "merkle_leaf_index": 0,
      "created_at": "2025-01-02T08:00:00Z"
    },
    {
      "sequence_number": 2,
      "request_id": "e2f3a4b5-c6d7-8901-2345-67890abcdef1",
      "tenant_id": "acme-corp",
      "timestamp": "2025-01-02T09:15:00Z",
      "record_hash": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      "previous_record_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      "dsse_envelope": { "..." : "..." },
      "merkle_leaf_index": 1,
      "created_at": "2025-01-02T09:15:00Z"
    }
  ],
  "count": 2
}
```

**Pagination:** To fetch the next page, use the `sequence_number` of the last record in the response as the `cursor` parameter in the next request.

---

### GET /v1/records/{id}/proof

Retrieve the current Merkle inclusion proof for a record. The proof is computed against the latest tree size at the time of the request.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | UUID string | The `request_id` of the record. |

**Request Example:**

```
GET /v1/records/a1b2c3d4-e5f6-7890-abcd-ef1234567890/proof
```

**Response:** `200 OK`

```json
{
  "proof_type": "inclusion",
  "leaf_index": 41,
  "tree_size": 100,
  "root_hash": "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
  "hashes": [
    "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
    "sha256:bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8",
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  ]
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Invalid UUID format. |
| `404 Not Found` | No record exists with the given `request_id`. |

---

### GET /v1/proofs/{id}

Retrieve a persisted inclusion proof by proof identifier. Proof IDs are returned in record receipts as `inclusion_proof_ref`.

**Request Example:**

```
GET /v1/proofs/proof:a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Response:** `200 OK` (same structure as inclusion proof)

---

### POST /v1/verify

Verify a DSSE envelope containing a signed DecisionRecord. The server performs the following checks:

1. **Signature verification** -- Validates the DSSE signature(s) against known verifier keys.
2. **Schema validation** -- Confirms the payload conforms to the DecisionRecord v1 schema.
3. **Record hash verification** -- Recomputes the hash from the JCS-canonicalized payload and compares it to the stored `record_hash`.

Optional profile selectors:

1. Query parameter: `?profile=basic|strict|fips`
2. Request body field: `"verification_profile": "basic|strict|fips"`

If both query and body profile are provided, they must match.

`strict` profile enforces additional evidence requirements:

1. `policy_context.policy_bundle_id`, `policy_context.policy_hash`, and `policy_context.decision_reason_code` must be present.
2. `integrity.previous_record_hash`, `integrity.merkle_root`, `integrity.merkle_tree_size`, `integrity.inclusion_proof`, and `integrity.inclusion_proof_ref` must be present.
3. The embedded inclusion proof must verify against `integrity.record_hash`.
4. Every signature must include an RFC 3339 `timestamp`.
5. Sigstore/Fulcio signatures must include both `rekor_entry_id` and `cert`.
6. If `auth_context.authenticated=true`, strict mode requires `auth_context.subject`, `auth_context.token_hash`, `auth_context.issuer`, and `auth_context.source`.
7. If server runtime flag `--verify-strict-online-rekor=true` is enabled, strict mode additionally performs online Rekor verification against `--verify-rekor-url` and rejects payload hash mismatches deterministically.

`fips` profile runs all strict checks, then additionally rejects Ed25519 signatures.

**Request Body (direct envelope):** DSSE Envelope JSON

```json
{
  "payloadType": "application/vnd.vaol.decision-record.v1+json",
  "payload": "<base64url-encoded DecisionRecord JSON>",
  "signatures": [
    {
      "keyid": "vaol-ed25519-001",
      "sig": "<base64url-encoded Ed25519 signature>",
      "timestamp": "2025-01-15T10:30:00Z"
    }
  ]
}
```

**Request Body (wrapped):**

```json
{
  "envelope": {
    "payloadType": "application/vnd.vaol.decision-record.v1+json",
    "payload": "<base64url-encoded DecisionRecord JSON>",
    "signatures": [
      {
        "keyid": "vaol-ed25519-001",
        "sig": "<base64url-encoded Ed25519 signature>",
        "timestamp": "2025-01-15T10:30:00Z"
      }
    ]
  },
  "verification_profile": "strict"
}
```

**Response:** `200 OK`

```json
{
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2025-01-15T12:00:00Z",
  "valid": true,
  "checks": [
    {
      "name": "signature",
      "passed": true,
      "details": "1 signature(s) verified"
    },
    {
      "name": "schema",
      "passed": true,
      "details": "DecisionRecord v1 schema valid"
    },
    {
      "name": "record_hash",
      "passed": true,
      "details": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }
  ]
}
```

**Response when verification fails:**

```json
{
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2025-01-15T12:00:00Z",
  "valid": false,
  "checks": [
    {
      "name": "signature",
      "passed": false,
      "error": "no signatures could be verified"
    },
    {
      "name": "schema",
      "passed": true,
      "details": "DecisionRecord v1 schema valid"
    },
    {
      "name": "record_hash",
      "passed": true,
      "details": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }
  ]
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Malformed envelope JSON or invalid/conflicting profile. |

---

### POST /v1/verify/record

Alias for `POST /v1/verify`. Supports the same request/response contract and profile selectors.

---

### POST /v1/verify/bundle

Verify an entire audit bundle. Each record in the bundle is individually verified for signature validity, schema conformance, hash chain integrity, and Merkle inclusion. The response provides an aggregate result.

Optional profile selectors:

1. Query parameter: `?profile=basic|strict|fips`
2. Request body field: `"verification_profile": "basic|strict|fips"`

If both query and body profile are provided, they must match.

**Request Body (direct bundle):** Bundle JSON

```json
{
  "version": "1.0",
  "exported_at": "2025-01-15T12:00:00Z",
  "filter": {
    "tenant_id": "acme-corp"
  },
  "records": [
    {
      "sequence_number": 1,
      "dsse_envelope": {
        "payloadType": "application/vnd.vaol.decision-record.v1+json",
        "payload": "<base64url-encoded record>",
        "signatures": [
          {
            "keyid": "vaol-ed25519-001",
            "sig": "<base64url-encoded signature>",
            "timestamp": "2025-01-10T08:00:00Z"
          }
        ]
      },
      "inclusion_proof": {
        "proof_type": "inclusion",
        "leaf_index": 0,
        "tree_size": 50,
        "root_hash": "sha256:...",
        "hashes": ["sha256:...", "sha256:..."]
      }
    }
  ],
  "checkpoints": [],
  "metadata": {
    "total_records": 1,
    "first_sequence": 1,
    "last_sequence": 1,
    "merkle_root_hash": "",
    "merkle_tree_size": 0
  }
}
```

**Request Body (wrapped):**

```json
{
  "bundle": {
    "version": "1.0",
    "records": [],
    "checkpoints": [],
    "metadata": {
      "total_records": 0,
      "first_sequence": 0,
      "last_sequence": 0
    }
  },
  "verification_profile": "fips"
}
```

**Response:** `200 OK`

```json
{
  "total_records": 25,
  "valid_records": 25,
  "invalid_records": 0,
  "chain_intact": true,
  "merkle_valid": true,
  "signatures_valid": true,
  "schema_valid": true,
  "checkpoint_valid": true,
  "policy_hash_valid": true,
  "manifest_valid": true,
  "summary": "VERIFICATION PASSED"
}
```

**Response when bundle contains failures:**

```json
{
  "total_records": 25,
  "valid_records": 23,
  "invalid_records": 2,
  "chain_intact": false,
  "merkle_valid": true,
  "signatures_valid": true,
  "schema_valid": false,
  "checkpoint_valid": true,
  "policy_hash_valid": false,
  "manifest_valid": false,
  "summary": "VERIFICATION FAILED"
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Malformed bundle JSON or invalid/conflicting profile. |

---

### GET /v1/ledger/checkpoint

Retrieve the latest Merkle tree checkpoint. The checkpoint represents the current state of the append-only Merkle tree, including the tree size, root hash, and the timestamp at which the checkpoint was generated.

**Request Example:**

```
GET /v1/ledger/checkpoint
```

**Response:** `200 OK`

```json
{
  "tree_size": 1024,
  "root_hash": "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
  "timestamp": "2025-01-15T12:00:00Z"
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `tree_size` | integer | Total number of leaves in the Merkle tree. |
| `root_hash` | string | SHA-256 root hash of the Merkle tree in `sha256:<hex>` format. |
| `timestamp` | string | RFC 3339 UTC timestamp of checkpoint generation. |

---

### GET /v1/ledger/checkpoints/latest

Alias of `GET /v1/ledger/checkpoint` for explicit signed-checkpoint retrieval.

---

### GET /v1/ledger/consistency

Retrieve a Merkle consistency proof between two tree sizes.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `from` | integer | Earlier tree size. |
| `to` | integer | Later tree size. |

**Request Example:**

```
GET /v1/ledger/consistency?from=100&to=250
```

---

### POST /v1/export

Export a set of records as a self-contained audit bundle. The bundle includes DSSE-signed records, Merkle inclusion proofs, and metadata sufficient for offline verification without access to the VAOL server.

**Request Body:**

```json
{
  "tenant_id": "acme-corp",
  "after": "2025-01-01T00:00:00Z",
  "before": "2025-02-01T00:00:00Z",
  "limit": 500
}
```

**Request Fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tenant_id` | string | _(none)_ | Optional explicit tenant filter. If provided, it must match tenant context header. If omitted, tenant context header is applied automatically. |
| `after` | RFC 3339 datetime | _(none)_ | Include records created after this timestamp. |
| `before` | RFC 3339 datetime | _(none)_ | Include records created before this timestamp. |
| `limit` | integer | `1000` | Maximum number of records to include. |

**Response:** `200 OK`

```json
{
  "version": "1.0",
  "exported_at": "2025-01-15T12:30:00Z",
  "filter": {
    "tenant_id": "acme-corp"
  },
  "records": [
    {
      "sequence_number": 1,
      "dsse_envelope": {
        "payloadType": "application/vnd.vaol.decision-record.v1+json",
        "payload": "<base64url-encoded DecisionRecord>",
        "signatures": [
          {
            "keyid": "vaol-ed25519-001",
            "sig": "<base64url-encoded signature>",
            "timestamp": "2025-01-02T08:00:00Z"
          }
        ]
      },
      "inclusion_proof": {
        "proof_type": "inclusion",
        "leaf_index": 0,
        "tree_size": 100,
        "root_hash": "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
        "hashes": [
          "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"
        ]
      }
    }
  ],
  "checkpoints": [],
  "metadata": {
    "total_records": 1,
    "first_sequence": 1,
    "last_sequence": 1,
    "merkle_root_hash": "",
    "merkle_tree_size": 0
  }
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | Malformed export request JSON. |

---

### GET /v1/health

Health check endpoint. Returns the server status, version, total record count, and Merkle tree size.

**Request Example:**

```
GET /v1/health
```

**Response:** `200 OK`

```json
{
  "status": "ok",
  "version": "0.2.24",
  "record_count": 1024,
  "tree_size": 1024
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Server health status. `"ok"` when healthy. |
| `version` | string | VAOL server version. |
| `record_count` | integer | Total number of records stored in the ledger. |
| `tree_size` | integer | Total number of leaves in the Merkle tree. |

---

## Data Types

### DecisionRecord

The core evidence type for a single AI inference decision. See the full JSON Schema at `schemas/v1/decision-record.schema.json`.

**Required fields:** `schema_version`, `request_id`, `timestamp`, `identity`, `model`, `parameters`, `prompt_context`, `policy_context`, `output`, `trace`, `integrity`.

| Section | Description |
|---------|-------------|
| `identity` | Tenant and pseudonymous subject identity. Required: `tenant_id`, `subject`. |
| `model` | AI model provider, name, version, and endpoint metadata. Required: `provider`, `name`. |
| `parameters` | Inference parameters (temperature, top_p, max_tokens, etc.). |
| `prompt_context` | SHA-256 hashes of prompt components. Raw content is never stored. Required: `user_prompt_hash`. |
| `policy_context` | Policy evaluation result sealed at record creation time. Required: `policy_decision`. Values: `allow`, `deny`, `allow_with_transform`, `log_only`. |
| `rag_context` | Optional. Retrieval-Augmented Generation context including connector IDs, document IDs, chunk hashes, and prompt injection check results. |
| `output` | Output evidence. Required: `output_hash`, `mode`. Modes: `hash_only`, `encrypted`, `plaintext`. |
| `auth_context` | Optional. Server-populated authenticated identity context (`issuer`, `subject`, `source`, `token_hash`). |
| `trace` | OpenTelemetry trace/span IDs, parent request ID, and session ID for distributed tracing correlation. |
| `integrity` | Server-computed cryptographic integrity fields: `record_hash`, `previous_record_hash`, `sequence_number`, `merkle_root`, `merkle_tree_size`, `inclusion_proof`, and `inclusion_proof_ref`. |

### Receipt

Returned by `POST /v1/records` after a record is successfully appended.

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | UUID | Unique identifier for this record. |
| `sequence_number` | integer | Monotonically increasing position in the ledger. |
| `record_hash` | string | SHA-256 hash of the JCS-canonicalized record (`sha256:<hex>`). |
| `merkle_root` | string | Merkle tree root hash after this record was appended. |
| `merkle_tree_size` | integer | Tree size after this record was appended. |
| `inclusion_proof_ref` | string | Stable API reference to persisted proof (`/v1/proofs/{id}`). |
| `inclusion_proof` | object | Merkle inclusion proof (see below). |
| `timestamp` | datetime | Record creation timestamp (RFC 3339 UTC). |

### InclusionProof

| Field | Type | Description |
|-------|------|-------------|
| `leaf_index` | integer | This record's position (0-based) in the Merkle tree. |
| `hashes` | string[] | Sibling hashes from leaf to root for inclusion verification (`sha256:<hex>`). |

### Proof (full)

Returned by `GET /v1/records/{id}/proof`.

| Field | Type | Description |
|-------|------|-------------|
| `proof_type` | string | `"inclusion"`. |
| `leaf_index` | integer | Leaf position in the Merkle tree. |
| `tree_size` | integer | Size of the tree this proof is computed against. |
| `root_hash` | string | Root hash of the tree at `tree_size`. |
| `hashes` | string[] | Sibling hashes for proof verification. |
| `checkpoint` | object | Optional signed checkpoint (when available). |

### StoredRecord

Returned by `GET /v1/records/{id}` and as elements in `GET /v1/records` list responses.

| Field | Type | Description |
|-------|------|-------------|
| `sequence_number` | integer | Monotonically increasing ledger position. |
| `request_id` | UUID | Unique record identifier. |
| `tenant_id` | string | Tenant that owns this record. |
| `timestamp` | datetime | Record creation timestamp. |
| `record_hash` | string | SHA-256 hash of the canonicalized record. |
| `previous_record_hash` | string | Hash of the preceding record in the chain. Genesis records use the zero hash. |
| `dsse_envelope` | object | The signed DSSE envelope containing the full DecisionRecord payload. |
| `merkle_leaf_index` | integer | Position in the Merkle tree. |
| `created_at` | datetime | Server-side storage timestamp. |

### DSSE Envelope

Dead Simple Signing Envelope per the [DSSE specification](https://github.com/secure-systems-lab/dsse).

| Field | Type | Description |
|-------|------|-------------|
| `payloadType` | string | Always `"application/vnd.vaol.decision-record.v1+json"`. |
| `payload` | string | Base64url-encoded DecisionRecord JSON. |
| `signatures` | Signature[] | One or more cryptographic signatures. |

### Signature

| Field | Type | Description |
|-------|------|-------------|
| `keyid` | string | Identifier for the signing key (e.g., `"vaol-ed25519-001"`). |
| `sig` | string | Base64url-encoded signature bytes. |
| `cert` | string | Optional. Fulcio certificate for Sigstore keyless signing. |
| `rekor_entry_id` | string | Optional. Rekor transparency log entry for this signature (strict profile requires it for Sigstore signatures). |
| `timestamp` | string | RFC 3339 timestamp of when the signature was created. |

### VerificationResult

Returned by `POST /v1/verify`.

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | The record's `request_id` extracted from the payload. |
| `sequence_number` | integer | Sequence number, if available. |
| `timestamp` | datetime | Timestamp of the verification. |
| `valid` | boolean | `true` if all checks passed. |
| `checks` | CheckResult[] | Individual verification check results. |
| `error` | string | Top-level error message if payload extraction failed. |

### CheckResult

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Check identifier: `"signature"`, `"schema"`, `"record_hash"`, `"hash_chain"`, `"merkle_inclusion"`. |
| `passed` | boolean | Whether this check passed. |
| `details` | string | Human-readable details on success. |
| `error` | string | Error description on failure. |

### BundleVerificationResult

Returned by `POST /v1/verify/bundle`.

| Field | Type | Description |
|-------|------|-------------|
| `total_records` | integer | Total number of records in the bundle. |
| `valid_records` | integer | Number of records that passed all verification checks. |
| `invalid_records` | integer | Number of records that failed one or more checks. |
| `chain_intact` | boolean | `true` if the hash chain is unbroken across all records. |
| `merkle_valid` | boolean | `true` if all Merkle inclusion proofs are valid. |
| `signatures_valid` | boolean | `true` if all signatures are valid. |
| `schema_valid` | boolean | `true` if all records conform to the DecisionRecord v1 schema. |
| `checkpoint_valid` | boolean | `true` if signed checkpoint verification succeeds. |
| `policy_hash_valid` | boolean | `true` when policy hash requirements for the selected profile are met. |
| `manifest_valid` | boolean | `true` if the bundle manifest hash matches recomputed deterministic evidence digest. |
| `summary` | string | Overall status: `VERIFICATION PASSED` or `VERIFICATION FAILED`. |

### Bundle

Returned by `POST /v1/export`. A self-contained audit evidence package.

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Bundle format version (currently `"1.0"`). |
| `exported_at` | datetime | Timestamp of export. |
| `exported_by` | string | Optional. Identity of the exporter. |
| `filter` | BundleFilter | The filter criteria used to select records. |
| `records` | BundleRecord[] | Array of signed records with inclusion proofs. |
| `checkpoints` | BundleCheckpoint[] | Signed Merkle checkpoints for offline verification. |
| `privacy_evidence` | BundlePrivacyEvidence | Optional retention and key-rotation evidence attached to the bundle. |
| `metadata` | BundleMetadata | Summary statistics for the bundle. |
| `manifest` | BundleManifest | Deterministic digest over records, checkpoints, and privacy evidence. |

### BundleMetadata

| Field | Type | Description |
|-------|------|-------------|
| `total_records` | integer | Number of records in the bundle. |
| `first_sequence` | integer | Lowest sequence number in the bundle. |
| `last_sequence` | integer | Highest sequence number in the bundle. |
| `merkle_root_hash` | string | Merkle root hash from the latest checkpoint. |
| `merkle_tree_size` | integer | Tree size from the latest checkpoint. |

### BundleManifest

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | string | Digest algorithm (`sha256`). |
| `evidence_hash` | string | Deterministic digest over bundle evidence. |
| `record_digest_count` | integer | Number of record digests included in manifest input. |
| `checkpoint_digest_count` | integer | Number of checkpoint digests included in manifest input. |
| `privacy_digest_count` | integer | Number of privacy-evidence digests included in manifest input. |

### BundlePrivacyEvidence

| Field | Type | Description |
|-------|------|-------------|
| `payload_tombstones` | array | Immutable evidence generated by encrypted payload retention deletion. |
| `key_rotation_events` | array | Immutable evidence generated by encryption key rotation metadata jobs. |

### Checkpoint

| Field | Type | Description |
|-------|------|-------------|
| `tree_size` | integer | Number of leaves in the Merkle tree at checkpoint time. |
| `root_hash` | string | Merkle root hash (`sha256:<hex>`). |
| `timestamp` | datetime | When the checkpoint was created. |
| `signature` | string | Optional. Cryptographic signature over the checkpoint. |
| `rekor_entry_id` | string | Optional. Sigstore Rekor transparency log entry ID. |
