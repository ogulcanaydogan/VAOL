# VAOL Architecture

## Overview

The Verifiable AI Output Ledger (VAOL) is a self-hostable, cryptographically verifiable ledger that captures every AI inference decision as a signed, hash-chained, Merkle-tree-anchored evidence record. It provides organizations with a tamper-evident audit trail for all LLM interactions, enabling regulatory compliance, forensic investigations, and governance over AI-generated outputs.

Every inference call -- whether routed through a transparent proxy, instrumented via an SDK, or submitted directly through the REST API -- produces a `DecisionRecord`. This record is validated against a JSON Schema, evaluated by a policy engine, sealed with a cryptographic signature inside a DSSE (Dead Simple Signing Envelope), chained to its predecessor via SHA-256, and anchored into an RFC 6962-style Merkle tree. The resulting receipt proves both the record's inclusion and the integrity of the entire ledger at that point in time.

VAOL never stores raw prompts or outputs by default. Prompt and output content is captured only as SHA-256 digests (`sha256:<hex>`). Organizations may optionally enable `age`-encrypted blob storage or, where policy explicitly permits, plaintext retention.

---

## System Components

### vaol-server (Go)

The core ledger server. It exposes both REST and gRPC APIs and orchestrates the full record lifecycle: schema validation, policy evaluation, hash computation, DSSE signing, Merkle tree insertion, and persistent storage.

| Package | Responsibility |
|---------|---------------|
| `cmd/vaol-server` | CLI entrypoint; wires together store, signer, Merkle tree, policy engine, and HTTP server |
| `pkg/api` | HTTP server, routing (`http.ServeMux`), middleware (request ID, CORS, auth, logging), startup rebuild checks, and all REST handlers |
| `pkg/grpc` | gRPC server (`VAOLLedger`) with auth verification, tenant metadata enforcement, streaming list/export, and parity checks for cross-tenant access |
| `pkg/record` | `DecisionRecord` v1 type definitions, JSON Schema validation, JCS canonicalization, and hash computation |
| `pkg/signer` | DSSE envelope creation and verification; `Signer` / `Verifier` interfaces with Ed25519, Sigstore, and KMS backends |
| `pkg/merkle` | RFC 6962 append-only Merkle tree -- inclusion proofs, consistency proofs, and root computation |
| `pkg/store` | `Store` interface with PostgreSQL and in-memory implementations; schema migration; encrypted payload retention/rotation jobs |
| `pkg/policy` | OPA integration via REST; `FailClosedEngine` wrapper; `DenyAllEngine` for no-policy fail-closed and `NoopEngine` for development |
| `pkg/auth` | JWT/OIDC verification (`HS256`,`RS256`,`ES256`) and trusted tenant/subject claim binding |
| `pkg/verifier` | Composite verification: signature, schema, record hash, hash chain, and Merkle inclusion |
| `pkg/crypto` | SHA-256 utilities, RFC 6962 leaf/node hashing, `age` encryption/decryption |
| `pkg/export` | Audit bundle creation: portable JSON packages of signed records with Merkle proofs |

**REST API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/records` | Append a new DecisionRecord to the ledger |
| `GET` | `/v1/records/{id}` | Retrieve a stored record by request ID |
| `GET` | `/v1/records` | List records with tenant, time range, and cursor filters |
| `GET` | `/v1/records/{id}/proof` | Get the Merkle inclusion proof for a record |
| `GET` | `/v1/proofs/{id}` | Get a persisted inclusion proof by proof ID |
| `POST` | `/v1/verify` | Verify a single DSSE envelope |
| `POST` | `/v1/verify/bundle` | Verify an exported audit bundle |
| `GET` | `/v1/ledger/checkpoint` | Get the latest Merkle tree checkpoint (root hash and size) |
| `GET` | `/v1/ledger/checkpoints/latest` | Alias for latest signed checkpoint |
| `GET` | `/v1/ledger/consistency` | Get consistency proof between two tree sizes |
| `POST` | `/v1/export` | Export records as a portable audit bundle |
| `GET` | `/v1/health` | Server health check |

**gRPC Service Endpoints (`VAOLLedger`):**

- `Health` (unauthenticated)
- `AppendRecord`
- `GetRecord`
- `ListRecords` (server-streaming)
- `GetInclusionProof`
- `GetProofByID`
- `GetConsistencyProof`
- `GetCheckpoint`
- `VerifyRecord`
- `ExportBundle` (server-streaming)

Tenant-scoped gRPC calls enforce JWT + tenant semantics equivalent to REST. Metadata keys are:

- `authorization: Bearer <JWT>`
- `x-vaol-tenant-id` (preferred explicit tenant context)
- `x-tenant-id` (legacy compatibility; rejected if it conflicts with `x-vaol-tenant-id`)

### vaol-cli (Go)

A command-line tool built with Cobra for offline operations:

- `vaol init` -- Initialize a VAOL configuration directory and key storage at `~/.vaol`
- `vaol keys generate` -- Generate and persist an Ed25519 signing key pair (`vaol-signing.pem` + `vaol-signing.pub`)
- `vaol verify record <file>` -- Verify a single DSSE envelope (signature, schema, record hash)
- `vaol verify bundle <file>` -- Verify an exported audit bundle end-to-end
- `vaol inspect <file>` -- Decode and pretty-print a DSSE envelope's payload
- `vaol export` -- Instructions for exporting records from a running server

### vaol-proxy (Go)

An OpenAI-compatible transparent HTTP proxy. Applications point their `OPENAI_API_BASE` (or equivalent) at the proxy, which:

1. Captures the inbound request body (model, parameters, prompt hash).
2. Forwards the request to the upstream LLM API unchanged.
3. Captures the response (output hash, token counts, latency).
4. Asynchronously constructs a `DecisionRecord` and POSTs it to `vaol-server`.
5. Returns the original LLM response to the caller with `X-VAOL-Record-ID` and `X-VAOL-Proxy` headers injected.

The proxy requires zero application code changes. Default listen address is `:8443`; the upstream defaults to `https://api.openai.com`.

### vaol-sdk-python

A Python SDK (`vaol` package) providing:

- **`VAOLClient` / `AsyncVAOLClient`** -- Synchronous and async HTTP clients (built on `httpx`) wrapping the full REST API: `append`, `get`, `list`, `get_proof`, `verify`, `export`, `health`, `checkpoint`.
- **`DecisionRecord`** -- Dataclass builder for constructing records programmatically.
- **`instrument_openai()`** -- A monkey-patching wrapper that intercepts `client.chat.completions.create()` on any OpenAI client instance. Before the call it hashes the prompt context; after the call it captures output evidence; then it emits a `DecisionRecord` to the VAOL server. The wrapper is best-effort: failures to emit records are logged but never block the LLM response.

### vaol-sdk-typescript

A TypeScript SDK (`@vaol/sdk`) providing:

- **`VAOLClient`** -- Fetch-based HTTP client with timeout, tenant ID, and bearer token support.
- **`DecisionRecordBuilder`** -- Fluent builder for constructing records.
- **`instrumentOpenAI()`** -- Wraps `openai.chat.completions.create()` identically to the Python SDK. Supports fire-and-forget async emission (default) or synchronous mode.
- **`VAOLClient.sha256()`** -- Static utility for computing `sha256:<hex>` digests.

### OPA Sidecar

An Open Policy Agent (OPA) instance running as a sidecar or standalone service. VAOL ships with Rego policies under the `policies/` directory:

| Policy | Package | Purpose |
|--------|---------|---------|
| `base.rego` | `vaol.decision` | Validates required fields (tenant ID, model, output mode) |
| `deny_plaintext.rego` | `vaol.deny_plaintext` | Denies records that attempt plaintext output storage |
| `model_allowlist.rego` | `vaol.model_allowlist` | Restricts inference to an approved set of models |
| `phi_redaction.rego` | `vaol.phi_redaction` | Enforces PHI/PII redaction transforms |
| `mandatory_citations.rego` | `vaol.mandatory_citations` | Requires citation hashes when RAG context is present |

The server communicates with OPA via its REST API (`POST /v1/data/vaol/decision`). If OPA is unreachable, the `FailClosedEngine` wrapper denies the request rather than silently allowing it.

---

## Architecture Diagram

```mermaid
graph TB
    subgraph Client Environment
        APP[Application Code]
        SDK_PY[vaol-sdk-python]
        SDK_TS[vaol-sdk-typescript]
        PROXY[vaol-proxy]
    end

    subgraph LLM Providers
        OPENAI[OpenAI API]
        ANTHROPIC[Anthropic API]
        AZURE[Azure OpenAI]
    end

    subgraph VAOL Server
        API[REST API<br/>pkg/api]
        VALIDATE[Schema Validation<br/>pkg/record]
        POLICY[Policy Engine<br/>pkg/policy]
        HASH[Hash Chain<br/>pkg/crypto]
        SIGN[DSSE Signer<br/>pkg/signer]
        MERKLE[Merkle Tree<br/>pkg/merkle]
        VERIFY[Verifier<br/>pkg/verifier]
        EXPORT[Export / Bundle<br/>pkg/export]
    end

    subgraph Storage
        PG[(PostgreSQL<br/>decision_records<br/>merkle_checkpoints<br/>encrypted_payloads)]
    end

    subgraph External Services
        OPA[OPA Sidecar<br/>Rego Policies]
        SIGSTORE[Sigstore<br/>Fulcio + Rekor]
        KMS[Cloud KMS<br/>AWS / GCP / Azure]
    end

    subgraph Auditor
        CLI[vaol-cli]
    end

    APP -->|LLM call| SDK_PY
    APP -->|LLM call| SDK_TS
    APP -->|LLM call via proxy| PROXY

    SDK_PY -->|inference| OPENAI
    SDK_TS -->|inference| OPENAI
    PROXY -->|forward| OPENAI
    SDK_PY -->|inference| ANTHROPIC
    SDK_TS -->|inference| ANTHROPIC
    PROXY -->|forward| AZURE

    SDK_PY -->|POST /v1/records| API
    SDK_TS -->|POST /v1/records| API
    PROXY -->|POST /v1/records| API

    API --> VALIDATE
    VALIDATE --> POLICY
    POLICY -->|evaluate| OPA
    POLICY --> HASH
    HASH --> SIGN
    SIGN -->|Ed25519 / Sigstore / KMS| SIGSTORE
    SIGN -->|KMS sign| KMS
    SIGN --> MERKLE
    MERKLE --> PG
    API --> VERIFY
    API --> EXPORT

    CLI -->|verify bundle| VERIFY
    CLI -->|inspect / export| EXPORT
```

---

## Record Lifecycle

The following sequence describes the complete lifecycle of a single `DecisionRecord`, from the initial LLM call through to the returned receipt.

```mermaid
sequenceDiagram
    participant App as Application
    participant SDK as SDK / Proxy
    participant LLM as LLM Provider
    participant Server as vaol-server
    participant OPA as OPA Sidecar
    participant Tree as Merkle Tree
    participant Store as PostgreSQL

    App->>SDK: LLM call (model, messages, params)
    Note over SDK: Capture pre-call evidence:<br/>prompt hashes, parameters,<br/>tool schema hash, identity

    SDK->>LLM: Forward inference request
    LLM-->>SDK: LLM response

    Note over SDK: Capture post-call evidence:<br/>output hash, token counts,<br/>latency, finish reason

    SDK->>SDK: Build DecisionRecord

    SDK->>Server: POST /v1/records (DecisionRecord JSON)

    Server->>Server: 1. Set defaults (schema_version, request_id, timestamp)

    Server->>OPA: 2. POST policy evaluation input
    OPA-->>Server: Decision (allow / deny / allow_with_transform / log_only)

    alt Policy denies request
        Server-->>SDK: 403 Forbidden + decision details
    end

    Server->>Server: 3. Canonicalize record (JCS) and compute record_hash (SHA-256)

    Server->>Store: 4. Get latest record for hash chain linkage
    Store-->>Server: previous_record_hash

    Server->>Server: 5. Sign full record JSON as DSSE envelope (PAE encoding)

    Server->>Tree: 6. Append record_hash as leaf
    Tree-->>Server: leaf_index, merkle_root, tree_size

    Server->>Tree: 7. Generate inclusion proof
    Tree-->>Server: InclusionProof (sibling hashes)

    Server->>Store: 8. Persist StoredRecord (envelope, hashes, leaf index)
    Store-->>Server: sequence_number

    Server-->>SDK: 201 Created + Receipt

    Note over SDK: Receipt contains:<br/>request_id, sequence_number,<br/>record_hash, merkle_root,<br/>merkle_tree_size, inclusion_proof

    SDK-->>App: Original LLM response (unmodified)
```

### Step-by-Step Detail

1. **Evidence capture** -- The SDK (or proxy) wraps the LLM client call. Before the call, it hashes the prompt components (system prompt, user messages, tool schemas). After the call, it hashes the output and records token counts, latency, and finish reason.

2. **DecisionRecord construction** -- The SDK assembles a `DecisionRecord` v1 with identity, model, parameters, prompt context, output evidence, and trace fields. Prompts and outputs are stored as `sha256:<hex>` digests by default.

3. **Submission** -- The record is POSTed to `POST /v1/records` on the VAOL server.

4. **Schema validation** -- The server sets missing defaults (`schema_version`, `request_id`, `timestamp`), then validates the record structure against the v1 JSON Schema.

5. **Policy evaluation** -- If an OPA engine is configured, the server sends the record's metadata to OPA for evaluation. The policy decision (`allow`, `deny`, `allow_with_transform`, `log_only`) is sealed into `policy_context`. A `deny` decision returns HTTP 403 immediately.

6. **Record hash** -- The server computes a JCS-canonicalized SHA-256 hash of the record (excluding server-computed integrity fields). This `record_hash` becomes the fingerprint for chain linkage and Merkle anchoring.

7. **Hash chain** -- The server retrieves the `record_hash` of the most recent stored record and writes it into `integrity.previous_record_hash`. The genesis record uses a well-known zero hash (`sha256:0000...`).

8. **DSSE signing** -- The complete record JSON (with `record_hash` set) is signed inside a DSSE envelope using Pre-Authentication Encoding (PAE). The envelope contains the base64-encoded payload, the payload type (`application/vnd.vaol.decision-record.v1+json`), and one or more signatures.

9. **Merkle tree insertion** -- The `record_hash` bytes are appended as a leaf to the RFC 6962 Merkle tree. The tree returns the leaf index, updated root hash, and tree size.

10. **Inclusion proof** -- An inclusion proof (sibling hashes from leaf to root) is generated and attached to the record's integrity block.

11. **Persistence** -- The signed envelope, hash chain metadata, and Merkle leaf index are stored in PostgreSQL in a single `INSERT` with a `BIGSERIAL` sequence number.

12. **Receipt** -- The server returns a `Receipt` containing the `request_id`, `sequence_number`, `record_hash`, `merkle_root`, `merkle_tree_size`, `inclusion_proof`, and `timestamp`.

---

## DecisionRecord Schema (v1)

The `DecisionRecord` is the fundamental evidence type. Its JSON Schema is defined in `schemas/v1/decision-record.schema.json`. The top-level structure:

```
DecisionRecord
  +-- schema_version: "v1"
  +-- request_id: UUID v4
  +-- timestamp: ISO 8601 UTC
  +-- identity
  |     +-- tenant_id
  |     +-- subject (pseudonymous)
  |     +-- subject_type: user | service | pipeline
  |     +-- claims: map<string, string>
  +-- model
  |     +-- provider: openai | anthropic | azure | bedrock | ...
  |     +-- name: gpt-4o | claude-sonnet-4-5-20250929 | ...
  |     +-- version, endpoint, deployment_id
  +-- parameters
  |     +-- temperature, top_p, max_tokens, seed, ...
  +-- prompt_context
  |     +-- system_prompt_hash: sha256:<hex>
  |     +-- user_prompt_hash: sha256:<hex>
  |     +-- tool_schema_hash, safety_prompt_hash
  |     +-- message_count, total_input_tokens
  +-- policy_context
  |     +-- policy_bundle_id, policy_hash
  |     +-- policy_decision: allow | deny | allow_with_transform | log_only
  |     +-- rule_ids[], transforms_applied[]
  +-- rag_context (optional)
  |     +-- connector_ids[], document_ids[]
  |     +-- chunk_hashes[], citation_hashes[]
  |     +-- prompt_injection_check
  +-- output
  |     +-- output_hash: sha256:<hex>
  |     +-- mode: hash_only | encrypted | plaintext
  |     +-- output_encrypted, output_plaintext
  |     +-- output_tokens, finish_reason, latency_ms
  +-- trace
  |     +-- otel_trace_id, otel_span_id
  |     +-- parent_request_id, session_id
  +-- integrity
        +-- sequence_number
        +-- record_hash: sha256:<hex>
        +-- previous_record_hash: sha256:<hex>
        +-- merkle_root, merkle_tree_size
        +-- inclusion_proof { leaf_index, hashes[] }
```

---

## Signing Options

VAOL supports three signing backends, all implementing the `signer.Signer` interface. Each produces a DSSE envelope with Pre-Authentication Encoding (PAE) per the DSSE specification.

### Ed25519 (Local Key)

The default and simplest option. An Ed25519 private key is loaded from a PEM file or generated ephemerally for development. Key IDs are derived from the first 8 bytes of the public key (`ed25519:<hex>`).

- **Use case:** Self-hosted deployments with key material managed by the operator.
- **Key generation:** `vaol keys generate` or server auto-generates an ephemeral key if `--key` is not provided.
- **Verification:** The corresponding `Ed25519Verifier` checks signatures using the public key.

### Sigstore (Keyless)

OIDC-based identity signing using the Sigstore ecosystem (Fulcio for certificate issuance, Rekor for transparency logging). Each signing operation:

1. Generates an ephemeral Ed25519 key pair.
2. Obtains a short-lived Fulcio certificate binding the key to an OIDC identity.
3. Signs the PAE-encoded payload.
4. Submits the entry to Rekor for timestamping and transparency.

The DSSE `Signature` includes the Fulcio certificate in the `cert` field, enabling offline verification without access to the original key material.

- **Use case:** Zero-trust environments where key management overhead is unacceptable, or where identity-based signing provenance (tied to OIDC tokens from GitHub Actions, Google Workload Identity, etc.) is required.
- **Configuration:** `SigstoreConfig` with Fulcio URL, Rekor URL, OIDC issuer, and optional pre-obtained identity token.

### KMS / HSM (Cloud)

Delegates signing to a cloud key management service or hardware security module. The `KMSSigner` accepts a pluggable `KMSBackend` interface:

| Provider | Key URI Format |
|----------|---------------|
| AWS KMS | `arn:aws:kms:<region>:<account>:key/<key-id>` |
| GCP Cloud KMS | `projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<ver>` |
| Azure Key Vault | `https://<vault>.vault.azure.net/keys/<key>/<version>` |

The MVP includes a `LocalECDSABackend` (ECDSA P-256) for testing the KMS interface without cloud credentials. Cloud backends use SHA-256 digests of the PAE payload for the actual signing operation.

- **Use case:** Regulated environments requiring FIPS 140-2/3 compliant key storage, or organizations centralizing key management in their cloud provider.

---

## Cryptographic Primitives

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Record hashing | SHA-256 (prefixed `sha256:<hex>`) | Prompt hashes, output hashes, record hash, chain linkage |
| Merkle leaf hash | SHA-256(0x00 \|\| data) | RFC 6962 leaf computation |
| Merkle node hash | SHA-256(0x01 \|\| left \|\| right) | RFC 6962 interior node computation |
| DSSE signing | Ed25519 / ECDSA P-256 (KMS) | Envelope authentication |
| Payload encryption | `age` (X25519 + ChaCha20-Poly1305) | Optional encrypted output blob storage |
| PAE encoding | `DSSEv1 <len(type)> <type> <len(payload)> <payload>` | Pre-Authentication Encoding for DSSE |

---

## Storage

### PostgreSQL

PostgreSQL is the primary persistent store. The core schema includes:

**`decision_records`** -- The core append-only ledger.

| Column | Type | Description |
|--------|------|-------------|
| `sequence_number` | `BIGSERIAL PRIMARY KEY` | Monotonically increasing ledger position |
| `request_id` | `UUID UNIQUE NOT NULL` | Idempotency key; prevents duplicate records |
| `tenant_id` | `TEXT NOT NULL` | Organization/tenant identifier for multi-tenancy |
| `timestamp` | `TIMESTAMPTZ NOT NULL` | Record creation time |
| `record_hash` | `TEXT NOT NULL` | SHA-256 digest of the canonicalized record |
| `previous_record_hash` | `TEXT NOT NULL` | Hash chain link to predecessor |
| `dsse_envelope` | `JSONB NOT NULL` | Full signed DSSE envelope |
| `merkle_leaf_index` | `BIGINT` | Leaf position in the Merkle tree |
| `created_at` | `TIMESTAMPTZ DEFAULT NOW()` | Server-side insertion timestamp |

Indexed on `(tenant_id, timestamp DESC)` and `(record_hash)`.

**`merkle_checkpoints`** -- Periodic signed snapshots of the Merkle tree state.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `BIGSERIAL PRIMARY KEY` | Checkpoint sequence |
| `tree_size` | `BIGINT NOT NULL` | Number of leaves at checkpoint time |
| `root_hash` | `TEXT NOT NULL` | Merkle root hash |
| `signed_checkpoint` | `JSONB NOT NULL` | Signed checkpoint (signature + metadata) |
| `rekor_entry_id` | `TEXT` | Optional Rekor transparency log entry ID |
| `created_at` | `TIMESTAMPTZ DEFAULT NOW()` | Checkpoint creation time |

**`merkle_leaves`** -- Persisted Merkle leaf state for startup restoration and anti-tamper validation.

| Column | Type | Description |
|--------|------|-------------|
| `leaf_index` | `BIGINT PRIMARY KEY` | Stable RFC 6962 leaf position |
| `sequence_number` | `BIGINT NOT NULL` | Linked ledger sequence (`decision_records.sequence_number`) |
| `request_id` | `UUID NOT NULL` | Linked record (`decision_records.request_id`) |
| `record_hash` | `TEXT NOT NULL` | Stored record hash used as leaf input |
| `leaf_hash` | `TEXT NOT NULL` | Persisted `SHA-256(0x00 || record_hash)` |
| `created_at` | `TIMESTAMPTZ DEFAULT NOW()` | Insertion timestamp |

**`encrypted_payloads`** -- Optional table for `age`-encrypted prompt and output blobs plus lifecycle metadata.

| Column | Type | Description |
|--------|------|-------------|
| `request_id` | `UUID PRIMARY KEY` | References `decision_records(request_id)` |
| `encrypted_prompt` | `BYTEA` | `age`-encrypted prompt content |
| `encrypted_output` | `BYTEA` | `age`-encrypted output content |
| `tenant_id` | `TEXT NOT NULL` | Tenant binding for payload isolation |
| `encryption_key_id` | `TEXT NOT NULL` | Identifier of the encryption key used |
| `ciphertext_hash` | `TEXT` | Deterministic digest over ciphertext bytes |
| `plaintext_hash` | `TEXT` | Deterministic digest over plaintext bytes |
| `retain_until` | `TIMESTAMPTZ` | Retention cutoff for lifecycle deletion |
| `rotated_at` | `TIMESTAMPTZ` | Timestamp of latest key metadata rotation |
| `created_at` | `TIMESTAMPTZ DEFAULT NOW()` | Insertion timestamp |

**`payload_tombstones`** -- Immutable deletion evidence for encrypted payload retention actions.

| Column | Type | Description |
|--------|------|-------------|
| `tombstone_id` | `TEXT PRIMARY KEY` | Stable tombstone identifier |
| `request_id` | `UUID NOT NULL` | Request linked to deleted payload |
| `tenant_id` | `TEXT NOT NULL` | Tenant binding |
| `ciphertext_hash` | `TEXT` | Hash of deleted ciphertext |
| `encryption_key_id` | `TEXT NOT NULL` | Key metadata at deletion time |
| `deleted_at` | `TIMESTAMPTZ NOT NULL` | Deletion timestamp |
| `delete_reason` | `TEXT NOT NULL` | Deterministic deletion reason code/string |
| `created_at` | `TIMESTAMPTZ DEFAULT NOW()` | Tombstone creation timestamp |

### In-Memory Store

An in-memory implementation (`store.MemoryStore`) is provided for development and testing. It implements the same `Store` interface but does not persist data across restarts. The server automatically uses it when no PostgreSQL DSN is provided.

### Merkle Tree State

The Merkle tree is maintained in-memory for hot-path append/proof operations and persisted via `merkle_leaves` for startup restoration. On server startup, VAOL attempts restoration in this order:

1. Load persisted leaf hashes from `merkle_leaves`.
2. Validate contiguous leaf ordering and deterministic `leaf_hash` binding to `record_hash`.
3. Validate rebuilt tree size against `decision_records` count.
4. Validate latest signed checkpoint root/signature/anchor continuity.
5. If persisted leaf validation fails, fall back to full record traversal rebuild.

The startup check can fail-closed via `fail_on_startup_check=true` (default). The tree supports:

- **Append** -- O(1) amortized leaf addition
- **Root computation** -- Computed from the leaf array on demand
- **Inclusion proofs** -- Audit path from leaf to root
- **Consistency proofs** -- Proof that an older tree is a prefix of the current tree

---

## Verification

The `verifier.Verifier` performs four independent checks on each record:

1. **Signature verification** -- Validates all DSSE signatures in the envelope against registered `Verifier` instances (Ed25519, Sigstore, or KMS).

2. **Schema validation** -- Confirms the extracted payload deserializes as a valid `DecisionRecord` v1 and passes structural validation.

3. **Record hash verification** -- Recomputes the SHA-256 hash using JCS canonicalization and compares it against `integrity.record_hash`.

4. **Hash chain verification** -- For sequential records, confirms each record's `previous_record_hash` matches its predecessor's `record_hash`.

5. **Merkle inclusion verification** -- Recomputes the Merkle root from the leaf hash and inclusion proof path, confirming the record is anchored in the tree.

Bundle verification repeats these checks across all records in an exported audit bundle, additionally validating chain continuity across the full sequence.

---

## Audit Bundles

An audit bundle (`export.Bundle`) is a portable, self-contained JSON package that can be verified offline without access to the VAOL server. It contains:

- **Version** -- Bundle format version (currently `1.0`).
- **Filter** -- The criteria used to select records (tenant ID, time range).
- **Records** -- Array of `BundleRecord` entries, each containing the DSSE envelope and Merkle inclusion proof.
- **Checkpoints** -- Signed Merkle checkpoints covering the included records.
- **Metadata** -- Summary: total records, first/last sequence numbers, Merkle root hash.

Bundles are produced via `POST /v1/export` or the `vaol export` CLI command, and verified via `POST /v1/verify/bundle` or `vaol verify bundle <file>`.

---

## Policy Engine

### Architecture

```mermaid
graph LR
    SERVER[vaol-server] -->|POST /v1/data/vaol/decision| OPA[OPA Instance]
    OPA -->|evaluates| POLICIES[Rego Policy Bundle]
    OPA -->|returns| DECISION[Decision:<br/>allow / deny /<br/>allow_with_transform / log_only]
    SERVER -->|wraps| FAILCLOSED[FailClosedEngine]
    FAILCLOSED -->|on error| DENY[Deny by default]
```

### Policy Input

The server sends a structured input object to OPA containing:

```json
{
  "tenant_id": "acme-corp",
  "subject_type": "user",
  "model_provider": "openai",
  "model_name": "gpt-4o",
  "output_mode": "hash_only",
  "has_rag_context": false,
  "has_citations": false
}
```

### Policy Decisions

| Decision | Effect |
|----------|--------|
| `allow` | Record is accepted and appended to the ledger |
| `deny` | Record is rejected; server returns HTTP 403 |
| `allow_with_transform` | Record is accepted after specified transforms (e.g., PII redaction) |
| `log_only` | Record is appended for audit purposes but flagged as log-only |

### Fail-Closed Semantics

The `FailClosedEngine` wrapper ensures that if OPA is unreachable or returns an error, the request is denied rather than silently allowed. This prevents policy bypass during infrastructure failures.

---

## Deployment

### Docker Compose (Development)

The `deploy/docker/docker-compose.yml` file provides a complete local development stack:

```
docker compose -f deploy/docker/docker-compose.yml up
```

Services:

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `vaol-server` | Built from `Dockerfile.server` | 8080 | Core ledger server |
| `vaol-proxy` | Built from `Dockerfile.proxy` | 8443 | OpenAI-compatible proxy |
| `postgres` | `postgres:16-alpine` | 5432 | PostgreSQL 16 data store |
| `opa` | `openpolicyagent/opa:latest-static` | 8181 | OPA policy engine with `policies/` mounted |

The server connects to PostgreSQL via `postgres://vaol:vaol@postgres:5432/vaol` and to OPA via `http://opa:8181`. Postgres data is persisted in a Docker volume (`pgdata`).

### Helm Chart (Kubernetes)

The `deploy/helm/vaol/` Helm chart deploys the full VAOL stack to Kubernetes. Key features:

- **VAOL server deployment** with configurable replicas, resource limits, health probes (`/v1/health`), and security context (read-only root filesystem, non-root user, dropped capabilities).
- **OPA sidecar deployment** (`openpolicyagent/opa:0.70.0-static`) with policies loaded from a ConfigMap.
- **PostgreSQL** via the Bitnami subchart (toggle with `postgresql.enabled`) or external database connection.
- **Signing key** mounted from a Kubernetes Secret (existing or chart-created).
- **Optional proxy deployment** (`proxy.enabled: true`).
- **Ingress** resource with configurable class, annotations, hosts, and TLS.

Minimal installation:

```bash
helm install vaol deploy/helm/vaol \
  --set signingKey.existingSecret=vaol-signing-key \
  --set postgresql.auth.postgresPassword=<password>
```

### Configuration Reference

| Flag / Environment | Default | Description |
|---------------------|---------|-------------|
| `--addr` | `:8080` | Server listen address |
| `--dsn` | (empty -- in-memory) | PostgreSQL connection string |
| `--key` | (empty -- ephemeral) | Ed25519 private key PEM path |
| `--opa-url` | (empty -- noop engine) | OPA endpoint URL |
| `--opa-policy` | `v1/data/vaol/decision` | OPA policy path |
| `--verify-revocations-file` | (empty) | Verifier key revocation list JSON for `/v1/verify*` routes |
| `--web-dir` | (empty) | Path to auditor web UI static files (served at `/ui/`) |

---

## Security Considerations

- **Default privacy** -- Prompts and outputs are stored as SHA-256 hashes only. Plaintext storage must be explicitly enabled by policy.
- **Fail-closed policy** -- OPA unavailability results in request denial, not silent pass-through.
- **Append-only storage** -- The PostgreSQL schema and `Store` interface provide no `UPDATE` or `DELETE` operations on decision records.
- **Hash chain integrity** -- Each record links to its predecessor, making silent insertion or deletion detectable.
- **Merkle anchoring** -- Inclusion and consistency proofs enable efficient verification that no records have been added, removed, or modified.
- **DSSE envelopes** -- Payloads are signed with PAE to prevent type confusion and length-extension attacks.
- **Encryption at rest** -- Optional `age` encryption (X25519 + ChaCha20-Poly1305) for prompt and output blobs stored in the `encrypted_payloads` table.
- **Non-root containers** -- Helm chart enforces `runAsNonRoot: true`, read-only root filesystem, and drops all capabilities.

---

## Protocol Buffers and gRPC (Implemented)

VAOL ships an implemented gRPC service definition at `proto/vaol/v1/ledger.proto` (`VAOLLedger`), including streaming support for `ListRecords` and `ExportBundle`.

Current runtime behavior:

- `Health` is intentionally unauthenticated (parity with REST `/v1/health`).
- All other RPCs execute JWT verification based on configured auth mode (`disabled|optional|required`).
- Tenant-scoped RPCs enforce claim/header parity and reject cross-tenant access with deterministic `PermissionDenied` (`tenant mismatch` or `missing tenant context`).
- `AppendRecord` binds trusted auth evidence into `auth_context` and rejects subject/tenant mismatches against authenticated claims.
