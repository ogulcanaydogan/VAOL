# VAOL — Verifiable AI Output Ledger

**Cryptographically verifiable, append-only audit ledger for AI/LLM inference decisions.**

Provides tamper-evident audit trails for regulated industries where organizations must prove the provenance, policy compliance, and integrity of every AI-generated output. DSSE envelopes, RFC 6962 Merkle trees, OPA policy-as-code, and multi-tenant JWT authentication.

[![CI](https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger)](https://goreportcard.com/report/github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](go.mod)
[![Python SDK](https://img.shields.io/badge/Python_SDK-3.11+-3776AB.svg)](sdk/python)
[![TypeScript SDK](https://img.shields.io/badge/TypeScript_SDK-5.0+-3178C6.svg)](sdk/typescript)

---

## Why This Exists

AI systems in regulated industries (healthcare, finance, legal, government) face a critical challenge: **how do you prove what an AI system actually said, when, under what policy, and that the record hasn't been tampered with?**

Current approaches are inadequate:
- Application logs can be modified or deleted
- Database records lack cryptographic integrity guarantees
- No standardized way to prove policy compliance at inference time
- Auditors cannot independently verify AI decision provenance

VAOL solves this by providing a **cryptographic audit ledger** that:

- Creates **tamper-evident records** of every AI inference with digital signatures and hash chains
- Enforces **policy-as-code** via OPA/Rego evaluated at decision time
- Provides **verifiable proofs** using RFC 6962 Merkle trees that auditors can independently validate
- Supports **privacy-preserving modes** — store hashes only, encrypted content, or plaintext based on policy
- Enables **zero-trust verification** — clients can verify signatures and proofs without trusting the server

The project targets compliance teams, auditors, and engineers building AI systems that require demonstrable governance for regulatory, legal, or enterprise requirements.

---

## How It Works

```mermaid
graph LR
    A[Application] --> B[VAOL SDK/Proxy]
    B --> C[LLM Provider]
    B --> D[VAOL Server]
    D --> E[Policy Engine<br/>OPA/Rego]
    D --> F[Signer<br/>Ed25519/Sigstore/KMS]
    D --> G[Merkle Log<br/>RFC 6962]
    D --> H[Ledger Store<br/>PostgreSQL]
    G --> I[Auditor<br/>CLI Verifier]
    H --> I

    style A fill:#4A90D9,stroke:#2C5F8A,color:#fff
    style B fill:#7B68EE,stroke:#5B48CE,color:#fff
    style C fill:#50C878,stroke:#3AA862,color:#fff
    style D fill:#F5A623,stroke:#C7851A,color:#fff
    style E fill:#FF6B6B,stroke:#CC4444,color:#fff
    style F fill:#FF8C42,stroke:#CC6A2E,color:#fff
    style G fill:#4ECDC4,stroke:#36B5AC,color:#fff
    style H fill:#9B59B6,stroke:#7D3C98,color:#fff
    style I fill:#2ECC71,stroke:#27AE60,color:#fff
```

Every time your application calls an LLM, VAOL captures a **DecisionRecord** containing:

| Field | Description |
|-------|-------------|
| **Identity** | Tenant, user, service making the request |
| **Model** | Provider, name, version, endpoint |
| **Prompt** | Cryptographic hash (never raw content by default) |
| **Policy** | OPA bundle, decision result, rule IDs evaluated |
| **RAG Context** | Document IDs, chunk hashes, citations |
| **Output** | Hash, optionally encrypted or plaintext |
| **Proof** | Digital signature, hash chain link, Merkle inclusion proof |

Each record is **signed** (Ed25519, Sigstore keyless, or KMS/HSM), **hash-chained** to its predecessor, and anchored in an **RFC 6962 Merkle tree** with verifiable inclusion proofs.

---

## Verification Layers

```mermaid
graph TD
    A[DecisionRecord] --> B{Layer 1<br/>Signature}
    B -->|Valid| C{Layer 2<br/>Schema}
    B -->|Invalid| X[REJECT]
    C -->|Valid| D{Layer 3<br/>Hash Chain}
    C -->|Invalid| X
    D -->|Valid| E{Layer 4<br/>Merkle Proof}
    D -->|Invalid| X
    E -->|Valid| F[VERIFIED ✓]
    E -->|Invalid| X

    style A fill:#4A90D9,stroke:#2C5F8A,color:#fff
    style B fill:#FF6B6B,stroke:#CC4444,color:#fff
    style C fill:#FF8C42,stroke:#CC6A2E,color:#fff
    style D fill:#F5A623,stroke:#C7851A,color:#fff
    style E fill:#7B68EE,stroke:#5B48CE,color:#fff
    style F fill:#2ECC71,stroke:#27AE60,color:#fff
    style X fill:#E74C3C,stroke:#C0392B,color:#fff
```

| Layer | Verification | Purpose |
|-------|-------------|---------|
| **1. Signature** | DSSE envelope signature valid (Ed25519/Sigstore/KMS) | Proves record authenticity |
| **2. Key Revocation** | Signature keyid not revoked at signature timestamp (when a revocation list is configured) | Detects compromised signing identities |
| **3. Schema** | DecisionRecord conforms to v1 JSON Schema | Ensures structural integrity |
| **4. Hash Chain** | `previous_record_hash` matches predecessor | Detects insertion/deletion |
| **5. Merkle Inclusion** | Inclusion proof valid against tree root | Enables global consistency audit |

The `vaol verify` CLI command and `/v1/verify` API perform these checks, with key revocation enforcement enabled when a revocation list is supplied.

---

## Privacy Modes

```mermaid
graph LR
    subgraph Modes ["Privacy Mode Selection"]
        A[hash_only<br/>Maximum Privacy]
        B[encrypted<br/>Recoverable]
        C[plaintext<br/>Full Audit]
    end

    A --> D[SHA-256<br/>Digest Only]
    B --> E[age X25519<br/>Encrypted + Digest]
    C --> F[Raw Content<br/>Policy-Gated]

    style A fill:#2ECC71,stroke:#27AE60,color:#fff
    style B fill:#F5A623,stroke:#C7851A,color:#fff
    style C fill:#E74C3C,stroke:#C0392B,color:#fff
    style D fill:#4ECDC4,stroke:#36B5AC,color:#fff
    style E fill:#4ECDC4,stroke:#36B5AC,color:#fff
    style F fill:#4ECDC4,stroke:#36B5AC,color:#fff
```

| Mode | What's Stored | Use Case |
|------|--------------|----------|
| `hash_only` (default) | SHA-256 digests only | Maximum privacy; prove integrity without exposing content |
| `encrypted` | age X25519 encrypted blobs + digest | Content recoverable with key; digest binding prevents swap |
| `plaintext` | Raw text (policy-gated) | Full content for internal audit; requires explicit policy allow |

---

## Quick Start

### Docker Compose

```bash
# Start VAOL server + PostgreSQL + OPA
docker compose -f deploy/docker/docker-compose.yml up -d

# Check health
curl http://localhost:8080/v1/health

# Optional: run the mandatory-citations policy
VAOL_OPA_POLICY=v1/data/vaol/mandatory_citations \
docker compose -f deploy/docker/docker-compose.yml up -d
```

### Build from Source

```bash
make build

# Run server with in-memory store (development)
./bin/vaol-server --addr :8080 --auth-mode disabled --policy-mode allow-all

# Optional: enable gRPC API on a second listener
./bin/vaol-server --addr :8080 --grpc-addr :9090 --auth-mode disabled --policy-mode allow-all

# Run server with PostgreSQL
./bin/vaol-server --addr :8080 --dsn "postgres://vaol:vaol@localhost:5432/vaol"

# Run with signer backends
./bin/vaol-server --signer-mode ed25519 --key ~/.vaol/keys/vaol-signing.pem
./bin/vaol-server --signer-mode sigstore --sigstore-rekor-required
./bin/vaol-server --signer-mode kms --kms-provider aws-kms --kms-key-uri arn:aws:kms:...

# Optional high-scale append event publishing to Kafka
./bin/vaol-server \
  --ingest-mode kafka \
  --ingest-kafka-brokers kafka-1:9092,kafka-2:9092 \
  --ingest-kafka-topic vaol.decision-records \
  --ingest-kafka-client-id vaol-server \
  --ingest-kafka-required

# Enforce startup anchor continuity verification (production hardening)
./bin/vaol-server --anchor-mode local --anchor-continuity-required

# Enforce verifier key revocations for /v1/verify and /v1/verify/bundle
./bin/vaol-server --verify-revocations-file /etc/vaol/revocations.json

# Async high-scale Merkle/checkpoint worker fed from Kafka append events
./bin/vaol-ingest-worker \
  --kafka-brokers kafka-1:9092,kafka-2:9092 \
  --kafka-topic vaol.decision-records \
  --kafka-group-id vaol-ingest-worker \
  --checkpoint-topic vaol.tenant-checkpoints \
  --anchor-mode local \
  --checkpoint-every 100
```

### Python SDK

```bash
pip install vaol
```

```python
from openai import OpenAI
import vaol

client = OpenAI()
vaol_client = vaol.VAOLClient("http://localhost:8080")

# Instrument: every LLM call now emits a DecisionRecord
wrapped = vaol.instrument_openai(client, vaol_client, tenant_id="my-org")

response = wrapped.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this patient report."}],
)
# DecisionRecord automatically emitted with prompt hash,
# output hash, model identity, and policy context.

# Anthropic and LiteLLM wrappers are also available:
# vaol.instrument_anthropic(anthropic_client, vaol_client, tenant_id="my-org")
# vaol.instrument_litellm(vaol_client, tenant_id="my-org")
```

### TypeScript SDK

```bash
npm install @vaol/sdk
```

```typescript
import OpenAI from "openai";
import { VAOLClient, instrumentOpenAI } from "@vaol/sdk";

const openai = new OpenAI();
const vaol = new VAOLClient({ baseURL: "http://localhost:8080" });

// Instrument: every LLM call now emits a DecisionRecord
instrumentOpenAI(openai, {
  client: vaol,
  tenantID: "my-org",
  subject: "my-service",
});

const response = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Summarize this patient report." }],
});
// DecisionRecord automatically emitted to VAOL
```

### Client-Side Verification

Both SDKs support offline verification without trusting the server:

**Python:**
```python
from vaol import verify_dsse_ed25519, verify_inclusion_proof

sig_result = verify_dsse_ed25519(envelope, public_key_bytes)
proof_result = verify_inclusion_proof(leaf_data, leaf_index, tree_size, hashes, root)
```

**TypeScript:**
```typescript
import { verifyDSSEEd25519, verifyInclusionProof } from "@vaol/sdk";

const sigResult = verifyDSSEEd25519(envelope, publicKey);
const proofResult = verifyInclusionProof(leafData, leafIndex, treeSize, hashes, root);
```

---

## Architecture

```mermaid
graph TB
    subgraph Clients ["Client Integration"]
        SDK_PY[Python SDK]
        SDK_TS[TypeScript SDK]
        PROXY[OpenAI Proxy]
        CLI[CLI Tool]
    end

    subgraph Server ["VAOL Server — Go"]
        API[REST API]
        AUTH[JWT/OIDC Auth]
        POLICY[OPA Policy Engine]
        SIGNER[Signer<br/>Ed25519 · Sigstore · KMS]
        MERKLE[Merkle Log<br/>RFC 6962]
        EXPORT[Evidence Exporter]
    end

    subgraph Storage ["Data Layer"]
        PG[(PostgreSQL)]
        MEM[(In-Memory<br/>Dev Only)]
    end

    SDK_PY --> API
    SDK_TS --> API
    PROXY --> API
    CLI --> API
    API --> AUTH
    AUTH --> POLICY
    POLICY --> SIGNER
    SIGNER --> MERKLE
    MERKLE --> PG
    MERKLE --> MEM
    EXPORT --> PG

    style Clients fill:#1a1a2e,stroke:#4A90D9,color:#fff
    style Server fill:#1a1a2e,stroke:#50C878,color:#fff
    style Storage fill:#1a1a2e,stroke:#F5A623,color:#fff
    style API fill:#4A90D9,stroke:#2C5F8A,color:#fff
    style AUTH fill:#7B68EE,stroke:#5B48CE,color:#fff
    style POLICY fill:#FF6B6B,stroke:#CC4444,color:#fff
    style SIGNER fill:#FF8C42,stroke:#CC6A2E,color:#fff
    style MERKLE fill:#4ECDC4,stroke:#36B5AC,color:#fff
    style EXPORT fill:#9B59B6,stroke:#7D3C98,color:#fff
    style PG fill:#336791,stroke:#254E6C,color:#fff
    style MEM fill:#95A5A6,stroke:#7F8C8D,color:#fff
```

---

## Policy Engine

VAOL uses OPA/Rego for runtime policy evaluation with **fail-closed defaults**:

```mermaid
graph LR
    A[Request] --> B{OPA<br/>Configured?}
    B -->|Yes| C{Policy<br/>Evaluation}
    B -->|No| D[DENY<br/>missing_policy_engine]
    C -->|Allow| E[Proceed]
    C -->|Deny| F[DENY<br/>policy_violation]
    C -->|Error| G[DENY<br/>policy_error]

    style A fill:#4A90D9,stroke:#2C5F8A,color:#fff
    style B fill:#F5A623,stroke:#C7851A,color:#fff
    style C fill:#7B68EE,stroke:#5B48CE,color:#fff
    style D fill:#E74C3C,stroke:#C0392B,color:#fff
    style E fill:#2ECC71,stroke:#27AE60,color:#fff
    style F fill:#E74C3C,stroke:#C0392B,color:#fff
    style G fill:#E74C3C,stroke:#C0392B,color:#fff
```

**Included Policies:**

| Policy | Purpose |
|--------|---------|
| `base.rego` | Required field validation |
| `deny_plaintext.rego` | Prevent plaintext output storage |
| `model_allowlist.rego` | Only approved models permitted |
| `phi_redaction.rego` | PHI/PII redaction required for healthcare tenants |
| `mandatory_citations.rego` | RAG outputs must include citations |

For local development only, use `--policy-mode allow-all`.

---

## CLI

```bash
# Initialize VAOL config
./bin/vaol init

# Generate signing keys
./bin/vaol keys generate
# Writes: ~/.vaol/keys/vaol-signing.pem (private)
# Writes: ~/.vaol/keys/vaol-signing.pub (public)

# Verify an audit bundle
./bin/vaol verify bundle audit-bundle.json \
  --public-key ~/.vaol/keys/vaol-signing.pub \
  --revocations-file ./revocations.json \
  --transcript-json verification-transcript.json \
  --report-markdown verification-report.md

# Verify a single DSSE record with key revocation enforcement
./bin/vaol verify record record.json \
  --public-key ~/.vaol/keys/vaol-signing.pub \
  --revocations-file ./revocations.json

# Example revocation list format
cat > revocations.json <<'JSON'
{
  "version": "v1",
  "generated_at": "2026-02-23T00:00:00Z",
  "revocations": [
    {
      "keyid": "ed25519:abc123...",
      "effective_at": "2026-02-01T00:00:00Z",
      "reason": "compromised"
    }
  ]
}
JSON

# Inspect a DSSE envelope
./bin/vaol inspect record.json
```

### Auditor Demo

```bash
./scripts/demo_auditor.sh
```

Creates a reproducible evidence package under `tmp/demo-auditor/<timestamp>/`. See `docs/demo-auditor-storyline.md` for the full walkthrough.

### OpenAI-Compatible Proxy

```bash
# Start the transparent proxy
./bin/vaol-proxy --upstream https://api.openai.com --vaol-server http://localhost:8080

# Point your app at the proxy
export OPENAI_BASE_URL=http://localhost:8443/v1
# All requests now automatically logged to VAOL
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/records` | Append a DecisionRecord |
| `GET` | `/v1/records/{id}` | Retrieve a record |
| `GET` | `/v1/records` | List records (with filters) |
| `GET` | `/v1/records/{id}/proof` | Get Merkle inclusion proof |
| `GET` | `/v1/proofs/{id}` | Get inclusion proof by proof ID |
| `POST` | `/v1/verify` | Verify a DSSE envelope (`profile` query or `verification_profile` body) |
| `POST` | `/v1/verify/record` | Verify record (`basic\|strict\|fips`) |
| `POST` | `/v1/verify/bundle` | Verify an audit bundle (`profile` query or `verification_profile` body) |
| `GET` | `/v1/ledger/checkpoint` | Get latest Merkle checkpoint |
| `GET` | `/v1/ledger/checkpoints/latest` | Alias for latest signed checkpoint |
| `GET` | `/v1/ledger/consistency` | Get consistency proof (`from`,`to`) |
| `POST` | `/v1/export` | Export audit bundle |
| `GET` | `/v1/health` | Health check |

gRPC API is also available through `VAOLLedger` when `--grpc-addr` is enabled. See `proto/vaol/v1/ledger.proto`.

---

## Authentication

| Mode | Description |
|------|-------------|
| `disabled` | No JWT verification (local development only) |
| `optional` | Verify JWT if provided |
| `required` (default) | Require valid JWT with bound tenant/subject claims |

Supported algorithms: `HS256`, `RS256`, `ES256` with key material from `--jwks-file`, `--jwks-url`, or `--jwt-hs256-secret`.

### Tenant-Bound Access

Tenant-scoped APIs require header:
- `X-VAOL-Tenant-ID` (preferred), or
- `X-Tenant-ID`

Cross-tenant access is rejected with deterministic deny reason codes.

---

## Project Structure

```
vaol/
├── cmd/
│   ├── vaol-server/         # Ledger server
│   ├── vaol-cli/            # CLI tool
│   └── vaol-proxy/          # OpenAI-compatible proxy
├── pkg/
│   ├── record/              # DecisionRecord types + JCS canonicalization
│   ├── signer/              # DSSE envelopes, Ed25519, Sigstore, KMS
│   ├── merkle/              # RFC 6962 Merkle tree + proofs
│   ├── store/               # PostgreSQL + in-memory backends
│   ├── policy/              # OPA engine + fail-closed wrapper
│   ├── auth/                # JWT/OIDC verification + tenant binding
│   ├── verifier/            # Composite verification
│   ├── export/              # Audit bundle creation
│   ├── crypto/              # SHA-256, age encryption
│   ├── api/                 # REST API server
│   └── grpc/                # gRPC API server
├── sdk/
│   ├── python/              # Python SDK with OpenAI/Anthropic/LiteLLM instrumentation
│   └── typescript/          # TypeScript SDK with OpenAI instrumentation
├── policies/                # OPA/Rego example policies
├── schemas/v1/              # JSON Schema for DecisionRecord
├── deploy/
│   ├── docker/              # Docker Compose
│   └── helm/                # Kubernetes Helm charts
├── scripts/                 # Demo and operational scripts
├── docs/                    # Architecture, API, deployment guides
└── tests/                   # E2E + tamper detection tests
```

---

## Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Cryptographic Design](docs/crypto-design.md)
- [Threat Model](docs/threat-model.md)
- [Auditor Guide](docs/auditor-guide.md)
- [Deployment Guide](docs/deployment-production-profile.md)
- [Release Runbook](docs/releases/release-runbook.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/)

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Server** | Go 1.24+ | High-performance ledger server |
| **Storage** | PostgreSQL 15 | Persistent record and proof storage |
| **Policy** | OPA/Rego | Runtime policy evaluation |
| **Cryptography** | Ed25519, Sigstore, age | Signing and encryption |
| **Auth** | JWT/OIDC | Multi-tenant authentication |
| **SDKs** | Python 3.10+, TypeScript 5.0+ | Client integration |
| **Infrastructure** | Docker, Kubernetes (Helm) | Deployment targets |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
