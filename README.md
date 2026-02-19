# VAOL — Verifiable AI Output Ledger

[![CI](https://github.com/yapay-ai/vaol/actions/workflows/ci.yml/badge.svg)](https://github.com/yapay-ai/vaol/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/yapay-ai/vaol)](https://goreportcard.com/report/github.com/yapay-ai/vaol)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/yapay-ai/vaol)](go.mod)

A cryptographically verifiable, append-only ledger for AI/LLM inference decisions. VAOL provides tamper-evident audit trails for regulated industries where organizations must prove the provenance, policy compliance, and integrity of every AI-generated output.

## What VAOL Does

Every time your application calls an LLM, VAOL captures a **DecisionRecord** containing:

- **Who** made the request (tenant, user identity)
- **Which model** produced the output (provider, name, version, endpoint)
- **What prompt** was sent (cryptographic hashes — never raw content by default)
- **What policy** governed it (OPA/Rego bundle, decision, rule IDs)
- **What RAG context** was used (document IDs, chunk hashes, citations)
- **What output** was produced (hash, optionally encrypted or plaintext)
- **Proof of integrity** (digital signature, hash chain link, Merkle inclusion proof)

Each record is **signed** (Ed25519, Sigstore keyless, or KMS/HSM), **hash-chained** to its predecessor, and anchored in an **RFC 6962 Merkle tree** with verifiable inclusion proofs.

## Quick Start

### Run with Docker Compose

```bash
# Start VAOL server + PostgreSQL + OPA
docker compose -f deploy/docker/docker-compose.yml up -d

# Check health
curl http://localhost:8080/v1/health

# Optional: run the mandatory-citations policy in compose
VAOL_OPA_POLICY=v1/data/vaol/mandatory_citations \
docker compose -f deploy/docker/docker-compose.yml up -d
```

Compose defaults to `--auth-mode disabled` for local bootstrap only. Set `VAOL_AUTH_MODE=required` and JWT verification material for production.

For hardened Kubernetes deployment defaults, see `docs/deployment-production-profile.md`.

### Build from Source

```bash
make build

# Run server with in-memory store (development, explicit allow-all)
./bin/vaol-server --addr :8080 --auth-mode disabled --policy-mode allow-all

# Run server with PostgreSQL
./bin/vaol-server --addr :8080 --dsn "postgres://vaol:vaol@localhost:5432/vaol" --auth-mode disabled

# Run with signer backends
./bin/vaol-server --signer-mode ed25519 --key ~/.vaol/keys/vaol-signing.pem --auth-mode disabled
./bin/vaol-server --signer-mode sigstore --sigstore-rekor-required
./bin/vaol-server --signer-mode kms --kms-provider aws-kms --kms-key-uri arn:aws:kms:us-east-1:111122223333:key/abcd...
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
# DecisionRecord automatically emitted to VAOL with prompt hash,
# output hash, model identity, and policy context.
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

### CLI

```bash
# Initialize VAOL config
./bin/vaol init

# Generate signing keys
./bin/vaol keys generate

# Verify an audit bundle
./bin/vaol verify bundle audit-bundle.json --public-key ~/.vaol/keys/vaol-signing.pub

# Inspect a DSSE envelope
./bin/vaol inspect record.json
```

`vaol keys generate` now writes both:
- private key: `~/.vaol/keys/vaol-signing.pem`
- public key: `~/.vaol/keys/vaol-signing.pub`

### Auditor Demo Scenario

```bash
./scripts/demo_auditor.sh
```

This creates a reproducible evidence package and tamper-proof demonstration under `tmp/demo-auditor/<timestamp>/`. Full storyline: `docs/demo-auditor-storyline.md`.

### OpenAI-Compatible Proxy

```bash
# Start the transparent proxy
./bin/vaol-proxy --upstream https://api.openai.com --vaol-server http://localhost:8080

# Point your app at the proxy instead of OpenAI directly
export OPENAI_BASE_URL=http://localhost:8443/v1
# All requests are now automatically logged to VAOL
```

## Architecture

```
App → VAOL SDK/Proxy → LLM Provider
         ↓
    VAOL Server
    ├── Policy Engine (OPA/Rego)
    ├── Signer (Ed25519/Sigstore/KMS)
    ├── Ledger Store (PostgreSQL)
    ├── Merkle Log (RFC 6962)
    └── Evidence Exporter
         ↓
    Auditor (CLI verifier)
```

## Privacy Modes

| Mode | What's Stored | Use Case |
|------|--------------|----------|
| `hash_only` (default) | SHA-256 digests only | Maximum privacy; prove integrity without exposing content |
| `encrypted` | age X25519 encrypted blobs + digest | Content recoverable with key; digest binding prevents swap |
| `plaintext` | Raw text (policy-gated) | Full content for internal audit; requires explicit policy allow |

## Policy Engine

VAOL uses OPA/Rego for runtime policy evaluation. Example policies included:

- **base.rego** — Required field validation
- **deny_plaintext.rego** — Prevent plaintext output storage
- **model_allowlist.rego** — Only approved models permitted
- **phi_redaction.rego** — PHI/PII redaction required for healthcare tenants
- **mandatory_citations.rego** — RAG outputs must include citations

Fail-closed is the default behavior:
- with OPA configured, OPA failures are deterministically denied
- without OPA configured, requests are denied with `decision_reason_code=missing_policy_engine`

For local development only, set `--policy-mode allow-all`.

## Tenant-Bound Access

Tenant-scoped read APIs (`GET /v1/records`, `GET /v1/records/{id}`, proofs, and `POST /v1/export`) require a tenant context header:

- `X-VAOL-Tenant-ID` (preferred), or
- `X-Tenant-ID`

VAOL enforces tenant match server-side and rejects cross-tenant access with deterministic deny reason codes.

## Authentication Modes

- `disabled`: no JWT verification (local development only)
- `optional`: verify JWT if provided
- `required` (server default): require valid JWT and bound tenant/subject claims

JWT algorithms supported: `HS256`, `RS256`, `ES256`, with key material from `--jwks-file`, `--jwks-url`, or `--jwt-hs256-secret`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/records` | Append a DecisionRecord |
| `GET` | `/v1/records/{id}` | Retrieve a record |
| `GET` | `/v1/records` | List records (with filters) |
| `GET` | `/v1/records/{id}/proof` | Get Merkle inclusion proof |
| `GET` | `/v1/proofs/{id}` | Get inclusion proof by proof ID |
| `POST` | `/v1/verify` | Verify a DSSE envelope |
| `POST` | `/v1/verify/record` | Alias for record verification (`?profile=basic|strict|fips`) |
| `POST` | `/v1/verify/bundle` | Verify an audit bundle |
| `GET` | `/v1/ledger/checkpoint` | Get latest Merkle checkpoint |
| `GET` | `/v1/ledger/checkpoints/latest` | Alias for latest signed checkpoint |
| `GET` | `/v1/ledger/consistency` | Get Merkle consistency proof (`from`,`to`) |
| `POST` | `/v1/export` | Export audit bundle |
| `GET` | `/v1/health` | Health check |

## Project Structure

```
vaol/
├── cmd/vaol-server/     # Ledger server
├── cmd/vaol-cli/        # CLI tool
├── cmd/vaol-proxy/      # OpenAI-compatible proxy
├── pkg/
│   ├── record/          # DecisionRecord types + JCS canonicalization
│   ├── signer/          # DSSE envelopes, Ed25519, Sigstore, KMS
│   ├── merkle/          # RFC 6962 Merkle tree + proofs
│   ├── store/           # PostgreSQL + in-memory backends
│   ├── policy/          # OPA engine + fail-closed wrapper
│   ├── auth/            # JWT/OIDC verification + tenant/subject binding
│   ├── verifier/        # Composite verification
│   ├── export/          # Audit bundle creation
│   ├── crypto/          # SHA-256, age encryption
│   └── api/             # REST API server
├── sdk/python/          # Python SDK
├── sdk/typescript/      # TypeScript SDK
├── policies/            # OPA/Rego example policies
├── schemas/v1/          # JSON Schema for DecisionRecord
├── deploy/              # Docker Compose + Helm charts
├── scripts/             # Demo and operational scripts
└── tests/               # E2E + tamper detection tests
```

## Verification

VAOL provides four layers of cryptographic verification:

1. **Signature** — DSSE envelope signature valid (Ed25519/Sigstore/KMS)
2. **Schema** — DecisionRecord conforms to v1 JSON Schema
3. **Hash Chain** — Each record's `previous_record_hash` matches predecessor
4. **Merkle Inclusion** — Record's inclusion proof valid against tree root

The `vaol verify` CLI command and the `/v1/verify` API perform all four checks.

## Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Cryptographic Design](docs/crypto-design.md)
- [Threat Model](docs/threat-model.md)
- [Auditor Guide](docs/auditor-guide.md)
- [Deployment Guide](docs/deployment-production-profile.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
