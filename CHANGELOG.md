# Changelog

All notable changes to VAOL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-02-20

### Fixed

- **Version injection** — All three Go binaries (`vaol-server`, `vaol-cli`, `vaol-proxy`) now accept build-time `version`, `commit`, and `date` variables via ldflags, matching `.goreleaser.yml` configuration. The `/v1/health` endpoint and `X-VAOL-Version` header are now dynamic instead of hardcoded.
- **SDK version sync** — Bumped Python SDK (`pyproject.toml`, `__init__.py`), TypeScript SDK (`package.json`), and API reference docs from 0.2.0 to 0.3.0.

### Added

- **TypeScript wrapper tests** — 13 dedicated tests for `instrumentOpenAI()` in `sdk/typescript/tests/wrapper.test.ts`, matching Python SDK `test_wrapper.py` coverage: client validation, method replacement, response forwarding, record emission, prompt/output hashing, token counts, model/temperature capture, error resilience, finish reason, latency, and onError callback.

## [0.3.0] - 2026-02-20

### Added

- **Go benchmarks** — Performance benchmarks for Merkle tree operations (append, root, inclusion proof, consistency proof, verify inclusion, tree rebuild), signer (Ed25519 sign/verify, DSSE envelope sign/verify, PAE, key generation), and record (canonicalize, compute hash, JSON marshal).
- **Helm HPA template** — `autoscaling/v2` HorizontalPodAutoscaler wired to `autoscaling` values.
- **Helm NOTES.txt** — Post-install instructions for accessing the VAOL server, proxy, and signing key setup guidance.
- **Helm signing key Secret** — Template for creating Ed25519 signing key secrets when `signingKey.create=true`.
- **Helm proxy Deployment and Service** — Kubernetes templates for the OpenAI-compatible proxy when `proxy.enabled=true`.
- **`.goreleaser.yml`** — Cross-platform release configuration for all three binaries (linux/darwin/windows × amd64/arm64) with Docker image publishing to GHCR.
- **`.dockerignore`** — Optimized Docker build context excluding SDKs, docs, tests, keys, and CI configs.

### Fixed

- Docker Compose OPA image pinned to `0.70.0-static` for consistency with Helm chart values.

## [0.2.0] - 2026-02-20

### Added

- **Client-Side Verification (Python)** — `verify_dsse_ed25519()` for Ed25519 DSSE signature verification and `verify_inclusion_proof()` for RFC 6962 Merkle proof validation. Auditors can now verify records without trusting the server.
- **Client-Side Verification (TypeScript)** — `verifyDSSEEd25519()` and `verifyInclusionProof()` with matching functionality, exported from `@vaol/sdk` and `@vaol/sdk/verifier`.
- **AsyncVAOLClient completeness** — Added missing `list()`, `get_proof()`, `verify()`, `export()`, and `checkpoint()` async methods to match the synchronous client API.
- **Python SDK `py.typed` marker** — PEP 561 compliance for downstream type checking.
- **TypeScript SDK ESM packaging** — Proper `exports` field with `type: "module"` for modern Node.js resolution.

### Changed

- Python SDK version bumped to 0.2.0 with `cryptography>=42.0` dependency.
- TypeScript SDK version bumped to 0.2.0 with dual `exports` map.
- Python `pyproject.toml` mypy configuration set to `strict = true`.

## [0.1.0] - 2026-02-19

Initial public release of the Verifiable AI Output Ledger.

### Added

- **Core Ledger** — Append-only record storage with SHA-256 hash chaining and DSSE-signed envelopes.
- **Signing Backends** — Ed25519 (local PEM), Sigstore keyless (Fulcio/Rekor), KMS/HSM (AWS, GCP, Azure, PKCS#11 via ECDSA P-256).
- **Merkle Tree** — RFC 6962-style append-only log with inclusion proofs, consistency proofs, and signed checkpoints.
- **Policy Engine** — OPA/Rego integration with fail-closed semantics. Five example policies: base validation, deny plaintext, model allowlist, PHI redaction, mandatory citations.
- **REST API** — 12 endpoints for record lifecycle, verification, proofs, checkpoints, and audit export.
- **Verification** — Four-layer composite verification: signature, schema, hash chain, Merkle inclusion. Configurable profiles (basic, strict, FIPS).
- **Privacy Modes** — `hash_only` (default), `encrypted` (age X25519), `plaintext` (policy-gated).
- **Authentication** — JWT/OIDC verification (HS256, RS256, ES256) with tenant/subject claim binding. Three modes: disabled, optional, required.
- **Audit Export** — Portable JSON bundles with DSSE envelopes, inclusion proofs, and signed checkpoints for offline verification.
- **CLI** — `vaol init`, `vaol keys generate`, `vaol verify`, `vaol inspect`, `vaol export`.
- **OpenAI Proxy** — Transparent proxy that auto-instruments LLM calls without code changes.
- **Python SDK** — Client, DecisionRecord builder, `instrument_openai()` wrapper. Installable via `pip install vaol`.
- **TypeScript SDK** — Client, DecisionRecordBuilder, `instrumentOpenAI()` wrapper. Installable via `npm install @vaol/sdk`.
- **PostgreSQL Backend** — Append-only storage with REVOKE UPDATE/DELETE, tenant-scoped indexes.
- **Docker Compose** — Local development stack with server, proxy, PostgreSQL, and OPA.
- **Helm Chart** — Kubernetes deployment with production profile support (required auth, fail-closed policy, strict Sigstore).
- **CI/CD** — GitHub Actions for lint, test, security scan (gosec, govulncheck, trivy), SBOM, provenance, Docker builds, and auditor demo.
- **Tamper Detection Tests** — Dedicated regression suite verifying detection of payload modification, chain breaks, signature forgery, record deletion, and replay attacks.
- **Documentation** — Architecture, API reference, cryptographic design, threat model, auditor guide, deployment guide.

### Security

- DSSE envelope signing with PAE (Pre-Authentication Encoding) per in-toto specification.
- JCS canonicalization (RFC 8785) for deterministic hash computation.
- Fail-closed policy enforcement: missing policy engine triggers deterministic deny.
- Startup Merkle rebuild with checkpoint/root validation.
- Tenant-bound API access with cross-tenant rejection.

[0.3.1]: https://github.com/ogulcanaydogan/vaol/releases/tag/v0.3.1
[0.3.0]: https://github.com/ogulcanaydogan/vaol/releases/tag/v0.3.0
[0.2.0]: https://github.com/ogulcanaydogan/vaol/releases/tag/v0.2.0
[0.1.0]: https://github.com/ogulcanaydogan/vaol/releases/tag/v0.1.0
