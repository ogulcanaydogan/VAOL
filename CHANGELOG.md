# Changelog

All notable changes to VAOL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/ogulcanaydogan/vaol/releases/tag/v0.1.0
