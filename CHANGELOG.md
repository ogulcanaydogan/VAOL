# Changelog

All notable changes to VAOL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.24] - 2026-02-23

### Added

- **Strict verifier policy controls** — Added `StrictPolicy` configuration and setter in `pkg/verifier` with secure defaults for strict-profile auth-context completeness and optional online Rekor checks.
- **Online Rekor verification client** — Added `pkg/verifier/rekor.go` with payload-hash binding validation against Rekor entry `spec.payload_hash`.
- **CLI Sigstore parity flags** — Added `vaol verify record|bundle` flags:
  - `--sigstore-verify`
  - `--sigstore-oidc-issuer`
  - `--sigstore-rekor-url`
  - `--sigstore-rekor-required`
- **Regression coverage for strict hardening** — Added verifier, API, gRPC, and CLI tests for strict auth-context checks, Rekor mismatch failures, and Sigstore verification wiring.

### Changed

- **Strict-profile auth-context hardening** — When `auth_context.authenticated=true`, strict verification now deterministically requires `auth_context.issuer` and `auth_context.source` in addition to existing `subject` and `token_hash` checks.
- **Server-configurable strict online Rekor checks** — Added `vaol-server` flags:
  - `--verify-strict-online-rekor` (default `false`)
  - `--verify-rekor-url` (default `https://rekor.sigstore.dev`)
  - `--verify-rekor-timeout` (default `10s`)
- **REST + gRPC verifier parity** — `cmd/vaol-server` now applies strict-policy settings to both REST and gRPC verifier instances.
- **Helm production controls** — Added chart values/schema/template wiring for strict online Rekor verification server flags.
- **CLI verification command behavior** — `vaol verify record|bundle` now return errors on verification failure instead of calling `os.Exit` inside subcommand handlers (non-zero process exit behavior remains via root command).

### Fixed

- **Deterministic strict Rekor failure semantics** — Strict-profile online Rekor mismatches now fail with stable `strict profile rekor verification failed: ...` message prefix.
- **Release metadata alignment** — Synchronized Python SDK, TypeScript SDK, Helm chart, and API reference to version `0.2.24`.

## [0.2.23] - 2026-02-23

### Added

- **gRPC auth regression coverage** — Added auth-required and tenant-isolation bufconn tests for missing/invalid JWT handling, claim tenant forcing, cross-tenant read/proof/export denial, and unauthenticated health behavior.
- **Trusted auth-context binding for gRPC append** — `AppendRecord` now binds verified JWT issuer/subject/token hash into sealed `auth_context` evidence.

### Changed

- **gRPC auth parity with REST** — gRPC now validates `authorization` metadata using the same JWT verifier/modes (`disabled|optional|required`) and enforces deterministic tenant semantics (`tenant mismatch`, `missing tenant context`) across tenant-scoped RPCs.
- **gRPC tenant filter behavior** — `ListRecords` and `ExportBundle` now force caller-tenant scoping when the request tenant is empty, and reject explicit cross-tenant filters.
- **Documentation parity** — Updated architecture, threat model, and API reference docs to describe implemented gRPC behavior and metadata/status-code requirements.

### Fixed

- **Cross-tenant proof/read exposure risk on gRPC** — `GetRecord`, `GetInclusionProof`, `GetProofByID`, and `ExportBundle` now verify underlying record tenant against authenticated caller context before returning evidence.
- **Release metadata alignment** — Synchronized Python SDK, TypeScript SDK, Helm chart, and API reference to version `0.2.23`.

## [0.2.22] - 2026-02-23

### Added

- **gRPC ledger server implementation** — Added `pkg/grpc` with full `VAOLLedger` RPC coverage (`Health`, `AppendRecord`, `GetRecord`, `ListRecords`, `GetInclusionProof`, `GetProofByID`, `GetConsistencyProof`, `GetCheckpoint`, `VerifyRecord`, `ExportBundle`) plus protobuf conversion helpers and bufconn integration tests.
- **Dual-protocol server startup** — `vaol-server` now supports optional gRPC listener startup via `--grpc-addr`, sharing the same store/signer/policy/merkle dependencies as REST.
- **Python SDK wrappers for Anthropic and LiteLLM** — Added `instrument_anthropic()` and `instrument_litellm()` with dedicated tests and package exports.

### Changed

- **Startup rebuild regression coverage** — Expanded startup rebuild tests to cover sparse/non-zero sequence traversal, checkpoint validation, pagination rebuild behavior, and deterministic mismatch failures.
- **Release metadata alignment** — Synchronized Python SDK, TypeScript SDK, and Helm chart versions to `0.2.22`.

### Fixed

- **Verifier revocation file wiring** — Added missing `SetRevocationsFromFile()` helper on the verifier to support startup configuration paths.

## [0.2.11] - 2026-02-22

### Added

- **Kafka ingest publisher path** — Added optional Kafka append-event publishing (`--ingest-mode kafka`) with deterministic event schema for high-scale downstream indexing/export pipelines.
- **Ingest configuration surfaces** — Added server flags, Helm values/schema/template wiring, and deployment documentation for Kafka ingest mode.
- **Ingest tests** — Added dedicated tests for Kafka publisher validation, message encoding, write error propagation, and server startup behavior when ingest initialization is required vs optional.

### Changed

- **Strict verifier hardening** — `strict` profile now requires `policy_context.decision_reason_code`, `integrity.inclusion_proof_ref`, RFC 3339 signature timestamps, and valid Merkle inclusion verification over the embedded proof.
- **FIPS profile enforcement path** — `fips` profile now uses a dedicated Ed25519 detection helper after strict checks.
- **Verifier API documentation** — Expanded profile behavior documentation to explicitly define strict/fips requirements.

### Fixed

- **Helm schema compatibility** — Quoted `server.ingestMode` default to avoid YAML boolean coercion (`off` -> `false`) and chart validation failures.
- **Release hygiene** — Removed stale draft release `v0.2.8` from GitHub releases.

## [0.2.10] - 2026-02-22

### Added

- **CI Go toolchain guard** — Added `scripts/check_go_toolchain.sh` and enforced it in the CI workflow to fail fast when workflow `go-version` and Docker builder `golang:` versions drift.

### Changed

- **GHCR smoke cadence** — `ghcr-smoke.yml` now runs on every push to `main` in addition to release events.
- **GHCR smoke tag resolution** — Manual and push-triggered runs now resolve tags deterministically (explicit input first, otherwise latest repository tag) and emit the chosen tag in logs.

### Fixed

- **Guard portability** — Replaced `rg` dependency in toolchain guard with portable `grep/sed` parsing so GitHub-hosted runners pass without extra packages.

## [0.2.9] - 2026-02-22

### Fixed

- **Release pipeline repo slug** — Updated GoReleaser release target to `ogulcanaydogan/Verifiable-AI-Output-Ledger` to prevent GitHub upload redirect failures.
- **CI mainline recovery** — Fixed `golangci-lint` unused build metadata vars in `vaol-cli`, excluded generated protobuf code from `gosec`, and aligned Docker builder images with Go 1.24.

### Changed

- **Release-line lock** — Standardized public artifact/version metadata on the `0.2.x` line (`0.2.9`) for Python SDK, TypeScript SDK, Helm chart, and API reference.

## [0.2.8] - 2026-02-21

### Added

- **Server binary tests** — 8 tests for `buildSignerAndVerifiers` covering Ed25519 (ephemeral and PEM-loaded), Sigstore, KMS (local ECDSA with defaults), bad key path, unsupported mode, and ldflags variable verification.
- **Proxy binary tests** — 9 tests for `Proxy.ServeHTTP` and `Proxy.emitRecord` covering request forwarding, VAOL header injection, upstream header copying, request header passthrough, error transparency, response body preservation, record emission to VAOL server, VAOL server error resilience, and ldflags verification.

### Changed

- **Pre-release version milestone** — Components were temporarily aligned to `1.0.0` as a stabilization milestone before release-line normalization in `0.2.9`.
- **Python SDK classifier** — Upgraded from `Development Status :: 3 - Alpha` to `Development Status :: 5 - Production/Stable`.

## [0.2.7] - 2026-02-21

### Added

- **Merkle proof tests** — 8 tests for `VerifyInclusion`, `rootFromInclusionProof`, `recomputeRoot` covering single-leaf, multi-leaf, wrong root, wrong proof type, and edge cases.
- **Checkpoint tests** — 6 tests for `SignCheckpoint` and `VerifyCheckpoint` covering valid round-trip, timestamp accuracy, tamper detection, wrong-key rejection, and field preservation.
- **Anchor client tests** — 10 tests for `NoopAnchorClient`, `HashAnchorClient`, and `HTTPAnchorClient` covering deterministic hashing, nil checkpoints, HTTP mocking, and server errors.
- **OPA engine tests** — 9 tests for `OPAEngine.Evaluate` covering allow/deny decisions, server errors, nil results, timeout handling, and engine metadata.
- **Verification report tests** — 7 tests for `Report.ToJSON`, `Report.ToMarkdown`, `passFailIcon` covering field population, summary tables, failure rendering, and conclusion text.
- **Helm values schema** — JSON Schema (`values.schema.json`) for validating Helm chart `values.yaml` with type constraints and enums for all configuration options.
- **gRPC protobuf generation** — Compiled `proto/vaol/v1/ledger.proto` into Go stubs (`gen/vaol/v1/ledger.pb.go`, `ledger_grpc.pb.go`) with 10 RPC definitions and 28 message types.
- **GitHub issue templates** — Bug report, feature request, and config.yml with security policy link.
- **Code of Conduct** — Contributor Covenant v2.1.

### Fixed

- **Dead code in `pkg/export/format.go`** — Removed unused `json.Marshal` call and `encoding/json` import; replaced with nil-envelope guard.

## [0.2.6] - 2026-02-20

### Fixed

- **Version injection** — All three Go binaries (`vaol-server`, `vaol-cli`, `vaol-proxy`) now accept build-time `version`, `commit`, and `date` variables via ldflags, matching `.goreleaser.yml` configuration. The `/v1/health` endpoint and `X-VAOL-Version` header are now dynamic instead of hardcoded.
- **SDK version sync** — Aligned Python SDK (`pyproject.toml`, `__init__.py`), TypeScript SDK (`package.json`), and API reference documentation in one coordinated release step.

### Added

- **TypeScript wrapper tests** — 13 dedicated tests for `instrumentOpenAI()` in `sdk/typescript/tests/wrapper.test.ts`, matching Python SDK `test_wrapper.py` coverage: client validation, method replacement, response forwarding, record emission, prompt/output hashing, token counts, model/temperature capture, error resilience, finish reason, latency, and onError callback.

## [0.2.5] - 2026-02-20

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

[0.2.24]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.24
[0.2.23]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.23
[0.2.22]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.22
[0.2.11]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.11
[0.2.10]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.10
[0.2.9]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.9
[0.2.8]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.8
[0.2.7]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.7
[0.2.6]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.6
[0.2.5]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.5
[0.2.0]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.2.0
[0.1.0]: https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger/releases/tag/v0.1.0
