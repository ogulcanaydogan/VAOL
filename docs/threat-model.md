# VAOL Threat Model

**Document version:** 1.0
**Applies to:** Verifiable AI Output Ledger (VAOL) v0.2.x
**Last updated:** 2026-02-23

---

## 1. System Overview

VAOL is an append-only, tamper-evident ledger that captures cryptographically signed evidence records for every AI inference decision. Each `DecisionRecord` is canonicalized (RFC 8785 JCS), hashed (SHA-256), chained to its predecessor, signed in a DSSE envelope, and committed to an RFC 6962 Merkle tree. Signed checkpoints and optional Rekor anchoring provide external witness guarantees.

The system is designed so that no single actor -- including the platform operator -- can undetectably alter, delete, or fabricate audit evidence after the fact.

---

## 2. Actors

| Actor | Trust Level | Description |
|---|---|---|
| **Tenant Developer** | Semi-trusted | Integrates VAOL via SDK or proxy. Submits DecisionRecords to the ledger. Trusted to construct honest input payloads, but may attempt to omit fields, replay requests, or swap prompts to influence the audit trail. |
| **Platform Operator** | Semi-trusted | Deploys and administers the VAOL server, storage layer, and signing infrastructure. Has privileged access to the runtime environment. May be compelled or incentivized to tamper with, truncate, or selectively delete log entries. |
| **AI Provider** | Untrusted for integrity | External LLM service (e.g., OpenAI, Anthropic, custom model). Provides inference outputs but is not trusted to guarantee that the output corresponds to the claimed prompt and parameters. VAOL seals prompt hashes and output hashes at capture time to bind them cryptographically. |
| **Auditor** | Trusted for read | Authorized party (regulatory body, compliance officer, internal audit) that verifies the integrity of the ledger. Receives audit bundles containing DSSE envelopes, Merkle inclusion proofs, and signed checkpoints. Has read-only access; does not submit or modify records. |
| **External Attacker** | Untrusted | Unauthenticated or unauthorized party attempting to access, modify, or corrupt ledger data from outside the system boundary. May exploit network-facing APIs, inject malicious payloads, or attempt denial-of-service. |
| **Malicious Insider** | Untrusted | An individual with legitimate access to one or more system components (e.g., database credentials, server SSH access, signing key material) who deliberately attempts to undermine the integrity or confidentiality of the audit trail. |

---

## 3. Trust Boundaries

The system is decomposed into four trust zones. All data crossing a boundary is subject to validation, authentication, or cryptographic verification.

```
+---------------------+       +---------------------+
|  Client Environment |       |  External Services  |
|                     |       |                     |
|  - Tenant SDK       | HTTPS |  - AI Provider API  |
|  - vaol-proxy       |<----->|  - Fulcio CA        |
|  - vaol-cli         |       |  - Rekor Log        |
|                     |       |  - OPA Engine        |
+----------+----------+       +----------+----------+
           |                             |
           | mTLS / HTTPS                | HTTPS
           |                             |
+----------v-----------------------------v----------+
|                  VAOL Server                       |
|                                                    |
|  - REST API (pkg/api)                              |
|  - gRPC API (pkg/grpc)                             |
|  - DSSE Signing (signer package)                   |
|  - Policy Evaluation (policy package)              |
|  - Merkle Tree (merkle package)                    |
|  - Record Canonicalization (record package)         |
|  - Schema Validation (record.Validate)             |
+-------------------------+--------------------------+
                          |
                          | Authenticated connection
                          |
+-------------------------v--------------------------+
|                  Storage Layer                      |
|                                                    |
|  - PostgreSQL (primary)                            |
|  - In-memory store (testing)                       |
|  - Stored envelopes + Merkle leaf indices          |
+----------------------------------------------------|
```

### Boundary details

| Boundary | From | To | Controls |
|---|---|---|---|
| B1: Client to Server | Client Environment | VAOL Server | HTTPS/TLS, request validation, schema enforcement, request_id uniqueness, rate limiting |
| B2: Server to Storage | VAOL Server | Storage Layer | Authenticated database connection, parameterized queries, append-only write pattern |
| B3: Server to External | VAOL Server | External Services | HTTPS/TLS, OPA policy timeout + fail-closed semantics, Sigstore OIDC verification |
| B4: Auditor to Server | Client Environment (Auditor) | VAOL Server | Read-only API endpoints, offline bundle verification, checkpoint signature validation |

---

## 4. Attacks and Mitigations

### 4.1 Record Integrity Attacks

| # | Attack | Description | Impact | Mitigations | Residual Risk |
|---|--------|-------------|--------|-------------|---------------|
| A1 | **Record tampering** | An attacker (insider or operator) modifies the content of a stored DecisionRecord after it has been committed to the ledger. | Audit evidence no longer reflects the actual AI decision. Regulatory compliance is undermined. | (1) Every record is signed in a DSSE envelope using PAE (Pre-Authentication Encoding); any modification invalidates the signature. (2) The `record_hash` is computed over the JCS-canonicalized payload (RFC 8785) and verified independently by the auditor. (3) The record hash is committed as a leaf in the RFC 6962 Merkle tree; tampering changes the leaf hash and invalidates the Merkle root and all dependent inclusion proofs. (4) Signed checkpoints and Rekor anchoring provide an external witness of the Merkle root at a point in time. | Negligible if signing keys are protected. See A7 for key compromise. |
| A2 | **Record deletion** | An operator or insider deletes one or more records from the storage layer to hide evidence of a particular AI decision. | Gap in the audit trail. Missing evidence for compliance or litigation. | (1) The SHA-256 hash chain (`previous_record_hash`) creates a linked sequence; deletion of any record breaks the chain and is detected during `VerifyChain`. (2) The Merkle tree size is monotonically increasing; any regression in tree size indicates deletion. (3) Signed checkpoints record the tree size and root hash at regular intervals; a checkpoint referencing a larger tree than the current state proves truncation. (4) Rekor witness entries provide an immutable external record of checkpoint state. | If all checkpoints are also deleted and no external witness (Rekor) was used, deletion may go undetected. Rekor anchoring is strongly recommended for production. |
| A3 | **Record insertion (fabrication)** | An attacker inserts a fabricated record into the ledger to create false evidence that a particular AI decision occurred. | False audit trail could be used to frame a tenant, fabricate compliance, or pollute analytics. | (1) DSSE signature verification fails unless the attacker possesses a valid signing key. (2) The hash chain requires the fabricated record's `previous_record_hash` to match the predecessor's `record_hash`; insertion at any position other than the end breaks the chain. (3) Insertion at the end without updating the Merkle tree creates an inconsistency between the tree size, the Merkle root, and existing signed checkpoints. (4) Consistency proofs between checkpoints detect any rewriting of the tree. | If the signing key is compromised, fabrication is possible but detectable through Merkle consistency proof violations against prior checkpoints. |
| A4 | **Replay attack** | An attacker re-submits a previously valid DecisionRecord to create a duplicate entry in the ledger. | Inflated record counts, duplicated audit evidence, potential confusion during compliance review. | (1) Each record contains a unique `request_id` (UUID v4); the store enforces uniqueness and rejects duplicates with `ErrDuplicateRequestID`. (2) Monotonic `sequence_number` assignment prevents out-of-order insertion. (3) Timestamp validation can reject records with timestamps that fall outside an acceptable window. | Replay is effectively prevented by request_id uniqueness enforcement at the storage layer. |

### 4.2 Content Integrity Attacks

| # | Attack | Description | Impact | Mitigations | Residual Risk |
|---|--------|-------------|--------|-------------|---------------|
| A5 | **Prompt swap** | A tenant or insider substitutes the actual prompt with a different one after the AI inference, so the logged prompt hash does not correspond to the prompt that was actually sent to the model. | The audit trail records a false association between the prompt and the output, undermining forensic analysis and accountability. | (1) `prompt_context.user_prompt_hash` and `prompt_context.system_prompt_hash` are computed at capture time (in the proxy or SDK) before the payload reaches the VAOL server. The hash is sealed into the record before signing. (2) The DSSE signature covers the entire canonical payload including all prompt hashes; any post-hoc modification invalidates the signature. (3) The `tool_schema_hash` and `safety_prompt_hash` fields similarly bind tool definitions and safety prompts to the record. | If the capture point itself (proxy/SDK) is compromised, the attacker can compute a valid hash of the substituted prompt. Defense-in-depth requires securing the capture layer. |
| A6 | **Metadata stripping** | An attacker removes or nullifies required fields (e.g., `policy_context`, `rag_context`, `trace`) from a record to hide information about how a decision was made. | Incomplete audit trail. Missing policy decisions, RAG sources, or tracing data reduces the value of the evidence. | (1) `record.Validate()` enforces that all required fields are present and correctly formatted; records with missing required fields are rejected before signing. (2) The DSSE signature covers the entire JSON payload; removing any field after signing invalidates the signature. (3) JCS canonicalization ensures that the hash computation is deterministic and includes every field present at signing time; post-signing removal changes the canonical form and breaks the record hash. | Optional fields (those marked `omitempty`) can legitimately be absent. The schema should be configured to require all fields that are considered mandatory for a given deployment. |

### 4.3 Policy and Access Control Attacks

| # | Attack | Description | Impact | Mitigations | Residual Risk |
|---|--------|-------------|--------|-------------|---------------|
| A7 | **Policy bypass** | An attacker crafts a request that circumvents OPA policy evaluation, allowing a record to be logged without proper policy adjudication. | Records are created without policy governance; sensitive outputs may be logged without required transforms (e.g., PII redaction). | (1) The `FailClosedEngine` wrapper ensures that if the OPA engine is unreachable or returns an error, the policy decision defaults to `deny`. (2) Schema validation requires `policy_context.policy_decision` to be one of the allowed enum values (`allow`, `deny`, `allow_with_transform`, `log_only`); arbitrary values are rejected. (3) Policy evaluation occurs server-side before record hashing and signing; the client cannot skip it. (4) The `policy_hash` and `policy_bundle_id` are sealed into the record, providing an auditable link to the exact policy that was evaluated. | If OPA is compromised or the policy bundle is replaced with a permissive policy, bypass is possible. Policy bundle integrity should be verified via its hash. |
| A8 | **Tenant impersonation** | An attacker submits records with a `tenant_id` or `subject` that belongs to a different tenant. | Cross-tenant pollution of audit data. False attribution of AI decisions. | (1) Authentication at the API boundary must bind the caller identity to the `tenant_id` claim. (2) The `identity.claims` field can carry verified OIDC/JWT claims from the authentication layer. (3) Server-side enforcement rejects tenant/subject mismatches on append when auth headers are present. (4) Tenant-scoped read/export endpoints require tenant context headers and reject cross-tenant access. | A compromised gateway can still forge tenant headers. Deployments should enforce signed identity tokens or mTLS-bound identity at the edge. |
| A15 | **gRPC metadata spoofing** | A caller sends mismatched tenant metadata (`x-vaol-tenant-id` vs `x-tenant-id`) or attempts to override claim tenant with forged metadata. | Cross-tenant data exposure or polluted tenant attribution if accepted. | (1) gRPC auth verifies `authorization: Bearer <JWT>` with the same verifier as REST. (2) gRPC rejects conflicting tenant metadata and claim/header mismatches with deterministic `PermissionDenied` (`tenant mismatch`). (3) `AppendRecord` rejects tenant and subject mismatches against trusted claims and writes trusted auth context into the sealed record payload. | If auth mode is `disabled`, tenant isolation depends on explicit tenant metadata and caller discipline. Production should use `required` auth mode. |
| A16 | **gRPC cross-tenant read/query/export** | A caller authenticates as tenant A but requests tenant B records via `GetRecord`, `ListRecords`, `GetProofByID`, `ExportBundle`, or related proof APIs. | Unauthorized cross-tenant evidence disclosure. | (1) Tenant-scoped RPCs force or validate effective tenant against authenticated claims. (2) Empty tenant filters are resolved to caller tenant; explicit mismatches are denied. (3) Proof lookups dereference underlying record tenant before returning data. | Misconfigured auth claims (wrong tenant claim mapping) can still cause denial/overexposure. Validate claim mapping in deployment tests. |

### 4.4 Cryptographic and Key Management Attacks

| # | Attack | Description | Impact | Mitigations | Residual Risk |
|---|--------|-------------|--------|-------------|---------------|
| A9 | **Signing key compromise** | An attacker obtains the private signing key and can forge valid DSSE signatures on fabricated records. | Complete loss of signature-based integrity guarantees. The attacker can create, modify, or backdate records with valid signatures. | (1) **Sigstore keyless signing**: Ephemeral Ed25519 keys are generated per-signing operation; there is no long-lived private key to steal. The key is bound to an OIDC identity via a Fulcio certificate. (2) **KMS/HSM backend**: When using AWS KMS, GCP KMS, Azure Key Vault, or PKCS#11, the private key never leaves the hardware boundary. Signing operations are performed within the HSM. (3) Rekor transparency log entries provide a timestamped, immutable record of each signature; forged signatures created after key compromise can be detected if they lack corresponding Rekor entries. (4) Short-lived Fulcio certificates (typically 10-minute validity) limit the window of exploitation. | If Sigstore is not used and a local Ed25519 key is deployed without HSM protection, key compromise is a critical risk. Production deployments must use Sigstore keyless or KMS/HSM signing. |
| A10 | **Merkle tree manipulation** | An operator or insider modifies the in-memory Merkle tree state (e.g., recomputes the tree with altered leaves) to produce valid-looking proofs for tampered records. | Tampered records appear to have valid Merkle inclusion proofs, defeating tree-based integrity verification. | (1) **Signed checkpoints** capture the Merkle root and tree size at regular intervals; the checkpoint signature binds the tree state to a specific point in time. Rewriting the tree invalidates consistency proofs against prior checkpoints. (2) **Rekor anchoring** publishes checkpoint data to an external, append-only transparency log operated by the Sigstore project. An operator cannot retroactively alter Rekor entries. (3) **Consistency proofs** (`ConsistencyProof` in the merkle package) allow any verifier to confirm that a newer tree is an append-only extension of an older tree. (4) Auditors who retain previously received checkpoints can independently detect tree rewrites. | If no checkpoints have been distributed to auditors or anchored in Rekor before the manipulation occurs, the attack may succeed. Frequent checkpointing and immediate Rekor submission are essential. |
| A11 | **Operator log truncation** | The platform operator truncates the ledger by discarding the most recent records, effectively rolling back the log to a prior state. | Recent AI decisions are erased from the audit trail. | (1) Signed checkpoints include a monotonically increasing `tree_size`; any reduction in tree size between consecutive checkpoints proves truncation. (2) Rekor witness entries provide an independent, immutable record of the tree size at each checkpoint. (3) Auditors who have received receipts for records at higher sequence numbers can detect that the log has been rolled back. (4) The hash chain requires that the latest record's `record_hash` matches the `previous_record_hash` of any future record; truncation breaks this linkage. | Requires at least one external party (auditor or Rekor) to have observed the pre-truncation state. Fully offline deployments without external witnesses are more vulnerable. |

### 4.5 Infrastructure and Network Attacks

| # | Attack | Description | Impact | Mitigations | Residual Risk |
|---|--------|-------------|--------|-------------|---------------|
| A12 | **Man-in-the-middle** | An attacker intercepts communication between the client and the VAOL server to modify records in transit. | Modified records could be accepted by the server, or valid receipts could be altered before reaching the client. | (1) TLS encryption on all client-to-server communication. (2) DSSE signatures are computed client-side (in the proxy/SDK) before transmission; server-side re-verification detects any in-transit modification. (3) Receipts include Merkle roots and inclusion proofs that the client can independently verify. | Standard TLS risks apply. Certificate pinning is recommended for high-security deployments. |
| A13 | **Denial of service** | An attacker floods the VAOL API with requests to prevent legitimate records from being logged. | AI decisions occur without audit evidence, creating compliance gaps. | (1) HTTP server timeouts (`ReadTimeout`, `WriteTimeout`) limit resource consumption per request. (2) Rate limiting should be applied at the API gateway or load balancer layer. (3) The fail-closed policy engine ensures that if VAOL is unavailable, AI requests are denied rather than proceeding without logging. | DoS is an availability concern. Standard infrastructure mitigations (WAF, rate limiting, autoscaling) apply. VAOL does not implement application-level rate limiting in the core server. |
| A14 | **Storage layer compromise** | An attacker gains direct access to the PostgreSQL database and modifies stored DSSE envelopes or metadata. | Stored records are altered at the storage level, bypassing VAOL server controls. | (1) Every stored record is a signed DSSE envelope; modifying the envelope payload invalidates the signature. (2) The Merkle tree state is independent of the storage layer; alterations to stored records do not affect the in-memory tree. (3) Auditors verify records by checking DSSE signatures, record hashes, and Merkle proofs; database-level tampering is detected during verification. (4) Database access should be restricted to the VAOL server service account with minimal privileges. | If the attacker can also manipulate the in-memory Merkle tree (i.e., has server process access), they could attempt a coordinated attack. See A10. |

---

## 5. Cryptographic Guarantees

### 5.1 DSSE Envelope (Dead Simple Signing Envelope)

Every DecisionRecord is wrapped in a DSSE envelope before storage. The DSSE specification provides:

- **Pre-Authentication Encoding (PAE):** The signing input is `"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload`, which prevents type confusion and length-extension attacks. VAOL uses `application/vnd.vaol.decision-record.v1+json` as the payload type.
- **Multi-signature support:** The envelope can carry multiple signatures from different signers (e.g., tenant signer + server signer), enabling dual-attestation workflows.
- **Payload binding:** The signature covers the entire payload including the payload type, ensuring that the payload cannot be reinterpreted under a different schema.

### 5.2 SHA-256 Hash Chaining

Records are linked in a sequential chain:

- Each record's `integrity.record_hash` is the SHA-256 digest of the JCS-canonicalized payload (excluding computed integrity fields such as `record_hash` itself, `previous_record_hash`, Merkle data, and `sequence_number`).
- `integrity.previous_record_hash` references the `record_hash` of the immediately preceding record.
- The genesis record uses a well-known zero hash (`sha256:0000...0000`) as its `previous_record_hash`.
- Any modification to a record changes its `record_hash`, which in turn invalidates the `previous_record_hash` of all subsequent records, creating a detectable cascade failure.

### 5.3 RFC 6962 Merkle Tree

VAOL implements an append-only Merkle hash tree per RFC 6962 (Certificate Transparency):

- **Leaf hashing:** `SHA-256(0x00 || data)` -- the `0x00` domain separator prevents second-preimage attacks by distinguishing leaf nodes from interior nodes.
- **Interior node hashing:** `SHA-256(0x01 || left || right)` -- the `0x01` domain separator provides the same second-preimage protection at interior levels.
- **Inclusion proofs:** Given a leaf index and tree size, the tree produces a logarithmic-size proof that the leaf is committed in the tree with a specific root hash.
- **Consistency proofs:** Given two tree sizes, the tree produces a proof that the smaller tree is a prefix of the larger tree, demonstrating append-only behavior.
- **Signed checkpoints:** The Merkle root and tree size are periodically signed by the server's signing key, creating a verifiable snapshot of the tree state.

### 5.4 JCS Canonicalization (RFC 8785)

Before hashing, each DecisionRecord is serialized using the JSON Canonicalization Scheme (RFC 8785):

- Object keys are sorted lexicographically by Unicode code point.
- No unnecessary whitespace is emitted.
- Numbers are serialized per ECMAScript 2015 `Number.toString` rules.
- Computed integrity fields (`record_hash`, `previous_record_hash`, `merkle_root`, `merkle_tree_size`, `inclusion_proof`, `sequence_number`) are excluded from the canonical form since they are populated after the hash is computed.

This ensures that logically identical records always produce the same hash, regardless of JSON serialization order or whitespace differences.

---

## 6. Assumptions and Limitations

1. **Authentication is validated in-service, and still depends on trusted identity infrastructure.** VAOL verifies JWTs in both REST and gRPC entrypoints when auth mode is `optional` or `required`, then enforces tenant/subject binding using verified claims. Tenant identity still depends on correct IdP/JWKS configuration; compromised identity infrastructure undermines isolation guarantees.

2. **Sigstore availability.** Keyless signing depends on the availability of Fulcio (certificate authority) and Rekor (transparency log). If these services are unavailable, signing falls back to local key material if configured. Production deployments should plan for Sigstore outages.

3. **Clock integrity.** Timestamps in DecisionRecords are generated by the VAOL server. If the server clock is manipulated, records can be backdated or postdated. NTP synchronization and monitoring are assumed.

4. **In-memory Merkle tree.** The current implementation maintains the Merkle tree in memory. A server restart requires tree reconstruction from the stored leaf hashes. Persistent Merkle tree storage is planned for future versions.

5. **Policy engine trust.** OPA policy evaluation is performed via HTTP REST API. The connection between VAOL and OPA must be secured (localhost or mTLS). A compromised OPA instance can issue permissive policy decisions.

6. **Single-server model.** The current architecture assumes a single VAOL server instance. Multi-region or multi-primary deployments introduce additional consistency challenges for hash chain ordering and Merkle tree state that are not addressed in this threat model.

---

## 7. Recommended Controls

| Priority | Control | Addresses |
|---|---|---|
| Critical | Deploy Sigstore keyless signing or KMS/HSM for all production signing operations. Never use local Ed25519 keys in production. | A9 |
| Critical | Enable Rekor anchoring for Merkle checkpoints. Publish checkpoints to Rekor at a regular cadence (e.g., every N records or every M minutes). | A2, A10, A11 |
| High | Enforce authentication and tenant identity binding at the API gateway. Reject records where the authenticated caller does not match the declared `tenant_id`. | A8 |
| High | Deploy the policy engine with fail-closed semantics (`FailClosedEngine`). Monitor OPA availability and alert on repeated deny-by-failure. | A7 |
| High | Distribute signed checkpoints to auditors through an out-of-band channel. Auditors should retain checkpoints independently for comparison. | A2, A10, A11 |
| Medium | Implement rate limiting and request size limits at the API gateway or load balancer. | A13 |
| Medium | Restrict database access to the VAOL service account. Use row-level security or append-only table permissions where supported. | A14 |
| Medium | Monitor Merkle tree size for monotonic growth. Alert on any decrease or unexpected stagnation. | A2, A11 |
| Low | Enable TLS certificate pinning between the client SDK/proxy and the VAOL server for high-security deployments. | A12 |
| Low | Implement persistent Merkle tree storage to eliminate reconstruction cost on server restart and reduce the window for tree manipulation. | A10 |
