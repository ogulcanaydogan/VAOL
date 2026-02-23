# VAOL Auditor Guide

This guide is written for auditors, compliance officers, and security reviewers who need to verify that AI inference decisions were recorded faithfully and in accordance with organizational policy. It covers the full audit workflow: exporting evidence, verifying it offline, inspecting individual records, and understanding what VAOL does and does not prove.

For a reproducible end-to-end scenario (accepted record, denied record, export, offline verify, tamper failure), run `./scripts/demo_auditor.sh` and review `docs/demo-auditor-storyline.md`.

---

## 1. What Is an Audit Bundle

An **audit bundle** is a portable, self-contained JSON file that packages everything needed to verify a set of AI decision records without access to the running VAOL server. A single bundle contains:

- **Signed DSSE envelopes** -- Each record is wrapped in a Dead Simple Signing Envelope (DSSE) containing the JSON payload and one or more Ed25519 signatures. The envelope binds the payload to the signer's identity and a timestamp.

- **Merkle inclusion proofs** -- For every record, the bundle includes the sibling hashes from the record's leaf position up to the tree root. This lets you confirm that the record was part of the Merkle tree at the stated tree size without replaying the entire tree.

- **Signed checkpoints** -- Snapshots of the Merkle tree state (root hash, tree size, timestamp). Checkpoints may also carry a Rekor transparency log entry ID if the deployment publishes to Sigstore Rekor.

- **Bundle metadata** -- Summary fields: total record count, first and last sequence numbers, the latest Merkle root hash, and the tree size at export time.

The top-level structure of a bundle file looks like this:

```json
{
  "version": "1.0",
  "exported_at": "2025-03-31T23:59:59Z",
  "filter": {
    "tenant_id": "acme-health"
  },
  "records": [
    {
      "sequence_number": 1042,
      "dsse_envelope": { "payloadType": "...", "payload": "...", "signatures": [...] },
      "inclusion_proof": { "proof_type": "inclusion", "leaf_index": 1041, "tree_size": 2048, "root_hash": "sha256:...", "hashes": ["sha256:...", "..."] }
    }
  ],
  "checkpoints": [
    {
      "checkpoint": { "root_hash": "sha256:...", "tree_size": 2048, "timestamp": "..." },
      "rekor_entry_id": "..."
    }
  ],
  "metadata": {
    "total_records": 500,
    "first_sequence": 1042,
    "last_sequence": 1541,
    "merkle_root_hash": "sha256:...",
    "merkle_tree_size": 2048
  }
}
```

Because the bundle is self-contained, you can copy it to an air-gapped machine, archive it to immutable storage, or hand it to an external auditor. No network access to the VAOL server is required for verification.

---

## 2. Requesting an Export

### Using the CLI

```bash
vaol export \
  --tenant acme-health \
  --after 2025-03-01 \
  --before 2025-03-31 \
  --output audit-bundle.json
```

The `--tenant` flag filters records by organization. The `--after` and `--before` flags accept date strings and define the time window. The `--output` flag sets the destination file path.

If the CLI is not configured with a server address, it will print a `curl` equivalent you can run directly.

### Using the REST API

Send a `POST` request to the `/v1/export` endpoint:

```bash
curl -X POST http://localhost:8080/v1/export \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant_id": "acme-health",
    "after": "2025-03-01T00:00:00Z",
    "before": "2025-03-31T23:59:59Z",
    "limit": 5000
  }' \
  -o audit-bundle.json
```

**Parameters:**

| Field       | Type   | Description                                                |
|-------------|--------|------------------------------------------------------------|
| `tenant_id` | string | Filter to a specific tenant/organization (optional).       |
| `after`     | string | ISO 8601 timestamp. Only records created after this time.  |
| `before`    | string | ISO 8601 timestamp. Only records created before this time. |
| `limit`     | int    | Maximum number of records to include. Default: 1000.       |

The server returns the bundle as a JSON response. Save it to a file for offline verification.

---

## 3. Verifying a Bundle

### Running the Verification

Ed25519 workflow (offline/local key trust):

```bash
vaol verify bundle audit-bundle.json \
  --public-key /path/to/vaol-signing.pub \
  --revocations-file /path/to/revocations.json
```

The `--public-key` flag points to the Ed25519 public key PEM used by the VAOL server that signed the records. If your organization distributes the public key through a key management system, retrieve it from there. The optional `--revocations-file` flag enforces compromised-key deny rules with RFC3339 effective timestamps.

Sigstore workflow (keyless/certificate-bound trust):

```bash
vaol verify bundle audit-bundle.json \
  --profile strict \
  --sigstore-verify \
  --sigstore-oidc-issuer https://oauth2.sigstore.dev/auth \
  --sigstore-rekor-url https://rekor.sigstore.dev \
  --sigstore-rekor-required
```

The same Sigstore flags are supported by `vaol verify record` for single-envelope checks.

### What the Verifier Checks

The verifier performs these checks on every record in the bundle:

1. **Signature validity** -- Each DSSE envelope signature is verified against configured verifiers (Ed25519 public key and/or Sigstore verifier). The check confirms that the payload has not been altered since signing.

2. **Schema conformance** -- The payload inside each envelope is validated against the DecisionRecord v1 schema. Required fields (`schema_version`, `request_id`, `timestamp`, `identity`, `model`, `parameters`, `prompt_context`, `policy_context`, `output`, `trace`, `integrity`) must all be present and correctly typed.

3. **Record hash integrity** -- The verifier recomputes the SHA-256 hash of the JCS-canonicalized record payload (excluding computed integrity sub-fields) and compares it to the stored `record_hash`. A mismatch means the record was tampered with after hashing.

4. **Hash chain continuity** -- Each record's `previous_record_hash` must match the `record_hash` of the preceding record in sequence. The first record in the bundle links to either the zero hash (genesis) or the hash of the record immediately before the export window. A break in this chain indicates deletion or insertion.

5. **Merkle inclusion** -- For each record, the verifier walks the inclusion proof (sibling hashes from leaf to root) and confirms the computed root matches the checkpoint root hash at the stated tree size.

6. **Policy fields present** -- Every record must contain a `policy_context` with at least a `policy_decision` value (`allow`, `deny`, `allow_with_transform`, or `log_only`).

7. **Key revocation enforcement (optional)** -- If a revocation list is supplied, every envelope signature `keyid` must be valid for the signature timestamp. Any key revoked at or before the signature time causes deterministic verification failure.

### Interpreting the Output

A successful verification prints:

```
Bundle verification complete:
  Total records:   500
  Valid:           500
  Invalid:         0

VERIFICATION PASSED
```

A failed verification prints the failing checks for each invalid record, then exits with a non-zero status:

```
  FAIL  seq=1087 check=signature error=signature verification failed
  FAIL  seq=1088 check=record_hash error=hash mismatch: computed sha256:abc... != stored sha256:def...

Bundle verification complete:
  Total records:   500
  Valid:           498
  Invalid:         2

VERIFICATION FAILED
```

You can also verify a bundle through the REST API by sending it to `POST /v1/verify/bundle`. The response is a JSON object with fields: `total_records`, `valid_records`, `invalid_records`, `chain_intact`, `merkle_valid`, `signatures_valid`, and `schema_valid`.

---

## 4. Inspecting a Record

### Using the CLI

To inspect a single record saved as a DSSE envelope file:

```bash
vaol inspect record-envelope.json
```

This prints the envelope metadata and the full DecisionRecord payload:

```
Payload Type: application/vnd.vaol.decision-record.v1+json
Signatures:   1
  [0] keyid=vaol-ed25519-abc123 timestamp=2025-03-15T14:30:00Z

Payload:
{
  "schema_version": "v1",
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2025-03-15T14:30:00Z",
  "identity": {
    "tenant_id": "acme-health",
    "subject": "hmac:sha256:...",
    "subject_type": "user"
  },
  "model": {
    "provider": "openai",
    "name": "gpt-4o",
    "version": "2025-01-01"
  },
  "parameters": {
    "temperature": 0.2,
    "max_tokens": 4096
  },
  "prompt_context": {
    "system_prompt_hash": "sha256:abc123...",
    "user_prompt_hash": "sha256:def456...",
    "message_count": 3,
    "total_input_tokens": 1250
  },
  "policy_context": {
    "policy_bundle_id": "acme-health/prod/v12",
    "policy_hash": "sha256:789abc...",
    "policy_decision": "allow",
    "rule_ids": ["base/require_logging", "phi_redaction/check_output"],
    "policy_engine_version": "0.68.0"
  },
  "output": {
    "output_hash": "sha256:fedcba...",
    "mode": "hash_only",
    "output_tokens": 312,
    "finish_reason": "stop",
    "latency_ms": 1420
  },
  "trace": {
    "otel_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "otel_span_id": "00f067aa0ba902b7"
  },
  "integrity": {
    "sequence_number": 1042,
    "record_hash": "sha256:...",
    "previous_record_hash": "sha256:...",
    "merkle_root": "sha256:...",
    "merkle_tree_size": 2048,
    "inclusion_proof": {
      "leaf_index": 1041,
      "hashes": ["sha256:...", "sha256:..."]
    }
  }
}
```

### Using the REST API

Retrieve a record by its request ID:

```bash
curl http://localhost:8080/v1/records/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Retrieve its Merkle inclusion proof separately:

```bash
curl http://localhost:8080/v1/records/a1b2c3d4-e5f6-7890-abcd-ef1234567890/proof
```

### What You Will See

Each record contains these auditable fields:

| Section            | Key Fields                                                              |
|--------------------|-------------------------------------------------------------------------|
| **Identity**       | `tenant_id`, `subject` (pseudonymous), `subject_type`                   |
| **Model**          | `provider`, `name`, `version`, `endpoint`, `deployment_id`              |
| **Parameters**     | `temperature`, `top_p`, `max_tokens`, `seed`, `tools_enabled`           |
| **Prompt context** | `user_prompt_hash`, `system_prompt_hash`, `message_count`, `total_input_tokens` |
| **Policy context** | `policy_decision`, `rule_ids`, `policy_hash`, `policy_bundle_id`        |
| **Output**         | `output_hash`, `mode`, `output_tokens`, `finish_reason`, `latency_ms`   |
| **Trace**          | `otel_trace_id`, `otel_span_id`, `parent_request_id`, `session_id`     |
| **Integrity**      | `record_hash`, `previous_record_hash`, `merkle_root`, `merkle_tree_size`, `inclusion_proof` |

In `hash_only` mode (the default), prompts and outputs are represented exclusively by their SHA-256 digests. The raw text is never stored in the ledger. This means you can confirm *that* a specific prompt and output were used (by comparing hashes against your own copies), but you cannot retrieve the text from the ledger itself.

---

## 5. Web UI

### Accessing the Dashboard

When the VAOL server is started with a `web_dir` configuration pointing to the auditor UI assets, the dashboard is served at:

```
http://<server-host>:8080/ui/
```

### Dashboard Features

- **Record count and tree size** -- The landing page shows the current number of records in the ledger and the Merkle tree size, pulled from the `/v1/health` endpoint.

- **Verification status** -- The dashboard displays a summary of the latest checkpoint, including the root hash and timestamp.

- **Upload bundle for verification** -- Drag and drop (or browse to select) an exported audit bundle JSON file. The UI sends it to `POST /v1/verify/bundle` and displays the results in a table: total records, valid count, invalid count, and per-check status (signatures, schema, hash chain, Merkle proofs).

- **Browse individual records** -- Use the search interface to query records by tenant ID, time range, or sequence number. Click a record to see its full DecisionRecord payload, including identity, model, policy decision, and integrity fields.

- **Checkpoint viewer** -- View the current Merkle checkpoint (`GET /v1/ledger/checkpoint`) showing the tree size, root hash, and timestamp.

---

## 6. What VAOL Proves

When verification passes, the following properties have been established:

### Integrity

Records have not been modified after creation. Each record is signed with Ed25519 inside a DSSE envelope. The signature covers the entire JSON payload. Any alteration -- even a single byte -- causes signature verification to fail. Additionally, the record hash is independently recomputed from the canonicalized payload and compared to the stored value.

### Completeness

No records have been deleted or inserted out of order. The hash chain links each record to its predecessor via `previous_record_hash`. Removing a record breaks the chain. Inserting a record requires forging the hash chain, which is computationally infeasible. The Merkle tree provides a second, independent completeness guarantee: each record is a leaf, and the inclusion proof binds it to a specific root hash at a specific tree size.

### Provenance

Every record captures which model was used (`provider`, `name`, `version`), what parameters governed inference (`temperature`, `max_tokens`, `seed`, etc.), and what policy was applied (`policy_bundle_id`, `policy_hash`). This creates an unbroken chain from a specific AI decision back to the exact model and configuration that produced it.

### Policy Compliance

Every record contains a `policy_context` with a `policy_decision` field. The auditor can confirm that every inference request was evaluated against the organization's OPA policy bundle, and can see the outcome: `allow`, `deny`, `allow_with_transform`, or `log_only`. The `rule_ids` field identifies exactly which policy rules contributed to each decision. Any applied transforms (PII redaction, PHI redaction, masking) are recorded in `transforms_applied`.

### Temporal Ordering

Records carry monotonically increasing `sequence_number` values and ISO 8601 `timestamp` fields. The sequence number is assigned by the server at append time and cannot be reassigned. Combined with the hash chain, this guarantees a total ordering of all decisions in the ledger.

---

## 7. What VAOL Does NOT Prove

### Correctness of AI Output

VAOL records the fact that an AI model produced a specific output (identified by its hash), but it does not evaluate whether that output is factually correct, clinically appropriate, legally sound, or otherwise "right." Output quality assessment is outside the scope of the ledger.

### Appropriateness of Prompt Content

In `hash_only` mode (the default), only the SHA-256 digest of the user prompt is stored. The auditor can verify that a specific prompt was used by comparing hashes, but cannot determine from the ledger alone whether the prompt content was appropriate, compliant, or well-formed. The same applies to `encrypted` mode unless the auditor possesses the decryption key.

### Honest Behavior by the AI Provider

VAOL records what was sent to the model and what came back, but it cannot guarantee that the AI provider actually ran the stated model at the stated parameters. If a provider silently substitutes a different model or ignores the temperature setting, the ledger will faithfully record the provider's response, but it has no way to detect the substitution. Trust in the provider's execution environment is outside VAOL's threat model.

### Availability of Raw Content

In `hash_only` mode, the raw prompt and output text are never stored. If your organization needs to reproduce the original content for review, it must be retrieved from the system that generated it (your application logs, prompt management system, etc.) and verified against the hashes in the ledger.

---

## 8. Privacy Modes

VAOL supports three output storage modes, configured per-tenant or per-request via policy. The mode is recorded in the `output.mode` field of every DecisionRecord.

### hash_only (Default)

```
"output": {
  "output_hash": "sha256:fedcba987654...",
  "mode": "hash_only"
}
```

Only the SHA-256 digest of the model's output is stored. No raw text enters the ledger. This is the most privacy-preserving mode and the recommended default for environments handling sensitive data (PHI, PII, financial records).

**Auditor impact:** You can verify that a specific output was produced by comparing your copy of the output against the stored hash. You cannot retrieve the output from the ledger.

### encrypted

```
"output": {
  "output_hash": "sha256:fedcba987654...",
  "mode": "encrypted",
  "output_encrypted": "<base64-encoded age ciphertext>"
}
```

The output is encrypted using age with X25519 keys before storage. The `output_hash` field still contains the SHA-256 digest of the plaintext, so integrity verification works without decryption. To read the actual output, you need the corresponding age identity (private key).

**Auditor impact:** Integrity checks (hash, signature, Merkle proof) work without the decryption key. Content review requires the age private key. This mode is useful when authorized auditors need to review AI outputs but the data should remain encrypted at rest.

To decrypt an output given the age identity string:

```
echo "<base64-ciphertext>" | base64 -d | age -d -i age-identity.txt
```

VAOL will verify that the decrypted plaintext matches `output_hash` to guard against ciphertext substitution.

### plaintext

```
"output": {
  "output_hash": "sha256:fedcba987654...",
  "mode": "plaintext",
  "output_plaintext": "The patient's lab results indicate..."
}
```

The raw model output is stored directly in the record. This mode should only be used for internal, non-sensitive workloads where full content auditability is required and the data does not contain PII, PHI, or other protected information.

**Auditor impact:** Full content is available in the record. The `output_hash` can be verified against the plaintext. Be aware that exporting a bundle in this mode means the bundle file itself contains sensitive data and must be handled accordingly.

---

## Appendix: Quick Reference

### CLI Commands for Auditors

| Task                        | Command                                                                 |
|-----------------------------|-------------------------------------------------------------------------|
| Export a bundle             | `vaol export --tenant <id> --after <date> --before <date> --output <file>` |
| Verify a bundle (Ed25519)   | `vaol verify bundle <file> --public-key <key.pub> [--revocations-file <revocations.json>]` |
| Verify a bundle (Sigstore)  | `vaol verify bundle <file> --profile strict --sigstore-verify --sigstore-rekor-required [--sigstore-oidc-issuer <issuer>] [--sigstore-rekor-url <url>]` |
| Verify a single envelope    | `vaol verify record <file> --public-key <key.pub> [--sigstore-verify] [--revocations-file <revocations.json>]` |
| Inspect a record            | `vaol inspect <envelope-file>`                                          |
| Generate a signing key pair | `vaol keys generate --output <dir>`                                     |

### API Endpoints for Auditors

| Endpoint                        | Method | Description                                  |
|---------------------------------|--------|----------------------------------------------|
| `/v1/export`                    | POST   | Export records as an audit bundle.            |
| `/v1/verify/bundle`            | POST   | Verify an uploaded audit bundle.             |
| `/v1/verify`                    | POST   | Verify a single DSSE envelope.               |
| `/v1/records/{id}`              | GET    | Retrieve a record by request ID.             |
| `/v1/records/{id}/proof`        | GET    | Retrieve a record's Merkle inclusion proof.  |
| `/v1/records`                   | GET    | List records with optional filters.          |
| `/v1/ledger/checkpoint`         | GET    | Get the current Merkle tree checkpoint.      |
| `/v1/health`                    | GET    | Server health, record count, and tree size.  |

### Verification Checks Summary

| Check              | What It Confirms                                           | Failure Means                              |
|--------------------|------------------------------------------------------------|--------------------------------------------|
| `signature`        | DSSE envelope signature is valid                           | Payload was altered or key mismatch        |
| `schema`           | DecisionRecord conforms to v1 schema                       | Missing required fields or wrong types     |
| `record_hash`      | Recomputed hash matches stored `record_hash`               | Record content was tampered with           |
| `hash_chain`       | `previous_record_hash` links to predecessor                | Records were deleted or inserted           |
| `merkle_inclusion` | Inclusion proof resolves to the checkpoint root hash       | Record was not part of the stated tree     |
