# VAOL Cryptography Design Document

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-02-19

---

## Table of Contents

1. [Overview](#overview)
2. [Signing: DSSE Envelopes](#signing-dsse-envelopes)
3. [Signing Backends](#signing-backends)
4. [Canonicalization](#canonicalization)
5. [Hash Chaining](#hash-chaining)
6. [Merkle Tree](#merkle-tree)
7. [Encryption](#encryption)
8. [Key Management](#key-management)
9. [Security Considerations](#security-considerations)

---

## Overview

VAOL employs a layered cryptographic architecture to ensure the integrity, authenticity, and non-repudiation of AI decision records. The design combines hash chaining for sequential integrity, Merkle trees for efficient bulk verification, and digital signatures for authentication. Each layer serves a distinct purpose:

- **Canonicalization** produces a deterministic byte representation of a record.
- **Hash chaining** links records into a tamper-evident sequence.
- **Merkle trees** enable logarithmic-time inclusion and consistency proofs.
- **DSSE signing** binds a record to an identity with a verifiable signature.
- **Encryption** (optional) protects sensitive output content at rest.

All cryptographic operations use well-established standards and avoid custom constructions.

---

## Signing: DSSE Envelopes

VAOL uses **Dead Simple Signing Envelopes (DSSE)** as defined by the [in-toto specification](https://github.com/secure-systems-lab/dsse). DSSE provides a simple, unambiguous signing format that prevents confusion attacks between payload types.

### Pre-Authentication Encoding (PAE)

Before signing, the payload is encoded using PAE to bind the payload type and payload content into a single authenticated message. The PAE function is defined as:

```
PAE(payloadType, payload) = "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
```

Where:
- `SP` is the ASCII space character (0x20).
- `len()` returns the byte length of the argument, encoded as an ASCII decimal integer with no leading zeros.
- `payloadType` is the media type string.
- `payload` is the raw payload bytes.

### Payload Definition

- **PayloadType:** `application/vnd.vaol.decision-record.v1+json`
- **Payload:** The full JSON-serialized `DecisionRecord` with the `record_hash` field populated.

The payload is the UTF-8 encoded JSON serialization of the complete decision record. This is the original (non-canonical) JSON representation, since canonicalization is used only for computing the `record_hash`, not for the signing payload. The `record_hash` field MUST be set before signing so that verifiers can confirm the hash independently.

### Envelope Structure

The DSSE envelope is serialized as JSON:

```json
{
  "payloadType": "application/vnd.vaol.decision-record.v1+json",
  "payload": "<base64url-encoded payload>",
  "signatures": [
    {
      "keyid": "<key identifier>",
      "sig": "<base64url-encoded signature>"
    }
  ]
}
```

- `payload` is the base64url encoding (RFC 4648, no padding) of the raw payload bytes.
- `sig` is the base64url encoding of the signature over `PAE(payloadType, payload)`.
- `keyid` identifies the signing key (derivation is backend-specific; see below).

### Verification Procedure

1. Decode the `payload` from base64url.
2. Reconstruct `PAE(payloadType, payload)` using the envelope's `payloadType` and the decoded payload bytes.
3. Verify the signature in `sig` over the PAE output using the public key identified by `keyid`.
4. Deserialize the payload JSON and verify that `record_hash` matches the SHA-256 digest of the JCS-canonicalized record (see [Canonicalization](#canonicalization)).

---

## Signing Backends

VAOL supports three signing backends, each suited to different deployment models and trust requirements.

### Ed25519 Local

**Algorithm:** Ed25519 (RFC 8032)

Ed25519 provides 128-bit security with compact 64-byte signatures and 32-byte keys. It is deterministic (no per-signature randomness required), which eliminates an entire class of implementation vulnerabilities.

- **Key format:** PEM-encoded PKCS#8 for private keys, PEM-encoded SPKI for public keys.
- **Key ID derivation:** The key ID is the hex-encoded first 16 bytes of the SHA-256 digest of the raw 32-byte public key. This produces a 32-character hexadecimal string that uniquely identifies the key without exposing the full public key material in the envelope.

```
keyid = hex(SHA-256(raw_public_key_bytes)[0:16])
```

- **Signature production:** Sign the PAE-encoded message directly with Ed25519. The signature is the raw 64-byte Ed25519 signature.

**Use case:** Development environments, self-hosted deployments, and air-gapped systems where key management is handled externally.

### Sigstore Keyless

**Algorithm:** Ephemeral Ed25519 + OIDC identity binding via Fulcio + Rekor transparency log

Sigstore keyless signing eliminates long-lived key management entirely. Instead of managing keys, the signer authenticates via an OpenID Connect (OIDC) provider, and Sigstore infrastructure binds the identity to an ephemeral signing key.

**Flow:**

1. Generate an ephemeral Ed25519 key pair in memory.
2. Authenticate with an OIDC provider (e.g., Google, GitHub, Microsoft) to obtain an identity token.
3. Submit the ephemeral public key and OIDC token to **Fulcio**, which issues a short-lived X.509 signing certificate binding the OIDC identity to the ephemeral public key.
4. Sign the PAE-encoded message with the ephemeral private key.
5. Submit the signature and certificate to the **Rekor** transparency log, which returns a Signed Certificate Timestamp (SCT) and a log entry inclusion proof.
6. Destroy the ephemeral private key.

**Key ID:** The key ID is the SHA-256 fingerprint of the Fulcio certificate (hex-encoded), providing a stable reference to the signing event.

```
keyid = hex(SHA-256(fulcio_certificate_der))
```

**Verification bundle:** In addition to the DSSE envelope, Sigstore keyless signatures produce a verification bundle containing:
- The Fulcio certificate chain.
- The Rekor log entry (including the SCT and inclusion proof).
- The OIDC issuer and subject identity.

Verifiers check that:
1. The Fulcio certificate was valid at the time of signing.
2. The certificate chains to the Fulcio root CA.
3. The Rekor log entry is consistent with the Rekor public key.
4. The OIDC identity in the certificate matches the expected signer.

**Use case:** CI/CD pipelines, multi-tenant SaaS deployments, and environments where key management overhead is unacceptable.

### KMS / HSM

**Algorithm:** ECDSA P-256 (FIPS 186-4) via cloud KMS or PKCS#11

For organizations requiring hardware-backed key protection or regulatory compliance (FIPS 140-2/3, PCI DSS), VAOL supports signing via external Key Management Services and Hardware Security Modules.

**Supported providers:**

| Provider | URI Scheme | Example |
|----------|-----------|---------|
| AWS KMS | `awskms://` | `awskms:///arn:aws:kms:us-east-1:123456789:key/abcd-1234` |
| GCP Cloud KMS | `gcpkms://` | `gcpkms://projects/my-proj/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1` |
| Azure Key Vault | `azurekms://` | `azurekms://my-vault.vault.azure.net/keys/my-key` |
| PKCS#11 (HSM) | `pkcs11:` | `pkcs11:token=my-hsm;object=signing-key` |

- **Algorithm:** ECDSA with the NIST P-256 curve and SHA-256 digest. The signature is ASN.1 DER-encoded per RFC 3279.
- **Key ID derivation:** The key ID is the KMS key URI itself, which uniquely identifies the key across providers.

```
keyid = "awskms:///arn:aws:kms:us-east-1:123456789:key/abcd-1234"
```

- **Signature production:** The PAE-encoded message is hashed with SHA-256 locally, and the digest is sent to the KMS/HSM for signing. The private key never leaves the hardware boundary.

**Use case:** Enterprise deployments, regulated industries, and environments requiring auditable key usage with hardware-backed protection.

---

## Canonicalization

VAOL uses **RFC 8785 (JSON Canonicalization Scheme, JCS)** to produce a deterministic byte representation of a decision record for hashing. Canonicalization ensures that semantically identical JSON documents produce identical byte sequences regardless of serialization differences (key ordering, whitespace, number formatting).

### JCS Rules

1. **Object key sorting:** Object members are sorted lexicographically by their key names, using Unicode code point ordering. Sorting is applied recursively to all nested objects.
2. **No insignificant whitespace:** No whitespace is inserted between tokens (no spaces after colons or commas, no newlines or indentation).
3. **Number formatting:** Numbers are serialized according to ES2015 (ECMAScript 6) `Number.toString()` semantics:
   - No leading zeros (except `0` itself and `0.x` fractional forms).
   - No trailing zeros in fractional parts.
   - No positive sign prefix.
   - Exponential notation (`e+N` / `e-N`) is used for very large or very small numbers, following ES2015 rules.
   - `-0` is serialized as `0`.
4. **String escaping:** Strings use minimal JSON escaping. Only control characters (U+0000 through U+001F), backslash, and double quote are escaped. Unicode characters above U+001F are output as literal UTF-8.

### Excluded Fields

Canonicalization is used **exclusively** for computing the `record_hash`. The following fields are **excluded** from the canonical form because they are integrity-computed fields that depend on the record hash or on external state:

| Excluded Field | Reason |
|---------------|--------|
| `record_hash` | This is the output of canonicalization + hashing. |
| `previous_record_hash` | Depends on the preceding record's hash. |
| `merkle_root` | Computed from the Merkle tree after record insertion. |
| `merkle_tree_size` | Reflects tree state at the time of insertion. |
| `inclusion_proof` | Derived from the Merkle tree structure. |
| `sequence_number` | Assigned by the ledger at insertion time. |

All other fields in the `DecisionRecord` are included in the canonical form.

### Canonical Form Construction

1. Start with the full `DecisionRecord` as a JSON object.
2. Remove the excluded fields listed above.
3. Apply JCS (RFC 8785) canonicalization to the remaining object.
4. The output is a UTF-8 byte string suitable for hashing.

**Example:**

Given a record (simplified):
```json
{
  "record_id": "vaol-rec-abc123",
  "timestamp": "2026-02-19T10:30:00Z",
  "model_id": "gpt-4o",
  "decision_type": "content_generation",
  "input_hash": "sha256:a1b2c3...",
  "output_hash": "sha256:d4e5f6...",
  "record_hash": "sha256:...",
  "previous_record_hash": "sha256:...",
  "sequence_number": 42
}
```

After removing excluded fields and applying JCS:
```
{"decision_type":"content_generation","input_hash":"sha256:a1b2c3...","model_id":"gpt-4o","output_hash":"sha256:d4e5f6...","record_id":"vaol-rec-abc123","timestamp":"2026-02-19T10:30:00Z"}
```

---

## Hash Chaining

VAOL uses SHA-256 hash chaining to create a tamper-evident, ordered sequence of decision records. Modifying any record in the chain invalidates all subsequent records, providing a strong integrity guarantee over the full history.

### Hash Algorithm

- **Algorithm:** SHA-256 (FIPS 180-4)
- **Output:** 256-bit (32-byte) digest
- **Encoding:** Hash values are represented as lowercase hexadecimal strings with a `sha256:` prefix.

```
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Record Hash Computation

The `record_hash` for a given record is computed as:

```
record_hash = "sha256:" + hex(SHA-256(JCS_canonical_payload))
```

Where `JCS_canonical_payload` is the UTF-8 byte output of JCS canonicalization with excluded fields removed (see [Canonicalization](#canonicalization)).

### Chain Linkage

Each record contains a `previous_record_hash` field that references the `record_hash` of the immediately preceding record in the ledger:

```
record[n].previous_record_hash = record[n-1].record_hash
```

### Genesis Record

The first record in a ledger (the genesis record) has no predecessor. Its `previous_record_hash` is set to the **zero hash**:

```
previous_record_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

This is the string `sha256:` followed by 64 ASCII zero characters, representing the all-zeros 256-bit hash value. The zero hash is a well-known sentinel that unambiguously identifies the start of a chain.

### Chain Verification

To verify the integrity of a chain of records:

1. For each record starting from the genesis record:
   a. Reconstruct the JCS canonical form (excluding integrity-computed fields).
   b. Compute `SHA-256(canonical_form)` and verify it matches `record_hash`.
   c. Verify that `previous_record_hash` matches the `record_hash` of the preceding record (or the zero hash for the genesis record).
2. If any hash mismatch is detected, the chain is broken at that point, and all records from the mismatch onward are considered potentially tampered.

### Properties

- **Tamper evidence:** Modifying any field in any record changes its canonical form, which changes its `record_hash`, which breaks the chain linkage for the next record.
- **Ordering guarantee:** The chain enforces a strict total order over records; records cannot be reordered without detection.
- **Append-only:** New records can only be appended to the end of the chain; insertion or deletion in the middle is detectable.

---

## Merkle Tree

VAOL uses an **RFC 6962**-style Merkle hash tree to enable efficient cryptographic proofs over the ledger. The Merkle tree provides logarithmic-time inclusion proofs (proving a record is in the ledger) and consistency proofs (proving the ledger has only been appended to).

### Hash Construction

The tree uses domain-separated SHA-256 hashing to prevent second-preimage attacks between leaf and internal nodes.

**Leaf hash:**

```
leaf_hash = SHA-256(0x00 || data)
```

Where `0x00` is a single zero byte prefix and `data` is the `record_hash` value (the full prefixed string, e.g., `sha256:abc123...`) encoded as UTF-8 bytes.

**Internal node hash:**

```
node_hash = SHA-256(0x01 || left || right)
```

Where `0x01` is a single one byte prefix, `left` is the 32-byte hash of the left child, and `right` is the 32-byte hash of the right child.

The domain separation bytes (`0x00` for leaves, `0x01` for nodes) prevent an attacker from constructing a leaf that hashes to the same value as an internal node or vice versa.

### Tree Structure

The tree is built incrementally as records are appended. For `n` leaves, the tree structure follows the RFC 6962 specification:

- If `n` is a power of two, the tree is a complete binary tree.
- If `n` is not a power of two, the tree is constructed by splitting at the largest power of two less than `n`, building a complete left subtree and a (possibly incomplete) right subtree, then combining them.

Formally, for `n > 1`:

```
MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

Where `k` is the largest power of two less than `n`.

For `n = 1`:

```
MTH(D[0:1]) = SHA-256(0x00 || D[0])
```

For `n = 0`, the empty tree hash is defined as:

```
MTH({}) = SHA-256("")  (the hash of the empty string)
```

### Inclusion Proof

An inclusion proof demonstrates that a specific record exists at a given index in a Merkle tree of a given size. The proof consists of an ordered list of sibling hashes from the leaf to the root.

**Structure:**

```json
{
  "leaf_index": 5,
  "tree_size": 12,
  "hashes": [
    "base64url-encoded sibling hash 1",
    "base64url-encoded sibling hash 2",
    "base64url-encoded sibling hash 3",
    "base64url-encoded sibling hash 4"
  ]
}
```

**Verification:**

1. Compute the leaf hash: `SHA-256(0x00 || record_hash_bytes)`.
2. Walk the proof hashes from bottom to top, combining with the current hash using the node hash function. The position (left or right) at each level is determined by the bits of `leaf_index` and `tree_size`.
3. The final computed hash must equal the known `merkle_root`.

The proof length is `O(log n)` where `n` is the tree size, making verification efficient even for very large ledgers.

### Consistency Proof

A consistency proof demonstrates that a Merkle tree of size `m` is a prefix of a Merkle tree of size `n` (where `m <= n`). This proves the ledger is append-only: no existing records have been modified or removed.

**Structure:**

```json
{
  "first_tree_size": 8,
  "second_tree_size": 12,
  "hashes": [
    "base64url-encoded hash 1",
    "base64url-encoded hash 2"
  ]
}
```

**Verification:**

1. Using the proof hashes, reconstruct both the root hash of the tree at size `m` and the root hash of the tree at size `n`.
2. Verify the reconstructed roots match the known roots for both tree sizes.

If the proof verifies, it is cryptographically guaranteed that the first `m` leaves of the size-`n` tree are identical to the `m` leaves of the size-`m` tree.

### Signed Checkpoints

The Merkle tree root is periodically captured in a signed checkpoint that attests to the state of the ledger at a given point in time.

**Checkpoint structure:**

```json
{
  "tree_size": 1024,
  "merkle_root": "sha256:abc123...",
  "timestamp": "2026-02-19T12:00:00Z",
  "signature": "<DSSE envelope over the checkpoint>"
}
```

The checkpoint is signed using the same DSSE envelope format as decision records, with the payload type:

```
application/vnd.vaol.checkpoint.v1+json
```

Checkpoints serve as trust anchors: a verifier who trusts a checkpoint can verify any record's inclusion using only the inclusion proof and the checkpoint, without needing to download the entire ledger.

---

## Encryption

VAOL supports optional encryption of decision record output content using the **age** encryption format with X25519 key agreement.

### Algorithm

- **Key agreement:** X25519 (Curve25519 Diffie-Hellman)
- **Symmetric encryption:** ChaCha20-Poly1305 (as specified by age)
- **Key derivation:** HKDF-SHA-256 (as specified by age)

### Scope

Encryption applies to the `output` field (and optionally the `input` field) of a decision record. Metadata fields (timestamps, model identifiers, decision types, hashes) remain in plaintext to preserve auditability and searchability.

The `record_hash` is computed over the record containing the **encrypted** content, not the plaintext. This means the hash chain and Merkle tree attest to the ciphertext, and decryption is not required for integrity verification.

### Encrypted Field Format

Encrypted fields are stored as age-encrypted ciphertext, base64-encoded with a distinguishing prefix:

```
age:base64url(<age-encrypted ciphertext>)
```

### Recipient Model

age supports multiple recipients, allowing a single encrypted record to be decryptable by multiple parties (e.g., the record creator, an auditor, and a compliance officer). Each recipient is identified by their age X25519 public key.

**Public key format (age recipient):**

```
age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

**Private key format (age identity):**

```
AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
```

### Key Rotation

When encryption keys are rotated, the new key is used for all new records. Existing records remain encrypted with their original keys. The record metadata includes a `key_id` field that identifies which encryption key was used, enabling verifiers and auditors to select the correct decryption key.

---

## Key Management

Each signing backend has its own key management model, ranging from explicit file-based management to fully managed keyless operation.

### Ed25519 Local Keys

**Storage format:** PEM-encoded files on disk.

**Private key (PKCS#8 PEM):**

```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL...
-----END PRIVATE KEY-----
```

**Public key (SPKI PEM):**

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----
```

**File permissions:** Private key files MUST be readable only by the owning user (`chmod 0600`). VAOL refuses to load private keys with group or world-readable permissions.

**Key generation:**

```bash
vaol-cli keygen --algorithm ed25519 --output /path/to/key.pem
```

This generates a new Ed25519 key pair and writes the private key to the specified path. The public key is written to `<path>.pub`.

**Key ID derivation:**

```
keyid = hex(SHA-256(raw_32_byte_public_key)[0:16])
```

This produces a 32-character hexadecimal key identifier.

### Sigstore Keyless

Sigstore keyless signing requires **no key management**. Keys are ephemeral and exist only for the duration of a single signing operation. Identity is established through OIDC authentication, and the signing event is recorded in the Rekor transparency log.

**Configuration:**

```yaml
signing:
  backend: sigstore
  sigstore:
    fulcio_url: "https://fulcio.sigstore.dev"
    rekor_url: "https://rekor.sigstore.dev"
    oidc_issuer: "https://accounts.google.com"
    oidc_client_id: "sigstore"
```

For private Sigstore deployments, the Fulcio and Rekor URLs can be overridden to point to internal instances.

**Identity binding:** The OIDC subject (e.g., `user@example.com`) is embedded in the Fulcio certificate and becomes the verifiable signer identity. No key files are stored or managed.

### KMS URIs

Cloud KMS and HSM keys are referenced by URI. The URI scheme identifies the provider, and the URI path identifies the specific key and version.

**Configuration:**

```yaml
signing:
  backend: kms
  kms:
    key_uri: "awskms:///arn:aws:kms:us-east-1:123456789012:key/abcd-1234-ef56-7890"
    # or
    key_uri: "gcpkms://projects/my-project/locations/us-east1/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
    # or
    key_uri: "azurekms://my-vault.vault.azure.net/keys/my-key/version-id"
    # or
    key_uri: "pkcs11:token=my-hsm;object=signing-key;pin-value=1234"
```

**Authentication:** KMS authentication uses the standard cloud provider credential chains (AWS IAM roles, GCP service accounts, Azure managed identities). No additional credential configuration is needed in VAOL beyond the key URI.

**Key ID:** For KMS-backed keys, the `keyid` in the DSSE envelope is the full KMS key URI. This enables verifiers to identify the exact key and provider without ambiguity.

**Key rotation:** Cloud KMS providers support key version rotation natively. When a new key version is created, the `key_uri` is updated to reference the new version, and old signatures remain verifiable against the old version URI.

---

## Security Considerations

### Algorithm Agility

VAOL currently mandates SHA-256 for hashing, Ed25519 or ECDSA P-256 for signing, and X25519 for encryption. Should any of these algorithms be found to be weak, the versioned payload type (`v1`) in the DSSE envelope and the `sha256:` prefix on hash values provide clear migration points. A future `v2` payload type can introduce new algorithms without breaking verification of existing `v1` records.

### Collision Resistance

SHA-256 provides 128-bit collision resistance. For VAOL's use cases (hash chaining and Merkle trees), collision resistance is the critical property: an attacker must not be able to produce two distinct records with the same hash. The 128-bit security level is sufficient for current threat models.

### Replay Protection

The combination of hash chaining (`previous_record_hash`), sequence numbers, and timestamps provides replay protection. A replayed record would either break the chain linkage or produce a duplicate sequence number, both of which are detectable.

### Side-Channel Resistance

Ed25519 signing is deterministic and does not require a random number generator at signing time, eliminating a common source of implementation vulnerabilities. For ECDSA P-256 via KMS/HSM, the nonce generation is handled within the hardware boundary, providing equivalent protection.

### Transparency and Auditability

Sigstore keyless signing provides public transparency: every signing event is recorded in the Rekor transparency log, creating an immutable public audit trail. For organizations requiring private auditability, the hash chain and Merkle tree provide equivalent tamper-evidence properties within the VAOL ledger itself.

### Canonicalization Attacks

JCS (RFC 8785) canonicalization is applied only for hash computation, never for display or storage. The canonical form is computed, hashed, and discarded. This minimizes the attack surface of the canonicalization step. Implementations MUST use a compliant RFC 8785 library and MUST NOT implement JCS from scratch.

### Key Compromise Recovery

- **Ed25519 local:** If a private key is compromised, all records signed with that key should be considered suspect. A new key pair must be generated, and the compromised key's ID should be added to a revocation list.
- **Sigstore keyless:** Key compromise is not applicable since keys are ephemeral. However, if an OIDC identity is compromised, the attacker can produce valid signatures until the OIDC credential is revoked.
- **KMS/HSM:** Key compromise requires breaching the hardware security boundary. Cloud KMS providers offer key disabling and deletion as immediate response actions. Audit logs from the KMS provider can identify unauthorized signing operations.
