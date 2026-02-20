"""Client-side cryptographic verification for VAOL decision records.

Provides Ed25519 DSSE signature verification and RFC 6962 Merkle inclusion
proof validation — enabling auditors to verify records without trusting the server.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# DSSE helpers
# ---------------------------------------------------------------------------

PAYLOAD_TYPE = "application/vnd.vaol.decision-record.v1+json"


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    return f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} ".encode() + payload


def _b64_decode(s: str) -> bytes:
    """Decode standard or URL-safe base64."""
    # Pad if needed
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s, altchars=b"-_")


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    """Outcome of a verification check."""

    valid: bool
    checks: list[dict[str, Any]]

    @property
    def summary(self) -> str:
        failed = [c for c in self.checks if not c.get("passed")]
        if not failed:
            return "all checks passed"
        names = ", ".join(c["name"] for c in failed)
        return f"failed: {names}"


def verify_dsse_ed25519(
    envelope: dict[str, Any],
    public_key_bytes: bytes,
) -> VerifyResult:
    """Verify Ed25519 signatures on a DSSE envelope.

    Args:
        envelope: DSSE envelope dict with ``payloadType``, ``payload``, ``signatures``.
        public_key_bytes: Raw 32-byte Ed25519 public key.

    Returns:
        VerifyResult with per-signature check details.
    """
    checks: list[dict[str, Any]] = []

    payload_type = envelope.get("payloadType", "")
    payload_b64 = envelope.get("payload", "")
    signatures = envelope.get("signatures", [])

    if not signatures:
        checks.append({"name": "signature_present", "passed": False, "error": "no signatures"})
        return VerifyResult(valid=False, checks=checks)

    try:
        payload = _b64_decode(payload_b64)
    except Exception as exc:
        checks.append({"name": "payload_decode", "passed": False, "error": str(exc)})
        return VerifyResult(valid=False, checks=checks)

    pae = _pae(payload_type, payload)
    pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    verified_count = 0
    for i, sig in enumerate(signatures):
        name = f"signature_{i}"
        try:
            sig_bytes = _b64_decode(sig["sig"])
            pub.verify(sig_bytes, pae)
            checks.append({"name": name, "passed": True})
            verified_count += 1
        except Exception as exc:
            checks.append({"name": name, "passed": False, "error": str(exc)})

    return VerifyResult(valid=verified_count > 0, checks=checks)


# ---------------------------------------------------------------------------
# Merkle proof verification (RFC 6962)
# ---------------------------------------------------------------------------

def _merkle_leaf_hash(data: bytes) -> bytes:
    """SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def _merkle_node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_2_less_than(n: int) -> int:
    """Largest power of 2 strictly less than *n*."""
    if n <= 1:
        return 0
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _hash_from_prefixed(prefixed: str) -> bytes:
    """Convert ``sha256:<hex>`` to raw bytes."""
    if not prefixed.startswith("sha256:"):
        raise ValueError(f"expected sha256: prefix, got {prefixed!r}")
    return bytes.fromhex(prefixed[7:])


def _bytes_to_prefixed(b: bytes) -> str:
    return "sha256:" + b.hex()


def _recompute_root(
    current_hash: bytes,
    index: int,
    size: int,
    path: list[bytes],
) -> bytes:
    if size == 1:
        if path:
            raise ValueError("excess proof hashes for single-leaf tree")
        return current_hash
    if not path:
        raise ValueError("insufficient proof hashes")

    k = _largest_power_of_2_less_than(size)
    sibling = path[-1]
    remaining = path[:-1]

    if index < k:
        sub = _recompute_root(current_hash, index, k, remaining)
        return _merkle_node_hash(sub, sibling)

    sub = _recompute_root(current_hash, index - k, size - k, remaining)
    return _merkle_node_hash(sibling, sub)


def verify_inclusion_proof(
    leaf_data: bytes,
    leaf_index: int,
    tree_size: int,
    proof_hashes: list[str],
    expected_root: str,
) -> VerifyResult:
    """Verify a Merkle inclusion proof per RFC 6962.

    Args:
        leaf_data: The raw leaf payload (e.g. canonical JSON of the record).
        leaf_index: Zero-based index of the leaf in the tree.
        tree_size: Total number of leaves when the proof was generated.
        proof_hashes: ``sha256:<hex>`` sibling hashes from leaf to root.
        expected_root: ``sha256:<hex>`` expected Merkle root.

    Returns:
        VerifyResult indicating whether the proof is valid.
    """
    checks: list[dict[str, Any]] = []

    if tree_size <= 0:
        checks.append({"name": "tree_size", "passed": False, "error": "tree size must be positive"})
        return VerifyResult(valid=False, checks=checks)

    if leaf_index < 0 or leaf_index >= tree_size:
        checks.append({
            "name": "leaf_index",
            "passed": False,
            "error": f"leaf index {leaf_index} out of range [0, {tree_size})",
        })
        return VerifyResult(valid=False, checks=checks)

    try:
        path_bytes = [_hash_from_prefixed(h) for h in proof_hashes]
    except Exception as exc:
        checks.append({"name": "proof_decode", "passed": False, "error": str(exc)})
        return VerifyResult(valid=False, checks=checks)

    leaf_hash = _merkle_leaf_hash(leaf_data)

    try:
        computed_root = _recompute_root(leaf_hash, leaf_index, tree_size, path_bytes)
    except Exception as exc:
        checks.append({"name": "proof_recompute", "passed": False, "error": str(exc)})
        return VerifyResult(valid=False, checks=checks)

    computed_str = _bytes_to_prefixed(computed_root)
    if computed_str == expected_root:
        checks.append({"name": "inclusion_proof", "passed": True})
        return VerifyResult(valid=True, checks=checks)

    checks.append({
        "name": "inclusion_proof",
        "passed": False,
        "error": f"computed root {computed_str} != expected {expected_root}",
    })
    return VerifyResult(valid=False, checks=checks)
