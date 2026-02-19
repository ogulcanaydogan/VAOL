// Package crypto provides cryptographic primitives for VAOL:
// SHA-256 hashing, age encryption, and related utilities.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const HashPrefix = "sha256:"

// SHA256Hex computes the SHA-256 digest of data and returns it as a hex string.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA256Prefixed computes SHA-256 and returns with the "sha256:" prefix.
func SHA256Prefixed(data []byte) string {
	return HashPrefix + SHA256Hex(data)
}

// SHA256Reader computes SHA-256 from an io.Reader.
func SHA256Reader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing reader: %w", err)
	}
	return HashPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyHash checks that the given data matches the expected prefixed hash.
func VerifyHash(data []byte, expected string) bool {
	return SHA256Prefixed(data) == expected
}

// ZeroHash is the well-known zero hash used as previous_record_hash for the genesis record.
var ZeroHash = HashPrefix + "0000000000000000000000000000000000000000000000000000000000000000"

// MerkleLeafHash computes a Merkle leaf hash per RFC 6962: SHA-256(0x00 || data).
func MerkleLeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// MerkleNodeHash computes a Merkle interior node hash per RFC 6962: SHA-256(0x01 || left || right).
func MerkleNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// HashToBytes converts a "sha256:<hex>" prefixed hash string to raw bytes.
func HashToBytes(prefixed string) ([]byte, error) {
	if len(prefixed) < len(HashPrefix) || prefixed[:len(HashPrefix)] != HashPrefix {
		return nil, fmt.Errorf("invalid hash prefix: %s", prefixed)
	}
	return hex.DecodeString(prefixed[len(HashPrefix):])
}

// BytesToHash converts raw hash bytes to a "sha256:<hex>" prefixed string.
func BytesToHash(b []byte) string {
	return HashPrefix + hex.EncodeToString(b)
}
