package signer

import (
	"encoding/base64"
)

// b64Encode encodes bytes to URL-safe base64 without padding (per DSSE spec).
func b64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// b64Decode decodes URL-safe base64 without padding.
func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// TestB64Encode is an exported wrapper for b64Encode, intended for use in tests
// outside this package that need to construct DSSE envelopes manually.
func TestB64Encode(data []byte) string {
	return b64Encode(data)
}
