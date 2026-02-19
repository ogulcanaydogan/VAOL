package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	// Known test vector: SHA-256 of empty string
	got := SHA256Hex([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("SHA256Hex(empty) = %s, want %s", got, want)
	}
}

func TestSHA256Prefixed(t *testing.T) {
	got := SHA256Prefixed([]byte("hello"))
	if !strings.HasPrefix(got, HashPrefix) {
		t.Errorf("SHA256Prefixed should start with %q, got %q", HashPrefix, got)
	}
	if len(got) != 71 { // "sha256:" (7) + 64 hex chars
		t.Errorf("SHA256Prefixed length = %d, want 71", len(got))
	}
}

func TestSHA256PrefixedDeterministic(t *testing.T) {
	data := []byte("test data for determinism")
	h1 := SHA256Prefixed(data)
	h2 := SHA256Prefixed(data)
	if h1 != h2 {
		t.Error("SHA256Prefixed should be deterministic")
	}
}

func TestSHA256PrefixedDifferentInputs(t *testing.T) {
	h1 := SHA256Prefixed([]byte("input a"))
	h2 := SHA256Prefixed([]byte("input b"))
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestSHA256Reader(t *testing.T) {
	data := []byte("reader test data")
	expected := SHA256Prefixed(data)

	got, err := SHA256Reader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SHA256Reader error: %v", err)
	}
	if got != expected {
		t.Errorf("SHA256Reader = %s, want %s", got, expected)
	}
}

func TestVerifyHash(t *testing.T) {
	data := []byte("verify me")
	hash := SHA256Prefixed(data)

	if !VerifyHash(data, hash) {
		t.Error("VerifyHash should return true for matching data")
	}
	if VerifyHash([]byte("wrong data"), hash) {
		t.Error("VerifyHash should return false for non-matching data")
	}
}

func TestZeroHash(t *testing.T) {
	if !strings.HasPrefix(ZeroHash, HashPrefix) {
		t.Errorf("ZeroHash should start with %q", HashPrefix)
	}
	if len(ZeroHash) != 71 {
		t.Errorf("ZeroHash length = %d, want 71", len(ZeroHash))
	}
	// All zeros after prefix
	for _, c := range ZeroHash[7:] {
		if c != '0' {
			t.Errorf("ZeroHash should be all zeros after prefix, got char %c", c)
			break
		}
	}
}

func TestMerkleLeafHash(t *testing.T) {
	data := []byte("leaf data")
	h := MerkleLeafHash(data)
	if len(h) != 32 {
		t.Errorf("MerkleLeafHash length = %d, want 32", len(h))
	}
	// Leaf hash should differ from raw SHA-256 (because of 0x00 prefix)
	raw := SHA256Hex(data)
	leafHex := BytesToHash(h)
	if leafHex == HashPrefix+raw {
		t.Error("MerkleLeafHash should differ from raw SHA-256 due to domain separation")
	}
}

func TestMerkleNodeHash(t *testing.T) {
	left := MerkleLeafHash([]byte("left"))
	right := MerkleLeafHash([]byte("right"))
	h := MerkleNodeHash(left, right)
	if len(h) != 32 {
		t.Errorf("MerkleNodeHash length = %d, want 32", len(h))
	}
	// Order matters
	h2 := MerkleNodeHash(right, left)
	if bytes.Equal(h, h2) {
		t.Error("MerkleNodeHash should be order-dependent")
	}
}

func TestHashToBytes(t *testing.T) {
	original := SHA256Prefixed([]byte("roundtrip"))
	b, err := HashToBytes(original)
	if err != nil {
		t.Fatalf("HashToBytes error: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("HashToBytes length = %d, want 32", len(b))
	}
	roundtrip := BytesToHash(b)
	if roundtrip != original {
		t.Errorf("roundtrip failed: %s != %s", roundtrip, original)
	}
}

func TestHashToBytesInvalidPrefix(t *testing.T) {
	_, err := HashToBytes("md5:abc123")
	if err == nil {
		t.Error("HashToBytes should reject invalid prefix")
	}
}

func TestHashToBytesInvalidHex(t *testing.T) {
	_, err := HashToBytes("sha256:zzzz")
	if err == nil {
		t.Error("HashToBytes should reject invalid hex")
	}
}
