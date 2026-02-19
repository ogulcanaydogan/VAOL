package crypto

import (
	"testing"
)

func TestReencryptWithAge(t *testing.T) {
	oldIdentity, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity old: %v", err)
	}
	newIdentity, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity new: %v", err)
	}
	plaintext := []byte("sensitive output to re-encrypt")
	ciphertextB64, plainHash, err := Encrypt(plaintext, oldIdentity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := ReencryptWithAge(ciphertextB64, plainHash, oldIdentity, newIdentity.Recipient())
	if err != nil {
		t.Fatalf("ReencryptWithAge: %v", err)
	}
	if result.CiphertextHash == "" || result.PlaintextHash == "" {
		t.Fatal("expected deterministic hashes after re-encryption")
	}

	roundtrip, err := Decrypt(result.CiphertextB64, result.PlaintextHash, newIdentity)
	if err != nil {
		t.Fatalf("Decrypt re-encrypted payload: %v", err)
	}
	if string(roundtrip) != string(plaintext) {
		t.Fatalf("plaintext mismatch after re-encryption")
	}
}
