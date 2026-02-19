package crypto

import (
	"testing"
)

func TestGenerateX25519Identity(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}
	if id == nil {
		t.Fatal("identity should not be nil")
	}
	if id.Recipient().String() == "" {
		t.Error("recipient (public key) should not be empty")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}

	plaintext := []byte("sensitive AI output that must be encrypted")
	ciphertext, plaintextHash, err := Encrypt(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	if ciphertext == "" {
		t.Error("ciphertext should not be empty")
	}
	if plaintextHash == "" {
		t.Error("plaintext hash should not be empty")
	}
	if plaintextHash != SHA256Prefixed(plaintext) {
		t.Error("plaintext hash should match SHA256 of original")
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, plaintextHash, id)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptVerifiesHash(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}

	plaintext := []byte("test data")
	ciphertext, _, err := Encrypt(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Decrypt with wrong expected hash should fail
	_, err = Decrypt(ciphertext, "sha256:0000000000000000000000000000000000000000000000000000000000000000", id)
	if err == nil {
		t.Error("Decrypt should fail when hash doesn't match")
	}
}

func TestDecryptWithoutHashCheck(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}

	plaintext := []byte("no hash check")
	ciphertext, _, err := Encrypt(plaintext, id.Recipient())
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Empty expectedHash skips verification
	decrypted, err := Decrypt(ciphertext, "", id)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	_, _, err := Encrypt([]byte("data"))
	if err == nil {
		t.Error("Encrypt with no recipients should fail")
	}
}

func TestDecryptNoIdentities(t *testing.T) {
	_, err := Decrypt("base64data", "")
	if err == nil {
		t.Error("Decrypt with no identities should fail")
	}
}

func TestDecryptInvalidBase64(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}
	_, err = Decrypt("not-valid-base64!!!", "", id)
	if err == nil {
		t.Error("Decrypt with invalid base64 should fail")
	}
}

func TestEncryptDifferentPlaintextsDifferentCiphertexts(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}

	ct1, _, _ := Encrypt([]byte("data1"), id.Recipient())
	ct2, _, _ := Encrypt([]byte("data2"), id.Recipient())
	if ct1 == ct2 {
		t.Error("different plaintexts should produce different ciphertexts")
	}
}

func TestParseX25519Identity(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}

	parsed, err := ParseX25519Identity(id.String())
	if err != nil {
		t.Fatalf("ParseX25519Identity error: %v", err)
	}
	if parsed.Recipient().String() != id.Recipient().String() {
		t.Error("parsed identity should have same public key")
	}
}

func TestParseX25519Recipient(t *testing.T) {
	id, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity error: %v", err)
	}

	parsed, err := ParseX25519Recipient(id.Recipient().String())
	if err != nil {
		t.Fatalf("ParseX25519Recipient error: %v", err)
	}
	if parsed.String() != id.Recipient().String() {
		t.Error("parsed recipient should match original")
	}
}
