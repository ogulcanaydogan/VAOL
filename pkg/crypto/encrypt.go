package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

// GenerateX25519Identity creates a new age X25519 key pair.
// Returns the identity (private key) which also exposes the recipient (public key).
func GenerateX25519Identity() (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating X25519 identity: %w", err)
	}
	return identity, nil
}

// Encrypt encrypts plaintext using one or more age recipients and returns the
// ciphertext as a base64-encoded string with the SHA-256 digest of the plaintext.
func Encrypt(plaintext []byte, recipients ...age.Recipient) (ciphertext string, plaintextHash string, err error) {
	if len(recipients) == 0 {
		return "", "", fmt.Errorf("at least one recipient is required")
	}

	plaintextHash = SHA256Prefixed(plaintext)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return "", "", fmt.Errorf("creating age encryptor: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", "", fmt.Errorf("writing to age encryptor: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", "", fmt.Errorf("closing age encryptor: %w", err)
	}

	ciphertext = base64.StdEncoding.EncodeToString(buf.Bytes())
	return ciphertext, plaintextHash, nil
}

// Decrypt decrypts a base64-encoded age ciphertext using the provided identities.
// Optionally verifies the plaintext against an expected hash.
func Decrypt(ciphertextB64 string, expectedHash string, identities ...age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one identity is required")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 ciphertext: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("creating age decryptor: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	if expectedHash != "" {
		actual := SHA256Prefixed(plaintext)
		if actual != expectedHash {
			return nil, fmt.Errorf("plaintext hash mismatch: expected %s, got %s", expectedHash, actual)
		}
	}

	return plaintext, nil
}

// ParseX25519Identity parses an age X25519 identity from its string representation.
func ParseX25519Identity(s string) (*age.X25519Identity, error) {
	identity, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 identity: %w", err)
	}
	return identity, nil
}

// ParseX25519Recipient parses an age X25519 recipient (public key) from its string representation.
func ParseX25519Recipient(s string) (*age.X25519Recipient, error) {
	recipient, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 recipient: %w", err)
	}
	return recipient, nil
}
