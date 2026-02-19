package crypto

import (
	"encoding/base64"
	"fmt"

	"filippo.io/age"
)

// ReencryptResult contains deterministic binding data after re-encryption.
type ReencryptResult struct {
	CiphertextB64  string `json:"ciphertext_b64"`
	CiphertextHash string `json:"ciphertext_hash"`
	PlaintextHash  string `json:"plaintext_hash"`
}

// ReencryptWithAge decrypts ciphertext with an old identity and re-encrypts it to new recipients.
func ReencryptWithAge(ciphertextB64 string, expectedPlaintextHash string, oldIdentity age.Identity, recipients ...age.Recipient) (*ReencryptResult, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required for re-encryption")
	}

	plaintext, err := Decrypt(ciphertextB64, expectedPlaintextHash, oldIdentity)
	if err != nil {
		return nil, fmt.Errorf("decrypting old ciphertext: %w", err)
	}
	newCiphertextB64, plaintextHash, err := Encrypt(plaintext, recipients...)
	if err != nil {
		return nil, fmt.Errorf("encrypting with new recipients: %w", err)
	}
	rawCiphertext, err := base64.StdEncoding.DecodeString(newCiphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decoding newly encrypted ciphertext: %w", err)
	}

	return &ReencryptResult{
		CiphertextB64:  newCiphertextB64,
		CiphertextHash: SHA256Prefixed(rawCiphertext),
		PlaintextHash:  plaintextHash,
	}, nil
}
