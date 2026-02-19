package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// Ed25519Signer implements the Signer interface using Ed25519.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

// NewEd25519Signer creates a signer from an Ed25519 private key.
func NewEd25519Signer(privateKey ed25519.PrivateKey) *Ed25519Signer {
	pub := privateKey.Public().(ed25519.PublicKey)
	return &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  pub,
		keyID:      "ed25519:" + hex.EncodeToString(pub[:8]),
	}
}

// GenerateEd25519Signer generates a new Ed25519 key pair and returns a signer.
func GenerateEd25519Signer() (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return NewEd25519Signer(priv), nil
}

func (s *Ed25519Signer) Sign(_ context.Context, payload []byte) (Signature, error) {
	sig := ed25519.Sign(s.privateKey, payload)
	return Signature{
		KeyID: s.keyID,
		Sig:   b64Encode(sig),
	}, nil
}

func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

func (s *Ed25519Signer) Algorithm() string {
	return "ed25519"
}

// PublicKey returns the public key for this signer.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.publicKey
}

// PrivateKey returns the private key for this signer.
func (s *Ed25519Signer) PrivateKey() ed25519.PrivateKey {
	return s.privateKey
}

// Ed25519Verifier implements the Verifier interface using Ed25519.
type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
	keyID     string
}

// NewEd25519Verifier creates a verifier from an Ed25519 public key.
func NewEd25519Verifier(publicKey ed25519.PublicKey) *Ed25519Verifier {
	return &Ed25519Verifier{
		publicKey: publicKey,
		keyID:     "ed25519:" + hex.EncodeToString(publicKey[:8]),
	}
}

func (v *Ed25519Verifier) Verify(_ context.Context, payload []byte, sig Signature) error {
	sigBytes, err := b64Decode(sig.Sig)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	if !ed25519.Verify(v.publicKey, payload, sigBytes) {
		return fmt.Errorf("ed25519 signature verification failed")
	}
	return nil
}

func (v *Ed25519Verifier) KeyID() string {
	return v.keyID
}

// SavePrivateKeyPEM writes an Ed25519 private key to a PEM file.
func SavePrivateKeyPEM(key ed25519.PrivateKey, path string) error {
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key.Seed(),
	}
	data := pem.EncodeToMemory(block)
	return os.WriteFile(path, data, 0600)
}

// LoadPrivateKeyPEM reads an Ed25519 private key from a PEM file.
func LoadPrivateKeyPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	if len(block.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed length: %d", len(block.Bytes))
	}

	return ed25519.NewKeyFromSeed(block.Bytes), nil
}

// SavePublicKeyPEM writes an Ed25519 public key to a PEM file.
func SavePublicKeyPEM(key ed25519.PublicKey, path string) error {
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: key,
	}
	data := pem.EncodeToMemory(block)
	return os.WriteFile(path, data, 0644)
}

// LoadPublicKeyPEM reads an Ed25519 public key from a PEM file.
func LoadPublicKeyPEM(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(block.Bytes))
	}

	return ed25519.PublicKey(block.Bytes), nil
}
