package signer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519SignerGenerate(t *testing.T) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}
	if s.KeyID() == "" {
		t.Error("KeyID should not be empty")
	}
	if s.Algorithm() != "ed25519" {
		t.Errorf("Algorithm = %q, want ed25519", s.Algorithm())
	}
}

func TestEd25519SignAndVerify(t *testing.T) {
	s, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer error: %v", err)
	}

	payload := []byte("test payload to sign")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	if sig.KeyID == "" {
		t.Error("signature KeyID should not be empty")
	}
	if sig.Sig == "" {
		t.Error("signature Sig should not be empty")
	}

	// Verify
	v := NewEd25519Verifier(s.PublicKey())
	if err := v.Verify(context.Background(), payload, sig); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestEd25519VerifyRejectsWrongPayload(t *testing.T) {
	s, _ := GenerateEd25519Signer()
	payload := []byte("original payload")
	sig, _ := s.Sign(context.Background(), payload)

	v := NewEd25519Verifier(s.PublicKey())
	err := v.Verify(context.Background(), []byte("tampered payload"), sig)
	if err == nil {
		t.Error("Verify should reject wrong payload")
	}
}

func TestEd25519VerifyRejectsWrongKey(t *testing.T) {
	s1, _ := GenerateEd25519Signer()
	s2, _ := GenerateEd25519Signer()

	payload := []byte("payload")
	sig, _ := s1.Sign(context.Background(), payload)

	v := NewEd25519Verifier(s2.PublicKey())
	err := v.Verify(context.Background(), payload, sig)
	if err == nil {
		t.Error("Verify should reject signature from wrong key")
	}
}

func TestDSSESignEnvelope(t *testing.T) {
	s, _ := GenerateEd25519Signer()
	payload := []byte(`{"test":"data"}`)

	env, err := SignEnvelope(context.Background(), payload, s)
	if err != nil {
		t.Fatalf("SignEnvelope error: %v", err)
	}

	if env.PayloadType != PayloadType {
		t.Errorf("PayloadType = %q, want %q", env.PayloadType, PayloadType)
	}
	if env.Payload == "" {
		t.Error("Payload should not be empty")
	}
	if len(env.Signatures) != 1 {
		t.Errorf("Signatures count = %d, want 1", len(env.Signatures))
	}
	if env.Signatures[0].Timestamp == "" {
		t.Error("Signature timestamp should be set")
	}
}

func TestDSSEVerifyEnvelope(t *testing.T) {
	s, _ := GenerateEd25519Signer()
	payload := []byte(`{"hello":"world"}`)

	env, err := SignEnvelope(context.Background(), payload, s)
	if err != nil {
		t.Fatalf("SignEnvelope error: %v", err)
	}

	v := NewEd25519Verifier(s.PublicKey())
	if err := VerifyEnvelope(context.Background(), env, v); err != nil {
		t.Errorf("VerifyEnvelope failed: %v", err)
	}
}

func TestDSSEVerifyEnvelopeRejectsTamperedPayload(t *testing.T) {
	s, _ := GenerateEd25519Signer()
	payload := []byte(`{"hello":"world"}`)

	env, _ := SignEnvelope(context.Background(), payload, s)
	// Tamper with the payload
	env.Payload = b64Encode([]byte(`{"hello":"tampered"}`))

	v := NewEd25519Verifier(s.PublicKey())
	err := VerifyEnvelope(context.Background(), env, v)
	if err == nil {
		t.Error("VerifyEnvelope should reject tampered payload")
	}
}

func TestDSSEExtractPayload(t *testing.T) {
	s, _ := GenerateEd25519Signer()
	original := []byte(`{"test":"extract"}`)

	env, _ := SignEnvelope(context.Background(), original, s)
	extracted, err := ExtractPayload(env)
	if err != nil {
		t.Fatalf("ExtractPayload error: %v", err)
	}
	if string(extracted) != string(original) {
		t.Errorf("extracted = %q, want %q", extracted, original)
	}
}

func TestDSSEMultipleSigners(t *testing.T) {
	s1, _ := GenerateEd25519Signer()
	s2, _ := GenerateEd25519Signer()

	payload := []byte("multi-signed payload")
	env, err := SignEnvelope(context.Background(), payload, s1, s2)
	if err != nil {
		t.Fatalf("SignEnvelope error: %v", err)
	}
	if len(env.Signatures) != 2 {
		t.Errorf("Signatures count = %d, want 2", len(env.Signatures))
	}

	// Verify with either verifier
	v1 := NewEd25519Verifier(s1.PublicKey())
	v2 := NewEd25519Verifier(s2.PublicKey())
	if err := VerifyEnvelope(context.Background(), env, v1, v2); err != nil {
		t.Errorf("VerifyEnvelope failed: %v", err)
	}
}

func TestSignEnvelopeNoSigners(t *testing.T) {
	_, err := SignEnvelope(context.Background(), []byte("data"))
	if err == nil {
		t.Error("SignEnvelope with no signers should fail")
	}
}

func TestVerifyEnvelopeNoSignatures(t *testing.T) {
	env := &Envelope{
		PayloadType: PayloadType,
		Payload:     b64Encode([]byte("data")),
		Signatures:  nil,
	}
	v, _ := GenerateEd25519Signer()
	err := VerifyEnvelope(context.Background(), env, NewEd25519Verifier(v.PublicKey()))
	if err == nil {
		t.Error("VerifyEnvelope with no signatures should fail")
	}
}

func TestPAE(t *testing.T) {
	pae := PAE("application/test", []byte("payload"))
	expected := "DSSEv1 16 application/test 7 payload"
	if string(pae) != expected {
		t.Errorf("PAE = %q, want %q", string(pae), expected)
	}
}

func TestEd25519KeyPersistence(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.pem")
	pubPath := filepath.Join(dir, "test.pub")

	s, _ := GenerateEd25519Signer()

	// Save
	if err := SavePrivateKeyPEM(s.privateKey, privPath); err != nil {
		t.Fatalf("SavePrivateKeyPEM error: %v", err)
	}
	if err := SavePublicKeyPEM(s.PublicKey(), pubPath); err != nil {
		t.Fatalf("SavePublicKeyPEM error: %v", err)
	}

	// Check permissions
	info, _ := os.Stat(privPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("private key permissions = %o, want 0600", info.Mode().Perm())
	}

	// Load and verify
	loadedPriv, err := LoadPrivateKeyPEM(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM error: %v", err)
	}
	loadedPub, err := LoadPublicKeyPEM(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM error: %v", err)
	}

	// Sign with loaded key, verify with loaded public key
	loaded := NewEd25519Signer(loadedPriv)
	sig, _ := loaded.Sign(context.Background(), []byte("persistence test"))
	v := NewEd25519Verifier(loadedPub)
	if err := v.Verify(context.Background(), []byte("persistence test"), sig); err != nil {
		t.Errorf("verification with loaded keys failed: %v", err)
	}
}
