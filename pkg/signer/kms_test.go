package signer

import (
	"context"
	"strings"
	"testing"
)

func TestKMSSignVerify(t *testing.T) {
	backend, err := NewLocalECDSABackend()
	if err != nil {
		t.Fatalf("creating ECDSA backend: %v", err)
	}

	cfg := KMSConfig{
		Provider: KMSProviderLocal,
		KeyURI:   "local://test-key",
	}
	signer := NewKMSSigner(cfg, backend)
	verifier := NewKMSVerifier(signer.KeyID(), backend)

	ctx := context.Background()
	payload := []byte("test payload for KMS signing")

	sig, err := signer.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if sig.KeyID != signer.KeyID() {
		t.Errorf("key ID mismatch: got %s, want %s", sig.KeyID, signer.KeyID())
	}
	if sig.Sig == "" {
		t.Error("signature is empty")
	}
	if sig.Timestamp == "" {
		t.Error("timestamp is empty")
	}

	// Verify with correct payload
	if err := verifier.Verify(ctx, payload, sig); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}

	// Verify with wrong payload should fail
	if err := verifier.Verify(ctx, []byte("wrong payload"), sig); err == nil {
		t.Error("verify should fail with wrong payload")
	}
}

func TestKMSSignEnvelopeRoundTrip(t *testing.T) {
	backend, err := NewLocalECDSABackend()
	if err != nil {
		t.Fatalf("creating ECDSA backend: %v", err)
	}

	cfg := KMSConfig{Provider: KMSProviderLocal, KeyURI: "local://envelope-test"}
	s := NewKMSSigner(cfg, backend)
	v := NewKMSVerifier(s.KeyID(), backend)

	ctx := context.Background()
	payload := []byte(`{"schema_version":"v1","test":"kms_envelope"}`)

	env, err := SignEnvelope(ctx, payload, s)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	if err := VerifyEnvelope(ctx, env, v); err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}

	// Tamper with payload
	env.Payload = b64Encode([]byte(`{"tampered":"true"}`))
	if err := VerifyEnvelope(ctx, env, v); err == nil {
		t.Error("VerifyEnvelope should fail after payload tampering")
	}
}

func TestKMSSignerAlgorithm(t *testing.T) {
	backend, _ := NewLocalECDSABackend()
	cfg := KMSConfig{Provider: KMSProviderAWS, KeyURI: "arn:aws:kms:us-east-1:123:key/abc"}
	s := NewKMSSigner(cfg, backend)

	if s.Algorithm() != "kms-aws-kms" {
		t.Errorf("unexpected algorithm: %s", s.Algorithm())
	}
	expected := "aws-kms:arn:aws:kms:us-east-1:123:key/abc"
	if s.KeyID() != expected {
		t.Errorf("unexpected key ID: %s, want %s", s.KeyID(), expected)
	}
}

func TestKMSVerifier_InvalidSignature(t *testing.T) {
	backend, _ := NewLocalECDSABackend()
	v := NewKMSVerifier("test-key", backend)

	ctx := context.Background()
	sig := Signature{
		KeyID: "test-key",
		Sig:   b64Encode([]byte("not-a-valid-asn1-signature")),
	}

	if err := v.Verify(ctx, []byte("payload"), sig); err == nil {
		t.Error("should fail with invalid ASN.1 signature")
	}
}

func TestKMSVerifier_RejectsMismatchedKeyID(t *testing.T) {
	backend, err := NewLocalECDSABackend()
	if err != nil {
		t.Fatalf("creating backend: %v", err)
	}
	cfg := KMSConfig{Provider: KMSProviderLocal, KeyURI: "local://keyid-check"}
	s := NewKMSSigner(cfg, backend)
	v := NewKMSVerifier("local-ecdsa:local://different-key", backend)

	ctx := context.Background()
	sig, err := s.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	err = v.Verify(ctx, []byte("payload"), sig)
	if err == nil || !strings.Contains(err.Error(), "keyid mismatch") {
		t.Fatalf("expected keyid mismatch error, got: %v", err)
	}
}

func TestKMSVerifier_RejectsMissingKeyID(t *testing.T) {
	backend, err := NewLocalECDSABackend()
	if err != nil {
		t.Fatalf("creating backend: %v", err)
	}
	cfg := KMSConfig{Provider: KMSProviderLocal, KeyURI: "local://missing-keyid"}
	s := NewKMSSigner(cfg, backend)
	v := NewKMSVerifier(s.KeyID(), backend)

	ctx := context.Background()
	sig, err := s.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig.KeyID = ""
	err = v.Verify(ctx, []byte("payload"), sig)
	if err == nil || !strings.Contains(err.Error(), "missing keyid") {
		t.Fatalf("expected missing keyid error, got: %v", err)
	}
}

func TestKMSVerifier_RejectsInvalidTimestamp(t *testing.T) {
	backend, err := NewLocalECDSABackend()
	if err != nil {
		t.Fatalf("creating backend: %v", err)
	}
	cfg := KMSConfig{Provider: KMSProviderLocal, KeyURI: "local://timestamp-check"}
	s := NewKMSSigner(cfg, backend)
	v := NewKMSVerifier(s.KeyID(), backend)

	ctx := context.Background()
	sig, err := s.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig.Timestamp = "not-rfc3339"
	err = v.Verify(ctx, []byte("payload"), sig)
	if err == nil || !strings.Contains(err.Error(), "invalid kms signature timestamp") {
		t.Fatalf("expected invalid timestamp error, got: %v", err)
	}
}

func TestLocalECDSABackend_PublicKeyPEM(t *testing.T) {
	backend, err := NewLocalECDSABackend()
	if err != nil {
		t.Fatalf("creating backend: %v", err)
	}

	pem, err := backend.PublicKeyPEM()
	if err != nil {
		t.Fatalf("getting PEM: %v", err)
	}

	if len(pem) == 0 {
		t.Error("PEM is empty")
	}
	if string(pem[:27]) != "-----BEGIN PUBLIC KEY-----\n" {
		t.Errorf("unexpected PEM prefix: %s", string(pem[:27]))
	}
}
