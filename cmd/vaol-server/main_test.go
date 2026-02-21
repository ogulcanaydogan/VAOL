package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

func TestBuildSignerEd25519Ephemeral(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	sig, verifiers, err := buildSignerAndVerifiers("ed25519", "", signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerEd25519FromPEM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Generate a key and write it to a temp file.
	generated, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := signer.SavePrivateKeyPEM(generated.PrivateKey(), keyPath); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	sig, verifiers, err := buildSignerAndVerifiers("ed25519", keyPath, signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
	if sig.KeyID() != generated.KeyID() {
		t.Fatalf("key ID mismatch: got %q, want %q", sig.KeyID(), generated.KeyID())
	}
}

func TestBuildSignerEd25519BadKeyPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, _, err := buildSignerAndVerifiers("ed25519", "/nonexistent/key.pem", signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

func TestBuildSignerSigstore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := signer.SigstoreConfig{
		FulcioURL: "https://fulcio.example.com",
		RekorURL:  "https://rekor.example.com",
	}
	sig, verifiers, err := buildSignerAndVerifiers("sigstore", "", cfg, signer.KMSConfig{}, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerKMSLocalECDSA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	kmsCfg := signer.KMSConfig{
		Provider: signer.KMSProviderLocal,
		KeyURI:   "local://test-key",
	}
	sig, verifiers, err := buildSignerAndVerifiers("kms", "", signer.SigstoreConfig{}, kmsCfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerKMSDefaultsApplied(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Empty provider and key URI should get defaults.
	kmsCfg := signer.KMSConfig{}
	sig, verifiers, err := buildSignerAndVerifiers("kms", "", signer.SigstoreConfig{}, kmsCfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signer")
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected 1 verifier, got %d", len(verifiers))
	}
}

func TestBuildSignerUnsupportedMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, _, err := buildSignerAndVerifiers("unknown-mode", "", signer.SigstoreConfig{}, signer.KMSConfig{}, logger)
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}

func TestBuildVariablesExist(t *testing.T) {
	// Verify that ldflags-injected variables have their defaults.
	if version == "" {
		t.Fatal("version should have a default value")
	}
	if commit == "" {
		t.Fatal("commit should have a default value")
	}
	if date == "" {
		t.Fatal("date should have a default value")
	}
}
