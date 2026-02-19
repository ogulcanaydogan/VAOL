package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

func TestKeysGenerateWritesPrivateAndPublicKeys(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := newKeysGenerateCmd()
	if err := cmd.Flags().Set("output", tmpDir); err != nil {
		t.Fatalf("setting output flag: %v", err)
	}

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("keys generate failed: %v", err)
	}

	privPath := filepath.Join(tmpDir, "vaol-signing.pem")
	pubPath := filepath.Join(tmpDir, "vaol-signing.pub")

	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("expected private key at %s: %v", privPath, err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("expected public key at %s: %v", pubPath, err)
	}

	privateKey, err := signer.LoadPrivateKeyPEM(privPath)
	if err != nil {
		t.Fatalf("loading private key: %v", err)
	}
	publicKey, err := signer.LoadPublicKeyPEM(pubPath)
	if err != nil {
		t.Fatalf("loading public key: %v", err)
	}

	derived := privateKey.Public().(ed25519.PublicKey)
	if string(derived) != string(publicKey) {
		t.Fatalf("public key does not match private key")
	}
}
