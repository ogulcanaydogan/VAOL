package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/record"
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

func TestBuildVerificationVerifiersIncludesSigstore(t *testing.T) {
	verifiers, err := buildVerificationVerifiers(
		"",
		true,
		"https://oauth2.sigstore.dev/auth",
		"https://rekor.sigstore.dev",
		false,
	)
	if err != nil {
		t.Fatalf("buildVerificationVerifiers: %v", err)
	}
	if len(verifiers) != 1 {
		t.Fatalf("expected one Sigstore verifier, got %d", len(verifiers))
	}
	if verifiers[0].KeyID() != "sigstore-keyless" {
		t.Fatalf("expected sigstore-keyless verifier, got %q", verifiers[0].KeyID())
	}
}

func TestVerifyRecordCmdSigstoreStrictPassesWithRekorRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"uuid": "entry-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/log/entries/entry-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := signer.DefaultSigstoreConfig()
	cfg.RekorURL = ts.URL
	cfg.RequireRekor = true
	sigstoreSigner := signer.NewSigstoreSigner(cfg)

	payload := mustBuildStrictRecordPayload(t)
	env, err := signer.SignEnvelope(context.Background(), payload, sigstoreSigner)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	envPath := writeEnvelopeFile(t, env)

	cmd := newVerifyRecordCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		envPath,
		"--profile", "strict",
		"--sigstore-verify",
		"--sigstore-rekor-required",
		"--sigstore-rekor-url", ts.URL,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify record command failed: %v", err)
	}
}

func TestVerifyRecordCmdSigstoreStrictFailsWithInvalidRekorEntry(t *testing.T) {
	signTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"uuid": "entry-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/log/entries/entry-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer signTS.Close()

	verifyTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer verifyTS.Close()

	cfg := signer.DefaultSigstoreConfig()
	cfg.RekorURL = signTS.URL
	cfg.RequireRekor = true
	sigstoreSigner := signer.NewSigstoreSigner(cfg)

	payload := mustBuildStrictRecordPayload(t)
	env, err := signer.SignEnvelope(context.Background(), payload, sigstoreSigner)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	envPath := writeEnvelopeFile(t, env)

	cmd := newVerifyRecordCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		envPath,
		"--profile", "strict",
		"--sigstore-verify",
		"--sigstore-rekor-required",
		"--sigstore-rekor-url", verifyTS.URL,
	})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected strict Sigstore verification failure")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected deterministic verification failure, got %v", err)
	}
}

func mustBuildStrictRecordPayload(t *testing.T) []byte {
	t.Helper()

	rec := record.New()
	rec.Identity.TenantID = "tenant-a"
	rec.Identity.Subject = "svc-a"
	rec.Identity.SubjectType = "service"
	rec.Model.Provider = "openai"
	rec.Model.Name = "gpt-4o"
	rec.PromptContext.UserPromptHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rec.PolicyContext.PolicyDecision = record.PolicyAllow
	rec.PolicyContext.PolicyBundleID = "bundle/v1"
	rec.PolicyContext.PolicyHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rec.PolicyContext.DecisionReasonCode = "policy_allow"
	rec.Output.OutputHash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	rec.Output.Mode = record.OutputModeHashOnly
	rec.Integrity.PreviousRecordHash = vaolcrypto.ZeroHash

	hash, err := record.ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("compute record hash: %v", err)
	}
	rec.Integrity.RecordHash = hash

	tree := merkle.New()
	leaf := tree.Append([]byte(hash))
	rec.Integrity.MerkleTreeSize = tree.Size()
	rec.Integrity.MerkleRoot = tree.Root()
	proof, err := tree.InclusionProof(leaf, tree.Size())
	if err != nil {
		t.Fatalf("build inclusion proof: %v", err)
	}
	rec.Integrity.InclusionProof = &record.InclusionProof{
		LeafIndex: proof.LeafIndex,
		Hashes:    proof.Hashes,
	}
	rec.Integrity.InclusionProofRef = "/v1/proofs/proof:" + rec.RequestID.String()

	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record payload: %v", err)
	}
	return payload
}

func writeEnvelopeFile(t *testing.T, env *signer.Envelope) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "envelope.json")
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	return path
}
