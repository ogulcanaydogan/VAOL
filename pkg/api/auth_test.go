package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/yapay-ai/vaol/pkg/api"
	vaolcrypto "github.com/yapay-ai/vaol/pkg/crypto"
	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/signer"
	"github.com/yapay-ai/vaol/pkg/store"
)

func TestAuthRequired_DeniesMissingToken(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, _ := signer.GenerateEd25519Signer()
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.AuthMode = "required"
	cfg.JWTHS256Secret = "test-secret"
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/records", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthRequired_AllowsValidTokenAndInjectsTenant(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, _ := signer.GenerateEd25519Signer()
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.AuthMode = "required"
	cfg.JWTHS256Secret = "test-secret"
	cfg.JWTIssuer = "https://issuer.example"
	cfg.JWTAudience = "vaol-api"
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	token := mustHS256Token(t, map[string]any{
		"iss":       "https://issuer.example",
		"aud":       "vaol-api",
		"sub":       "test-user",
		"tenant_id": "test-tenant",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}, "test-secret")

	body := validRecordJSON(t)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/records", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new append request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("append request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	listReq, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/records?limit=10", nil)
	if err != nil {
		t.Fatalf("new list request: %v", err)
	}
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from list, got %d", listResp.StatusCode)
	}

	var listBody struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listBody); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listBody.Count != 1 {
		t.Fatalf("expected 1 record, got %d", listBody.Count)
	}
}

func mustHS256Token(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()

	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestServerRebuildMerkleTreeFromStore(t *testing.T) {
	ctx := context.Background()
	ms := store.NewMemoryStore()

	// Seed store with two records.
	for i := 0; i < 2; i++ {
		rec := makeTestStoredRecordForAuthTests(t)
		rec.RecordHash = mustHashString(t, "record-"+time.Now().UTC().String()+string(rune('a'+i)))
		rec.MerkleLeafIndex = int64(i)
		if _, err := ms.Append(ctx, rec); err != nil {
			t.Fatalf("append seed: %v", err)
		}
	}

	sig, _ := signer.GenerateEd25519Signer()
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := mustGet(t, ts.URL+"/v1/health")
	defer resp.Body.Close()
	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["tree_size"].(float64) != 2 {
		t.Fatalf("expected rebuilt tree_size=2, got %v", health["tree_size"])
	}
}

func TestServerStartupErrorOnCheckpointMismatch(t *testing.T) {
	ctx := context.Background()
	ms := store.NewMemoryStore()

	rec := makeTestStoredRecordForAuthTests(t)
	rec.RecordHash = mustHashString(t, "checkpoint-mismatch-record")
	rec.MerkleLeafIndex = 0
	if _, err := ms.Append(ctx, rec); err != nil {
		t.Fatalf("append seed: %v", err)
	}

	if err := ms.SaveCheckpoint(ctx, &store.StoredCheckpoint{
		TreeSize: 1,
		RootHash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		Checkpoint: &merkle.Checkpoint{
			TreeSize: 1,
			RootHash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
	}); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}

	sig, _ := signer.GenerateEd25519Signer()
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.FailOnStartupCheck = true
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if srv.StartupError() == nil {
		t.Fatal("expected startup error for checkpoint mismatch, got nil")
	}
}

func makeTestStoredRecordForAuthTests(t *testing.T) *store.StoredRecord {
	t.Helper()
	s, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	env, err := signer.SignEnvelope(context.Background(), []byte(`{"test":"record"}`), s)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	return &store.StoredRecord{
		RequestID:          mustUUID(t),
		TenantID:           "test-tenant",
		Timestamp:          time.Now().UTC(),
		RecordHash:         "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		PreviousRecordHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Envelope:           env,
	}
}

func mustUUID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("uuid.NewRandom: %v", err)
	}
	return id
}

func mustHashString(t *testing.T, s string) string {
	t.Helper()
	return vaolcrypto.SHA256Prefixed([]byte(s))
}
