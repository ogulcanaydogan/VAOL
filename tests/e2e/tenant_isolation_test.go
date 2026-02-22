package e2e

import (
	"bytes"
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
	"github.com/ogulcanaydogan/vaol/pkg/api"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

func TestTenantIsolationAcrossAuthenticatedTokens(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.AuthMode = "required"
	cfg.JWTHS256Secret = "tenant-secret"
	cfg.JWTIssuer = "https://issuer.example"
	cfg.JWTAudience = "vaol-api"
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tokenA := mustTenantToken(t, "tenant-a", "svc-a", "tenant-secret")
	tokenB := mustTenantToken(t, "tenant-b", "svc-b", "tenant-secret")

	body := tenantRecordJSON(t, "tenant-a", "svc-a")
	appendReq, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/records", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new append request: %v", err)
	}
	appendReq.Header.Set("Authorization", "Bearer "+tokenA)
	appendReq.Header.Set("Content-Type", "application/json")
	appendResp, err := http.DefaultClient.Do(appendReq)
	if err != nil {
		t.Fatalf("append request failed: %v", err)
	}
	defer appendResp.Body.Close()
	if appendResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", appendResp.StatusCode)
	}

	var receipt struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(appendResp.Body).Decode(&receipt); err != nil {
		t.Fatalf("decode append receipt: %v", err)
	}

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/records/"+receipt.RequestID, nil)
	getReq.Header.Set("Authorization", "Bearer "+tokenB)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("cross-tenant get failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected cross-tenant get 403, got %d", getResp.StatusCode)
	}

	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/records?tenant_id=tenant-a&limit=10", nil)
	listReq.Header.Set("Authorization", "Bearer "+tokenB)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("cross-tenant list failed: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected cross-tenant filtered list 403, got %d", listResp.StatusCode)
	}

	safeListReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/records?limit=10", nil)
	safeListReq.Header.Set("Authorization", "Bearer "+tokenB)
	safeListResp, err := http.DefaultClient.Do(safeListReq)
	if err != nil {
		t.Fatalf("tenant-b list failed: %v", err)
	}
	defer safeListResp.Body.Close()
	if safeListResp.StatusCode != http.StatusOK {
		t.Fatalf("expected tenant-b list 200, got %d", safeListResp.StatusCode)
	}
	var listBody struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(safeListResp.Body).Decode(&listBody); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listBody.Count != 0 {
		t.Fatalf("expected tenant-b list count=0, got %d", listBody.Count)
	}

	exportReqBody := []byte(`{"tenant_id":"tenant-a","limit":10}`)
	exportReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/export", bytes.NewReader(exportReqBody))
	exportReq.Header.Set("Authorization", "Bearer "+tokenB)
	exportReq.Header.Set("Content-Type", "application/json")
	exportResp, err := http.DefaultClient.Do(exportReq)
	if err != nil {
		t.Fatalf("cross-tenant export failed: %v", err)
	}
	defer exportResp.Body.Close()
	if exportResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected cross-tenant export 403, got %d", exportResp.StatusCode)
	}
}

func mustTenantToken(t *testing.T, tenantID, subject, secret string) string {
	t.Helper()
	claims := map[string]any{
		"iss":       "https://issuer.example",
		"aud":       "vaol-api",
		"sub":       subject,
		"tenant_id": tenantID,
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}
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
	signature := mac.Sum(nil)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func tenantRecordJSON(t *testing.T, tenantID string, subject string) []byte {
	t.Helper()
	rec := map[string]any{
		"schema_version": "v1",
		"request_id":     uuid.NewString(),
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"identity": map[string]any{
			"tenant_id": tenantID,
			"subject":   subject,
		},
		"model": map[string]any{
			"provider": "openai",
			"name":     "gpt-4o",
		},
		"parameters": map[string]any{},
		"prompt_context": map[string]any{
			"user_prompt_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		"policy_context": map[string]any{
			"policy_decision": "allow",
		},
		"output": map[string]any{
			"output_hash": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			"mode":        "hash_only",
		},
		"trace":     map[string]any{},
		"integrity": map[string]any{},
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal tenant record: %v", err)
	}
	return data
}
