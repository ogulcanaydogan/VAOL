package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ogulcanaydogan/vaol/pkg/api"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/policy"
	"github.com/ogulcanaydogan/vaol/pkg/record"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

type proofFailStore struct {
	*store.MemoryStore
}

func (s *proofFailStore) SaveProof(_ context.Context, _ *store.StoredProof) error {
	return fmt.Errorf("saving proof: foreign key violation")
}

// newTestServer sets up a VAOL API server backed by in-memory store + ed25519 signer.
func newTestServer(t *testing.T) (*httptest.Server, *store.MemoryStore, *signer.Ed25519Signer) {
	t.Helper()

	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	logger := slog.Default()
	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, logger)
	ts := httptest.NewServer(srv.Handler())
	return ts, ms, sig
}

// mustPost is a test helper that performs a POST and fatals on error.
func mustPost(t *testing.T, url, contentType string, body []byte) *http.Response {
	t.Helper()
	return mustPostWithHeaders(t, url, contentType, body, map[string]string{
		"X-VAOL-Tenant-ID": "test-tenant",
	})
}

// mustPostWithHeaders is a test helper that performs a POST with custom headers.
func mustPostWithHeaders(t *testing.T, url, contentType string, body []byte, headers map[string]string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new POST request %s: %v", url, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// mustGet is a test helper that performs a GET and fatals on error.
func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	return mustGetWithHeaders(t, url, map[string]string{
		"X-VAOL-Tenant-ID": "test-tenant",
	})
}

// mustGetWithHeaders is a test helper that performs a GET with custom headers.
func mustGetWithHeaders(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new GET request %s: %v", url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func decodeJSON(t *testing.T, r io.Reader, v any) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

// validRecordJSON returns a minimal valid DecisionRecord JSON body.
func validRecordJSON(t *testing.T) []byte {
	t.Helper()
	rec := map[string]any{
		"schema_version": "v1",
		"request_id":     uuid.New().String(),
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"identity": map[string]any{
			"tenant_id": "test-tenant",
			"subject":   "test-user",
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
		t.Fatalf("marshaling record: %v", err)
	}
	return data
}

func writeRevocationsFile(t *testing.T, keyID, effectiveAt string) string {
	t.Helper()

	payload := map[string]any{
		"version":      "v1",
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"revocations": []map[string]any{
			{
				"keyid":        keyID,
				"effective_at": effectiveAt,
				"reason":       "compromised",
			},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal revocations: %v", err)
	}

	path := t.TempDir() + "/revocations.json"
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write revocations file: %v", err)
	}
	return path
}

func TestAppendRecord(t *testing.T) {
	ts, ms, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]string
		decodeJSON(t, resp.Body, &errBody)
		t.Fatalf("expected 201 Created, got %d: %v", resp.StatusCode, errBody)
	}

	var receipt record.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		t.Fatalf("decoding receipt: %v", err)
	}

	if receipt.RequestID == uuid.Nil {
		t.Error("receipt.request_id is nil")
	}
	if receipt.RecordHash == "" {
		t.Error("receipt.record_hash is empty")
	}
	if receipt.MerkleRoot == "" {
		t.Error("receipt.merkle_root is empty")
	}

	count, _ := ms.Count(context.Background())
	if count != 1 {
		t.Errorf("expected 1 record in store, got %d", count)
	}

	if resp.Header.Get("X-VAOL-Record-ID") == "" {
		t.Error("missing X-VAOL-Record-ID header")
	}
	if resp.Header.Get("X-VAOL-Sequence") == "" {
		t.Error("missing X-VAOL-Sequence header")
	}
}

func TestAppendRecord_InvalidBody(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	resp := mustPost(t, ts.URL+"/v1/records", "application/json", []byte("not json"))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAppendRecord_DuplicateRequestID(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)

	resp1 := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first append: expected 201, got %d", resp1.StatusCode)
	}

	resp2 := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate append: expected 409, got %d", resp2.StatusCode)
	}
}

func TestGetRecord(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String())
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	var stored store.StoredRecord
	if err := json.NewDecoder(resp2.Body).Decode(&stored); err != nil {
		t.Fatalf("decoding stored record: %v", err)
	}
	if stored.RequestID != receipt.RequestID {
		t.Errorf("request_id mismatch: got %s, want %s", stored.RequestID, receipt.RequestID)
	}
}

func TestGetRecord_NotFound(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	resp := mustGet(t, ts.URL+"/v1/records/"+uuid.New().String())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetRecord_TenantMismatch(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	resp.Body.Close()

	resp2 := mustGetWithHeaders(t, ts.URL+"/v1/records/"+receipt.RequestID.String(), map[string]string{
		"X-VAOL-Tenant-ID": "other-tenant",
	})
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp2.StatusCode)
	}
}

func TestGetRecord_InvalidID(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	resp := mustGet(t, ts.URL+"/v1/records/not-a-uuid")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestListRecords(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		body := validRecordJSON(t)
		r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		r.Body.Close()
	}

	resp := mustGet(t, ts.URL+"/v1/records?limit=10")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Records []json.RawMessage `json:"records"`
		Count   int               `json:"count"`
	}
	decodeJSON(t, resp.Body, &result)
	if result.Count != 3 {
		t.Errorf("expected 3 records, got %d", result.Count)
	}
}

func TestListRecords_MissingTenantContext(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	r.Body.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/records?limit=10", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/records: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestListRecords_WithTenantFilter(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	for i := 0; i < 2; i++ {
		body := validRecordJSON(t)
		r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		r.Body.Close()
	}

	resp := mustGet(t, ts.URL+"/v1/records?tenant_id=test-tenant&limit=10")
	defer resp.Body.Close()

	var result struct {
		Records []json.RawMessage `json:"records"`
		Count   int               `json:"count"`
	}
	decodeJSON(t, resp.Body, &result)
	if result.Count != 2 {
		t.Errorf("expected 2 records for test-tenant, got %d", result.Count)
	}

	resp2 := mustGetWithHeaders(t, ts.URL+"/v1/records?tenant_id=no-such-tenant", map[string]string{
		"X-VAOL-Tenant-ID": "no-such-tenant",
	})
	defer resp2.Body.Close()
	var result2 struct {
		Count int `json:"count"`
	}
	decodeJSON(t, resp2.Body, &result2)
	if result2.Count != 0 {
		t.Errorf("expected 0 records for non-existent tenant, got %d", result2.Count)
	}
}

func TestAppendRecord_ConflictingTenantHeaders(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPostWithHeaders(t, ts.URL+"/v1/records", "application/json", body, map[string]string{
		"X-VAOL-Tenant-ID": "tenant-a",
		"X-Tenant-ID":      "tenant-b",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var deny map[string]any
	decodeJSON(t, resp.Body, &deny)
	decision, _ := deny["decision"].(map[string]any)
	if decision["decision_reason_code"] != "tenant_context_conflict" {
		t.Fatalf("expected tenant_context_conflict, got %v", decision["decision_reason_code"])
	}
}

func TestListRecords_ConflictingTenantHeaders(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	r.Body.Close()

	resp := mustGetWithHeaders(t, ts.URL+"/v1/records?limit=10", map[string]string{
		"X-VAOL-Tenant-ID": "tenant-a",
		"X-Tenant-ID":      "tenant-b",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestGetProof(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String()+"/proof")
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	var proof merkle.Proof
	decodeJSON(t, resp2.Body, &proof)
	if proof.ProofType != merkle.ProofTypeInclusion {
		t.Errorf("expected inclusion proof, got %s", proof.ProofType)
	}
}

func TestGetProofByID(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	if receipt.InclusionProofRef == "" {
		t.Fatal("expected inclusion_proof_ref in receipt")
	}

	resp2 := mustGet(t, ts.URL+receipt.InclusionProofRef)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

func TestAppendRecord_ProofPersistFailureDoesNotFailAppend(t *testing.T) {
	fs := &proofFailStore{MemoryStore: store.NewMemoryStore()}
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	srv := api.NewServer(api.DefaultConfig(), fs, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 even when proof persistence fails, got %d", resp.StatusCode)
	}

	var receipt record.Receipt
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		t.Fatalf("decoding receipt: %v", err)
	}
	if receipt.InclusionProofRef == "" {
		t.Fatal("expected inclusion_proof_ref in receipt")
	}

	// /v1/proofs/{id} should fall back to proof reconstruction when proof index
	// persistence fails (e.g., FK constraint violation in SQL backends).
	resp2 := mustGet(t, ts.URL+receipt.InclusionProofRef)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from proof fallback, got %d", resp2.StatusCode)
	}
}

func TestVerifyRecord(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String())
	var stored store.StoredRecord
	decodeJSON(t, resp2.Body, &stored)
	resp2.Body.Close()

	envJSON, _ := json.Marshal(stored.Envelope)
	resp3 := mustPost(t, ts.URL+"/v1/verify", "application/json", envJSON)
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp3.StatusCode)
	}

	var result map[string]any
	decodeJSON(t, resp3.Body, &result)
	if result["valid"] != true {
		t.Errorf("expected valid=true, got %v", result["valid"])
	}
}

func TestVerifyRecordRevokedByServerRevocationPolicy(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.RebuildOnStart = false
	cfg.VerificationRevocationsFile = writeRevocationsFile(t, sig.KeyID(), "2000-01-01T00:00:00Z")

	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String())
	var stored store.StoredRecord
	decodeJSON(t, resp2.Body, &stored)
	resp2.Body.Close()

	envJSON, _ := json.Marshal(stored.Envelope)
	resp3 := mustPost(t, ts.URL+"/v1/verify", "application/json", envJSON)
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp3.StatusCode)
	}

	var result map[string]any
	decodeJSON(t, resp3.Body, &result)
	if result["valid"] != false {
		t.Fatalf("expected valid=false when signer key is revoked, got %v", result["valid"])
	}

	checks, ok := result["checks"].([]any)
	if !ok {
		t.Fatalf("checks has unexpected type %T", result["checks"])
	}
	found := false
	for _, item := range checks {
		check, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if check["name"] == "key_revocation" {
			found = true
			if check["passed"] != false {
				t.Fatalf("expected key_revocation check to fail, got %+v", check)
			}
		}
	}
	if !found {
		t.Fatal("expected key_revocation check in verification response")
	}
}

func TestVerifyRecordWrappedRequestWithProfile(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String())
	var stored store.StoredRecord
	decodeJSON(t, resp2.Body, &stored)
	resp2.Body.Close()

	verifyReq := map[string]any{
		"envelope":             stored.Envelope,
		"verification_profile": "strict",
	}
	verifyBody, _ := json.Marshal(verifyReq)
	resp3 := mustPost(t, ts.URL+"/v1/verify", "application/json", verifyBody)
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp3.StatusCode)
	}

	var result map[string]any
	decodeJSON(t, resp3.Body, &result)
	if result["valid"] != false {
		t.Fatalf("expected strict verification to fail, got %v", result["valid"])
	}
	checks, ok := result["checks"].([]any)
	if !ok {
		t.Fatalf("checks has unexpected type %T", result["checks"])
	}
	foundStrictCheck := false
	for _, item := range checks {
		check, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if check["name"] == "profile_strict" {
			foundStrictCheck = true
			if check["passed"] != false {
				t.Fatalf("expected strict check to fail, got %+v", check)
			}
		}
	}
	if !foundStrictCheck {
		t.Fatal("expected profile_strict check in verification result")
	}
}

func TestVerifyRecordRejectsInvalidProfile(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String())
	var stored store.StoredRecord
	decodeJSON(t, resp2.Body, &stored)
	resp2.Body.Close()

	verifyReq := map[string]any{
		"envelope":             stored.Envelope,
		"verification_profile": "ultra",
	}
	verifyBody, _ := json.Marshal(verifyReq)
	resp3 := mustPost(t, ts.URL+"/v1/verify", "application/json", verifyBody)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp3.StatusCode)
	}
}

func TestVerifyRecordRejectsConflictingProfileInputs(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	var receipt record.Receipt
	decodeJSON(t, resp.Body, &receipt)
	resp.Body.Close()

	resp2 := mustGet(t, ts.URL+"/v1/records/"+receipt.RequestID.String())
	var stored store.StoredRecord
	decodeJSON(t, resp2.Body, &stored)
	resp2.Body.Close()

	verifyReq := map[string]any{
		"envelope":             stored.Envelope,
		"verification_profile": "strict",
	}
	verifyBody, _ := json.Marshal(verifyReq)
	resp3 := mustPost(t, ts.URL+"/v1/verify?profile=basic", "application/json", verifyBody)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp3.StatusCode)
	}
}

func TestVerifyRecordStrictOnlineRekorRejectsPayloadHashMismatch(t *testing.T) {
	rekorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/log/entries/entry-1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entry-1": map[string]any{
				"spec": map[string]any{
					"payload_hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				},
			},
		})
	}))
	defer rekorServer.Close()

	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.VerifyStrictOnlineRekor = true
	cfg.VerifyRekorURL = rekorServer.URL
	cfg.VerifyRekorTimeout = 2 * time.Second

	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	rec := record.New()
	rec.Identity.TenantID = "test-tenant"
	rec.Identity.Subject = "test-user"
	rec.Model.Provider = "openai"
	rec.Model.Name = "gpt-4o"
	rec.PromptContext.UserPromptHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rec.PolicyContext.PolicyDecision = record.PolicyAllow
	rec.PolicyContext.PolicyBundleID = "bundle/v1"
	rec.PolicyContext.PolicyHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rec.PolicyContext.DecisionReasonCode = "policy_allow"
	rec.Output.OutputHash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	rec.Output.Mode = record.OutputModeHashOnly
	rec.Integrity.PreviousRecordHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	recordHash, err := record.ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("ComputeRecordHash error: %v", err)
	}
	rec.Integrity.RecordHash = recordHash

	leaf := tree.Append([]byte(recordHash))
	rec.Integrity.MerkleTreeSize = tree.Size()
	rec.Integrity.MerkleRoot = tree.Root()
	proof, err := tree.InclusionProof(leaf, tree.Size())
	if err != nil {
		t.Fatalf("InclusionProof error: %v", err)
	}
	rec.Integrity.InclusionProof = &record.InclusionProof{
		LeafIndex: proof.LeafIndex,
		Hashes:    proof.Hashes,
	}
	rec.Integrity.InclusionProofRef = "/v1/proofs/proof:" + rec.RequestID.String()

	fullPayload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	env, err := signer.SignEnvelope(context.Background(), fullPayload, sig)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	env.Signatures[0].KeyID = "fulcio:https://oauth2.sigstore.dev/auth::svc-a"
	env.Signatures[0].Cert = "mock-cert"
	env.Signatures[0].RekorEntryID = "entry-1"

	verifyReq := map[string]any{
		"envelope": env,
	}
	verifyBody, _ := json.Marshal(verifyReq)
	resp := mustPost(t, ts.URL+"/v1/verify?profile=strict", "application/json", verifyBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	decodeJSON(t, resp.Body, &result)
	if result["valid"] != false {
		t.Fatalf("expected strict verification failure, got %v", result["valid"])
	}
	checks, ok := result["checks"].([]any)
	if !ok {
		t.Fatalf("checks has unexpected type %T", result["checks"])
	}
	found := false
	for _, c := range checks {
		check, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if check["name"] == "profile_strict" {
			if msg, _ := check["error"].(string); strings.Contains(msg, "strict profile rekor verification failed:") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected strict profile rekor verification failure, checks=%+v", checks)
	}
}

func TestCheckpoint(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	r.Body.Close()

	resp := mustGet(t, ts.URL+"/v1/ledger/checkpoint")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var cp map[string]any
	decodeJSON(t, resp.Body, &cp)
	if cp["tree_size"].(float64) < 1 {
		t.Error("tree_size should be >= 1 after appending a record")
	}
	if cp["root_hash"] == "" {
		t.Error("root_hash should not be empty")
	}
}

func TestConsistencyProof(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	for i := 0; i < 4; i++ {
		body := validRecordJSON(t)
		r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		r.Body.Close()
	}

	resp := mustGet(t, ts.URL+"/v1/ledger/consistency?from=2&to=4")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var proof merkle.Proof
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		t.Fatalf("decode consistency proof: %v", err)
	}
	if proof.ProofType != merkle.ProofTypeConsistency {
		t.Fatalf("expected consistency proof, got %s", proof.ProofType)
	}
}

func TestExport(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		body := validRecordJSON(t)
		r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		r.Body.Close()
	}

	exportReq := map[string]any{
		"tenant_id": "test-tenant",
		"limit":     10,
	}
	exportBody, _ := json.Marshal(exportReq)
	resp := mustPost(t, ts.URL+"/v1/export", "application/json", exportBody)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var bundle map[string]any
	decodeJSON(t, resp.Body, &bundle)
	records := bundle["records"].([]any)
	if len(records) != 3 {
		t.Errorf("expected 3 records in export, got %d", len(records))
	}
}

func TestExport_MissingTenantContext(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	body := validRecordJSON(t)
	r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	r.Body.Close()

	exportReq := map[string]any{
		"tenant_id": "test-tenant",
		"limit":     10,
	}
	exportBody, _ := json.Marshal(exportReq)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/export", bytes.NewReader(exportBody))
	if err != nil {
		t.Fatalf("new export request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/export: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestVerifyBundle(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	for i := 0; i < 3; i++ {
		body := validRecordJSON(t)
		r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		r.Body.Close()
	}

	exportReq := map[string]any{
		"tenant_id": "test-tenant",
		"limit":     10,
	}
	exportBody, _ := json.Marshal(exportReq)
	exportResp := mustPost(t, ts.URL+"/v1/export", "application/json", exportBody)
	defer exportResp.Body.Close()

	var bundle map[string]any
	if err := json.NewDecoder(exportResp.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode export bundle: %v", err)
	}

	verifyBody, _ := json.Marshal(bundle)
	verifyResp := mustPost(t, ts.URL+"/v1/verify/bundle", "application/json", verifyBody)
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", verifyResp.StatusCode)
	}

	var verifyResult map[string]any
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
		t.Fatalf("decode verify result: %v", err)
	}

	if verifyResult["summary"] != "VERIFICATION PASSED" {
		t.Fatalf("expected VERIFICATION PASSED, got %v", verifyResult["summary"])
	}
}

func TestVerifyBundleRevokedByServerRevocationPolicy(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := api.DefaultConfig()
	cfg.RebuildOnStart = false
	cfg.VerificationRevocationsFile = writeRevocationsFile(t, sig.KeyID(), "2000-01-01T00:00:00Z")

	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := validRecordJSON(t)
	r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	r.Body.Close()

	exportReq := map[string]any{
		"tenant_id": "test-tenant",
		"limit":     10,
	}
	exportBody, _ := json.Marshal(exportReq)
	exportResp := mustPost(t, ts.URL+"/v1/export", "application/json", exportBody)
	defer exportResp.Body.Close()

	var bundle map[string]any
	if err := json.NewDecoder(exportResp.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode export bundle: %v", err)
	}

	verifyBody, _ := json.Marshal(bundle)
	verifyResp := mustPost(t, ts.URL+"/v1/verify/bundle", "application/json", verifyBody)
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", verifyResp.StatusCode)
	}

	var verifyResult map[string]any
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
		t.Fatalf("decode verify result: %v", err)
	}

	if verifyResult["summary"] != "VERIFICATION FAILED" {
		t.Fatalf("expected VERIFICATION FAILED, got %v", verifyResult["summary"])
	}
	if verifyResult["signatures_valid"] != false {
		t.Fatalf("expected signatures_valid=false, got %v", verifyResult["signatures_valid"])
	}
}

func TestVerifyBundleWrappedRequestWithProfile(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	for i := 0; i < 2; i++ {
		body := validRecordJSON(t)
		r := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		r.Body.Close()
	}

	exportReq := map[string]any{
		"tenant_id": "test-tenant",
		"limit":     10,
	}
	exportBody, _ := json.Marshal(exportReq)
	exportResp := mustPost(t, ts.URL+"/v1/export", "application/json", exportBody)
	defer exportResp.Body.Close()

	var bundle map[string]any
	if err := json.NewDecoder(exportResp.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode export bundle: %v", err)
	}

	verifyReq := map[string]any{
		"bundle":               bundle,
		"verification_profile": "basic",
	}
	verifyBody, _ := json.Marshal(verifyReq)
	verifyResp := mustPost(t, ts.URL+"/v1/verify/bundle", "application/json", verifyBody)
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", verifyResp.StatusCode)
	}

	var verifyResult map[string]any
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
		t.Fatalf("decode verify result: %v", err)
	}
	if verifyResult["summary"] != "VERIFICATION PASSED" {
		t.Fatalf("expected VERIFICATION PASSED, got %v", verifyResult["summary"])
	}
}

func TestHealth(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	resp := mustGet(t, ts.URL+"/v1/health")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var health map[string]any
	decodeJSON(t, resp.Body, &health)
	if health["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", health["status"])
	}
}

func TestCORSHeaders(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	resp := mustGet(t, ts.URL+"/v1/health")
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS Allow-Origin header")
	}
	if resp.Header.Get("X-VAOL-Version") == "" {
		t.Error("missing X-VAOL-Version header")
	}
}

func TestOptionsPreFlight(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/v1/records", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS, got %d", resp.StatusCode)
	}
}

func TestAppendRecord_WithPolicyDeny(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	denyEngine := &denyAllEngine{}
	logger := slog.Default()
	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, denyEngine, logger)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden with deny policy, got %d", resp.StatusCode)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()

	var receipts []record.Receipt
	for i := 0; i < 5; i++ {
		body := validRecordJSON(t)
		resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
		var receipt record.Receipt
		decodeJSON(t, resp.Body, &receipt)
		resp.Body.Close()
		receipts = append(receipts, receipt)
	}

	for _, r := range receipts {
		resp := mustGet(t, ts.URL+"/v1/records/"+r.RequestID.String())
		var stored store.StoredRecord
		decodeJSON(t, resp.Body, &stored)
		resp.Body.Close()

		envJSON, _ := json.Marshal(stored.Envelope)
		vResp := mustPost(t, ts.URL+"/v1/verify", "application/json", envJSON)
		var result map[string]any
		decodeJSON(t, vResp.Body, &result)
		vResp.Body.Close()

		if result["valid"] != true {
			t.Errorf("record %s: expected valid=true, got %v", r.RequestID, result["valid"])
		}
	}
}

// denyAllEngine is a test policy engine that denies all requests.
type denyAllEngine struct{}

func (e *denyAllEngine) Evaluate(_ context.Context, _ *policy.Input) (*policy.Decision, error) {
	return &policy.Decision{
		Allow:    false,
		Decision: "deny",
		RuleIDs:  []string{"test_deny_all"},
		Reason:   "test: deny all",
	}, nil
}

func (e *denyAllEngine) PolicyHash() string {
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
func (e *denyAllEngine) PolicyBundleID() string { return "test-bundle" }
func (e *denyAllEngine) Version() string        { return "test/1.0" }

// allowAllEngine is a test policy engine that allows all requests.
type allowAllEngine struct{}

func (e *allowAllEngine) Evaluate(_ context.Context, _ *policy.Input) (*policy.Decision, error) {
	return &policy.Decision{
		Allow:    true,
		Decision: "allow",
		RuleIDs:  []string{"test_allow_all"},
	}, nil
}

func (e *allowAllEngine) PolicyHash() string {
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
func (e *allowAllEngine) PolicyBundleID() string { return "test-bundle" }
func (e *allowAllEngine) Version() string        { return "test/1.0" }

// failingEngine is a test policy engine that always returns an error.
type failingEngine struct{}

func (e *failingEngine) Evaluate(_ context.Context, _ *policy.Input) (*policy.Decision, error) {
	return nil, fmt.Errorf("policy engine unavailable")
}

func (e *failingEngine) PolicyHash() string     { return "" }
func (e *failingEngine) PolicyBundleID() string { return "" }
func (e *failingEngine) Version() string        { return "test-failing/1.0" }

func TestAppendRecord_WithPolicyAllow(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	srv := api.NewServer(api.DefaultConfig(), ms, sig, []signer.Verifier{ver}, tree, &allowAllEngine{}, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 with allow policy, got %d", resp.StatusCode)
	}
}

func TestAppendRecord_PolicyEngineError(t *testing.T) {
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	srv := api.NewServer(api.DefaultConfig(), ms, sig, []signer.Verifier{ver}, tree, &failingEngine{}, slog.Default())
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body := validRecordJSON(t)
	resp := mustPost(t, ts.URL+"/v1/records", "application/json", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 with failing policy engine, got %d", resp.StatusCode)
	}
}
