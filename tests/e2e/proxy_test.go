package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/yapay-ai/vaol/pkg/api"
	vaolcrypto "github.com/yapay-ai/vaol/pkg/crypto"
	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/record"
	"github.com/yapay-ai/vaol/pkg/signer"
	"github.com/yapay-ai/vaol/pkg/store"
)

// proxyHandler implements the proxy logic from cmd/vaol-proxy for testing.
type proxyHandler struct {
	upstream   *url.URL
	vaolServer string
	tenantID   string
	client     *http.Client
	logger     *slog.Logger
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.New()

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}

	proxyURL := *p.upstream
	proxyURL.Path = r.URL.Path
	proxyURL.RawQuery = r.URL.RawQuery

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, proxyURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "failed to create proxy request", http.StatusBadGateway)
		return
	}
	for key, values := range r.Header {
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	proxyReq.Header.Del("Host")

	resp, err := p.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	latency := time.Since(start)

	w.Header().Set("X-VAOL-Record-ID", requestID.String())
	w.Header().Set("X-VAOL-Proxy", "true")

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(respBody); err != nil {
		p.logger.Error("failed to write proxy response", "error", err)
		return
	}

	// Synchronous emission for test determinism
	p.emitRecord(requestID, reqBody, respBody, latency)
}

func (p *proxyHandler) emitRecord(requestID uuid.UUID, reqBody, respBody []byte, latency time.Duration) {
	var chatReq struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(reqBody, &chatReq); err != nil {
		p.logger.Warn("failed to parse chat request body", "error", err)
	}

	rec := record.New()
	rec.RequestID = requestID
	rec.Identity.TenantID = p.tenantID
	rec.Identity.Subject = "vaol-proxy"
	rec.Identity.SubjectType = "service"
	rec.Model.Provider = p.upstream.Host
	rec.Model.Name = chatReq.Model
	rec.Model.Endpoint = p.upstream.String()
	rec.PromptContext.UserPromptHash = vaolcrypto.SHA256Prefixed(reqBody)
	rec.Output.OutputHash = vaolcrypto.SHA256Prefixed(respBody)
	rec.Output.Mode = record.OutputModeHashOnly
	rec.Output.LatencyMs = float64(latency.Milliseconds())
	rec.PolicyContext.PolicyDecision = record.PolicyLogOnly

	recJSON, _ := json.Marshal(rec)
	req, err := http.NewRequest(http.MethodPost, p.vaolServer+"/v1/records", bytes.NewReader(recJSON))
	if err != nil {
		p.logger.Error("failed to build VAOL request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VAOL-Tenant-ID", p.tenantID)
	req.Header.Set("X-Auth-Source", "proxy-test")
	req.Header.Set("X-Auth-Subject", "vaol-proxy")

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Error("failed to emit record", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		p.logger.Error("VAOL server rejected record", "status", resp.StatusCode, "body", string(body))
	}
}

func TestProxyIntegration(t *testing.T) {
	// 1. Set up a mock OpenAI upstream that returns a canned chat completion
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "not found", 404)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request", http.StatusBadRequest)
			return
		}
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid request JSON", http.StatusBadRequest)
			return
		}

		response := map[string]any{
			"id":      "chatcmpl-test123",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   req["model"],
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Hello! How can I help you today?",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 8,
				"total_tokens":      18,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Logf("failed to encode response: %v", err)
		}
	}))
	defer mockUpstream.Close()

	// 2. Set up a real VAOL server
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())
	logger := slog.Default()
	vaolSrv := api.NewServer(api.DefaultConfig(), ms, sig, []signer.Verifier{ver}, tree, nil, logger)
	vaolTS := httptest.NewServer(vaolSrv.Handler())
	defer vaolTS.Close()

	// 3. Set up the proxy
	upstreamURL, _ := url.Parse(mockUpstream.URL)
	proxy := &proxyHandler{
		upstream:   upstreamURL,
		vaolServer: vaolTS.URL,
		tenantID:   "proxy-test-tenant",
		client:     &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
	proxyTS := httptest.NewServer(proxy)
	defer proxyTS.Close()

	// 4. Send a chat completion request through the proxy
	chatReq := map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello!"},
		},
	}
	chatBody, _ := json.Marshal(chatReq)

	resp, err := http.Post(proxyTS.URL+"/v1/chat/completions", "application/json", bytes.NewReader(chatBody))
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	// 5. Verify the response came through from upstream
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 from proxy, got %d: %s", resp.StatusCode, body)
	}

	var chatResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		t.Fatalf("decoding chat response: %v", err)
	}
	if chatResp["model"] != "gpt-4o" {
		t.Errorf("expected model gpt-4o, got %v", chatResp["model"])
	}

	// 6. Verify VAOL headers are present
	if resp.Header.Get("X-VAOL-Record-ID") == "" {
		t.Error("missing X-VAOL-Record-ID header")
	}
	if resp.Header.Get("X-VAOL-Proxy") != "true" {
		t.Error("missing X-VAOL-Proxy header")
	}

	// 7. Verify a record was emitted to the VAOL server
	count, err := ms.Count(context.Background())
	if err != nil {
		t.Fatalf("counting records: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 record in VAOL, got %d", count)
	}

	// 8. Verify the stored record details
	stored, err := ms.GetBySequence(context.Background(), 0)
	if err != nil {
		t.Fatalf("getting stored record: %v", err)
	}
	if stored.TenantID != "proxy-test-tenant" {
		t.Errorf("expected tenant proxy-test-tenant, got %s", stored.TenantID)
	}

	// 9. Verify the envelope can be verified
	verifyBody, _ := json.Marshal(stored.Envelope)
	verifyResp, err := http.Post(vaolTS.URL+"/v1/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("verify request failed: %v", err)
	}
	defer verifyResp.Body.Close()

	var verifyResult map[string]any
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if verifyResult["valid"] != true {
		t.Errorf("expected valid=true, got %v", verifyResult["valid"])
	}
}

func TestProxyMultipleRequests(t *testing.T) {
	// Mock upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid request JSON", http.StatusBadRequest)
			return
		}

		response := map[string]any{
			"id":    fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()),
			"model": req["model"],
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "response"}, "finish_reason": "stop"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Logf("failed to encode response: %v", err)
		}
	}))
	defer mockUpstream.Close()

	// VAOL server
	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, _ := signer.GenerateEd25519Signer()
	ver := signer.NewEd25519Verifier(sig.PublicKey())
	vaolSrv := api.NewServer(api.DefaultConfig(), ms, sig, []signer.Verifier{ver}, tree, nil, slog.Default())
	vaolTS := httptest.NewServer(vaolSrv.Handler())
	defer vaolTS.Close()

	// Proxy
	upstreamURL, _ := url.Parse(mockUpstream.URL)
	proxy := &proxyHandler{
		upstream:   upstreamURL,
		vaolServer: vaolTS.URL,
		tenantID:   "multi-test",
		client:     &http.Client{Timeout: 30 * time.Second},
		logger:     slog.Default(),
	}
	proxyTS := httptest.NewServer(proxy)
	defer proxyTS.Close()

	// Send 5 requests
	for i := 0; i < 5; i++ {
		chatReq := map[string]any{
			"model":    fmt.Sprintf("gpt-4o-%d", i),
			"messages": []map[string]string{{"role": "user", "content": fmt.Sprintf("msg %d", i)}},
		}
		chatBody, _ := json.Marshal(chatReq)
		resp, err := http.Post(proxyTS.URL+"/v1/chat/completions", "application/json", bytes.NewReader(chatBody))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
	}

	// Verify 5 records in VAOL
	count, _ := ms.Count(context.Background())
	if count != 5 {
		t.Errorf("expected 5 records, got %d", count)
	}

	// Verify all records via verify endpoint
	for i := int64(0); i < 5; i++ {
		stored, err := ms.GetBySequence(context.Background(), i)
		if err != nil {
			t.Fatalf("getting record %d: %v", i, err)
		}
		envJSON, _ := json.Marshal(stored.Envelope)
		resp, err := http.Post(vaolTS.URL+"/v1/verify", "application/json", bytes.NewReader(envJSON))
		if err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("decode verify result %d: %v", i, err)
		}
		resp.Body.Close()
		if result["valid"] != true {
			t.Errorf("record %d: expected valid, got %v", i, result["valid"])
		}
	}
}
