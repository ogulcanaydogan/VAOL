package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestProxy(t *testing.T, upstream *httptest.Server, vaolServer *httptest.Server) *Proxy {
	t.Helper()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parsing upstream URL: %v", err)
	}
	return &Proxy{
		upstream:   upstreamURL,
		vaolServer: vaolServer.URL,
		tenantID:   "test-tenant",
		logger:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

func TestProxyForwardsRequestToUpstream(t *testing.T) {
	var receivedPath string
	var receivedMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"id": "chatcmpl-123"})
	}))
	defer upstream.Close()

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if receivedPath != "/v1/chat/completions" {
		t.Fatalf("upstream got path %q, want /v1/chat/completions", receivedPath)
	}
	if receivedMethod != http.MethodPost {
		t.Fatalf("upstream got method %q, want POST", receivedMethod)
	}
}

func TestProxyAddsVAOLHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Header().Get("X-VAOL-Record-ID") == "" {
		t.Fatal("expected X-VAOL-Record-ID header to be set")
	}
	if rec.Header().Get("X-VAOL-Proxy") != "true" {
		t.Fatalf("expected X-VAOL-Proxy=true, got %q", rec.Header().Get("X-VAOL-Proxy"))
	}
}

func TestProxyCopiesUpstreamHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Upstream", "hello")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Header().Get("X-Custom-Upstream") != "hello" {
		t.Fatalf("expected X-Custom-Upstream=hello, got %q", rec.Header().Get("X-Custom-Upstream"))
	}
}

func TestProxyCopiesRequestHeaders(t *testing.T) {
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer sk-test-123")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if receivedAuth != "Bearer sk-test-123" {
		t.Fatalf("upstream did not receive Authorization header, got %q", receivedAuth)
	}
}

func TestProxyUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer upstream.Close()

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// The proxy should transparently forward the upstream's 500 status.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestProxyPreservesResponseBody(t *testing.T) {
	expectedBody := `{"id":"chatcmpl-test","choices":[{"message":{"content":"Hello!"}}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedBody))
	}))
	defer upstream.Close()

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4"}`))
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	body := rec.Body.String()
	if body != expectedBody {
		t.Fatalf("response body mismatch:\n  got:  %q\n  want: %q", body, expectedBody)
	}
}

func TestEmitRecordSendsToVAOLServer(t *testing.T) {
	var receivedContentType string
	var receivedTenantID string
	var receivedBody []byte

	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedTenantID = r.Header.Get("X-VAOL-Tenant-ID")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer vaolSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)

	reqBody := []byte(`{"model":"gpt-4","temperature":0.7}`)
	respBody := []byte(`{"id":"chatcmpl-test","choices":[]}`)

	// Call emitRecord synchronously for testing.
	proxy.emitRecord(
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		reqBody,
		respBody,
		100*time.Millisecond,
		"/v1/chat/completions",
	)

	if receivedContentType != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", receivedContentType)
	}
	if receivedTenantID != "test-tenant" {
		t.Fatalf("expected tenant test-tenant, got %q", receivedTenantID)
	}
	if len(receivedBody) == 0 {
		t.Fatal("expected non-empty body sent to VAOL server")
	}

	// Verify the body is valid JSON with expected fields.
	var rec map[string]interface{}
	if err := json.Unmarshal(receivedBody, &rec); err != nil {
		t.Fatalf("expected valid JSON body: %v", err)
	}
	model, ok := rec["model"].(map[string]interface{})
	if !ok {
		t.Fatal("expected model field in record")
	}
	if model["name"] != "gpt-4" {
		t.Fatalf("expected model.name=gpt-4, got %v", model["name"])
	}
}

func TestEmitRecordHandlesVAOLServerError(t *testing.T) {
	vaolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"test error"}`))
	}))
	defer vaolSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, upstream, vaolSrv)

	// Should not panic when VAOL server returns an error.
	proxy.emitRecord(
		[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		[]byte(`{"model":"gpt-4"}`),
		[]byte(`{"ok":true}`),
		50*time.Millisecond,
		"/v1/chat/completions",
	)
}

func TestBuildTimeVariablesExist(t *testing.T) {
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
