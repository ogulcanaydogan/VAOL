package merkle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNoopAnchorClient(t *testing.T) {
	client := &NoopAnchorClient{}
	cp := &Checkpoint{TreeSize: 10, RootHash: "sha256:abc", Timestamp: time.Now().UTC()}

	result, err := client.Anchor(context.Background(), cp)
	if err != nil {
		t.Fatalf("NoopAnchorClient.Anchor error: %v", err)
	}
	if result != "" {
		t.Errorf("NoopAnchorClient should return empty string, got %q", result)
	}
}

func TestNoopAnchorClientNilCheckpoint(t *testing.T) {
	client := &NoopAnchorClient{}
	result, err := client.Anchor(context.Background(), nil)
	if err != nil {
		t.Fatalf("NoopAnchorClient.Anchor with nil should not error, got: %v", err)
	}
	if result != "" {
		t.Errorf("NoopAnchorClient should return empty string, got %q", result)
	}
}

func TestNoopAnchorClientVerifyUnsupported(t *testing.T) {
	client := &NoopAnchorClient{}
	err := client.VerifyCheckpoint(context.Background(), &Checkpoint{}, "entry-1")
	if err == nil {
		t.Fatal("expected unsupported verification error")
	}
}

func TestHashAnchorClientValid(t *testing.T) {
	client := &HashAnchorClient{}
	cp := &Checkpoint{
		TreeSize:  42,
		RootHash:  "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Signature: "test-sig",
	}

	result, err := client.Anchor(context.Background(), cp)
	if err != nil {
		t.Fatalf("HashAnchorClient.Anchor error: %v", err)
	}
	if !strings.HasPrefix(result, "local:sha256:") {
		t.Errorf("result should start with 'local:sha256:', got %q", result)
	}
}

func TestHashAnchorClientDeterministic(t *testing.T) {
	client := &HashAnchorClient{}
	cp := &Checkpoint{
		TreeSize:  10,
		RootHash:  "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Timestamp: time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
		Signature: "sig",
	}

	r1, err := client.Anchor(context.Background(), cp)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	r2, err := client.Anchor(context.Background(), cp)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if r1 != r2 {
		t.Errorf("results should be deterministic: %q != %q", r1, r2)
	}
}

func TestHashAnchorClientVerifyCheckpoint(t *testing.T) {
	client := &HashAnchorClient{}
	cp := &Checkpoint{
		TreeSize:  10,
		RootHash:  "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Timestamp: time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
		Signature: "sig",
	}

	entryID, err := client.Anchor(context.Background(), cp)
	if err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if err := client.VerifyCheckpoint(context.Background(), cp, entryID); err != nil {
		t.Fatalf("VerifyCheckpoint should pass: %v", err)
	}
	if err := client.VerifyCheckpoint(context.Background(), cp, "local:sha256:deadbeef"); err == nil {
		t.Fatal("VerifyCheckpoint should fail on mismatch")
	}
}

func TestHashAnchorClientNilCheckpoint(t *testing.T) {
	client := &HashAnchorClient{}
	_, err := client.Anchor(context.Background(), nil)
	if err == nil {
		t.Fatal("should fail with nil checkpoint")
	}
	if !strings.Contains(err.Error(), "checkpoint is nil") {
		t.Errorf("error should contain 'checkpoint is nil', got: %v", err)
	}
}

func TestHTTPAnchorClientValid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"entry_id": "rekor-12345"})
	}))
	defer ts.Close()

	client := &HTTPAnchorClient{Endpoint: ts.URL}
	cp := &Checkpoint{TreeSize: 5, RootHash: "sha256:abc", Timestamp: time.Now().UTC()}

	result, err := client.Anchor(context.Background(), cp)
	if err != nil {
		t.Fatalf("HTTPAnchorClient.Anchor error: %v", err)
	}
	if result != "rekor-12345" {
		t.Errorf("result = %q, want rekor-12345", result)
	}
}

func TestHTTPAnchorClientServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	client := &HTTPAnchorClient{Endpoint: ts.URL}
	cp := &Checkpoint{TreeSize: 5, RootHash: "sha256:abc", Timestamp: time.Now().UTC()}

	_, err := client.Anchor(context.Background(), cp)
	if err == nil {
		t.Fatal("should fail with server error")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should contain 'status 500', got: %v", err)
	}
}

func TestHTTPAnchorClientEmptyEndpoint(t *testing.T) {
	client := &HTTPAnchorClient{Endpoint: ""}
	cp := &Checkpoint{TreeSize: 5, RootHash: "sha256:abc", Timestamp: time.Now().UTC()}

	_, err := client.Anchor(context.Background(), cp)
	if err == nil {
		t.Fatal("should fail with empty endpoint")
	}
	if !strings.Contains(err.Error(), "anchor endpoint is required") {
		t.Errorf("error should contain 'anchor endpoint is required', got: %v", err)
	}
}

func TestHTTPAnchorClientNilCheckpoint(t *testing.T) {
	client := &HTTPAnchorClient{Endpoint: "http://localhost:9999"}
	_, err := client.Anchor(context.Background(), nil)
	if err == nil {
		t.Fatal("should fail with nil checkpoint")
	}
	if !strings.Contains(err.Error(), "checkpoint is nil") {
		t.Errorf("error should contain 'checkpoint is nil', got: %v", err)
	}
}

func TestHTTPAnchorClientEmptyEntryID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"entry_id": ""})
	}))
	defer ts.Close()

	client := &HTTPAnchorClient{Endpoint: ts.URL}
	cp := &Checkpoint{TreeSize: 5, RootHash: "sha256:abc", Timestamp: time.Now().UTC()}

	_, err := client.Anchor(context.Background(), cp)
	if err == nil {
		t.Fatal("should fail with empty entry_id")
	}
	if !strings.Contains(err.Error(), "missing entry_id") {
		t.Errorf("error should contain 'missing entry_id', got: %v", err)
	}
}

func TestHTTPAnchorClientVerifyCheckpoint(t *testing.T) {
	var verifyCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify":
			verifyCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"entry_id": "rekor-12345"})
		}
	}))
	defer ts.Close()

	client := &HTTPAnchorClient{Endpoint: ts.URL}
	cp := &Checkpoint{TreeSize: 5, RootHash: "sha256:abc", Timestamp: time.Now().UTC()}

	if err := client.VerifyCheckpoint(context.Background(), cp, "rekor-12345"); err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected one verify call, got %d", verifyCalls)
	}
}
