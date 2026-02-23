package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

func TestHTTPRekorClientVerifyEntryPassesWithMatchingPayloadHash(t *testing.T) {
	payload := []byte("signed-dsse-pae-bytes")
	expectedHash := vaolcrypto.SHA256Prefixed(payload)

	entryBody, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"payload_hash": expectedHash,
		},
	})
	if err != nil {
		t.Fatalf("marshal entry body: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/log/entries/entry-123" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entry-123": map[string]any{
				"body": base64.StdEncoding.EncodeToString(entryBody),
			},
		})
	}))
	defer ts.Close()

	client := NewHTTPRekorClient(nil)
	if err := client.VerifyEntry(context.Background(), ts.URL, "entry-123", payload); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
}

func TestHTTPRekorClientVerifyEntryFailsOnPayloadHashMismatch(t *testing.T) {
	payload := []byte("signed-dsse-pae-bytes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/log/entries/entry-123" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entry-123": map[string]any{
				"spec": map[string]any{
					"payload_hash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
				},
			},
		})
	}))
	defer ts.Close()

	client := NewHTTPRekorClient(nil)
	err := client.VerifyEntry(context.Background(), ts.URL, "entry-123", payload)
	if err == nil || !strings.Contains(err.Error(), "payload hash mismatch") {
		t.Fatalf("expected payload hash mismatch, got %v", err)
	}
}

func TestHTTPRekorClientVerifyEntryFailsWhenPayloadHashMissing(t *testing.T) {
	payload := []byte("signed-dsse-pae-bytes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/log/entries/entry-123" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entry-123": map[string]any{
				"spec": map[string]any{},
			},
		})
	}))
	defer ts.Close()

	client := NewHTTPRekorClient(nil)
	err := client.VerifyEntry(context.Background(), ts.URL, "entry-123", payload)
	if err == nil || !strings.Contains(err.Error(), "missing spec.payload_hash in Rekor entry") {
		t.Fatalf("expected missing payload_hash error, got %v", err)
	}
}
