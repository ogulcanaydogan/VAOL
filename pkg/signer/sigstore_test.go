package signer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSigstoreSignVerifyRelaxed(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ""
	cfg.RequireRekor = false

	s := NewSigstoreSigner(cfg)
	v := NewSigstoreVerifier(cfg)

	payload := []byte("sigstore payload")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Cert == "" {
		t.Fatal("expected certificate")
	}
	if err := v.Verify(context.Background(), payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigstoreStrictRekorRoundTrip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"uuid": "entry-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/log/entries/entry-1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := DefaultSigstoreConfig()
	cfg.RekorURL = ts.URL
	cfg.RequireRekor = true

	s := NewSigstoreSigner(cfg)
	v := NewSigstoreVerifier(cfg)

	payload := []byte("strict sigstore payload")
	sig, err := s.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.RekorEntryID == "" {
		t.Fatal("expected rekor entry ID")
	}
	if err := v.Verify(context.Background(), payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigstoreStrictFailsWithoutRekorEntry(t *testing.T) {
	cfg := DefaultSigstoreConfig()
	cfg.RequireRekor = true
	cfg.RekorURL = "https://rekor.example.invalid"

	v := NewSigstoreVerifier(cfg)
	err := v.Verify(context.Background(), []byte("payload"), Signature{
		KeyID: "fulcio:https://issuer::oidc-bound",
		Sig:   "dGVzdA",
		Cert:  "dGVzdA",
	})
	if err == nil {
		t.Fatal("expected strict verification error for missing rekor entry")
	}
}
