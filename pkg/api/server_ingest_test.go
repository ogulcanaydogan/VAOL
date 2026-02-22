package api

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

func TestNewIngestPublisher(t *testing.T) {
	t.Parallel()

	pub, err := newIngestPublisher(Config{IngestMode: "off"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil publisher")
	}
	_ = pub.Close()

	if _, err := newIngestPublisher(Config{IngestMode: "invalid"}); err == nil {
		t.Fatal("expected invalid mode error")
	}

	if _, err := newIngestPublisher(Config{
		IngestMode:       "kafka",
		IngestKafkaTopic: "vaol.events",
	}); err == nil {
		t.Fatal("expected missing brokers error")
	}
}

func TestNewServerIngestInitRequired(t *testing.T) {
	t.Parallel()

	ms := store.NewMemoryStore()
	defer ms.Close()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := DefaultConfig()
	cfg.IngestMode = "kafka"
	cfg.IngestKafkaRequired = true
	cfg.IngestKafkaTopic = "vaol.events"
	cfg.IngestKafkaBrokers = nil
	cfg.RebuildOnStart = false

	srv := NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if srv.StartupError() == nil {
		t.Fatal("expected startup error when required ingest publisher fails")
	}
}

func TestNewServerIngestInitOptional(t *testing.T) {
	t.Parallel()

	ms := store.NewMemoryStore()
	defer ms.Close()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	cfg := DefaultConfig()
	cfg.IngestMode = "kafka"
	cfg.IngestKafkaRequired = false
	cfg.IngestKafkaTopic = "vaol.events"
	cfg.RebuildOnStart = false

	srv := NewServer(cfg, ms, sig, []signer.Verifier{ver}, tree, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if srv.StartupError() != nil {
		t.Fatalf("unexpected startup error for optional ingest publisher failure: %v", srv.StartupError())
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}
