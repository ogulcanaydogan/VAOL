// Command vaol-ingest-worker consumes Kafka decision-record events and builds
// per-tenant Merkle/checkpoint state asynchronously.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/ingest"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

func main() {
	var (
		brokersRaw         = flag.String("kafka-brokers", "", "comma-separated Kafka brokers")
		topic              = flag.String("kafka-topic", "vaol.decision-records", "Kafka topic containing decision-record append events")
		groupID            = flag.String("kafka-group-id", "vaol-ingest-worker", "Kafka consumer group ID")
		clientID           = flag.String("kafka-client-id", "vaol-ingest-worker", "Kafka client ID")
		checkpointTopic    = flag.String("checkpoint-topic", "", "Kafka topic for emitted tenant checkpoint events (optional)")
		checkpointEvery    = flag.Int64("checkpoint-every", 100, "emit a checkpoint every N events per tenant")
		checkpointInterval = flag.Duration("checkpoint-interval", 5*time.Minute, "emit a checkpoint at least every duration per tenant")
		strictDecoding     = flag.Bool("strict-decoding", true, "stop on malformed consumed events")
		anchorMode         = flag.String("anchor-mode", "local", "checkpoint anchor mode: off, local, http")
		anchorURL          = flag.String("anchor-url", "", "checkpoint anchoring endpoint URL (required for anchor-mode=http)")
		keyPath            = flag.String("key", "", "Ed25519 private key PEM path for checkpoint signing")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	brokers := parseCommaSeparatedNonEmpty(*brokersRaw)
	if len(brokers) == 0 {
		logger.Error("kafka brokers are required")
		os.Exit(1)
	}

	sig, err := buildSigner(*keyPath, logger)
	if err != nil {
		logger.Error("failed to initialize signer", "error", err)
		os.Exit(1)
	}

	anchorClient, err := newAnchorClient(*anchorMode, *anchorURL)
	if err != nil {
		logger.Error("invalid anchor config", "error", err)
		os.Exit(1)
	}

	var emitter ingest.CheckpointEventEmitter
	var emitterCloser interface{ Close() error }
	if strings.TrimSpace(*checkpointTopic) != "" {
		pub, err := ingest.NewKafkaCheckpointPublisher(ingest.CheckpointKafkaConfig{
			Brokers:  brokers,
			Topic:    *checkpointTopic,
			ClientID: *clientID,
		})
		if err != nil {
			logger.Error("failed to initialize checkpoint publisher", "error", err)
			os.Exit(1)
		}
		emitter = pub
		emitterCloser = pub
	}

	builder := ingest.NewTenantMerkleBuilder(ingest.TenantMerkleBuilderConfig{
		CheckpointEvery:    *checkpointEvery,
		CheckpointInterval: *checkpointInterval,
		CheckpointSigner:   merkle.NewCheckpointSigner(sig),
		AnchorClient:       anchorClient,
		Emitter:            emitter,
		Logger:             logger,
	})

	consumer, err := ingest.NewDecisionRecordConsumer(ingest.ConsumerConfig{
		Brokers:        brokers,
		Topic:          *topic,
		GroupID:        *groupID,
		ClientID:       *clientID,
		StrictDecoding: *strictDecoding,
	}, builder, logger)
	if err != nil {
		logger.Error("failed to initialize decision-record consumer", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = consumer.Close()
		if emitterCloser != nil {
			_ = emitterCloser.Close()
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting vaol ingest worker",
		"topic", *topic,
		"group_id", *groupID,
		"checkpoint_topic", *checkpointTopic,
		"anchor_mode", *anchorMode,
	)

	if err := consumer.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		logger.Error("ingest worker stopped with error", "error", err)
		os.Exit(1)
	}

	logger.Info("ingest worker stopped")
}

func buildSigner(keyPath string, logger *slog.Logger) (*signer.Ed25519Signer, error) {
	if strings.TrimSpace(keyPath) == "" {
		sig, err := signer.GenerateEd25519Signer()
		if err != nil {
			return nil, fmt.Errorf("generating ephemeral ed25519 signer: %w", err)
		}
		logger.Warn("using ephemeral ed25519 checkpoint signer", "key_id", sig.KeyID())
		return sig, nil
	}
	priv, err := signer.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading ed25519 key: %w", err)
	}
	sig := signer.NewEd25519Signer(priv)
	logger.Info("loaded checkpoint signing key", "key_id", sig.KeyID())
	return sig, nil
}

func newAnchorClient(mode string, url string) (merkle.AnchorClient, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "off":
		return &merkle.NoopAnchorClient{}, nil
	case "local":
		return &merkle.HashAnchorClient{}, nil
	case "http":
		if strings.TrimSpace(url) == "" {
			return nil, fmt.Errorf("anchor-url is required for anchor-mode=http")
		}
		return &merkle.HTTPAnchorClient{Endpoint: url}, nil
	default:
		return nil, fmt.Errorf("unsupported anchor mode %q", mode)
	}
}

func parseCommaSeparatedNonEmpty(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}
