package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

type stubCheckpointKafkaWriter struct {
	msgs     []kafka.Message
	writeErr error
}

func (s *stubCheckpointKafkaWriter) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.msgs = append(s.msgs, msgs...)
	return nil
}

func (s *stubCheckpointKafkaWriter) Close() error { return nil }

func TestKafkaCheckpointPublisherEmitCheckpoint(t *testing.T) {
	t.Parallel()

	stub := &stubCheckpointKafkaWriter{}
	p := &KafkaCheckpointPublisher{writer: stub, topic: "vaol.checkpoints"}
	event := &CheckpointEvent{
		EventVersion:       "v1",
		TenantID:           "tenant-a",
		TreeSize:           3,
		RootHash:           "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Timestamp:          time.Unix(1735689600, 0).UTC(),
		LastSequenceNumber: 2,
	}

	if err := p.EmitCheckpoint(context.Background(), event); err != nil {
		t.Fatalf("EmitCheckpoint: %v", err)
	}
	if len(stub.msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(stub.msgs))
	}
	var decoded CheckpointEvent
	if err := json.Unmarshal(stub.msgs[0].Value, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.TreeSize != 3 {
		t.Fatalf("unexpected tree size %d", decoded.TreeSize)
	}
}

func TestKafkaCheckpointPublisherEmitFailure(t *testing.T) {
	t.Parallel()

	stub := &stubCheckpointKafkaWriter{writeErr: errors.New("kafka unavailable")}
	p := &KafkaCheckpointPublisher{writer: stub, topic: "vaol.checkpoints"}

	err := p.EmitCheckpoint(context.Background(), &CheckpointEvent{
		EventVersion:       "v1",
		TenantID:           "tenant-a",
		TreeSize:           1,
		Timestamp:          time.Now().UTC(),
		LastSequenceNumber: 0,
	})
	if err == nil {
		t.Fatal("expected emit failure")
	}
}
