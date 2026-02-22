package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

type stubKafkaWriter struct {
	msgs      []kafka.Message
	writeErr  error
	closeErr  error
	closeCall int
}

func (s *stubKafkaWriter) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.msgs = append(s.msgs, msgs...)
	return nil
}

func (s *stubKafkaWriter) Close() error {
	s.closeCall++
	return s.closeErr
}

func TestNewKafkaPublisherValidation(t *testing.T) {
	t.Parallel()

	_, err := NewKafkaPublisher(KafkaConfig{
		Brokers: nil,
		Topic:   "vaol.events",
	})
	if err == nil {
		t.Fatal("expected error for missing brokers")
	}

	_, err = NewKafkaPublisher(KafkaConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "",
	})
	if err == nil {
		t.Fatal("expected error for missing topic")
	}
}

func TestKafkaPublisherPublishDecisionRecord(t *testing.T) {
	t.Parallel()

	stub := &stubKafkaWriter{}
	p := &KafkaPublisher{
		writer: stub,
		topic:  "vaol.events",
	}

	event := &DecisionRecordEvent{
		EventVersion:   "v1",
		RequestID:      "req-123",
		SequenceNumber: 42,
		TenantID:       "tenant-a",
		Timestamp:      time.Unix(1735689600, 0).UTC(),
		RecordHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	if err := p.PublishDecisionRecord(context.Background(), event); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	if len(stub.msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(stub.msgs))
	}

	msg := stub.msgs[0]
	if got, want := string(msg.Key), "tenant-a:req-123"; got != want {
		t.Fatalf("message key mismatch: got %q want %q", got, want)
	}

	var decoded DecisionRecordEvent
	if err := json.Unmarshal(msg.Value, &decoded); err != nil {
		t.Fatalf("unmarshal message value: %v", err)
	}
	if decoded.RequestID != event.RequestID {
		t.Fatalf("request_id mismatch: got %q want %q", decoded.RequestID, event.RequestID)
	}
}

func TestKafkaPublisherPublishError(t *testing.T) {
	t.Parallel()

	stub := &stubKafkaWriter{writeErr: errors.New("kafka unavailable")}
	p := &KafkaPublisher{writer: stub, topic: "vaol.events"}

	err := p.PublishDecisionRecord(context.Background(), &DecisionRecordEvent{
		EventVersion: "v1",
		RequestID:    "req-123",
		TenantID:     "tenant-a",
		Timestamp:    time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected publish error")
	}
}

func TestKafkaPublisherClose(t *testing.T) {
	t.Parallel()

	stub := &stubKafkaWriter{}
	p := &KafkaPublisher{writer: stub}
	if err := p.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if stub.closeCall != 1 {
		t.Fatalf("expected close called once, got %d", stub.closeCall)
	}
}
