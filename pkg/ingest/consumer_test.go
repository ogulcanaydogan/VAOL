package ingest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

type stubReader struct {
	msgs       []kafka.Message
	idx        int
	commitCall int
	closed     bool
}

func (s *stubReader) FetchMessage(_ context.Context) (kafka.Message, error) {
	if s.idx >= len(s.msgs) {
		return kafka.Message{}, io.EOF
	}
	msg := s.msgs[s.idx]
	s.idx++
	return msg, nil
}

func (s *stubReader) CommitMessages(_ context.Context, _ ...kafka.Message) error {
	s.commitCall++
	return nil
}

func (s *stubReader) Close() error {
	s.closed = true
	return nil
}

type stubHandler struct {
	events []*DecisionRecordEvent
	err    error
}

func (s *stubHandler) HandleDecisionRecordEvent(_ context.Context, event *DecisionRecordEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func TestDecisionRecordConsumerRunSuccess(t *testing.T) {
	t.Parallel()

	reader := &stubReader{
		msgs: []kafka.Message{
			{Value: []byte(`{"request_id":"r1","tenant_id":"t1","sequence_number":1,"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":"2026-02-22T20:00:00Z"}`)},
			{Value: []byte(`{"request_id":"r2","tenant_id":"t1","sequence_number":2,"record_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","previous_record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":"2026-02-22T20:00:01Z"}`)},
		},
	}
	handler := &stubHandler{}
	consumer, err := NewDecisionRecordConsumerWithReader(reader, handler, true, slog.Default())
	if err != nil {
		t.Fatalf("NewDecisionRecordConsumerWithReader: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := consumer.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(handler.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(handler.events))
	}
	if reader.commitCall != 2 {
		t.Fatalf("expected 2 commits, got %d", reader.commitCall)
	}
}

func TestDecisionRecordConsumerRunStrictDecodeFailure(t *testing.T) {
	t.Parallel()

	reader := &stubReader{msgs: []kafka.Message{{Value: []byte("not-json")}}}
	handler := &stubHandler{}
	consumer, err := NewDecisionRecordConsumerWithReader(reader, handler, true, slog.Default())
	if err != nil {
		t.Fatalf("NewDecisionRecordConsumerWithReader: %v", err)
	}

	err = consumer.Run(context.Background())
	if err == nil {
		t.Fatal("expected strict decoding error")
	}
	if reader.commitCall != 0 {
		t.Fatalf("unexpected commits on strict decoding failure: %d", reader.commitCall)
	}
}

func TestDecisionRecordConsumerRunHandlerFailure(t *testing.T) {
	t.Parallel()

	reader := &stubReader{msgs: []kafka.Message{{Value: []byte(`{"request_id":"r1","tenant_id":"t1","sequence_number":1,"record_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":"2026-02-22T20:00:00Z"}`)}}}
	handler := &stubHandler{err: errors.New("handler failed")}
	consumer, err := NewDecisionRecordConsumerWithReader(reader, handler, true, slog.Default())
	if err != nil {
		t.Fatalf("NewDecisionRecordConsumerWithReader: %v", err)
	}

	err = consumer.Run(context.Background())
	if err == nil {
		t.Fatal("expected handler error")
	}
	if reader.commitCall != 0 {
		t.Fatalf("unexpected commits on handler failure: %d", reader.commitCall)
	}
}
