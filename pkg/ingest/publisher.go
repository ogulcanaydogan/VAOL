// Package ingest publishes append events for downstream high-scale pipelines.
package ingest

import (
	"context"
	"time"
)

// DecisionRecordEvent is the append event emitted after a record is stored.
// It intentionally contains immutable evidence metadata, not raw prompt/output.
type DecisionRecordEvent struct {
	EventVersion       string    `json:"event_version"`
	RequestID          string    `json:"request_id"`
	SequenceNumber     int64     `json:"sequence_number"`
	TenantID           string    `json:"tenant_id"`
	Timestamp          time.Time `json:"timestamp"`
	RecordHash         string    `json:"record_hash"`
	PreviousRecordHash string    `json:"previous_record_hash"`
	MerkleRoot         string    `json:"merkle_root"`
	MerkleTreeSize     int64     `json:"merkle_tree_size"`
	PolicyDecision     string    `json:"policy_decision,omitempty"`
	PolicyHash         string    `json:"policy_hash,omitempty"`
	ModelProvider      string    `json:"model_provider,omitempty"`
	ModelName          string    `json:"model_name,omitempty"`
	OutputMode         string    `json:"output_mode,omitempty"`
}

// Publisher emits append events to downstream ingest systems.
type Publisher interface {
	PublishDecisionRecord(ctx context.Context, event *DecisionRecordEvent) error
	Close() error
}

// NoopPublisher is a disabled ingest publisher.
type NoopPublisher struct{}

// NewNoopPublisher returns a publisher that drops all events.
func NewNoopPublisher() *NoopPublisher {
	return &NoopPublisher{}
}

// PublishDecisionRecord accepts the event and does nothing.
func (p *NoopPublisher) PublishDecisionRecord(_ context.Context, _ *DecisionRecordEvent) error {
	return nil
}

// Close releases resources (none).
func (p *NoopPublisher) Close() error {
	return nil
}
