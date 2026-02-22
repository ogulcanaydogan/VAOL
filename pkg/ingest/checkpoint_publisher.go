package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

// CheckpointKafkaConfig configures Kafka publishing for checkpoint events.
type CheckpointKafkaConfig struct {
	Brokers      []string
	Topic        string
	ClientID     string
	BatchTimeout time.Duration
}

// KafkaCheckpointPublisher publishes checkpoint events to a Kafka topic.
type KafkaCheckpointPublisher struct {
	writer kafkaWriter
	topic  string
}

// NewKafkaCheckpointPublisher creates a checkpoint-event publisher.
func NewKafkaCheckpointPublisher(cfg CheckpointKafkaConfig) (*KafkaCheckpointPublisher, error) {
	brokers := normalizeBrokers(cfg.Brokers)
	if len(brokers) == 0 {
		return nil, fmt.Errorf("kafka checkpoint publisher requires at least one broker")
	}
	topic := strings.TrimSpace(cfg.Topic)
	if topic == "" {
		return nil, fmt.Errorf("kafka checkpoint publisher requires topic")
	}
	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = 10 * time.Millisecond
	}

	writer := &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  topic,
		Balancer:               &kafka.LeastBytes{},
		RequiredAcks:           kafka.RequireAll,
		AllowAutoTopicCreation: false,
		Async:                  false,
		BatchTimeout:           batchTimeout,
	}
	if cfg.ClientID != "" {
		writer.Transport = &kafka.Transport{ClientID: cfg.ClientID}
	}

	return &KafkaCheckpointPublisher{writer: writer, topic: topic}, nil
}

// EmitCheckpoint publishes an async checkpoint event.
func (p *KafkaCheckpointPublisher) EmitCheckpoint(ctx context.Context, event *CheckpointEvent) error {
	if event == nil {
		return fmt.Errorf("checkpoint event is nil")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling checkpoint event: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("%s:%d", event.TenantID, event.TreeSize)),
		Value: payload,
		Time:  event.Timestamp.UTC(),
		Headers: []kafka.Header{
			{Key: "event_type", Value: []byte("tenant_checkpoint_generated")},
			{Key: "event_version", Value: []byte(event.EventVersion)},
			{Key: "tenant_id", Value: []byte(event.TenantID)},
			{Key: "tree_size", Value: []byte(fmt.Sprintf("%d", event.TreeSize))},
			{Key: "sequence_number", Value: []byte(fmt.Sprintf("%d", event.LastSequenceNumber))},
		},
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("writing kafka checkpoint event to topic %q: %w", p.topic, err)
	}
	return nil
}

// Close releases writer resources.
func (p *KafkaCheckpointPublisher) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}
