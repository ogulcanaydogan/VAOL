package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

// KafkaConfig configures the Kafka ingest publisher.
type KafkaConfig struct {
	Brokers      []string
	Topic        string
	ClientID     string
	BatchTimeout time.Duration
}

type kafkaWriter interface {
	WriteMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// KafkaPublisher publishes decision-record events to a Kafka topic.
type KafkaPublisher struct {
	writer kafkaWriter
	topic  string
}

// NewKafkaPublisher creates a Kafka ingest publisher.
func NewKafkaPublisher(cfg KafkaConfig) (*KafkaPublisher, error) {
	normalizedBrokers := normalizeBrokers(cfg.Brokers)
	if len(normalizedBrokers) == 0 {
		return nil, fmt.Errorf("kafka ingest requires at least one broker")
	}
	topic := strings.TrimSpace(cfg.Topic)
	if topic == "" {
		return nil, fmt.Errorf("kafka ingest requires topic")
	}

	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = 10 * time.Millisecond
	}

	writer := &kafka.Writer{
		Addr:                   kafka.TCP(normalizedBrokers...),
		Topic:                  topic,
		Balancer:               &kafka.LeastBytes{},
		RequiredAcks:           kafka.RequireAll,
		AllowAutoTopicCreation: false,
		Async:                  false,
		BatchTimeout:           batchTimeout,
	}
	if cfg.ClientID != "" {
		writer.Transport = &kafka.Transport{
			ClientID: cfg.ClientID,
		}
	}

	return &KafkaPublisher{
		writer: writer,
		topic:  topic,
	}, nil
}

func normalizeBrokers(brokers []string) []string {
	out := make([]string, 0, len(brokers))
	for _, broker := range brokers {
		broker = strings.TrimSpace(broker)
		if broker == "" {
			continue
		}
		out = append(out, broker)
	}
	return out
}

// PublishDecisionRecord writes a single event to Kafka.
func (p *KafkaPublisher) PublishDecisionRecord(ctx context.Context, event *DecisionRecordEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(fmt.Sprintf("%s:%s", event.TenantID, event.RequestID)),
		Value: payload,
		Time:  event.Timestamp.UTC(),
		Headers: []kafka.Header{
			{Key: "event_type", Value: []byte("decision_record_appended")},
			{Key: "event_version", Value: []byte(event.EventVersion)},
			{Key: "tenant_id", Value: []byte(event.TenantID)},
			{Key: "request_id", Value: []byte(event.RequestID)},
			{Key: "sequence_number", Value: []byte(fmt.Sprintf("%d", event.SequenceNumber))},
		},
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("writing kafka message to topic %q: %w", p.topic, err)
	}
	return nil
}

// Close releases the Kafka writer.
func (p *KafkaPublisher) Close() error {
	if p == nil || p.writer == nil {
		return nil
	}
	return p.writer.Close()
}
