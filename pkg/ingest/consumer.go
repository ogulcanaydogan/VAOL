package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

// DecisionRecordEventHandler processes consumed decision-record events.
type DecisionRecordEventHandler interface {
	HandleDecisionRecordEvent(ctx context.Context, event *DecisionRecordEvent) error
}

type kafkaReader interface {
	FetchMessage(ctx context.Context) (kafka.Message, error)
	CommitMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// ConsumerConfig configures the Kafka decision-record consumer.
type ConsumerConfig struct {
	Brokers        []string
	Topic          string
	GroupID        string
	ClientID       string
	MinBytes       int
	MaxBytes       int
	MaxWait        time.Duration
	StrictDecoding bool
}

// DecisionRecordConsumer consumes decision-record append events from Kafka.
type DecisionRecordConsumer struct {
	reader         kafkaReader
	handler        DecisionRecordEventHandler
	strictDecoding bool
	logger         *slog.Logger
}

// NewDecisionRecordConsumer creates a consumer from Kafka settings.
func NewDecisionRecordConsumer(cfg ConsumerConfig, handler DecisionRecordEventHandler, logger *slog.Logger) (*DecisionRecordConsumer, error) {
	if handler == nil {
		return nil, fmt.Errorf("decision record event handler is required")
	}
	brokers := normalizeBrokers(cfg.Brokers)
	if len(brokers) == 0 {
		return nil, fmt.Errorf("kafka consumer requires at least one broker")
	}
	topic := strings.TrimSpace(cfg.Topic)
	if topic == "" {
		return nil, fmt.Errorf("kafka consumer requires topic")
	}
	groupID := strings.TrimSpace(cfg.GroupID)
	if groupID == "" {
		return nil, fmt.Errorf("kafka consumer requires group_id")
	}

	minBytes := cfg.MinBytes
	if minBytes <= 0 {
		minBytes = 1
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	maxWait := cfg.MaxWait
	if maxWait <= 0 {
		maxWait = 2 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}

	readerCfg := kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  groupID,
		MinBytes: minBytes,
		MaxBytes: maxBytes,
		MaxWait:  maxWait,
	}
	if cfg.ClientID != "" {
		readerCfg.Dialer = &kafka.Dialer{ClientID: cfg.ClientID}
	}
	reader := kafka.NewReader(readerCfg)

	return &DecisionRecordConsumer{
		reader:         reader,
		handler:        handler,
		strictDecoding: cfg.StrictDecoding,
		logger:         logger,
	}, nil
}

// NewDecisionRecordConsumerWithReader is a test helper constructor.
func NewDecisionRecordConsumerWithReader(reader kafkaReader, handler DecisionRecordEventHandler, strictDecoding bool, logger *slog.Logger) (*DecisionRecordConsumer, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader is required")
	}
	if handler == nil {
		return nil, fmt.Errorf("decision record event handler is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DecisionRecordConsumer{
		reader:         reader,
		handler:        handler,
		strictDecoding: strictDecoding,
		logger:         logger,
	}, nil
}

// Run starts the consume loop and blocks until context cancellation or fatal error.
func (c *DecisionRecordConsumer) Run(ctx context.Context) error {
	for {
		msg, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return nil
			}
			if errorsIsContextDone(ctx.Err()) {
				return nil
			}
			if isReaderClosedErr(err) {
				return nil
			}
			return fmt.Errorf("fetching kafka message: %w", err)
		}

		var event DecisionRecordEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			if c.strictDecoding {
				return fmt.Errorf("decoding decision record event: %w", err)
			}
			c.logger.Warn("dropping invalid decision-record event",
				"topic", msg.Topic,
				"partition", msg.Partition,
				"offset", msg.Offset,
				"error", err,
			)
			if commitErr := c.reader.CommitMessages(ctx, msg); commitErr != nil {
				return fmt.Errorf("committing dropped message offset: %w", commitErr)
			}
			continue
		}

		if err := c.handler.HandleDecisionRecordEvent(ctx, &event); err != nil {
			return fmt.Errorf("handling decision record event request_id=%s sequence=%d: %w", event.RequestID, event.SequenceNumber, err)
		}

		if err := c.reader.CommitMessages(ctx, msg); err != nil {
			return fmt.Errorf("committing kafka message offset: %w", err)
		}
	}
}

// Close closes the underlying Kafka reader.
func (c *DecisionRecordConsumer) Close() error {
	if c == nil || c.reader == nil {
		return nil
	}
	return c.reader.Close()
}

func isReaderClosedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "reader closed") || strings.Contains(msg, "use of closed network connection") || err == io.EOF
}

func errorsIsContextDone(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
