package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/merkle"
)

// CheckpointEvent captures an asynchronously generated tenant checkpoint.
type CheckpointEvent struct {
	EventVersion       string    `json:"event_version"`
	TenantID           string    `json:"tenant_id"`
	TreeSize           int64     `json:"tree_size"`
	RootHash           string    `json:"root_hash"`
	Timestamp          time.Time `json:"timestamp"`
	Signature          string    `json:"signature,omitempty"`
	RekorEntryID       string    `json:"rekor_entry_id,omitempty"`
	LastSequenceNumber int64     `json:"last_sequence_number"`
	LastRecordHash     string    `json:"last_record_hash"`
	PreviousRecordHash string    `json:"previous_record_hash"`
}

// CheckpointEventEmitter emits generated checkpoint events.
type CheckpointEventEmitter interface {
	EmitCheckpoint(ctx context.Context, event *CheckpointEvent) error
}

// TenantMerkleBuilderConfig controls async Merkle/checkpoint generation.
type TenantMerkleBuilderConfig struct {
	CheckpointEvery    int64
	CheckpointInterval time.Duration
	CheckpointSigner   *merkle.CheckpointSigner
	AnchorClient       merkle.AnchorClient
	Emitter            CheckpointEventEmitter
	Clock              func() time.Time
	Logger             *slog.Logger
}

type tenantBuilderState struct {
	tree             *merkle.Tree
	lastSequence     int64
	lastRecordHash   string
	lastCheckpointAt time.Time
}

// BuilderResult captures append/checkpoint state after an event is applied.
type BuilderResult struct {
	TenantID           string
	TreeSize           int64
	MerkleRoot         string
	LastSequenceNumber int64
	Checkpoint         *CheckpointEvent
}

// TenantMerkleBuilder maintains per-tenant Merkle trees from append events.
type TenantMerkleBuilder struct {
	mu   sync.Mutex
	cfg  TenantMerkleBuilderConfig
	data map[string]*tenantBuilderState
}

// NewTenantMerkleBuilder creates a new async Merkle/checkpoint builder.
func NewTenantMerkleBuilder(cfg TenantMerkleBuilderConfig) *TenantMerkleBuilder {
	if cfg.CheckpointEvery <= 0 {
		cfg.CheckpointEvery = 100
	}
	if cfg.CheckpointInterval <= 0 {
		cfg.CheckpointInterval = 5 * time.Minute
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.AnchorClient == nil {
		cfg.AnchorClient = &merkle.NoopAnchorClient{}
	}

	return &TenantMerkleBuilder{
		cfg:  cfg,
		data: make(map[string]*tenantBuilderState),
	}
}

// HandleDecisionRecordEvent applies a consumed append event to the tenant tree.
func (b *TenantMerkleBuilder) HandleDecisionRecordEvent(ctx context.Context, event *DecisionRecordEvent) error {
	_, err := b.Apply(ctx, event)
	return err
}

// Apply applies an event and returns updated Merkle/checkpoint state.
func (b *TenantMerkleBuilder) Apply(ctx context.Context, event *DecisionRecordEvent) (*BuilderResult, error) {
	if event == nil {
		return nil, fmt.Errorf("event is nil")
	}
	tenantID := strings.TrimSpace(event.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if strings.TrimSpace(event.RecordHash) == "" {
		return nil, fmt.Errorf("record_hash is required")
	}
	if event.SequenceNumber < 0 {
		return nil, fmt.Errorf("sequence_number must be non-negative")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	state, ok := b.data[tenantID]
	if !ok {
		state = &tenantBuilderState{
			tree:         merkle.New(),
			lastSequence: -1,
		}
		b.data[tenantID] = state
	}

	if event.SequenceNumber <= state.lastSequence {
		return nil, fmt.Errorf("non-increasing sequence for tenant %q: got=%d last=%d", tenantID, event.SequenceNumber, state.lastSequence)
	}
	if state.lastSequence >= 0 && event.PreviousRecordHash != state.lastRecordHash {
		return nil, fmt.Errorf(
			"previous_record_hash mismatch for tenant %q sequence=%d: got=%q expected=%q",
			tenantID,
			event.SequenceNumber,
			event.PreviousRecordHash,
			state.lastRecordHash,
		)
	}

	state.tree.Append([]byte(event.RecordHash))
	state.lastSequence = event.SequenceNumber
	state.lastRecordHash = event.RecordHash

	result := &BuilderResult{
		TenantID:           tenantID,
		TreeSize:           state.tree.Size(),
		MerkleRoot:         state.tree.Root(),
		LastSequenceNumber: state.lastSequence,
	}

	now := b.cfg.Clock().UTC()
	shouldCheckpoint := state.lastCheckpointAt.IsZero() ||
		(event.SequenceNumber+1)%b.cfg.CheckpointEvery == 0 ||
		now.Sub(state.lastCheckpointAt) >= b.cfg.CheckpointInterval
	if !shouldCheckpoint || b.cfg.CheckpointSigner == nil {
		return result, nil
	}

	cp, err := b.cfg.CheckpointSigner.SignCheckpoint(ctx, state.tree)
	if err != nil {
		return nil, fmt.Errorf("signing tenant checkpoint: %w", err)
	}

	entryID, err := b.cfg.AnchorClient.Anchor(ctx, cp)
	if err != nil {
		return nil, fmt.Errorf("anchoring tenant checkpoint: %w", err)
	}
	cp.RekorEntryID = entryID

	checkpointEvent := &CheckpointEvent{
		EventVersion:       "v1",
		TenantID:           tenantID,
		TreeSize:           cp.TreeSize,
		RootHash:           cp.RootHash,
		Timestamp:          cp.Timestamp.UTC(),
		Signature:          cp.Signature,
		RekorEntryID:       cp.RekorEntryID,
		LastSequenceNumber: event.SequenceNumber,
		LastRecordHash:     event.RecordHash,
		PreviousRecordHash: event.PreviousRecordHash,
	}

	if b.cfg.Emitter != nil {
		if err := b.cfg.Emitter.EmitCheckpoint(ctx, checkpointEvent); err != nil {
			return nil, fmt.Errorf("emitting checkpoint event: %w", err)
		}
	}

	state.lastCheckpointAt = now
	result.Checkpoint = checkpointEvent
	result.TreeSize = cp.TreeSize
	result.MerkleRoot = cp.RootHash

	b.cfg.Logger.Info("tenant checkpoint generated",
		"tenant_id", tenantID,
		"tree_size", cp.TreeSize,
		"root_hash", cp.RootHash,
		"sequence_number", event.SequenceNumber,
	)

	return result, nil
}
