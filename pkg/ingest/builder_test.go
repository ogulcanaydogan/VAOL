package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

type stubCheckpointEmitter struct {
	events []*CheckpointEvent
	err    error
}

func (s *stubCheckpointEmitter) EmitCheckpoint(_ context.Context, event *CheckpointEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

func TestTenantMerkleBuilderApplyCheckpointCadence(t *testing.T) {
	t.Parallel()

	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}

	now := time.Date(2026, 2, 22, 20, 0, 0, 0, time.UTC)
	emitter := &stubCheckpointEmitter{}
	builder := NewTenantMerkleBuilder(TenantMerkleBuilderConfig{
		CheckpointEvery:  2,
		CheckpointSigner: merkle.NewCheckpointSigner(sig),
		AnchorClient:     &merkle.HashAnchorClient{},
		Emitter:          emitter,
		Clock: func() time.Time {
			return now
		},
	})

	_, err = builder.Apply(context.Background(), &DecisionRecordEvent{
		TenantID:           "tenant-a",
		SequenceNumber:     0,
		RecordHash:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PreviousRecordHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Timestamp:          now,
	})
	if err != nil {
		t.Fatalf("apply first event: %v", err)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected checkpoint on first event, got %d", len(emitter.events))
	}

	_, err = builder.Apply(context.Background(), &DecisionRecordEvent{
		TenantID:           "tenant-a",
		SequenceNumber:     1,
		RecordHash:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PreviousRecordHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Timestamp:          now.Add(1 * time.Second),
	})
	if err != nil {
		t.Fatalf("apply second event: %v", err)
	}
	if len(emitter.events) != 2 {
		t.Fatalf("expected checkpoint on cadence boundary, got %d", len(emitter.events))
	}
}

func TestTenantMerkleBuilderRejectsChainBreak(t *testing.T) {
	t.Parallel()

	builder := NewTenantMerkleBuilder(TenantMerkleBuilderConfig{})

	_, err := builder.Apply(context.Background(), &DecisionRecordEvent{
		TenantID:       "tenant-a",
		SequenceNumber: 0,
		RecordHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("apply first event: %v", err)
	}

	_, err = builder.Apply(context.Background(), &DecisionRecordEvent{
		TenantID:           "tenant-a",
		SequenceNumber:     1,
		RecordHash:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PreviousRecordHash: "sha256:not-previous",
	})
	if err == nil {
		t.Fatal("expected chain break error")
	}
}

func TestTenantMerkleBuilderEmitterFailure(t *testing.T) {
	t.Parallel()

	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	emitter := &stubCheckpointEmitter{err: errors.New("emit failed")}
	builder := NewTenantMerkleBuilder(TenantMerkleBuilderConfig{
		CheckpointEvery:  1,
		CheckpointSigner: merkle.NewCheckpointSigner(sig),
		AnchorClient:     &merkle.HashAnchorClient{},
		Emitter:          emitter,
	})

	_, err = builder.Apply(context.Background(), &DecisionRecordEvent{
		TenantID:       "tenant-a",
		SequenceNumber: 0,
		RecordHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err == nil {
		t.Fatal("expected emitter failure")
	}
}
