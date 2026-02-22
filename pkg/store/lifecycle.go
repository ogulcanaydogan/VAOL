package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

// RetentionReport summarizes encrypted payload retention actions.
type RetentionReport struct {
	DeletedCount int                 `json:"deleted_count"`
	Tombstones   []*PayloadTombstone `json:"tombstones"`
	ExecutedAt   time.Time           `json:"executed_at"`
}

// KeyRotationReport summarizes encryption key metadata rotation actions.
type KeyRotationReport struct {
	EventID      string    `json:"event_id"`
	OldKeyID     string    `json:"old_key_id"`
	NewKeyID     string    `json:"new_key_id"`
	UpdatedCount int64     `json:"updated_count"`
	ExecutedAt   time.Time `json:"executed_at"`
	EvidenceHash string    `json:"evidence_hash"`
}

// RunRetentionJob deletes expired encrypted payloads and emits tombstones.
func RunRetentionJob(ctx context.Context, st Store, before time.Time, limit int, reason string) (*RetentionReport, error) {
	tombstones, err := st.DeleteExpiredEncryptedPayloads(ctx, before, limit, reason)
	if err != nil {
		return nil, err
	}
	return &RetentionReport{
		DeletedCount: len(tombstones),
		Tombstones:   tombstones,
		ExecutedAt:   time.Now().UTC(),
	}, nil
}

// RunKeyRotationMetadataJob rotates encryption key metadata for encrypted payload rows.
func RunKeyRotationMetadataJob(ctx context.Context, st Store, oldKeyID, newKeyID string, limit int) (int64, error) {
	report, err := RunKeyRotationJob(ctx, st, oldKeyID, newKeyID, limit)
	if err != nil {
		return 0, err
	}
	return report.UpdatedCount, nil
}

// RunKeyRotationJob rotates encryption-key metadata and persists immutable evidence.
func RunKeyRotationJob(ctx context.Context, st Store, oldKeyID, newKeyID string, limit int) (*KeyRotationReport, error) {
	updated, err := st.RotateEncryptionKeyMetadata(ctx, oldKeyID, newKeyID, limit)
	if err != nil {
		return nil, err
	}

	report := &KeyRotationReport{
		EventID:      "keyrot:" + uuid.NewString(),
		OldKeyID:     oldKeyID,
		NewKeyID:     newKeyID,
		UpdatedCount: updated,
		ExecutedAt:   time.Now().UTC(),
	}

	evidenceInput := map[string]any{
		"event_id":      report.EventID,
		"old_key_id":    report.OldKeyID,
		"new_key_id":    report.NewKeyID,
		"updated_count": report.UpdatedCount,
		"executed_at":   report.ExecutedAt.Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(evidenceInput)
	if err != nil {
		return nil, fmt.Errorf("marshaling key-rotation evidence: %w", err)
	}
	report.EvidenceHash = vaolcrypto.SHA256Prefixed(raw)

	if err := st.SaveKeyRotationEvent(ctx, &KeyRotationEvent{
		EventID:      report.EventID,
		OldKeyID:     report.OldKeyID,
		NewKeyID:     report.NewKeyID,
		UpdatedCount: report.UpdatedCount,
		ExecutedAt:   report.ExecutedAt,
		EvidenceHash: report.EvidenceHash,
		CreatedAt:    report.ExecutedAt,
	}); err != nil {
		return nil, fmt.Errorf("saving key-rotation evidence: %w", err)
	}

	return report, nil
}
