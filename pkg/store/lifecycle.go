package store

import (
	"context"
	"time"
)

// RetentionReport summarizes encrypted payload retention actions.
type RetentionReport struct {
	DeletedCount int                 `json:"deleted_count"`
	Tombstones   []*PayloadTombstone `json:"tombstones"`
	ExecutedAt   time.Time           `json:"executed_at"`
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
	return st.RotateEncryptionKeyMetadata(ctx, oldKeyID, newKeyID, limit)
}
