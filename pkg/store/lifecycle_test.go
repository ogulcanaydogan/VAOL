package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRunRetentionAndRotationJobs(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	reqID := uuid.New()
	retainUntil := time.Now().UTC().Add(-2 * time.Hour)

	if err := st.PutEncryptedPayload(ctx, &EncryptedPayload{
		RequestID:       reqID,
		TenantID:        "tenant-1",
		EncryptedOutput: []byte("cipher"),
		EncryptionKeyID: "kek-v1",
		CiphertextHash:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RetainUntil:     &retainUntil,
	}); err != nil {
		t.Fatalf("PutEncryptedPayload: %v", err)
	}

	rotated, err := RunKeyRotationMetadataJob(ctx, st, "kek-v1", "kek-v2", 10)
	if err != nil {
		t.Fatalf("RunKeyRotationMetadataJob: %v", err)
	}
	if rotated != 1 {
		t.Fatalf("expected 1 rotated row, got %d", rotated)
	}

	report, err := RunRetentionJob(ctx, st, time.Now().UTC(), 10, "retention_expired")
	if err != nil {
		t.Fatalf("RunRetentionJob: %v", err)
	}
	if report.DeletedCount != 1 {
		t.Fatalf("expected 1 deleted row, got %d", report.DeletedCount)
	}

	events, err := st.ListKeyRotationEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListKeyRotationEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 key rotation event, got %d", len(events))
	}
	if events[0].EvidenceHash == "" {
		t.Fatal("expected key rotation evidence hash")
	}
}
