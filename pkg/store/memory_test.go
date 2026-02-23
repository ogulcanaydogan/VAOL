package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

func TestMemoryStoreAppendAndGet(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	rec := makeTestStoredRecord()
	seq, err := s.Append(ctx, rec)
	if err != nil {
		t.Fatalf("Append error: %v", err)
	}
	if seq != 0 {
		t.Errorf("first sequence = %d, want 0", seq)
	}

	// Get by request ID
	got, err := s.GetByRequestID(ctx, rec.RequestID)
	if err != nil {
		t.Fatalf("GetByRequestID error: %v", err)
	}
	if got.RequestID != rec.RequestID {
		t.Error("RequestID mismatch")
	}
	if got.TenantID != rec.TenantID {
		t.Error("TenantID mismatch")
	}

	// Get by sequence
	got2, err := s.GetBySequence(ctx, 0)
	if err != nil {
		t.Fatalf("GetBySequence error: %v", err)
	}
	if got2.RequestID != rec.RequestID {
		t.Error("RequestID mismatch on GetBySequence")
	}
}

func TestMemoryStoreDuplicateRequestID(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	rec := makeTestStoredRecord()
	if _, err := s.Append(ctx, rec); err != nil {
		t.Fatalf("Append error: %v", err)
	}

	rec2 := makeTestStoredRecord()
	rec2.RequestID = rec.RequestID // duplicate
	_, err := s.Append(ctx, rec2)
	if err != ErrDuplicateRequestID {
		t.Errorf("expected ErrDuplicateRequestID, got: %v", err)
	}
}

func TestMemoryStoreNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	_, err := s.GetByRequestID(ctx, uuid.New())
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	_, err = s.GetBySequence(ctx, 999)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestMemoryStoreGetLatest(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	// Empty store
	_, err := s.GetLatest(ctx)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound on empty store, got: %v", err)
	}

	// Add records
	rec1 := makeTestStoredRecord()
	if _, err := s.Append(ctx, rec1); err != nil {
		t.Fatalf("Append rec1 error: %v", err)
	}
	rec2 := makeTestStoredRecord()
	if _, err := s.Append(ctx, rec2); err != nil {
		t.Fatalf("Append rec2 error: %v", err)
	}

	latest, err := s.GetLatest(ctx)
	if err != nil {
		t.Fatalf("GetLatest error: %v", err)
	}
	if latest.RequestID != rec2.RequestID {
		t.Error("GetLatest should return the most recent record")
	}
}

func TestMemoryStoreList(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	// Insert records for different tenants
	for i := 0; i < 5; i++ {
		rec := makeTestStoredRecord()
		rec.TenantID = "tenant-a"
		if _, err := s.Append(ctx, rec); err != nil {
			t.Fatalf("Append tenant-a record %d error: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		rec := makeTestStoredRecord()
		rec.TenantID = "tenant-b"
		if _, err := s.Append(ctx, rec); err != nil {
			t.Fatalf("Append tenant-b record %d error: %v", i, err)
		}
	}

	// List all
	all, err := s.List(ctx, ListFilter{})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(all) != 8 {
		t.Errorf("List all = %d, want 8", len(all))
	}

	// Filter by tenant
	tenantA, err := s.List(ctx, ListFilter{TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(tenantA) != 5 {
		t.Errorf("List tenant-a = %d, want 5", len(tenantA))
	}

	// Limit
	limited, err := s.List(ctx, ListFilter{Limit: 3})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(limited) != 3 {
		t.Errorf("List limit=3 = %d, want 3", len(limited))
	}
}

func TestMemoryStoreListWithCursor(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	for i := 0; i < 5; i++ {
		rec := makeTestStoredRecord()
		if _, err := s.Append(ctx, rec); err != nil {
			t.Fatalf("Append record %d error: %v", i, err)
		}
	}

	// Get first 2
	page1, _ := s.List(ctx, ListFilter{Limit: 2})
	if len(page1) != 2 {
		t.Fatalf("page1 = %d, want 2", len(page1))
	}

	// Get next using cursor
	cursor := page1[len(page1)-1].SequenceNumber
	page2, _ := s.List(ctx, ListFilter{Limit: 2, Cursor: cursor})
	if len(page2) != 2 {
		t.Errorf("page2 = %d, want 2", len(page2))
	}
	if page2[0].SequenceNumber <= cursor {
		t.Error("cursor pagination should return records after cursor")
	}
}

func TestMemoryStoreCount(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	count, _ := s.Count(ctx)
	if count != 0 {
		t.Errorf("Count on empty = %d, want 0", count)
	}

	for i := 0; i < 3; i++ {
		if _, err := s.Append(ctx, makeTestStoredRecord()); err != nil {
			t.Fatalf("Append record %d error: %v", i, err)
		}
	}

	count, _ = s.Count(ctx)
	if count != 3 {
		t.Errorf("Count = %d, want 3", count)
	}
}

func TestMemoryStoreClose(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
}

func TestMemoryStoreSequentialSequenceNumbers(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	for i := 0; i < 10; i++ {
		seq, err := s.Append(ctx, makeTestStoredRecord())
		if err != nil {
			t.Fatalf("Append record %d error: %v", i, err)
		}
		if seq != int64(i) {
			t.Errorf("sequence %d = %d", i, seq)
		}
	}
}

func TestMemoryStoreProofRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	reqID := uuid.New()
	proof := &StoredProof{
		ProofID:   "proof:test",
		RequestID: reqID,
		Proof: &merkle.Proof{
			ProofType: merkle.ProofTypeInclusion,
			LeafIndex: 0,
			TreeSize:  1,
			RootHash:  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	if err := s.SaveProof(ctx, proof); err != nil {
		t.Fatalf("SaveProof error: %v", err)
	}

	got, err := s.GetProofByID(ctx, "proof:test")
	if err != nil {
		t.Fatalf("GetProofByID error: %v", err)
	}
	if got.RequestID != reqID {
		t.Fatalf("request ID mismatch: got %s want %s", got.RequestID, reqID)
	}
}

func TestMemoryStoreCheckpointRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	cp := &StoredCheckpoint{
		TreeSize: 1,
		RootHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Checkpoint: &merkle.Checkpoint{
			TreeSize: 1,
			RootHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		RekorEntryID: "local:sha256:test",
	}

	if err := s.SaveCheckpoint(ctx, cp); err != nil {
		t.Fatalf("SaveCheckpoint error: %v", err)
	}

	got, err := s.GetLatestCheckpoint(ctx)
	if err != nil {
		t.Fatalf("GetLatestCheckpoint error: %v", err)
	}
	if got.RekorEntryID != cp.RekorEntryID {
		t.Fatalf("rekor entry mismatch: got %s want %s", got.RekorEntryID, cp.RekorEntryID)
	}
}

func TestMemoryStoreMerkleLeafRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	reqID := uuid.New()
	if err := s.SaveMerkleLeaf(ctx, &StoredMerkleLeaf{
		LeafIndex:      0,
		SequenceNumber: 0,
		RequestID:      reqID,
		RecordHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LeafHash:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}); err != nil {
		t.Fatalf("SaveMerkleLeaf: %v", err)
	}

	count, err := s.CountMerkleLeaves(ctx)
	if err != nil {
		t.Fatalf("CountMerkleLeaves: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected merkle leaf count 1, got %d", count)
	}

	leaves, err := s.ListMerkleLeaves(ctx, -1, 10)
	if err != nil {
		t.Fatalf("ListMerkleLeaves: %v", err)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected one leaf, got %d", len(leaves))
	}
	if leaves[0].RequestID != reqID {
		t.Fatalf("request id mismatch: got %s want %s", leaves[0].RequestID, reqID)
	}
}

func TestMemoryStoreMerkleLeafRejectsGap(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	err := s.SaveMerkleLeaf(ctx, &StoredMerkleLeaf{
		LeafIndex:      2,
		SequenceNumber: 2,
		RequestID:      uuid.New(),
		RecordHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LeafHash:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err == nil {
		t.Fatal("expected merkle leaf gap error, got nil")
	}
}

func TestMemoryStoreEncryptedPayloadLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	requestID := uuid.New()
	retainUntil := time.Now().UTC().Add(-1 * time.Hour)

	if err := s.PutEncryptedPayload(ctx, &EncryptedPayload{
		RequestID:       requestID,
		TenantID:        "tenant-a",
		EncryptedOutput: []byte("ciphertext"),
		EncryptionKeyID: "kek-v1",
		CiphertextHash:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RetainUntil:     &retainUntil,
	}); err != nil {
		t.Fatalf("PutEncryptedPayload: %v", err)
	}

	payload, err := s.GetEncryptedPayload(ctx, requestID)
	if err != nil {
		t.Fatalf("GetEncryptedPayload: %v", err)
	}
	if payload.EncryptionKeyID != "kek-v1" {
		t.Fatalf("unexpected key id: %s", payload.EncryptionKeyID)
	}

	rotated, err := s.RotateEncryptionKeyMetadata(ctx, "kek-v1", "kek-v2", 10)
	if err != nil {
		t.Fatalf("RotateEncryptionKeyMetadata: %v", err)
	}
	if rotated != 1 {
		t.Fatalf("expected 1 rotated payload, got %d", rotated)
	}

	tombstones, err := s.DeleteExpiredEncryptedPayloads(ctx, time.Now().UTC(), 10, "retention_expired")
	if err != nil {
		t.Fatalf("DeleteExpiredEncryptedPayloads: %v", err)
	}
	if len(tombstones) != 1 {
		t.Fatalf("expected 1 tombstone, got %d", len(tombstones))
	}

	if _, err := s.GetEncryptedPayload(ctx, requestID); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}

	listed, err := s.ListPayloadTombstones(ctx, "tenant-a", 10)
	if err != nil {
		t.Fatalf("ListPayloadTombstones: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 listed tombstone, got %d", len(listed))
	}
}

func TestMemoryStoreKeyRotationEvents(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	event := &KeyRotationEvent{
		EventID:      "keyrot:1",
		OldKeyID:     "kek-v1",
		NewKeyID:     "kek-v2",
		UpdatedCount: 3,
		ExecutedAt:   time.Now().UTC(),
		EvidenceHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := s.SaveKeyRotationEvent(ctx, event); err != nil {
		t.Fatalf("SaveKeyRotationEvent: %v", err)
	}

	events, err := s.ListKeyRotationEvents(ctx, 10)
	if err != nil {
		t.Fatalf("ListKeyRotationEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].NewKeyID != "kek-v2" {
		t.Fatalf("unexpected new key id %q", events[0].NewKeyID)
	}
}

func makeTestStoredRecord() *StoredRecord {
	return &StoredRecord{
		RequestID:          uuid.New(),
		TenantID:           "test-tenant",
		Timestamp:          time.Now().UTC(),
		RecordHash:         "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		PreviousRecordHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Envelope: &signer.Envelope{
			PayloadType: signer.PayloadType,
			Payload:     "dGVzdA",
			Signatures:  []signer.Signature{{KeyID: "test", Sig: "dGVzdA"}},
		},
		MerkleLeafIndex: 0,
	}
}
