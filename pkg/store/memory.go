package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore is an in-memory append-only store for testing and development.
type MemoryStore struct {
	mu           sync.RWMutex
	records      []*StoredRecord
	byReqID      map[uuid.UUID]*StoredRecord
	merkleLeaves []*StoredMerkleLeaf
	proofs       map[string]*StoredProof
	checkpoints  []*StoredCheckpoint
	encrypted    map[uuid.UUID]*EncryptedPayload
	tombstones   []*PayloadTombstone
	keyRotations []*KeyRotationEvent
	sequence     int64
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records:      make([]*StoredRecord, 0, 1024),
		byReqID:      make(map[uuid.UUID]*StoredRecord),
		merkleLeaves: make([]*StoredMerkleLeaf, 0, 1024),
		proofs:       make(map[string]*StoredProof),
		checkpoints:  make([]*StoredCheckpoint, 0, 64),
		encrypted:    make(map[uuid.UUID]*EncryptedPayload),
		tombstones:   make([]*PayloadTombstone, 0, 64),
		keyRotations: make([]*KeyRotationEvent, 0, 32),
	}
}

func (m *MemoryStore) Append(_ context.Context, rec *StoredRecord) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.byReqID[rec.RequestID]; exists {
		return 0, ErrDuplicateRequestID
	}

	rec.SequenceNumber = m.sequence
	rec.CreatedAt = time.Now().UTC()
	m.sequence++

	// Deep copy to prevent external mutation
	stored := *rec
	m.records = append(m.records, &stored)
	m.byReqID[rec.RequestID] = &stored

	return stored.SequenceNumber, nil
}

func (m *MemoryStore) GetByRequestID(_ context.Context, requestID uuid.UUID) (*StoredRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.byReqID[requestID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *MemoryStore) GetBySequence(_ context.Context, seq int64) (*StoredRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if seq < 0 || seq >= int64(len(m.records)) {
		return nil, ErrNotFound
	}
	cp := *m.records[seq]
	return &cp, nil
}

func (m *MemoryStore) GetLatest(_ context.Context) (*StoredRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.records) == 0 {
		return nil, ErrNotFound
	}
	cp := *m.records[len(m.records)-1]
	return &cp, nil
}

func (m *MemoryStore) List(_ context.Context, filter ListFilter) ([]*StoredRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var results []*StoredRecord
	for _, rec := range m.records {
		if rec.SequenceNumber <= filter.Cursor && filter.Cursor > 0 {
			continue
		}
		if filter.TenantID != "" && rec.TenantID != filter.TenantID {
			continue
		}
		if filter.After != nil && rec.Timestamp.Before(*filter.After) {
			continue
		}
		if filter.Before != nil && rec.Timestamp.After(*filter.Before) {
			continue
		}

		cp := *rec
		results = append(results, &cp)
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

func (m *MemoryStore) Count(_ context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.records)), nil
}

func (m *MemoryStore) SaveProof(_ context.Context, proof *StoredProof) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if proof == nil || proof.ProofID == "" {
		return ErrNotFound
	}
	cp := *proof
	cp.CreatedAt = time.Now().UTC()
	m.proofs[proof.ProofID] = &cp
	return nil
}

func (m *MemoryStore) GetProofByID(_ context.Context, proofID string) (*StoredProof, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	proof, ok := m.proofs[proofID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *proof
	return &cp, nil
}

func (m *MemoryStore) SaveCheckpoint(_ context.Context, checkpoint *StoredCheckpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if checkpoint == nil || checkpoint.Checkpoint == nil {
		return ErrNotFound
	}
	cp := *checkpoint
	cp.CreatedAt = time.Now().UTC()
	m.checkpoints = append(m.checkpoints, &cp)
	return nil
}

func (m *MemoryStore) GetLatestCheckpoint(_ context.Context) (*StoredCheckpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.checkpoints) == 0 {
		return nil, ErrNotFound
	}
	cp := *m.checkpoints[len(m.checkpoints)-1]
	return &cp, nil
}

func (m *MemoryStore) Close() error {
	return nil
}

func (m *MemoryStore) SaveMerkleLeaf(_ context.Context, leaf *StoredMerkleLeaf) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if leaf == nil {
		return fmt.Errorf("leaf is required")
	}
	if leaf.RequestID == uuid.Nil {
		return fmt.Errorf("request_id is required")
	}
	if leaf.RecordHash == "" {
		return fmt.Errorf("record_hash is required")
	}
	if leaf.LeafHash == "" {
		return fmt.Errorf("leaf_hash is required")
	}
	if leaf.LeafIndex < 0 {
		return fmt.Errorf("leaf_index must be non-negative")
	}

	next := int64(len(m.merkleLeaves))
	if leaf.LeafIndex > next {
		return fmt.Errorf("merkle leaf gap: got index %d expected %d", leaf.LeafIndex, next)
	}

	if leaf.LeafIndex < next {
		existing := m.merkleLeaves[leaf.LeafIndex]
		if existing.RequestID == leaf.RequestID &&
			existing.RecordHash == leaf.RecordHash &&
			existing.LeafHash == leaf.LeafHash &&
			existing.SequenceNumber == leaf.SequenceNumber {
			return nil
		}
		return fmt.Errorf("merkle leaf conflict at index %d", leaf.LeafIndex)
	}

	cp := *leaf
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	m.merkleLeaves = append(m.merkleLeaves, &cp)
	return nil
}

func (m *MemoryStore) ListMerkleLeaves(_ context.Context, cursor int64, limit int) ([]*StoredMerkleLeaf, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	out := make([]*StoredMerkleLeaf, 0, limit)
	for _, leaf := range m.merkleLeaves {
		if leaf.LeafIndex <= cursor {
			continue
		}
		cp := *leaf
		out = append(out, &cp)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) CountMerkleLeaves(_ context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.merkleLeaves)), nil
}

func (m *MemoryStore) PutEncryptedPayload(_ context.Context, payload *EncryptedPayload) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if payload == nil {
		return fmt.Errorf("payload is required")
	}
	if payload.RequestID == uuid.Nil {
		return fmt.Errorf("request_id is required")
	}
	if payload.EncryptionKeyID == "" {
		return fmt.Errorf("encryption_key_id is required")
	}
	cp := *payload
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	m.encrypted[payload.RequestID] = &cp
	return nil
}

func (m *MemoryStore) GetEncryptedPayload(_ context.Context, requestID uuid.UUID) (*EncryptedPayload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	payload, ok := m.encrypted[requestID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *payload
	return &cp, nil
}

func (m *MemoryStore) DeleteExpiredEncryptedPayloads(_ context.Context, before time.Time, limit int, reason string) ([]*PayloadTombstone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 {
		limit = 100
	}
	if reason == "" {
		reason = "retention_expired"
	}

	type candidate struct {
		requestID uuid.UUID
		payload   *EncryptedPayload
	}
	candidates := make([]candidate, 0, len(m.encrypted))
	for reqID, payload := range m.encrypted {
		if payload.RetainUntil == nil || payload.RetainUntil.After(before) {
			continue
		}
		candidates = append(candidates, candidate{requestID: reqID, payload: payload})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].payload.RetainUntil.Before(*candidates[j].payload.RetainUntil)
	})

	out := make([]*PayloadTombstone, 0, limit)
	for _, c := range candidates {
		if len(out) >= limit {
			break
		}
		ts := &PayloadTombstone{
			TombstoneID:     "tombstone:" + uuid.NewString(),
			RequestID:       c.requestID,
			TenantID:        c.payload.TenantID,
			CiphertextHash:  c.payload.CiphertextHash,
			EncryptionKeyID: c.payload.EncryptionKeyID,
			DeletedAt:       before.UTC(),
			DeleteReason:    reason,
			CreatedAt:       time.Now().UTC(),
		}
		m.tombstones = append(m.tombstones, ts)
		out = append(out, ts)
		delete(m.encrypted, c.requestID)
	}
	return out, nil
}

func (m *MemoryStore) RotateEncryptionKeyMetadata(_ context.Context, oldKeyID, newKeyID string, limit int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if oldKeyID == "" || newKeyID == "" {
		return 0, fmt.Errorf("old and new key IDs are required")
	}
	if limit <= 0 {
		limit = 1000
	}

	updated := int64(0)
	now := time.Now().UTC()
	for _, payload := range m.encrypted {
		if payload.EncryptionKeyID != oldKeyID {
			continue
		}
		payload.EncryptionKeyID = newKeyID
		payload.RotatedAt = &now
		updated++
		if updated >= int64(limit) {
			break
		}
	}
	return updated, nil
}

func (m *MemoryStore) ListPayloadTombstones(_ context.Context, tenantID string, limit int) ([]*PayloadTombstone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	out := make([]*PayloadTombstone, 0, limit)
	for _, ts := range m.tombstones {
		if tenantID != "" && ts.TenantID != tenantID {
			continue
		}
		cp := *ts
		out = append(out, &cp)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) SaveKeyRotationEvent(_ context.Context, event *KeyRotationEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if event == nil {
		return fmt.Errorf("event is required")
	}
	cp := *event
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	m.keyRotations = append(m.keyRotations, &cp)
	return nil
}

func (m *MemoryStore) ListKeyRotationEvents(_ context.Context, limit int) ([]*KeyRotationEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	out := make([]*KeyRotationEvent, 0, limit)
	for _, evt := range m.keyRotations {
		cp := *evt
		out = append(out, &cp)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
