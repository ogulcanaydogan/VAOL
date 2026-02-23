// Package store provides the append-only storage backend for VAOL decision records.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

// StoredRecord is the persisted form of a signed decision record.
type StoredRecord struct {
	SequenceNumber     int64            `json:"sequence_number"`
	RequestID          uuid.UUID        `json:"request_id"`
	TenantID           string           `json:"tenant_id"`
	Timestamp          time.Time        `json:"timestamp"`
	RecordHash         string           `json:"record_hash"`
	PreviousRecordHash string           `json:"previous_record_hash"`
	Envelope           *signer.Envelope `json:"dsse_envelope"`
	MerkleLeafIndex    int64            `json:"merkle_leaf_index"`
	CreatedAt          time.Time        `json:"created_at"`
}

// StoredProof is a persisted inclusion proof entry addressable by a stable ID.
type StoredProof struct {
	ProofID   string        `json:"proof_id"`
	RequestID uuid.UUID     `json:"request_id"`
	Proof     *merkle.Proof `json:"proof"`
	CreatedAt time.Time     `json:"created_at"`
}

// StoredCheckpoint is a persisted signed checkpoint entry.
type StoredCheckpoint struct {
	TreeSize     int64              `json:"tree_size"`
	RootHash     string             `json:"root_hash"`
	Checkpoint   *merkle.Checkpoint `json:"checkpoint"`
	RekorEntryID string             `json:"rekor_entry_id,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
}

// StoredMerkleLeaf is a persisted RFC 6962 leaf hash entry.
type StoredMerkleLeaf struct {
	LeafIndex      int64     `json:"leaf_index"`
	SequenceNumber int64     `json:"sequence_number"`
	RequestID      uuid.UUID `json:"request_id"`
	RecordHash     string    `json:"record_hash"`
	LeafHash       string    `json:"leaf_hash"`
	CreatedAt      time.Time `json:"created_at"`
}

// EncryptedPayload stores encrypted prompt/output blobs and lifecycle metadata.
type EncryptedPayload struct {
	RequestID       uuid.UUID  `json:"request_id"`
	TenantID        string     `json:"tenant_id"`
	EncryptedPrompt []byte     `json:"encrypted_prompt,omitempty"`
	EncryptedOutput []byte     `json:"encrypted_output,omitempty"`
	EncryptionKeyID string     `json:"encryption_key_id"`
	CiphertextHash  string     `json:"ciphertext_hash,omitempty"`
	PlaintextHash   string     `json:"plaintext_hash,omitempty"`
	RetainUntil     *time.Time `json:"retain_until,omitempty"`
	RotatedAt       *time.Time `json:"rotated_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// PayloadTombstone is immutable evidence that an encrypted payload was deleted.
type PayloadTombstone struct {
	TombstoneID     string    `json:"tombstone_id"`
	RequestID       uuid.UUID `json:"request_id"`
	TenantID        string    `json:"tenant_id"`
	CiphertextHash  string    `json:"ciphertext_hash"`
	EncryptionKeyID string    `json:"encryption_key_id"`
	DeletedAt       time.Time `json:"deleted_at"`
	DeleteReason    string    `json:"delete_reason"`
	CreatedAt       time.Time `json:"created_at"`
}

// KeyRotationEvent is immutable evidence for an encryption key metadata rotation run.
type KeyRotationEvent struct {
	EventID      string    `json:"event_id"`
	OldKeyID     string    `json:"old_key_id"`
	NewKeyID     string    `json:"new_key_id"`
	UpdatedCount int64     `json:"updated_count"`
	ExecutedAt   time.Time `json:"executed_at"`
	EvidenceHash string    `json:"evidence_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// ListFilter specifies criteria for listing records.
type ListFilter struct {
	TenantID       string
	After          *time.Time
	Before         *time.Time
	Model          string
	PolicyDecision string
	Limit          int
	Cursor         int64 // sequence_number to start after
}

// Store is the interface for the append-only ledger storage backend.
type Store interface {
	// Append adds a new signed record to the ledger. Returns the assigned sequence number.
	Append(ctx context.Context, rec *StoredRecord) (int64, error)

	// GetByRequestID retrieves a record by its request ID.
	GetByRequestID(ctx context.Context, requestID uuid.UUID) (*StoredRecord, error)

	// GetBySequence retrieves a record by its sequence number.
	GetBySequence(ctx context.Context, seq int64) (*StoredRecord, error)

	// GetLatest returns the most recent record in the ledger.
	GetLatest(ctx context.Context) (*StoredRecord, error)

	// List returns records matching the filter criteria.
	List(ctx context.Context, filter ListFilter) ([]*StoredRecord, error)

	// Count returns the total number of records in the ledger.
	Count(ctx context.Context) (int64, error)

	// PutEncryptedPayload upserts encrypted payload blobs and lifecycle metadata.
	PutEncryptedPayload(ctx context.Context, payload *EncryptedPayload) error

	// GetEncryptedPayload fetches encrypted payload metadata by request ID.
	GetEncryptedPayload(ctx context.Context, requestID uuid.UUID) (*EncryptedPayload, error)

	// DeleteExpiredEncryptedPayloads deletes expired payloads and emits tombstones.
	DeleteExpiredEncryptedPayloads(ctx context.Context, before time.Time, limit int, reason string) ([]*PayloadTombstone, error)

	// RotateEncryptionKeyMetadata updates encryption key metadata for payloads.
	RotateEncryptionKeyMetadata(ctx context.Context, oldKeyID, newKeyID string, limit int) (int64, error)

	// ListPayloadTombstones lists payload deletion tombstones (tenant optional).
	ListPayloadTombstones(ctx context.Context, tenantID string, limit int) ([]*PayloadTombstone, error)

	// SaveKeyRotationEvent persists immutable key-rotation evidence metadata.
	SaveKeyRotationEvent(ctx context.Context, event *KeyRotationEvent) error

	// ListKeyRotationEvents lists key-rotation evidence events.
	ListKeyRotationEvents(ctx context.Context, limit int) ([]*KeyRotationEvent, error)

	// SaveProof stores an inclusion proof and returns the assigned proof ID.
	SaveProof(ctx context.Context, proof *StoredProof) error

	// GetProofByID retrieves a previously stored inclusion proof by ID.
	GetProofByID(ctx context.Context, proofID string) (*StoredProof, error)

	// SaveCheckpoint stores a signed Merkle checkpoint.
	SaveCheckpoint(ctx context.Context, checkpoint *StoredCheckpoint) error

	// GetLatestCheckpoint retrieves the latest signed checkpoint.
	GetLatestCheckpoint(ctx context.Context) (*StoredCheckpoint, error)

	// Close releases any resources held by the store.
	Close() error
}

// MerkleLeafStore is an optional extension for stores that persist Merkle leaf hashes.
// When implemented, API startup can restore the in-memory Merkle tree from these
// persisted leaves without replaying full decision records.
type MerkleLeafStore interface {
	SaveMerkleLeaf(ctx context.Context, leaf *StoredMerkleLeaf) error
	ListMerkleLeaves(ctx context.Context, cursor int64, limit int) ([]*StoredMerkleLeaf, error)
	CountMerkleLeaves(ctx context.Context) (int64, error)
}

// ErrNotFound is returned when a record is not found.
var ErrNotFound = fmt.Errorf("record not found")

// ErrDuplicateRequestID is returned when a record with the same request_id already exists.
var ErrDuplicateRequestID = fmt.Errorf("duplicate request_id")
