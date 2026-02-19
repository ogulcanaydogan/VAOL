// Package export provides audit bundle creation and formatting for VAOL evidence exports.
package export

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/signer"
)

// Bundle is a portable, self-contained audit evidence package.
// It contains signed records, Merkle proofs, and checkpoint data
// that can be verified offline without access to the VAOL server.
type Bundle struct {
	Version     string           `json:"version"`
	ExportedAt  time.Time        `json:"exported_at"`
	ExportedBy  string           `json:"exported_by,omitempty"`
	Filter      BundleFilter     `json:"filter"`
	Records     []BundleRecord   `json:"records"`
	Checkpoints []BundleCheckpoint `json:"checkpoints"`
	Metadata    BundleMetadata   `json:"metadata"`
}

// BundleFilter describes the criteria used to select records for this bundle.
type BundleFilter struct {
	TenantID       string     `json:"tenant_id,omitempty"`
	After          *time.Time `json:"after,omitempty"`
	Before         *time.Time `json:"before,omitempty"`
	PolicyDecision string     `json:"policy_decision,omitempty"`
}

// BundleRecord is a single record within an audit bundle.
type BundleRecord struct {
	SequenceNumber int64            `json:"sequence_number"`
	Envelope       *signer.Envelope `json:"dsse_envelope"`
	InclusionProof *merkle.Proof    `json:"inclusion_proof,omitempty"`
}

// BundleCheckpoint is a signed Merkle checkpoint included in the bundle.
type BundleCheckpoint struct {
	Checkpoint   *merkle.Checkpoint `json:"checkpoint"`
	RekorEntryID string             `json:"rekor_entry_id,omitempty"`
}

// BundleMetadata contains summary information about the bundle.
type BundleMetadata struct {
	TotalRecords   int    `json:"total_records"`
	FirstSequence  int64  `json:"first_sequence"`
	LastSequence   int64  `json:"last_sequence"`
	MerkleRootHash string `json:"merkle_root_hash"`
	MerkleTreeSize int64  `json:"merkle_tree_size"`
}

// NewBundle creates a new empty bundle.
func NewBundle(filter BundleFilter) *Bundle {
	return &Bundle{
		Version:    "1.0",
		ExportedAt: time.Now().UTC(),
		Filter:     filter,
		Records:    make([]BundleRecord, 0),
		Checkpoints: make([]BundleCheckpoint, 0),
	}
}

// AddRecord adds a record to the bundle.
func (b *Bundle) AddRecord(rec BundleRecord) {
	b.Records = append(b.Records, rec)
}

// AddCheckpoint adds a checkpoint to the bundle.
func (b *Bundle) AddCheckpoint(cp BundleCheckpoint) {
	b.Checkpoints = append(b.Checkpoints, cp)
}

// Finalize computes the metadata for the bundle.
func (b *Bundle) Finalize() {
	b.Metadata.TotalRecords = len(b.Records)
	if len(b.Records) > 0 {
		b.Metadata.FirstSequence = b.Records[0].SequenceNumber
		b.Metadata.LastSequence = b.Records[len(b.Records)-1].SequenceNumber
	}
	if len(b.Checkpoints) > 0 {
		latest := b.Checkpoints[len(b.Checkpoints)-1]
		b.Metadata.MerkleRootHash = latest.Checkpoint.RootHash
		b.Metadata.MerkleTreeSize = latest.Checkpoint.TreeSize
	}
}

// Marshal serializes the bundle to indented JSON.
func (b *Bundle) Marshal() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// Unmarshal deserializes a bundle from JSON.
func Unmarshal(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}
	return &b, nil
}
