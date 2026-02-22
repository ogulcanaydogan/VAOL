// Package export provides audit bundle creation and formatting for VAOL evidence exports.
package export

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

// Bundle is a portable, self-contained audit evidence package.
// It contains signed records, Merkle proofs, checkpoint data, and privacy
// lifecycle evidence that can be verified offline without access to VAOL.
type Bundle struct {
	Version         string                `json:"version"`
	ExportedAt      time.Time             `json:"exported_at"`
	ExportedBy      string                `json:"exported_by,omitempty"`
	Filter          BundleFilter          `json:"filter"`
	Records         []BundleRecord        `json:"records"`
	Checkpoints     []BundleCheckpoint    `json:"checkpoints"`
	PrivacyEvidence BundlePrivacyEvidence `json:"privacy_evidence,omitempty"`
	Metadata        BundleMetadata        `json:"metadata"`
	Manifest        BundleManifest        `json:"manifest"`
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

// BundlePrivacyEvidence holds immutable retention and key-rotation evidence.
type BundlePrivacyEvidence struct {
	PayloadTombstones []*store.PayloadTombstone `json:"payload_tombstones,omitempty"`
	KeyRotationEvents []*store.KeyRotationEvent `json:"key_rotation_events,omitempty"`
}

// BundleMetadata contains summary information about the bundle.
type BundleMetadata struct {
	TotalRecords   int    `json:"total_records"`
	FirstSequence  int64  `json:"first_sequence"`
	LastSequence   int64  `json:"last_sequence"`
	MerkleRootHash string `json:"merkle_root_hash"`
	MerkleTreeSize int64  `json:"merkle_tree_size"`
}

// BundleManifest is a deterministic digest over the evidence payload.
type BundleManifest struct {
	Algorithm             string `json:"algorithm"`
	EvidenceHash          string `json:"evidence_hash"`
	RecordDigestCount     int    `json:"record_digest_count"`
	CheckpointDigestCount int    `json:"checkpoint_digest_count"`
	PrivacyDigestCount    int    `json:"privacy_digest_count"`
}

// NewBundle creates a new empty bundle.
func NewBundle(filter BundleFilter) *Bundle {
	return &Bundle{
		Version:     "1.0",
		ExportedAt:  time.Now().UTC(),
		Filter:      filter,
		Records:     make([]BundleRecord, 0),
		Checkpoints: make([]BundleCheckpoint, 0),
		Manifest: BundleManifest{
			Algorithm: "sha256",
		},
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

// AddPayloadTombstones appends payload retention tombstones.
func (b *Bundle) AddPayloadTombstones(tombstones []*store.PayloadTombstone) {
	if len(tombstones) == 0 {
		return
	}
	b.PrivacyEvidence.PayloadTombstones = append(b.PrivacyEvidence.PayloadTombstones, tombstones...)
}

// AddKeyRotationEvents appends key-rotation evidence events.
func (b *Bundle) AddKeyRotationEvents(events []*store.KeyRotationEvent) {
	if len(events) == 0 {
		return
	}
	b.PrivacyEvidence.KeyRotationEvents = append(b.PrivacyEvidence.KeyRotationEvents, events...)
}

// Finalize computes metadata and deterministic manifest for the bundle.
func (b *Bundle) Finalize() {
	b.sortEvidenceForDeterminism()

	b.Metadata.TotalRecords = len(b.Records)
	if len(b.Records) > 0 {
		b.Metadata.FirstSequence = b.Records[0].SequenceNumber
		b.Metadata.LastSequence = b.Records[len(b.Records)-1].SequenceNumber
	}
	if len(b.Checkpoints) > 0 {
		latest := b.Checkpoints[len(b.Checkpoints)-1]
		if latest.Checkpoint != nil {
			b.Metadata.MerkleRootHash = latest.Checkpoint.RootHash
			b.Metadata.MerkleTreeSize = latest.Checkpoint.TreeSize
		}
	}

	manifest, err := b.RecomputeManifest()
	if err != nil {
		b.Manifest = BundleManifest{Algorithm: "sha256"}
		return
	}
	b.Manifest = manifest
}

// RecomputeManifest recomputes the deterministic evidence manifest.
func (b *Bundle) RecomputeManifest() (BundleManifest, error) {
	hashInput, recordCount, checkpointCount, privacyCount, err := b.manifestInput()
	if err != nil {
		return BundleManifest{}, err
	}
	return BundleManifest{
		Algorithm:             "sha256",
		EvidenceHash:          vaolcrypto.SHA256Prefixed(hashInput),
		RecordDigestCount:     recordCount,
		CheckpointDigestCount: checkpointCount,
		PrivacyDigestCount:    privacyCount,
	}, nil
}

func (b *Bundle) sortEvidenceForDeterminism() {
	sort.Slice(b.Records, func(i, j int) bool {
		if b.Records[i].SequenceNumber == b.Records[j].SequenceNumber {
			left := ""
			right := ""
			if b.Records[i].Envelope != nil {
				left = b.Records[i].Envelope.Payload
			}
			if b.Records[j].Envelope != nil {
				right = b.Records[j].Envelope.Payload
			}
			return left < right
		}
		return b.Records[i].SequenceNumber < b.Records[j].SequenceNumber
	})

	sort.Slice(b.Checkpoints, func(i, j int) bool {
		left := b.Checkpoints[i]
		right := b.Checkpoints[j]
		leftSize := int64(0)
		rightSize := int64(0)
		leftRoot := ""
		rightRoot := ""
		if left.Checkpoint != nil {
			leftSize = left.Checkpoint.TreeSize
			leftRoot = left.Checkpoint.RootHash
		}
		if right.Checkpoint != nil {
			rightSize = right.Checkpoint.TreeSize
			rightRoot = right.Checkpoint.RootHash
		}
		if leftSize == rightSize {
			return leftRoot < rightRoot
		}
		return leftSize < rightSize
	})

	sort.Slice(b.PrivacyEvidence.PayloadTombstones, func(i, j int) bool {
		return b.PrivacyEvidence.PayloadTombstones[i].TombstoneID < b.PrivacyEvidence.PayloadTombstones[j].TombstoneID
	})
	sort.Slice(b.PrivacyEvidence.KeyRotationEvents, func(i, j int) bool {
		return b.PrivacyEvidence.KeyRotationEvents[i].EventID < b.PrivacyEvidence.KeyRotationEvents[j].EventID
	})
}

func (b *Bundle) manifestInput() ([]byte, int, int, int, error) {
	type manifestRecord struct {
		SequenceNumber     int64  `json:"sequence_number"`
		EnvelopeHash       string `json:"envelope_hash"`
		InclusionProofHash string `json:"inclusion_proof_hash,omitempty"`
	}
	type manifestCheckpoint struct {
		CheckpointHash string `json:"checkpoint_hash"`
	}
	type manifestPrivacy struct {
		PayloadTombstoneHashes []string `json:"payload_tombstone_hashes,omitempty"`
		KeyRotationHashes      []string `json:"key_rotation_hashes,omitempty"`
	}
	type manifestInput struct {
		Version     string               `json:"version"`
		Filter      BundleFilter         `json:"filter"`
		Metadata    BundleMetadata       `json:"metadata"`
		Records     []manifestRecord     `json:"records"`
		Checkpoints []manifestCheckpoint `json:"checkpoints"`
		Privacy     manifestPrivacy      `json:"privacy"`
	}

	records := make([]manifestRecord, 0, len(b.Records))
	for _, rec := range b.Records {
		envHash, err := hashValue(rec.Envelope)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("hashing envelope: %w", err)
		}
		proofHash := ""
		if rec.InclusionProof != nil {
			proofHash, err = hashValue(rec.InclusionProof)
			if err != nil {
				return nil, 0, 0, 0, fmt.Errorf("hashing inclusion proof: %w", err)
			}
		}
		records = append(records, manifestRecord{
			SequenceNumber:     rec.SequenceNumber,
			EnvelopeHash:       envHash,
			InclusionProofHash: proofHash,
		})
	}

	checkpoints := make([]manifestCheckpoint, 0, len(b.Checkpoints))
	for _, cp := range b.Checkpoints {
		hash, err := hashValue(cp)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("hashing checkpoint: %w", err)
		}
		checkpoints = append(checkpoints, manifestCheckpoint{CheckpointHash: hash})
	}

	privacy := manifestPrivacy{}
	for _, ts := range b.PrivacyEvidence.PayloadTombstones {
		h, err := hashValue(ts)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("hashing payload tombstone: %w", err)
		}
		privacy.PayloadTombstoneHashes = append(privacy.PayloadTombstoneHashes, h)
	}
	for _, evt := range b.PrivacyEvidence.KeyRotationEvents {
		h, err := hashValue(evt)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("hashing key rotation event: %w", err)
		}
		privacy.KeyRotationHashes = append(privacy.KeyRotationHashes, h)
	}

	input := manifestInput{
		Version:     b.Version,
		Filter:      b.Filter,
		Metadata:    b.Metadata,
		Records:     records,
		Checkpoints: checkpoints,
		Privacy:     privacy,
	}

	raw, err := json.Marshal(input)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("marshaling manifest input: %w", err)
	}
	return raw, len(records), len(checkpoints), len(privacy.PayloadTombstoneHashes) + len(privacy.KeyRotationHashes), nil
}

func hashValue(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return vaolcrypto.SHA256Prefixed(raw), nil
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
