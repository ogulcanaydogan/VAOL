package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

func TestNewBundle(t *testing.T) {
	filter := BundleFilter{TenantID: "acme"}
	b := NewBundle(filter)

	if b.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", b.Version)
	}
	if b.Filter.TenantID != "acme" {
		t.Errorf("expected tenant_id acme, got %s", b.Filter.TenantID)
	}
	if len(b.Records) != 0 {
		t.Errorf("expected empty records, got %d", len(b.Records))
	}
	if b.ExportedAt.IsZero() {
		t.Error("exported_at should not be zero")
	}
	if b.Manifest.Algorithm != "sha256" {
		t.Errorf("expected manifest algorithm sha256, got %s", b.Manifest.Algorithm)
	}
}

func TestBundleAddRecord(t *testing.T) {
	b := NewBundle(BundleFilter{})
	b.AddRecord(BundleRecord{SequenceNumber: 0, Envelope: &signer.Envelope{PayloadType: "test"}})
	b.AddRecord(BundleRecord{SequenceNumber: 1, Envelope: &signer.Envelope{PayloadType: "test"}})

	if len(b.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(b.Records))
	}
	if b.Records[0].SequenceNumber != 0 {
		t.Errorf("first record sequence: expected 0, got %d", b.Records[0].SequenceNumber)
	}
	if b.Records[1].SequenceNumber != 1 {
		t.Errorf("second record sequence: expected 1, got %d", b.Records[1].SequenceNumber)
	}
}

func TestBundleAddCheckpoint(t *testing.T) {
	b := NewBundle(BundleFilter{})
	cp := BundleCheckpoint{
		Checkpoint:   &merkle.Checkpoint{TreeSize: 10, RootHash: "sha256:abc"},
		RekorEntryID: "rekor-123",
	}
	b.AddCheckpoint(cp)

	if len(b.Checkpoints) != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", len(b.Checkpoints))
	}
	if b.Checkpoints[0].RekorEntryID != "rekor-123" {
		t.Errorf("expected rekor-123, got %s", b.Checkpoints[0].RekorEntryID)
	}
}

func TestBundleFinalize(t *testing.T) {
	b := NewBundle(BundleFilter{})
	for i := int64(0); i < 5; i++ {
		b.AddRecord(BundleRecord{
			SequenceNumber: i,
			Envelope:       &signer.Envelope{PayloadType: "test"},
		})
	}
	b.AddCheckpoint(BundleCheckpoint{
		Checkpoint: &merkle.Checkpoint{
			TreeSize: 5,
			RootHash: "sha256:rootabc",
		},
	})

	b.Finalize()

	if b.Metadata.TotalRecords != 5 {
		t.Errorf("expected 5 total records, got %d", b.Metadata.TotalRecords)
	}
	if b.Metadata.FirstSequence != 0 {
		t.Errorf("expected first_sequence=0, got %d", b.Metadata.FirstSequence)
	}
	if b.Metadata.LastSequence != 4 {
		t.Errorf("expected last_sequence=4, got %d", b.Metadata.LastSequence)
	}
	if b.Metadata.MerkleRootHash != "sha256:rootabc" {
		t.Errorf("expected merkle_root_hash from checkpoint, got %s", b.Metadata.MerkleRootHash)
	}
	if b.Metadata.MerkleTreeSize != 5 {
		t.Errorf("expected tree_size=5, got %d", b.Metadata.MerkleTreeSize)
	}
}

func TestBundleFinalize_Empty(t *testing.T) {
	b := NewBundle(BundleFilter{})
	b.Finalize()

	if b.Metadata.TotalRecords != 0 {
		t.Errorf("expected 0 total records, got %d", b.Metadata.TotalRecords)
	}
	if b.Manifest.EvidenceHash == "" {
		t.Error("expected manifest evidence hash")
	}
}

func TestBundleMarshalUnmarshal(t *testing.T) {
	b := NewBundle(BundleFilter{TenantID: "roundtrip-test"})
	b.AddRecord(BundleRecord{
		SequenceNumber: 42,
		Envelope: &signer.Envelope{
			PayloadType: "test",
			Payload:     "dGVzdA",
			Signatures:  []signer.Signature{{KeyID: "k1", Sig: "s1"}},
		},
	})
	b.Finalize()

	data, err := b.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if restored.Version != "1.0" {
		t.Errorf("version mismatch: %s", restored.Version)
	}
	if restored.Filter.TenantID != "roundtrip-test" {
		t.Errorf("tenant mismatch: %s", restored.Filter.TenantID)
	}
	if len(restored.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(restored.Records))
	}
	if restored.Records[0].SequenceNumber != 42 {
		t.Errorf("sequence mismatch: %d", restored.Records[0].SequenceNumber)
	}
}

func TestUnmarshal_Invalid(t *testing.T) {
	_, err := Unmarshal([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBundleFilter_TimeRange(t *testing.T) {
	now := time.Now().UTC()
	after := now.Add(-24 * time.Hour)
	before := now
	filter := BundleFilter{
		TenantID: "time-test",
		After:    &after,
		Before:   &before,
	}

	b := NewBundle(filter)
	data, err := b.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	restored, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.Filter.After == nil || restored.Filter.Before == nil {
		t.Error("time filters lost during roundtrip")
	}
}

func TestWriteReadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-bundle.json")

	b := NewBundle(BundleFilter{TenantID: "file-test"})
	b.AddRecord(BundleRecord{
		SequenceNumber: 0,
		Envelope:       &signer.Envelope{PayloadType: "test", Payload: "dGVzdA"},
	})
	b.Finalize()

	if err := WriteJSON(b, path); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Verify file exists
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("file is empty")
	}

	restored, err := ReadJSON(path)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if restored.Filter.TenantID != "file-test" {
		t.Errorf("tenant mismatch after read: %s", restored.Filter.TenantID)
	}
	if len(restored.Records) != 1 {
		t.Errorf("expected 1 record, got %d", len(restored.Records))
	}
}

func TestReadJSON_FileNotExist(t *testing.T) {
	_, err := ReadJSON("/nonexistent/path.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestFormatRecordSummary(t *testing.T) {
	rec := BundleRecord{
		SequenceNumber: 7,
		Envelope: &signer.Envelope{
			PayloadType: "test",
			Signatures: []signer.Signature{
				{KeyID: "k1", Sig: "s1"},
				{KeyID: "k2", Sig: "s2"},
			},
		},
	}

	summary := FormatRecordSummary(rec)
	if summary != "seq=7 sigs=2" {
		t.Errorf("unexpected summary: %s", summary)
	}
}

func TestBundleJSONStructure(t *testing.T) {
	b := NewBundle(BundleFilter{TenantID: "structure-test"})
	b.Finalize()

	data, _ := b.Marshal()

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON structure: %v", err)
	}

	requiredKeys := []string{"version", "exported_at", "filter", "records", "checkpoints", "metadata", "manifest"}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing required key: %s", key)
		}
	}
}

func TestBundleManifestDeterministic(t *testing.T) {
	b := NewBundle(BundleFilter{TenantID: "deterministic"})
	b.AddRecord(BundleRecord{
		SequenceNumber: 2,
		Envelope: &signer.Envelope{
			PayloadType: "test",
			Payload:     "bbb",
		},
	})
	b.AddRecord(BundleRecord{
		SequenceNumber: 1,
		Envelope: &signer.Envelope{
			PayloadType: "test",
			Payload:     "aaa",
		},
	})
	b.AddKeyRotationEvents([]*store.KeyRotationEvent{
		{
			EventID:      "keyrot:2",
			OldKeyID:     "k1",
			NewKeyID:     "k2",
			UpdatedCount: 5,
			ExecutedAt:   time.Date(2026, 2, 22, 20, 0, 0, 0, time.UTC),
			EvidenceHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	})
	b.Finalize()
	firstHash := b.Manifest.EvidenceHash
	if firstHash == "" {
		t.Fatal("expected manifest hash")
	}

	manifest, err := b.RecomputeManifest()
	if err != nil {
		t.Fatalf("RecomputeManifest: %v", err)
	}
	if manifest.EvidenceHash != firstHash {
		t.Fatalf("manifest hash mismatch: got %s want %s", manifest.EvidenceHash, firstHash)
	}

	b.Records[0].Envelope.Payload = "tampered"
	manifest2, err := b.RecomputeManifest()
	if err != nil {
		t.Fatalf("RecomputeManifest after tamper: %v", err)
	}
	if manifest2.EvidenceHash == firstHash {
		t.Fatal("expected manifest hash to change after tamper")
	}
}
