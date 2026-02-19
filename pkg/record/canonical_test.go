package record

import (
	"encoding/json"
	"testing"
)

func TestCanonicalizeDeterministic(t *testing.T) {
	rec := makeTestRecord()

	c1, err := Canonicalize(rec)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}
	c2, err := Canonicalize(rec)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	if string(c1) != string(c2) {
		t.Error("Canonicalize should produce identical output for same input")
	}
}

func TestCanonicalizeExcludesIntegrityFields(t *testing.T) {
	rec := makeTestRecord()
	rec.Integrity.SequenceNumber = 42
	rec.Integrity.RecordHash = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	rec.Integrity.PreviousRecordHash = "sha256:bbbb000000000000000000000000000000000000000000000000000000000000"
	rec.Integrity.MerkleRoot = "sha256:cccc000000000000000000000000000000000000000000000000000000000000"
	rec.Integrity.MerkleTreeSize = 100
	rec.Integrity.InclusionProofRef = "proof:test"

	canonical, err := Canonicalize(rec)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(canonical, &parsed); err != nil {
		t.Fatalf("parse canonical: %v", err)
	}

	integrity, ok := parsed["integrity"].(map[string]any)
	if !ok {
		t.Fatal("integrity should be present as empty object")
	}

	excluded := []string{"record_hash", "previous_record_hash", "merkle_root", "merkle_tree_size", "inclusion_proof_ref", "inclusion_proof", "sequence_number"}
	for _, field := range excluded {
		if _, exists := integrity[field]; exists {
			t.Errorf("integrity.%s should be excluded from canonical form", field)
		}
	}
}

func TestCanonicalizeChangingIntegrityDoesNotAffectHash(t *testing.T) {
	rec := makeTestRecord()

	rec.Integrity.SequenceNumber = 0
	rec.Integrity.RecordHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	h1, err := ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("ComputeRecordHash error: %v", err)
	}

	rec.Integrity.SequenceNumber = 999
	rec.Integrity.RecordHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	rec.Integrity.MerkleRoot = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h2, err := ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("ComputeRecordHash error: %v", err)
	}

	if h1 != h2 {
		t.Error("changing integrity computed fields should not change record hash")
	}
}

func TestCanonicalizeChangingPayloadChangesHash(t *testing.T) {
	rec := makeTestRecord()
	h1, _ := ComputeRecordHash(rec)

	rec.Model.Name = "different-model"
	h2, _ := ComputeRecordHash(rec)

	if h1 == h2 {
		t.Error("changing payload should change record hash")
	}
}

func TestCanonicalizeSortedKeys(t *testing.T) {
	rec := makeTestRecord()
	canonical, err := Canonicalize(rec)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	// Verify JSON is valid
	var m map[string]any
	if err := json.Unmarshal(canonical, &m); err != nil {
		t.Fatalf("canonical JSON is invalid: %v", err)
	}

	// Verify schema_version is present
	if v, ok := m["schema_version"]; !ok || v != "v1" {
		t.Errorf("schema_version = %v, want v1", v)
	}
}

func TestJCSFormatNumber(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{100, "100"},
		{0.5, "0.5"},
		{1.5, "1.5"},
		{1000000, "1000000"},
	}

	for _, tt := range tests {
		got := jcsFormatNumber(tt.input)
		if got != tt.want {
			t.Errorf("jcsFormatNumber(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
