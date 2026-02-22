package verifier

import (
	"testing"

	"github.com/ogulcanaydogan/vaol/pkg/export"
)

func TestNewBundleTranscript(t *testing.T) {
	bundle := export.NewBundle(export.BundleFilter{TenantID: "acme"})
	bundle.Manifest.EvidenceHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result := &BundleResult{
		Summary:         "VERIFICATION PASSED",
		TotalRecords:    3,
		ValidRecords:    3,
		InvalidRecords:  0,
		ChainIntact:     true,
		MerkleValid:     true,
		SignaturesValid: true,
		SchemaValid:     true,
		CheckpointValid: true,
		PolicyHashValid: true,
		ManifestValid:   true,
	}

	transcript, err := NewBundleTranscript(ProfileStrict, bundle, result)
	if err != nil {
		t.Fatalf("NewBundleTranscript: %v", err)
	}
	if transcript.Profile != ProfileStrict {
		t.Fatalf("profile mismatch: %s", transcript.Profile)
	}
	if transcript.EvidenceHash != bundle.Manifest.EvidenceHash {
		t.Fatalf("evidence hash mismatch: got %s want %s", transcript.EvidenceHash, bundle.Manifest.EvidenceHash)
	}
	if len(transcript.Steps) == 0 {
		t.Fatal("expected transcript steps")
	}

	payload, err := transcript.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("transcript json should not be empty")
	}
}
