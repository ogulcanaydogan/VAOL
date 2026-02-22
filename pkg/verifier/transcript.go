package verifier

import (
	"encoding/json"
	"fmt"

	"github.com/ogulcanaydogan/vaol/pkg/export"
)

// TranscriptStep is a deterministic verification step summary.
type TranscriptStep struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// BundleTranscript is a deterministic offline verification artifact.
type BundleTranscript struct {
	Version        string           `json:"version"`
	Profile        Profile          `json:"profile"`
	EvidenceHash   string           `json:"evidence_hash,omitempty"`
	Summary        string           `json:"summary"`
	TotalRecords   int              `json:"total_records"`
	ValidRecords   int              `json:"valid_records"`
	InvalidRecords int              `json:"invalid_records"`
	Steps          []TranscriptStep `json:"steps"`
}

// NewBundleTranscript builds a reproducible transcript from a bundle result.
func NewBundleTranscript(profile Profile, bundle *export.Bundle, result *BundleResult) (*BundleTranscript, error) {
	if bundle == nil {
		return nil, fmt.Errorf("bundle is nil")
	}
	if result == nil {
		return nil, fmt.Errorf("bundle result is nil")
	}

	transcript := &BundleTranscript{
		Version:        "1.0",
		Profile:        profile,
		Summary:        result.Summary,
		TotalRecords:   result.TotalRecords,
		ValidRecords:   result.ValidRecords,
		InvalidRecords: result.InvalidRecords,
		Steps: []TranscriptStep{
			{Name: "signatures", Passed: result.SignaturesValid, Detail: "DSSE signature verification"},
			{Name: "schema", Passed: result.SchemaValid, Detail: "DecisionRecord schema checks"},
			{Name: "hash_chain", Passed: result.ChainIntact, Detail: "append-only chain continuity"},
			{Name: "merkle", Passed: result.MerkleValid, Detail: "Merkle inclusion verification"},
			{Name: "checkpoint", Passed: result.CheckpointValid, Detail: "signed checkpoint validation"},
			{Name: "policy_hash", Passed: result.PolicyHashValid, Detail: "policy hash completeness"},
			{Name: "manifest", Passed: result.ManifestValid, Detail: "deterministic bundle manifest hash"},
		},
	}
	if bundle.Manifest.EvidenceHash != "" {
		transcript.EvidenceHash = bundle.Manifest.EvidenceHash
	}
	return transcript, nil
}

// ToJSON serializes a transcript in stable, indented JSON.
func (t *BundleTranscript) ToJSON() ([]byte, error) {
	return json.MarshalIndent(t, "", "  ")
}
