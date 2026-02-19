// Package verifier provides composite verification of VAOL decision records.
// It checks: signature validity, schema conformance, hash chain integrity,
// and Merkle inclusion proofs.
package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/export"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/record"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

// Result represents the outcome of verifying a single record.
type Result struct {
	RequestID      string        `json:"request_id"`
	SequenceNumber int64         `json:"sequence_number,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
	Valid          bool          `json:"valid"`
	Checks         []CheckResult `json:"checks"`
	Error          string        `json:"error,omitempty"`
}

// CheckResult is the result of a single verification check.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details,omitempty"`
	Error   string `json:"error,omitempty"`
}

// BundleResult represents the outcome of verifying an entire audit bundle.
type BundleResult struct {
	TotalRecords    int      `json:"total_records"`
	ValidRecords    int      `json:"valid_records"`
	InvalidRecords  int      `json:"invalid_records"`
	ChainIntact     bool     `json:"chain_intact"`
	MerkleValid     bool     `json:"merkle_valid"`
	SignaturesValid bool     `json:"signatures_valid"`
	SchemaValid     bool     `json:"schema_valid"`
	CheckpointValid bool     `json:"checkpoint_valid"`
	PolicyHashValid bool     `json:"policy_hash_valid"`
	Results         []Result `json:"results,omitempty"`
	Summary         string   `json:"summary"`
}

// Profile controls verification strictness.
type Profile string

const (
	ProfileBasic  Profile = "basic"
	ProfileStrict Profile = "strict"
	ProfileFIPS   Profile = "fips"
)

// Verifier performs composite verification of decision records.
type Verifier struct {
	sigVerifiers []signer.Verifier
}

// New creates a new Verifier with the given signature verifiers.
func New(verifiers ...signer.Verifier) *Verifier {
	return &Verifier{sigVerifiers: verifiers}
}

// VerifyEnvelope verifies a single DSSE envelope containing a DecisionRecord.
func (v *Verifier) VerifyEnvelope(ctx context.Context, env *signer.Envelope) (*Result, error) {
	return v.VerifyEnvelopeWithProfile(ctx, env, ProfileBasic)
}

// VerifyEnvelopeWithProfile verifies a DSSE envelope using the requested profile.
func (v *Verifier) VerifyEnvelopeWithProfile(ctx context.Context, env *signer.Envelope, profile Profile) (*Result, error) {
	result := &Result{
		Timestamp: time.Now().UTC(),
		Valid:     true,
	}

	// 1. Verify signature(s)
	sigCheck := CheckResult{Name: "signature"}
	if err := signer.VerifyEnvelope(ctx, env, v.sigVerifiers...); err != nil {
		sigCheck.Passed = false
		sigCheck.Error = err.Error()
		result.Valid = false
	} else {
		sigCheck.Passed = true
		sigCheck.Details = fmt.Sprintf("%d signature(s) verified", len(env.Signatures))
	}
	result.Checks = append(result.Checks, sigCheck)

	// 2. Extract and validate payload
	payload, err := signer.ExtractPayload(env)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("extracting payload: %v", err)
		return result, nil
	}

	var rec record.DecisionRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		schemaCheck := CheckResult{
			Name:   "schema",
			Passed: false,
			Error:  fmt.Sprintf("unmarshaling record: %v", err),
		}
		result.Checks = append(result.Checks, schemaCheck)
		result.Valid = false
		return result, nil
	}

	result.RequestID = rec.RequestID.String()

	// 3. Schema validation
	schemaCheck := CheckResult{Name: "schema"}
	if err := record.Validate(&rec); err != nil {
		schemaCheck.Passed = false
		schemaCheck.Error = err.Error()
		result.Valid = false
	} else {
		schemaCheck.Passed = true
		schemaCheck.Details = "DecisionRecord v1 schema valid"
	}
	result.Checks = append(result.Checks, schemaCheck)

	// 4. Record hash verification
	hashCheck := CheckResult{Name: "record_hash"}
	computed, err := record.ComputeRecordHash(&rec)
	if err != nil {
		hashCheck.Passed = false
		hashCheck.Error = fmt.Sprintf("computing hash: %v", err)
		result.Valid = false
	} else if computed != rec.Integrity.RecordHash {
		hashCheck.Passed = false
		hashCheck.Error = fmt.Sprintf("hash mismatch: computed %s != stored %s", computed, rec.Integrity.RecordHash)
		result.Valid = false
	} else {
		hashCheck.Passed = true
		hashCheck.Details = rec.Integrity.RecordHash
	}
	result.Checks = append(result.Checks, hashCheck)

	switch profile {
	case ProfileBasic:
		// No additional constraints.
	case ProfileStrict:
		strictCheck := CheckResult{Name: "profile_strict"}
		switch {
		case rec.PolicyContext.PolicyBundleID == "":
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires policy_context.policy_bundle_id"
			result.Valid = false
		case rec.PolicyContext.PolicyHash == "":
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires policy_context.policy_hash"
			result.Valid = false
		case rec.Integrity.PreviousRecordHash == "":
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires integrity.previous_record_hash"
			result.Valid = false
		case rec.Integrity.MerkleRoot == "":
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires integrity.merkle_root"
			result.Valid = false
		case rec.Integrity.MerkleTreeSize <= 0:
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires integrity.merkle_tree_size > 0"
			result.Valid = false
		case rec.Integrity.InclusionProof == nil:
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires integrity.inclusion_proof"
			result.Valid = false
		case hasSigstoreSignatureWithoutRekor(env):
			strictCheck.Passed = false
			strictCheck.Error = "strict profile requires rekor_entry_id for Sigstore signatures"
			result.Valid = false
		default:
			strictCheck.Passed = true
			strictCheck.Details = "strict profile checks passed"
		}
		result.Checks = append(result.Checks, strictCheck)
	case ProfileFIPS:
		// FIPS profile builds on strict checks, then enforces non-Ed25519 signatures.
		strictResult, err := v.VerifyEnvelopeWithProfile(ctx, env, ProfileStrict)
		if err != nil {
			return nil, err
		}
		fipsCheck := CheckResult{Name: "profile_fips"}
		fipsCheck.Passed = true
		for _, sig := range env.Signatures {
			if len(sig.KeyID) >= 8 && sig.KeyID[:8] == "ed25519:" {
				fipsCheck.Passed = false
				fipsCheck.Error = "fips profile rejects ed25519 signatures"
				break
			}
		}
		if !fipsCheck.Passed {
			strictResult.Valid = false
		} else {
			fipsCheck.Details = "fips profile checks passed"
		}
		strictResult.Checks = append(strictResult.Checks, fipsCheck)
		return strictResult, nil
	default:
		return nil, fmt.Errorf("unsupported verification profile: %s", profile)
	}

	return result, nil
}

func hasSigstoreSignatureWithoutRekor(env *signer.Envelope) bool {
	for _, sig := range env.Signatures {
		if strings.HasPrefix(sig.KeyID, "fulcio:") && sig.RekorEntryID == "" {
			return true
		}
	}
	return false
}

// VerifyChain verifies the hash chain integrity of a sequence of records.
func (v *Verifier) VerifyChain(records []*record.DecisionRecord) (*CheckResult, error) {
	check := &CheckResult{
		Name: "hash_chain",
	}

	if len(records) == 0 {
		check.Passed = true
		check.Details = "empty chain"
		return check, nil
	}

	for i, rec := range records {
		// Verify each record's hash
		computed, err := record.ComputeRecordHash(rec)
		if err != nil {
			check.Passed = false
			check.Error = fmt.Sprintf("record %d: hash computation failed: %v", i, err)
			return check, nil
		}
		if computed != rec.Integrity.RecordHash {
			check.Passed = false
			check.Error = fmt.Sprintf("record %d: hash mismatch (computed=%s, stored=%s)", i, computed, rec.Integrity.RecordHash)
			return check, nil
		}

		// Verify chain linkage
		if i == 0 {
			// Genesis record should link to zero hash or be the first record
			// (flexible: some deployments may start with non-zero previous hash)
			continue
		}
		expected := records[i-1].Integrity.RecordHash
		if rec.Integrity.PreviousRecordHash != expected {
			check.Passed = false
			check.Error = fmt.Sprintf("record %d: chain break (previous=%s, expected=%s)", i, rec.Integrity.PreviousRecordHash, expected)
			return check, nil
		}
	}

	check.Passed = true
	check.Details = fmt.Sprintf("%d records, chain intact", len(records))
	return check, nil
}

// VerifyMerkleInclusion verifies a record's Merkle inclusion proof.
func (v *Verifier) VerifyMerkleInclusion(rec *record.DecisionRecord) (*CheckResult, error) {
	check := &CheckResult{
		Name: "merkle_inclusion",
	}

	if rec.Integrity.InclusionProof == nil {
		check.Passed = false
		check.Error = "no inclusion proof present"
		return check, nil
	}

	recordHashBytes, err := json.Marshal(rec.Integrity.RecordHash)
	if err != nil {
		check.Passed = false
		check.Error = fmt.Sprintf("marshaling record hash: %v", err)
		return check, nil
	}

	// The leaf data is the record_hash string (what was appended to the Merkle tree)
	_ = recordHashBytes // The actual leaf data is the raw bytes of the record hash
	leafData := []byte(rec.Integrity.RecordHash)

	proof := &merkle.Proof{
		ProofType: merkle.ProofTypeInclusion,
		LeafIndex: rec.Integrity.InclusionProof.LeafIndex,
		TreeSize:  rec.Integrity.MerkleTreeSize,
		RootHash:  rec.Integrity.MerkleRoot,
		Hashes:    rec.Integrity.InclusionProof.Hashes,
	}

	if err := merkle.VerifyInclusion(leafData, proof); err != nil {
		check.Passed = false
		check.Error = err.Error()
		return check, nil
	}

	check.Passed = true
	check.Details = fmt.Sprintf("leaf %d in tree of size %d", rec.Integrity.InclusionProof.LeafIndex, rec.Integrity.MerkleTreeSize)
	return check, nil
}

// VerifyBundle performs end-to-end verification over an exported audit bundle.
func (v *Verifier) VerifyBundle(ctx context.Context, bundle *export.Bundle, profile Profile) (*BundleResult, error) {
	if bundle == nil {
		return nil, fmt.Errorf("bundle is nil")
	}

	out := &BundleResult{
		TotalRecords:    len(bundle.Records),
		ChainIntact:     true,
		MerkleValid:     true,
		SignaturesValid: true,
		SchemaValid:     true,
		CheckpointValid: true,
		PolicyHashValid: true,
		Results:         make([]Result, 0, len(bundle.Records)),
	}

	decoded := make([]*record.DecisionRecord, 0, len(bundle.Records))

	for _, entry := range bundle.Records {
		if entry.Envelope == nil {
			out.InvalidRecords++
			out.SignaturesValid = false
			out.Results = append(out.Results, Result{
				Valid: false,
				Error: "missing dsse_envelope",
				Checks: []CheckResult{
					{Name: "signature", Passed: false, Error: "missing dsse_envelope"},
				},
				Timestamp: time.Now().UTC(),
			})
			continue
		}

		result, err := v.VerifyEnvelopeWithProfile(ctx, entry.Envelope, profile)
		if err != nil {
			out.InvalidRecords++
			out.SignaturesValid = false
			out.Results = append(out.Results, Result{
				Valid: false,
				Error: err.Error(),
				Checks: []CheckResult{
					{Name: "signature", Passed: false, Error: err.Error()},
				},
				Timestamp: time.Now().UTC(),
			})
			continue
		}

		payload, err := signer.ExtractPayload(entry.Envelope)
		if err != nil {
			out.SignaturesValid = false
			result.Valid = false
			result.Checks = append(result.Checks, CheckResult{
				Name:   "payload",
				Passed: false,
				Error:  fmt.Sprintf("extracting payload: %v", err),
			})
			out.InvalidRecords++
			out.Results = append(out.Results, *result)
			continue
		}

		var rec record.DecisionRecord
		if err := json.Unmarshal(payload, &rec); err != nil {
			out.SchemaValid = false
			result.Valid = false
			result.Checks = append(result.Checks, CheckResult{
				Name:   "schema",
				Passed: false,
				Error:  fmt.Sprintf("unmarshaling record payload: %v", err),
			})
			out.InvalidRecords++
			out.Results = append(out.Results, *result)
			continue
		}
		result.SequenceNumber = entry.SequenceNumber
		if rec.PolicyContext.PolicyHash == "" && profile != ProfileBasic {
			out.PolicyHashValid = false
			result.Valid = false
			result.Checks = append(result.Checks, CheckResult{
				Name:   "policy_hash",
				Passed: false,
				Error:  "policy_context.policy_hash is missing",
			})
		}

		decoded = append(decoded, &rec)

		if entry.InclusionProof != nil {
			if err := merkle.VerifyInclusion([]byte(rec.Integrity.RecordHash), entry.InclusionProof); err != nil {
				out.MerkleValid = false
				result.Valid = false
				result.Checks = append(result.Checks, CheckResult{
					Name:   "merkle_inclusion",
					Passed: false,
					Error:  err.Error(),
				})
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:    "merkle_inclusion",
					Passed:  true,
					Details: fmt.Sprintf("leaf %d in tree of size %d", entry.InclusionProof.LeafIndex, entry.InclusionProof.TreeSize),
				})
			}
		} else {
			out.MerkleValid = false
			result.Valid = false
			result.Checks = append(result.Checks, CheckResult{
				Name:   "merkle_inclusion",
				Passed: false,
				Error:  "missing inclusion_proof in bundle record",
			})
		}

		if result.Valid {
			out.ValidRecords++
		} else {
			out.InvalidRecords++
			for _, check := range result.Checks {
				if check.Passed {
					continue
				}
				switch check.Name {
				case "signature":
					out.SignaturesValid = false
				case "schema":
					out.SchemaValid = false
				}
			}
		}
		out.Results = append(out.Results, *result)
	}

	chainCheck, err := v.VerifyChain(decoded)
	if err != nil {
		return nil, err
	}
	if !chainCheck.Passed {
		out.ChainIntact = false
	}

	if len(bundle.Checkpoints) > 0 {
		latest := bundle.Checkpoints[len(bundle.Checkpoints)-1].Checkpoint
		if latest == nil {
			out.CheckpointValid = false
		} else if latest.Signature == "" {
			out.CheckpointValid = false
		} else {
			ok := false
			for _, ver := range v.sigVerifiers {
				cpCopy := *latest
				if err := merkle.VerifyCheckpoint(ctx, &cpCopy, ver); err == nil {
					ok = true
					break
				}
			}
			if !ok {
				out.CheckpointValid = false
			}
		}
	}

	out.Summary = "VERIFICATION PASSED"
	if !out.ChainIntact || !out.MerkleValid || !out.SignaturesValid || !out.SchemaValid || !out.CheckpointValid || !out.PolicyHashValid || out.InvalidRecords > 0 {
		out.Summary = "VERIFICATION FAILED"
	}

	return out, nil
}
