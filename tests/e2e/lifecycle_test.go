// Package e2e tests the full record lifecycle without network dependencies.
// It exercises: record creation → signing → storage → chain verification →
// Merkle inclusion → export → bundle verification.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/yapay-ai/vaol/pkg/crypto"
	"github.com/yapay-ai/vaol/pkg/export"
	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/record"
	"github.com/yapay-ai/vaol/pkg/signer"
	"github.com/yapay-ai/vaol/pkg/store"
	"github.com/yapay-ai/vaol/pkg/verifier"
)

// TestFullRecordLifecycle exercises the complete happy path:
// create records → sign → store → verify → export → verify bundle.
func TestFullRecordLifecycle(t *testing.T) {
	ctx := context.Background()

	// --- Setup infrastructure ---
	signerKey, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	sigVerifier := signer.NewEd25519Verifier(signerKey.PublicKey())
	memStore := store.NewMemoryStore()
	tree := merkle.New()
	v := verifier.New(sigVerifier)

	const numRecords = 10

	records := make([]*record.DecisionRecord, numRecords)
	envelopes := make([]*signer.Envelope, numRecords)
	proofs := make([]*merkle.Proof, numRecords)

	// --- Phase 1: Create, sign, and store records ---
	for i := 0; i < numRecords; i++ {
		rec := record.New()
		rec.Identity.TenantID = "e2e-test"
		rec.Identity.Subject = fmt.Sprintf("user-%d", i%3)
		rec.Identity.SubjectType = "user"
		rec.Model.Provider = "openai"
		rec.Model.Name = "gpt-4o"
		rec.Model.Version = "2025-03-01"
		rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte(fmt.Sprintf("prompt-%d", i)))
		rec.PromptContext.MessageCount = i + 1
		rec.PolicyContext.PolicyDecision = record.PolicyAllow
		rec.PolicyContext.PolicyBundleID = "e2e-bundle-v1"
		rec.PolicyContext.PolicyHash = crypto.SHA256Prefixed([]byte("test-policy"))
		rec.Output.OutputHash = crypto.SHA256Prefixed([]byte(fmt.Sprintf("output-%d", i)))
		rec.Output.Mode = record.OutputModeHashOnly
		rec.Output.OutputTokens = 100 + i*10
		rec.Output.FinishReason = "stop"
		rec.Output.LatencyMs = float64(200 + i*50)

		// Compute record hash
		hash, err := record.ComputeRecordHash(rec)
		if err != nil {
			t.Fatalf("record %d: ComputeRecordHash: %v", i, err)
		}
		rec.Integrity.RecordHash = hash

		// Set chain linkage
		if i > 0 {
			rec.Integrity.PreviousRecordHash = records[i-1].Integrity.RecordHash
		} else {
			rec.Integrity.PreviousRecordHash = crypto.ZeroHash
		}

		// Sign the full record
		payload, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("record %d: Marshal: %v", i, err)
		}
		env, err := signer.SignEnvelope(ctx, payload, signerKey)
		if err != nil {
			t.Fatalf("record %d: SignEnvelope: %v", i, err)
		}

		// Append to Merkle tree
		leafIdx := tree.Append([]byte(rec.Integrity.RecordHash))

		// Get inclusion proof
		proof, err := tree.InclusionProof(leafIdx, tree.Size())
		if err != nil {
			t.Fatalf("record %d: InclusionProof: %v", i, err)
		}

		// Store
		stored := &store.StoredRecord{
			RequestID:          rec.RequestID,
			TenantID:           rec.Identity.TenantID,
			Timestamp:          rec.Timestamp,
			RecordHash:         rec.Integrity.RecordHash,
			PreviousRecordHash: rec.Integrity.PreviousRecordHash,
			Envelope:           env,
			MerkleLeafIndex:    leafIdx,
		}
		seq, err := memStore.Append(ctx, stored)
		if err != nil {
			t.Fatalf("record %d: Append: %v", i, err)
		}
		if seq != int64(i) {
			t.Fatalf("record %d: sequence = %d, want %d", i, seq, i)
		}

		records[i] = rec
		envelopes[i] = env
		proofs[i] = proof
	}

	// --- Phase 2: Verify all signatures ---
	t.Run("SignatureVerification", func(t *testing.T) {
		for i, env := range envelopes {
			result, err := v.VerifyEnvelope(ctx, env)
			if err != nil {
				t.Fatalf("record %d: VerifyEnvelope error: %v", i, err)
			}
			if !result.Valid {
				for _, check := range result.Checks {
					if !check.Passed {
						t.Errorf("record %d: check %q: %s", i, check.Name, check.Error)
					}
				}
			}
		}
	})

	// --- Phase 3: Verify hash chain ---
	t.Run("ChainVerification", func(t *testing.T) {
		check, err := v.VerifyChain(records)
		if err != nil {
			t.Fatalf("VerifyChain error: %v", err)
		}
		if !check.Passed {
			t.Errorf("chain should be intact: %s", check.Error)
		}
	})

	// --- Phase 4: Verify Merkle inclusion proofs ---
	t.Run("MerkleInclusion", func(t *testing.T) {
		for i := 0; i < numRecords; i++ {
			// Re-generate proof against the final tree
			proof, err := tree.InclusionProof(int64(i), tree.Size())
			if err != nil {
				t.Fatalf("record %d: InclusionProof: %v", i, err)
			}
			err = merkle.VerifyInclusion([]byte(records[i].Integrity.RecordHash), proof)
			if err != nil {
				t.Errorf("record %d: Merkle inclusion failed: %v", i, err)
			}
		}
	})

	// --- Phase 5: Store retrieval ---
	t.Run("StoreRetrieval", func(t *testing.T) {
		// By request ID
		for i := 0; i < numRecords; i++ {
			got, err := memStore.GetByRequestID(ctx, records[i].RequestID)
			if err != nil {
				t.Fatalf("record %d: GetByRequestID: %v", i, err)
			}
			if got.RecordHash != records[i].Integrity.RecordHash {
				t.Errorf("record %d: hash mismatch", i)
			}
		}

		// By sequence
		for i := 0; i < numRecords; i++ {
			got, err := memStore.GetBySequence(ctx, int64(i))
			if err != nil {
				t.Fatalf("record %d: GetBySequence: %v", i, err)
			}
			if got.RecordHash != records[i].Integrity.RecordHash {
				t.Errorf("record %d: hash mismatch on GetBySequence", i)
			}
		}

		// Latest
		latest, err := memStore.GetLatest(ctx)
		if err != nil {
			t.Fatalf("GetLatest: %v", err)
		}
		if latest.RecordHash != records[numRecords-1].Integrity.RecordHash {
			t.Error("latest should be the last record")
		}

		// Count
		count, err := memStore.Count(ctx)
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if count != numRecords {
			t.Errorf("Count = %d, want %d", count, numRecords)
		}
	})

	// --- Phase 6: Export and verify bundle ---
	t.Run("ExportBundle", func(t *testing.T) {
		filter := export.BundleFilter{
			TenantID: "e2e-test",
		}
		bundle := export.NewBundle(filter)

		cpSigner := merkle.NewCheckpointSigner(signerKey)
		cp, err := cpSigner.SignCheckpoint(ctx, tree)
		if err != nil {
			t.Fatalf("SignCheckpoint: %v", err)
		}

		for i, env := range envelopes {
			proof, _ := tree.InclusionProof(int64(i), tree.Size())
			bundle.AddRecord(export.BundleRecord{
				SequenceNumber: int64(i),
				Envelope:       env,
				InclusionProof: proof,
			})
		}

		bundle.AddCheckpoint(export.BundleCheckpoint{
			Checkpoint: cp,
		})
		bundle.Finalize()

		// Verify bundle metadata
		if bundle.Metadata.TotalRecords != numRecords {
			t.Errorf("bundle total = %d, want %d", bundle.Metadata.TotalRecords, numRecords)
		}
		if bundle.Metadata.FirstSequence != 0 {
			t.Errorf("first sequence = %d, want 0", bundle.Metadata.FirstSequence)
		}
		if bundle.Metadata.LastSequence != int64(numRecords-1) {
			t.Errorf("last sequence = %d, want %d", bundle.Metadata.LastSequence, numRecords-1)
		}

		// Serialize and deserialize
		data, err := bundle.Marshal()
		if err != nil {
			t.Fatalf("Marshal bundle: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("bundle should not be empty")
		}

		restored, err := export.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal bundle: %v", err)
		}
		if restored.Metadata.TotalRecords != numRecords {
			t.Errorf("restored total = %d, want %d", restored.Metadata.TotalRecords, numRecords)
		}
		if len(restored.Records) != numRecords {
			t.Errorf("restored records = %d, want %d", len(restored.Records), numRecords)
		}

		// Verify each record in the restored bundle
		for i, rec := range restored.Records {
			result, err := v.VerifyEnvelope(ctx, rec.Envelope)
			if err != nil {
				t.Fatalf("bundle record %d: VerifyEnvelope error: %v", i, err)
			}
			if !result.Valid {
				t.Errorf("bundle record %d should be valid", i)
			}
		}
	})

	// --- Phase 7: Merkle checkpoint verification ---
	t.Run("CheckpointVerification", func(t *testing.T) {
		cpSigner := merkle.NewCheckpointSigner(signerKey)
		cp, err := cpSigner.SignCheckpoint(ctx, tree)
		if err != nil {
			t.Fatalf("SignCheckpoint: %v", err)
		}

		if cp.TreeSize != tree.Size() {
			t.Errorf("checkpoint tree size = %d, want %d", cp.TreeSize, tree.Size())
		}
		if cp.RootHash != tree.Root() {
			t.Error("checkpoint root hash should match tree root")
		}
		if cp.Signature == "" {
			t.Error("checkpoint should be signed")
		}

		// Verify the checkpoint signature
		err = merkle.VerifyCheckpoint(ctx, cp, sigVerifier)
		if err != nil {
			t.Errorf("checkpoint verification failed: %v", err)
		}
	})
}

// TestEncryptedOutputMode tests the encrypted payload workflow.
func TestEncryptedOutputMode(t *testing.T) {
	ctx := context.Background()

	signerKey, _ := signer.GenerateEd25519Signer()
	identity, err := crypto.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}

	// Create a record with encrypted output
	rec := record.New()
	rec.Identity.TenantID = "encrypt-test"
	rec.Identity.Subject = "user"
	rec.Model.Provider = "openai"
	rec.Model.Name = "gpt-4o"
	rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte("prompt"))
	rec.PolicyContext.PolicyDecision = record.PolicyAllow
	rec.Output.Mode = record.OutputModeEncrypted

	// Encrypt the output
	outputText := []byte("This is the AI-generated output that should be encrypted")
	ciphertext, plaintextHash, err := crypto.Encrypt(outputText, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	rec.Output.OutputHash = plaintextHash
	rec.Output.OutputEncrypted = ciphertext

	// Compute hash and sign
	hash, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = hash
	rec.Integrity.PreviousRecordHash = crypto.ZeroHash

	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(ctx, payload, signerKey)

	// Verify the envelope
	v := verifier.New(signer.NewEd25519Verifier(signerKey.PublicKey()))
	result, _ := v.VerifyEnvelope(ctx, env)
	if !result.Valid {
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("check %q: %s", check.Name, check.Error)
			}
		}
		t.Fatal("encrypted record should be valid")
	}

	// Decrypt and verify the output
	decrypted, err := crypto.Decrypt(ciphertext, plaintextHash, identity)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decrypted) != string(outputText) {
		t.Error("decrypted output should match original")
	}
}

// TestPolicyContextPreservation verifies that policy decisions are
// correctly sealed into signed records.
func TestPolicyContextPreservation(t *testing.T) {
	ctx := context.Background()
	signerKey, _ := signer.GenerateEd25519Signer()

	decisions := []record.PolicyDecision{
		record.PolicyAllow,
		record.PolicyDeny,
		record.PolicyAllowWithTransform,
		record.PolicyLogOnly,
	}

	for _, decision := range decisions {
		t.Run(string(decision), func(t *testing.T) {
			rec := record.New()
			rec.Identity.TenantID = "policy-test"
			rec.Identity.Subject = "user"
			rec.Model.Provider = "openai"
			rec.Model.Name = "gpt-4o"
			rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte("prompt"))
			rec.PolicyContext.PolicyDecision = decision
			rec.PolicyContext.PolicyBundleID = "test-bundle"
			rec.PolicyContext.RuleIDs = []string{"rule-1", "rule-2"}
			rec.Output.OutputHash = crypto.SHA256Prefixed([]byte("output"))
			rec.Output.Mode = record.OutputModeHashOnly

			hash, _ := record.ComputeRecordHash(rec)
			rec.Integrity.RecordHash = hash

			payload, _ := json.Marshal(rec)
			env, _ := signer.SignEnvelope(ctx, payload, signerKey)

			// Extract and verify the policy context is preserved
			extracted, _ := signer.ExtractPayload(env)
			var restored record.DecisionRecord
			if err := json.Unmarshal(extracted, &restored); err != nil {
				t.Fatalf("unmarshal restored record: %v", err)
			}

			if restored.PolicyContext.PolicyDecision != decision {
				t.Errorf("policy decision = %s, want %s", restored.PolicyContext.PolicyDecision, decision)
			}
			if restored.PolicyContext.PolicyBundleID != "test-bundle" {
				t.Error("policy bundle ID should be preserved")
			}
			if len(restored.PolicyContext.RuleIDs) != 2 {
				t.Errorf("rule IDs count = %d, want 2", len(restored.PolicyContext.RuleIDs))
			}
		})
	}
}

// TestDeterministicHashing verifies that the same record always produces
// the same hash regardless of creation time.
func TestDeterministicHashing(t *testing.T) {
	makeRec := func() *record.DecisionRecord {
		rec := &record.DecisionRecord{
			SchemaVersion: record.SchemaVersion,
			Timestamp:     time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
			Identity: record.Identity{
				TenantID: "deterministic-test",
				Subject:  "user",
			},
			Model: record.Model{
				Provider: "openai",
				Name:     "gpt-4o",
			},
			PromptContext: record.PromptContext{
				UserPromptHash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			},
			PolicyContext: record.PolicyContext{
				PolicyDecision: record.PolicyAllow,
			},
			Output: record.Output{
				OutputHash: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Mode:       record.OutputModeHashOnly,
			},
		}
		return rec
	}

	hash1, _ := record.ComputeRecordHash(makeRec())
	hash2, _ := record.ComputeRecordHash(makeRec())

	if hash1 != hash2 {
		t.Errorf("same record data should always produce same hash\nhash1: %s\nhash2: %s", hash1, hash2)
	}
}
