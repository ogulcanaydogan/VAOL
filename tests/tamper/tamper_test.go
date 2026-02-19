// Package tamper provides an extensive tamper detection test suite.
// It validates that VAOL's cryptographic guarantees detect all classes of
// record modification, deletion, insertion, and replay attacks.
package tamper

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/yapay-ai/vaol/pkg/crypto"
	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/record"
	"github.com/yapay-ai/vaol/pkg/signer"
	"github.com/yapay-ai/vaol/pkg/store"
	"github.com/yapay-ai/vaol/pkg/verifier"
)

// helper builds a valid signed record and envelope.
func buildSignedRecord(t *testing.T, s *signer.Ed25519Signer) (*record.DecisionRecord, *signer.Envelope) {
	t.Helper()
	rec := record.New()
	rec.Identity.TenantID = "tamper-test"
	rec.Identity.Subject = "test-user"
	rec.Model.Provider = "openai"
	rec.Model.Name = "gpt-4o"
	rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte("test prompt"))
	rec.PolicyContext.PolicyDecision = record.PolicyAllow
	rec.Output.OutputHash = crypto.SHA256Prefixed([]byte("test output"))
	rec.Output.Mode = record.OutputModeHashOnly

	hash, err := record.ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("ComputeRecordHash: %v", err)
	}
	rec.Integrity.RecordHash = hash

	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	env, err := signer.SignEnvelope(context.Background(), payload, s)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	return rec, env
}

// --- 1. Payload Tampering ---

func TestTamper_ModifyModelName(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec, env := buildSignedRecord(t, s)

	rec.Model.Name = "tampered-model"
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("modifying model name should invalidate envelope")
	}
	assertCheckFailed(t, result, "signature")
}

func TestTamper_ModifyOutputHash(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec, env := buildSignedRecord(t, s)

	rec.Output.OutputHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("modifying output hash should invalidate envelope")
	}
}

func TestTamper_ModifyPromptHash(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec, env := buildSignedRecord(t, s)

	rec.PromptContext.UserPromptHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("modifying prompt hash should invalidate envelope")
	}
}

func TestTamper_ModifyPolicyDecision(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec, env := buildSignedRecord(t, s)

	rec.PolicyContext.PolicyDecision = record.PolicyDeny
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("modifying policy decision should invalidate envelope")
	}
}

func TestTamper_ModifyTenantID(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec, env := buildSignedRecord(t, s)

	rec.Identity.TenantID = "different-tenant"
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("modifying tenant ID should invalidate envelope")
	}
}

func TestTamper_ModifyTimestamp(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec, env := buildSignedRecord(t, s)

	rec.Timestamp = rec.Timestamp.AddDate(0, 0, -30)
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("modifying timestamp should invalidate envelope")
	}
}

// --- 2. Signature Forgery ---

func TestTamper_SignWithWrongKey(t *testing.T) {
	s1, _ := signer.GenerateEd25519Signer()
	s2, _ := signer.GenerateEd25519Signer()

	_, env := buildSignedRecord(t, s1)

	// Verify with s2's public key
	v := verifier.New(signer.NewEd25519Verifier(s2.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("verifying with wrong key should fail")
	}
	assertCheckFailed(t, result, "signature")
}

func TestTamper_CorruptSignature(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	_, env := buildSignedRecord(t, s)

	env.Signatures[0].Sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("corrupted signature should fail verification")
	}
}

func TestTamper_RemoveSignatures(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	_, env := buildSignedRecord(t, s)

	env.Signatures = nil

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)
	if result.Valid {
		t.Error("envelope with no signatures should fail verification")
	}
}

// --- 3. Record Hash Tampering ---

func TestTamper_WrongRecordHash(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := record.New()
	rec.Identity.TenantID = "tamper-test"
	rec.Identity.Subject = "test-user"
	rec.Model.Provider = "openai"
	rec.Model.Name = "gpt-4o"
	rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte("prompt"))
	rec.PolicyContext.PolicyDecision = record.PolicyAllow
	rec.Output.OutputHash = crypto.SHA256Prefixed([]byte("output"))
	rec.Output.Mode = record.OutputModeHashOnly

	// Set a deliberately wrong hash
	rec.Integrity.RecordHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)

	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)

	assertCheckFailed(t, result, "record_hash")
}

// --- 4. Hash Chain Attacks ---

func TestTamper_BrokenChainLink(t *testing.T) {
	records := buildChain(t, 5)

	// Break the chain at record 3
	records[3].Integrity.PreviousRecordHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	v := verifier.New()
	check, _ := v.VerifyChain(records)
	if check.Passed {
		t.Error("broken chain link should be detected")
	}
}

func TestTamper_ChainRecordTamperedAfterHash(t *testing.T) {
	records := buildChain(t, 3)

	// Tamper with record 1's content after hashing
	records[1].Model.Name = "tampered-after-hash"

	v := verifier.New()
	check, _ := v.VerifyChain(records)
	if check.Passed {
		t.Error("tampering with record content should break hash verification")
	}
}

func TestTamper_ChainGap(t *testing.T) {
	records := buildChain(t, 5)

	// Remove record 2, creating a gap
	gapped := append(records[:2], records[3:]...)

	v := verifier.New()
	check, _ := v.VerifyChain(gapped)
	if check.Passed {
		t.Error("gap in chain should be detected")
	}
}

func TestTamper_ChainReorder(t *testing.T) {
	records := buildChain(t, 4)

	// Swap records 1 and 2
	records[1], records[2] = records[2], records[1]

	v := verifier.New()
	check, _ := v.VerifyChain(records)
	if check.Passed {
		t.Error("reordered chain should be detected")
	}
}

// --- 5. Merkle Tree Attacks ---

func TestTamper_MerkleInclusionWrongData(t *testing.T) {
	tree := merkle.New()
	for i := 0; i < 8; i++ {
		tree.Append([]byte(fmt.Sprintf("record-%d", i)))
	}

	proof, err := tree.InclusionProof(3, tree.Size())
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}

	// Verify with wrong data
	err = merkle.VerifyInclusion([]byte("wrong-data"), proof)
	if err == nil {
		t.Error("Merkle inclusion should reject wrong data")
	}
}

func TestTamper_MerkleInclusionModifiedProof(t *testing.T) {
	tree := merkle.New()
	for i := 0; i < 8; i++ {
		tree.Append([]byte(fmt.Sprintf("record-%d", i)))
	}

	proof, _ := tree.InclusionProof(3, tree.Size())

	// Corrupt one of the proof hashes
	if len(proof.Hashes) > 0 {
		proof.Hashes[0] = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	}

	err := merkle.VerifyInclusion([]byte("record-3"), proof)
	if err == nil {
		t.Error("modified Merkle proof should fail verification")
	}
}

func TestTamper_MerkleRootMismatch(t *testing.T) {
	tree := merkle.New()
	for i := 0; i < 4; i++ {
		tree.Append([]byte(fmt.Sprintf("record-%d", i)))
	}

	proof, _ := tree.InclusionProof(0, tree.Size())
	proof.RootHash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	err := merkle.VerifyInclusion([]byte("record-0"), proof)
	if err == nil {
		t.Error("wrong root hash should fail verification")
	}
}

// --- 6. Replay Attacks ---

func TestTamper_ReplayDuplicateRecord(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()

	rec := &store.StoredRecord{
		RequestID:          record.New().RequestID,
		TenantID:           "test",
		RecordHash:         "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		PreviousRecordHash: crypto.ZeroHash,
		Envelope: &signer.Envelope{
			PayloadType: signer.PayloadType,
			Payload:     "dGVzdA",
			Signatures:  []signer.Signature{{KeyID: "test", Sig: "dGVzdA"}},
		},
	}

	_, err := s.Append(ctx, rec)
	if err != nil {
		t.Fatalf("first append: %v", err)
	}

	// Replay the same record
	_, err = s.Append(ctx, rec)
	if err != store.ErrDuplicateRequestID {
		t.Errorf("replay should be rejected with ErrDuplicateRequestID, got: %v", err)
	}
}

// --- 7. Merkle Tree Consistency ---

func TestTamper_MerkleConsistencyAfterAppend(t *testing.T) {
	tree := merkle.New()
	for i := 0; i < 4; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	oldRoot := tree.Root()
	oldSize := tree.Size()

	for i := 4; i < 8; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	// Old root should still be derivable
	root, err := tree.RootAt(oldSize)
	if err != nil {
		t.Fatalf("RootAt: %v", err)
	}
	if root != oldRoot {
		t.Error("historical root should be preserved after appending new leaves")
	}
}

func TestTamper_MerkleTreeSizeRegression(t *testing.T) {
	tree := merkle.New()
	for i := 0; i < 10; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	if tree.Size() != 10 {
		t.Errorf("tree size = %d, want 10", tree.Size())
	}

	// Verify that tree size only increases (append-only)
	prevSize := tree.Size()
	tree.Append([]byte("leaf-10"))
	if tree.Size() <= prevSize {
		t.Error("tree size should monotonically increase")
	}
}

// --- 8. Cross-Record Integrity ---

func TestTamper_FullLifecycleIntegrity(t *testing.T) {
	ctx := context.Background()
	s, _ := signer.GenerateEd25519Signer()
	memStore := store.NewMemoryStore()
	tree := merkle.New()

	records := make([]*record.DecisionRecord, 10)
	envelopes := make([]*signer.Envelope, 10)

	for i := 0; i < 10; i++ {
		rec := record.New()
		rec.Identity.TenantID = "integrity-test"
		rec.Identity.Subject = fmt.Sprintf("user-%d", i)
		rec.Model.Provider = "openai"
		rec.Model.Name = "gpt-4o"
		rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte(fmt.Sprintf("prompt-%d", i)))
		rec.PolicyContext.PolicyDecision = record.PolicyAllow
		rec.Output.OutputHash = crypto.SHA256Prefixed([]byte(fmt.Sprintf("output-%d", i)))
		rec.Output.Mode = record.OutputModeHashOnly

		hash, _ := record.ComputeRecordHash(rec)
		rec.Integrity.RecordHash = hash

		if i > 0 {
			rec.Integrity.PreviousRecordHash = records[i-1].Integrity.RecordHash
		} else {
			rec.Integrity.PreviousRecordHash = crypto.ZeroHash
		}

		payload, _ := json.Marshal(rec)
		env, _ := signer.SignEnvelope(ctx, payload, s)

		leafIdx := tree.Append([]byte(rec.Integrity.RecordHash))

		stored := &store.StoredRecord{
			RequestID:          rec.RequestID,
			TenantID:           rec.Identity.TenantID,
			Timestamp:          rec.Timestamp,
			RecordHash:         rec.Integrity.RecordHash,
			PreviousRecordHash: rec.Integrity.PreviousRecordHash,
			Envelope:           env,
			MerkleLeafIndex:    leafIdx,
		}
		memStore.Append(ctx, stored)

		records[i] = rec
		envelopes[i] = env
	}

	// Verify all envelopes
	v := verifier.New(signer.NewEd25519Verifier(s.PublicKey()))
	for i, env := range envelopes {
		result, _ := v.VerifyEnvelope(ctx, env)
		if !result.Valid {
			t.Errorf("record %d should be valid", i)
			for _, check := range result.Checks {
				if !check.Passed {
					t.Errorf("  check %q: %s", check.Name, check.Error)
				}
			}
		}
	}

	// Verify chain
	check, _ := v.VerifyChain(records)
	if !check.Passed {
		t.Errorf("chain should be intact: %s", check.Error)
	}

	// Verify Merkle inclusion for all records
	for i := int64(0); i < 10; i++ {
		proof, err := tree.InclusionProof(i, tree.Size())
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		err = merkle.VerifyInclusion([]byte(records[i].Integrity.RecordHash), proof)
		if err != nil {
			t.Errorf("record %d Merkle inclusion failed: %v", i, err)
		}
	}

	// Verify store consistency
	count, _ := memStore.Count(ctx)
	if count != 10 {
		t.Errorf("store count = %d, want 10", count)
	}
}

// --- Helpers ---

func buildChain(t *testing.T, n int) []*record.DecisionRecord {
	t.Helper()
	records := make([]*record.DecisionRecord, n)
	for i := 0; i < n; i++ {
		rec := record.New()
		rec.Identity.TenantID = "chain-test"
		rec.Identity.Subject = "test-user"
		rec.Model.Provider = "openai"
		rec.Model.Name = "gpt-4o"
		rec.PromptContext.UserPromptHash = crypto.SHA256Prefixed([]byte(fmt.Sprintf("prompt-%d", i)))
		rec.PolicyContext.PolicyDecision = record.PolicyAllow
		rec.Output.OutputHash = crypto.SHA256Prefixed([]byte(fmt.Sprintf("output-%d", i)))
		rec.Output.Mode = record.OutputModeHashOnly

		hash, err := record.ComputeRecordHash(rec)
		if err != nil {
			t.Fatalf("ComputeRecordHash[%d]: %v", i, err)
		}
		rec.Integrity.RecordHash = hash

		if i > 0 {
			rec.Integrity.PreviousRecordHash = records[i-1].Integrity.RecordHash
		} else {
			rec.Integrity.PreviousRecordHash = crypto.ZeroHash
		}
		records[i] = rec
	}
	return records
}

func assertCheckFailed(t *testing.T, result *verifier.Result, checkName string) {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == checkName && !check.Passed {
			return
		}
	}
	t.Errorf("expected check %q to fail, but it passed or was not found", checkName)
}
