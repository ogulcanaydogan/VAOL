package verifier

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ogulcanaydogan/vaol/pkg/export"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/record"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

func TestVerifyValidEnvelope(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()

	// Compute record hash (uses canonical form internally)
	hash, err := record.ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("ComputeRecordHash error: %v", err)
	}
	rec.Integrity.RecordHash = hash

	// Sign the full record (with record_hash set) — this is the DSSE payload
	payload, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	env, err := signer.SignEnvelope(context.Background(), payload, s)
	if err != nil {
		t.Fatalf("SignEnvelope error: %v", err)
	}

	// Verify
	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, err := v.VerifyEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("VerifyEnvelope error: %v", err)
	}

	if !result.Valid {
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("check %q failed: %s", check.Name, check.Error)
			}
		}
		t.Fatal("envelope should be valid")
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()

	hash, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = hash

	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)

	// Tamper: change the model name in the payload
	rec.Model.Name = "tampered-model"
	tampered, _ := json.Marshal(rec)
	env.Payload = signer.TestB64Encode(tampered)

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)

	if result.Valid {
		t.Error("tampered envelope should not be valid")
	}

	// Find which check failed
	sigFailed := false
	for _, check := range result.Checks {
		if check.Name == "signature" && !check.Passed {
			sigFailed = true
		}
	}
	if !sigFailed {
		t.Error("signature check should fail for tampered payload")
	}
}

func TestVerifyWrongRecordHash(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()

	// Set wrong hash deliberately
	rec.Integrity.RecordHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	// Sign the full record with the wrong hash in the payload
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, _ := v.VerifyEnvelope(context.Background(), env)

	hashFailed := false
	for _, check := range result.Checks {
		if check.Name == "record_hash" && !check.Passed {
			hashFailed = true
		}
	}
	if !hashFailed {
		t.Error("record_hash check should fail for wrong hash")
	}
}

func TestVerifyChainIntact(t *testing.T) {
	records := make([]*record.DecisionRecord, 3)
	for i := 0; i < 3; i++ {
		rec := makeTestDecisionRecord()
		h, _ := record.ComputeRecordHash(rec)
		rec.Integrity.RecordHash = h
		if i > 0 {
			rec.Integrity.PreviousRecordHash = records[i-1].Integrity.RecordHash
		}
		records[i] = rec
	}

	v := New()
	check, err := v.VerifyChain(records)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !check.Passed {
		t.Errorf("VerifyChain should pass: %s", check.Error)
	}
}

func TestVerifyChainBroken(t *testing.T) {
	records := make([]*record.DecisionRecord, 3)
	for i := 0; i < 3; i++ {
		rec := makeTestDecisionRecord()
		h, _ := record.ComputeRecordHash(rec)
		rec.Integrity.RecordHash = h
		if i > 0 {
			rec.Integrity.PreviousRecordHash = records[i-1].Integrity.RecordHash
		}
		records[i] = rec
	}

	// Break the chain at record 2
	records[2].Integrity.PreviousRecordHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	v := New()
	check, _ := v.VerifyChain(records)
	if check.Passed {
		t.Error("VerifyChain should fail for broken chain")
	}
}

func TestVerifyChainTamperedRecord(t *testing.T) {
	rec := makeTestDecisionRecord()
	h, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = h

	// Tamper after hashing
	rec.Model.Name = "tampered"

	v := New()
	check, _ := v.VerifyChain([]*record.DecisionRecord{rec})
	if check.Passed {
		t.Error("VerifyChain should detect tampered record hash")
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	v := New()
	check, _ := v.VerifyChain(nil)
	if !check.Passed {
		t.Error("empty chain should pass")
	}
}

func TestVerifyEnvelopeStrictProfileRequiresPolicyHash(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	hash, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = hash
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileStrict)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if result.Valid {
		t.Fatal("strict profile should fail when policy_hash is missing")
	}
}

func TestVerifyEnvelopeFIPSRejectsEd25519(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	enrichStrictEvidence(t, rec)
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileFIPS)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if result.Valid {
		t.Fatal("fips profile should fail for ed25519 signatures")
	}
}

func TestVerifyEnvelopeStrictRequiresRekorForSigstore(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	enrichStrictEvidence(t, rec)
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)
	env.Signatures[0].KeyID = "fulcio:https://issuer.example::svc"
	env.Signatures[0].Cert = "mock-cert-bytes"
	env.Signatures[0].RekorEntryID = ""

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileStrict)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if result.Valid {
		t.Fatal("strict profile should fail when Sigstore signature lacks rekor_entry_id")
	}
}

func TestVerifyEnvelopeStrictPassesWithCompleteEvidence(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	enrichStrictEvidence(t, rec)
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileStrict)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("strict profile should pass with complete evidence: %+v", result.Checks)
	}
}

func TestVerifyEnvelopeStrictRejectsPartiallyVerifiedMultiSignatureEnvelope(t *testing.T) {
	s1, _ := signer.GenerateEd25519Signer()
	s2, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	enrichStrictEvidence(t, rec)
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s1, s2)

	// Only provide verifier for the first signature.
	v := New(signer.NewEd25519Verifier(s1.PublicKey()))
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileStrict)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if result.Valid {
		t.Fatal("strict profile should fail when any envelope signature is unverifiable")
	}

	strictFailed := false
	for _, check := range result.Checks {
		if check.Name == "profile_strict" && !check.Passed {
			strictFailed = true
			if !strings.Contains(check.Error, "requires all signatures to verify") {
				t.Fatalf("unexpected strict check error: %s", check.Error)
			}
		}
	}
	if !strictFailed {
		t.Fatal("expected profile_strict check to fail")
	}
}

func TestVerifyEnvelopeStrictAcceptsFullyVerifiedMultiSignatureEnvelope(t *testing.T) {
	s1, _ := signer.GenerateEd25519Signer()
	s2, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	enrichStrictEvidence(t, rec)
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s1, s2)

	// Provide verifiers for both signatures.
	v := New(
		signer.NewEd25519Verifier(s1.PublicKey()),
		signer.NewEd25519Verifier(s2.PublicKey()),
	)
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileStrict)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("strict profile should pass when all signatures are verifiable: %+v", result.Checks)
	}
}

func TestVerifyEnvelopeStrictRejectsInvalidSignatureTimestamp(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	enrichStrictEvidence(t, rec)
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)
	env.Signatures[0].Timestamp = "not-a-rfc3339-time"

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	result, err := v.VerifyEnvelopeWithProfile(context.Background(), env, ProfileStrict)
	if err != nil {
		t.Fatalf("VerifyEnvelopeWithProfile error: %v", err)
	}
	if result.Valid {
		t.Fatal("strict profile should reject invalid signature timestamp")
	}
}

func TestVerifyEnvelopeRejectsRevokedKeyAtSignatureTime(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	hash, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = hash
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)
	env.Signatures[0].Timestamp = "2026-02-01T10:00:00Z"

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	if err := v.SetRevocations([]RevocationRule{
		{
			KeyID:       env.Signatures[0].KeyID,
			EffectiveAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
			Reason:      "compromised",
		},
	}); err != nil {
		t.Fatalf("SetRevocations error: %v", err)
	}

	result, err := v.VerifyEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("VerifyEnvelope error: %v", err)
	}
	if result.Valid {
		t.Fatal("verification should fail for revoked key")
	}

	revocationFailed := false
	for _, check := range result.Checks {
		if check.Name == "key_revocation" && !check.Passed {
			revocationFailed = true
			if !strings.Contains(check.Error, "signature key revoked") {
				t.Fatalf("unexpected key_revocation error: %s", check.Error)
			}
		}
	}
	if !revocationFailed {
		t.Fatal("expected key_revocation check to fail")
	}
}

func TestVerifyEnvelopeAllowsKeyBeforeRevocationEffectiveTime(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	hash, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = hash
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)
	env.Signatures[0].Timestamp = "2026-01-01T10:00:00Z"

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	if err := v.SetRevocations([]RevocationRule{
		{
			KeyID:       env.Signatures[0].KeyID,
			EffectiveAt: time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatalf("SetRevocations error: %v", err)
	}

	result, err := v.VerifyEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("VerifyEnvelope error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("verification should pass before revocation effective time: %+v", result.Checks)
	}
}

func TestVerifyEnvelopeRevocationRejectsMalformedSignatureTimestamp(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	rec := makeTestDecisionRecord()
	hash, _ := record.ComputeRecordHash(rec)
	rec.Integrity.RecordHash = hash
	payload, _ := json.Marshal(rec)
	env, _ := signer.SignEnvelope(context.Background(), payload, s)
	env.Signatures[0].Timestamp = "invalid-rfc3339"

	v := New(signer.NewEd25519Verifier(s.PublicKey()))
	if err := v.SetRevocations([]RevocationRule{
		{
			KeyID:       env.Signatures[0].KeyID,
			EffectiveAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatalf("SetRevocations error: %v", err)
	}

	result, err := v.VerifyEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("VerifyEnvelope error: %v", err)
	}
	if result.Valid {
		t.Fatal("verification should fail when revocation check cannot parse signature timestamp")
	}

	revocationFailed := false
	for _, check := range result.Checks {
		if check.Name == "key_revocation" && !check.Passed {
			revocationFailed = true
			if !strings.Contains(check.Error, "invalid signatures[0].timestamp") {
				t.Fatalf("unexpected key_revocation error: %s", check.Error)
			}
		}
	}
	if !revocationFailed {
		t.Fatal("expected key_revocation check to fail")
	}
}

func TestVerifyBundleBasic(t *testing.T) {
	s, _ := signer.GenerateEd25519Signer()
	v := New(signer.NewEd25519Verifier(s.PublicKey()))

	rec1 := makeTestDecisionRecord()
	rec1.PolicyContext.PolicyHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h1, _ := record.ComputeRecordHash(rec1)
	rec1.Integrity.RecordHash = h1
	payload1, _ := json.Marshal(rec1)
	env1, _ := signer.SignEnvelope(context.Background(), payload1, s)

	rec2 := makeTestDecisionRecord()
	rec2.PolicyContext.PolicyHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rec2.Integrity.PreviousRecordHash = h1
	h2, _ := record.ComputeRecordHash(rec2)
	rec2.Integrity.RecordHash = h2
	payload2, _ := json.Marshal(rec2)
	env2, _ := signer.SignEnvelope(context.Background(), payload2, s)

	tree := merkle.New()
	leaf0 := tree.Append([]byte(h1))
	leaf1 := tree.Append([]byte(h2))
	proof0, _ := tree.InclusionProof(leaf0, tree.Size())
	proof1, _ := tree.InclusionProof(leaf1, tree.Size())

	cpSigner := merkle.NewCheckpointSigner(s)
	checkpoint, _ := cpSigner.SignCheckpoint(context.Background(), tree)

	bundle := export.NewBundle(export.BundleFilter{TenantID: "test-tenant"})
	bundle.AddRecord(export.BundleRecord{SequenceNumber: 0, Envelope: env1, InclusionProof: proof0})
	bundle.AddRecord(export.BundleRecord{SequenceNumber: 1, Envelope: env2, InclusionProof: proof1})
	bundle.AddCheckpoint(export.BundleCheckpoint{Checkpoint: checkpoint})
	bundle.Finalize()

	result, err := v.VerifyBundle(context.Background(), bundle, ProfileBasic)
	if err != nil {
		t.Fatalf("VerifyBundle error: %v", err)
	}
	if result.Summary != "VERIFICATION PASSED" {
		t.Fatalf("expected VERIFICATION PASSED, got %s", result.Summary)
	}
}

func makeTestDecisionRecord() *record.DecisionRecord {
	rec := record.New()
	rec.Identity.TenantID = "test-tenant"
	rec.Identity.Subject = "test-user"
	rec.Model.Provider = "openai"
	rec.Model.Name = "gpt-4o"
	rec.PromptContext.UserPromptHash = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	rec.PolicyContext.PolicyDecision = record.PolicyAllow
	rec.Output.OutputHash = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	rec.Output.Mode = record.OutputModeHashOnly
	rec.Integrity.RecordHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	return rec
}

func enrichStrictEvidence(t *testing.T, rec *record.DecisionRecord) {
	t.Helper()

	rec.PolicyContext.PolicyBundleID = "bundle/v1"
	rec.PolicyContext.PolicyHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rec.PolicyContext.DecisionReasonCode = "policy_allow"
	rec.Integrity.PreviousRecordHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	hash, err := record.ComputeRecordHash(rec)
	if err != nil {
		t.Fatalf("ComputeRecordHash error: %v", err)
	}
	rec.Integrity.RecordHash = hash

	tree := merkle.New()
	leafIndex := tree.Append([]byte(hash))
	rec.Integrity.MerkleTreeSize = tree.Size()
	rec.Integrity.MerkleRoot = tree.Root()
	proof, err := tree.InclusionProof(leafIndex, tree.Size())
	if err != nil {
		t.Fatalf("InclusionProof error: %v", err)
	}
	rec.Integrity.InclusionProof = &record.InclusionProof{
		LeafIndex: proof.LeafIndex,
		Hashes:    proof.Hashes,
	}
	rec.Integrity.InclusionProofRef = "/v1/proofs/proof:" + rec.RequestID.String()
}
