package grpc

import (
	"time"

	vaolv1 "github.com/ogulcanaydogan/vaol/gen/vaol/v1"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
	"github.com/ogulcanaydogan/vaol/pkg/verifier"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- DSSE Envelope converters ---

func protoEnvelopeToGo(pb *vaolv1.DSSEEnvelope) *signer.Envelope {
	if pb == nil {
		return nil
	}
	env := &signer.Envelope{
		PayloadType: pb.PayloadType,
		Payload:     pb.Payload,
		Signatures:  make([]signer.Signature, len(pb.Signatures)),
	}
	for i, s := range pb.Signatures {
		env.Signatures[i] = signer.Signature{
			KeyID:     s.Keyid,
			Sig:       s.Sig,
			Cert:      s.Cert,
			Timestamp: s.Timestamp,
		}
	}
	return env
}

func goEnvelopeToProto(env *signer.Envelope) *vaolv1.DSSEEnvelope {
	if env == nil {
		return nil
	}
	pb := &vaolv1.DSSEEnvelope{
		PayloadType: env.PayloadType,
		Payload:     env.Payload,
		Signatures:  make([]*vaolv1.DSSESignature, len(env.Signatures)),
	}
	for i, s := range env.Signatures {
		pb.Signatures[i] = &vaolv1.DSSESignature{
			Keyid:     s.KeyID,
			Sig:       s.Sig,
			Cert:      s.Cert,
			Timestamp: s.Timestamp,
		}
	}
	return pb
}

// --- StoredRecord → proto DecisionRecordEnvelope ---

func goStoredRecordToProto(sr *store.StoredRecord) *vaolv1.DecisionRecordEnvelope {
	if sr == nil {
		return nil
	}
	pb := &vaolv1.DecisionRecordEnvelope{
		SequenceNumber:     sr.SequenceNumber,
		Envelope:           goEnvelopeToProto(sr.Envelope),
		RecordHash:         sr.RecordHash,
		PreviousRecordHash: sr.PreviousRecordHash,
		TenantId:           sr.TenantID,
		MerkleLeafIndex:    sr.MerkleLeafIndex,
	}
	if !sr.Timestamp.IsZero() {
		pb.Timestamp = timestamppb.New(sr.Timestamp)
	}
	return pb
}

// --- Merkle proof converters ---

func goProofToProto(p *merkle.Proof) *vaolv1.InclusionProof {
	if p == nil {
		return nil
	}
	pb := &vaolv1.InclusionProof{
		LeafIndex: p.LeafIndex,
		TreeSize:  p.TreeSize,
		RootHash:  p.RootHash,
		Hashes:    p.Hashes,
	}
	if p.Checkpoint != nil {
		pb.Checkpoint = goCheckpointToProto(p.Checkpoint)
	}
	return pb
}

func goConsistencyProofToProto(p *merkle.Proof) *vaolv1.ConsistencyProof {
	if p == nil {
		return nil
	}
	oldRoot := ""
	if p.Checkpoint != nil {
		oldRoot = p.Checkpoint.RootHash
	}
	return &vaolv1.ConsistencyProof{
		FirstTreeSize:  p.LeafIndex, // overloaded: consistency proof stores old size in LeafIndex
		SecondTreeSize: p.TreeSize,
		FirstRootHash:  oldRoot,
		SecondRootHash: p.RootHash,
		Hashes:         p.Hashes,
	}
}

// --- Checkpoint converters ---

func goCheckpointToProto(cp *merkle.Checkpoint) *vaolv1.SignedCheckpoint {
	if cp == nil {
		return nil
	}
	pb := &vaolv1.SignedCheckpoint{
		TreeSize:     cp.TreeSize,
		RootHash:     cp.RootHash,
		Signature:    cp.Signature,
		RekorEntryId: cp.RekorEntryID,
	}
	if !cp.Timestamp.IsZero() {
		pb.Timestamp = timestamppb.New(cp.Timestamp)
	}
	return pb
}

// --- Verification result converters ---

func goVerifyResultToProto(r *verifier.Result) *vaolv1.VerificationResult {
	if r == nil {
		return nil
	}
	pb := &vaolv1.VerificationResult{
		RequestId: r.RequestID,
		Valid:     r.Valid,
		Error:     r.Error,
		Checks:    make([]*vaolv1.CheckResult, len(r.Checks)),
	}
	for i, c := range r.Checks {
		pb.Checks[i] = &vaolv1.CheckResult{
			Name:    c.Name,
			Passed:  c.Passed,
			Details: c.Details,
			Error:   c.Error,
		}
	}
	return pb
}

// --- Timestamp helpers ---

func protoTimestampToTime(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}
