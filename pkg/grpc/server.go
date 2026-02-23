package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	vaolv1 "github.com/ogulcanaydogan/vaol/gen/vaol/v1"
	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/export"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/policy"
	"github.com/ogulcanaydogan/vaol/pkg/record"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
	"github.com/ogulcanaydogan/vaol/pkg/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// tenantMetadataKey is the gRPC metadata key for tenant context.
	tenantMetadataKey = "x-vaol-tenant-id"

	// exportChunkSize is the maximum bytes per ExportBundle stream chunk.
	exportChunkSize = 64 * 1024
)

// LedgerServer implements the vaolv1.VAOLLedgerServer interface.
type LedgerServer struct {
	vaolv1.UnimplementedVAOLLedgerServer

	store            store.Store
	signer           signer.Signer
	verifiers        []signer.Verifier
	tree             *merkle.Tree
	policy           policy.Engine
	verifier         *verifier.Verifier
	checkpointSigner *merkle.CheckpointSigner
	checkpointMu     *sync.Mutex
	version          string
	logger           *slog.Logger
}

// NewLedgerServer creates a new gRPC LedgerServer with the given dependencies.
func NewLedgerServer(
	cfg Config,
	st store.Store,
	sig signer.Signer,
	vers []signer.Verifier,
	tree *merkle.Tree,
	pol policy.Engine,
	ver *verifier.Verifier,
	cpSigner *merkle.CheckpointSigner,
	cpMu *sync.Mutex,
	logger *slog.Logger,
) *LedgerServer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LedgerServer{
		store:            st,
		signer:           sig,
		verifiers:        vers,
		tree:             tree,
		policy:           pol,
		verifier:         ver,
		checkpointSigner: cpSigner,
		checkpointMu:     cpMu,
		version:          cfg.Version,
		logger:           logger,
	}
}

// NewGRPCServer creates and configures a new grpc.Server with the LedgerServer
// registered and server reflection enabled.
func NewGRPCServer(ls *LedgerServer) *grpc.Server {
	srv := grpc.NewServer()
	vaolv1.RegisterVAOLLedgerServer(srv, ls)
	reflection.Register(srv)
	return srv
}

// Serve starts the gRPC server on the given listener.
func Serve(srv *grpc.Server, lis net.Listener) error {
	return srv.Serve(lis)
}

// --- Tenant context extraction ---

func tenantFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(tenantMetadataKey)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

// --- RPC implementations ---

func (s *LedgerServer) Health(ctx context.Context, _ *vaolv1.HealthRequest) (*vaolv1.HealthResponse, error) {
	count, _ := s.store.Count(ctx)
	return &vaolv1.HealthResponse{
		Status:         "ok",
		Version:        s.version,
		RecordCount:    count,
		MerkleTreeSize: s.tree.Size(),
	}, nil
}

func (s *LedgerServer) AppendRecord(ctx context.Context, req *vaolv1.AppendRecordRequest) (*vaolv1.AppendRecordResponse, error) {
	var rec record.DecisionRecord

	// Determine payload source
	var payload []byte
	if req.Envelope != nil && req.Envelope.Payload != "" {
		// Client sent a pre-signed envelope — extract payload for record parsing.
		env := protoEnvelopeToGo(req.Envelope)
		raw, err := signer.ExtractPayload(env)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "extracting envelope payload: %v", err)
		}
		payload = raw
	} else if len(req.RawPayload) > 0 {
		payload = req.RawPayload
	} else {
		return nil, status.Error(codes.InvalidArgument, "either envelope or raw_payload is required")
	}

	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid decision record JSON: %v", err)
	}

	// Set defaults
	if rec.SchemaVersion == "" {
		rec.SchemaVersion = record.SchemaVersion
	}
	if rec.RequestID.String() == "00000000-0000-0000-0000-000000000000" {
		rec.RequestID = uuid.New()
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	// Tenant from gRPC metadata
	tenantHeader := tenantFromContext(ctx)
	if tenantHeader != "" {
		if rec.Identity.TenantID == "" {
			rec.Identity.TenantID = tenantHeader
		} else if rec.Identity.TenantID != tenantHeader {
			return nil, status.Error(codes.PermissionDenied, "tenant mismatch between payload and gRPC metadata")
		}
	}

	// Policy evaluation
	if s.policy != nil {
		policyInput := &policy.Input{
			TenantID:      rec.Identity.TenantID,
			SubjectType:   rec.Identity.SubjectType,
			ModelProvider:  rec.Model.Provider,
			ModelName:      rec.Model.Name,
			OutputMode:     string(rec.Output.Mode),
			HasRAGContext:  rec.RAGContext != nil,
			HasCitations:   rec.RAGContext != nil && len(rec.RAGContext.CitationHashes) > 0,
		}

		decision, err := s.policy.Evaluate(ctx, policyInput)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "policy evaluation failed: %v", err)
		}

		rec.PolicyContext.PolicyDecision = record.PolicyDecision(decision.Decision)
		rec.PolicyContext.DecisionReasonCode = decision.DecisionReasonCode
		rec.PolicyContext.RuleIDs = decision.RuleIDs
		rec.PolicyContext.PolicyHash = s.policy.PolicyHash()
		rec.PolicyContext.PolicyBundleID = s.policy.PolicyBundleID()
		rec.PolicyContext.PolicyEngineVersion = s.policy.Version()

		if !decision.Allow && decision.Decision == "deny" {
			return nil, status.Errorf(codes.PermissionDenied, "request denied by policy: %s", decision.DecisionReasonCode)
		}
	}

	// Compute record hash
	recordHash, err := record.ComputeRecordHash(&rec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "computing record hash: %v", err)
	}
	rec.Integrity.RecordHash = recordHash

	// Hash chain
	latest, err := s.store.GetLatest(ctx)
	if err != nil {
		if err == store.ErrNotFound {
			rec.Integrity.PreviousRecordHash = vaolcrypto.ZeroHash
		} else {
			return nil, status.Errorf(codes.Internal, "getting latest record: %v", err)
		}
	} else {
		rec.Integrity.PreviousRecordHash = latest.RecordHash
	}

	// Merkle tree append
	leafIndex := s.tree.Append([]byte(recordHash))
	treeSize := s.tree.Size()
	merkleRoot := s.tree.Root()

	rec.Integrity.MerkleTreeSize = treeSize
	rec.Integrity.MerkleRoot = merkleRoot

	// Inclusion proof
	proof, err := s.tree.InclusionProof(leafIndex, treeSize)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating inclusion proof: %v", err)
	}
	rec.Integrity.InclusionProof = &record.InclusionProof{
		LeafIndex: proof.LeafIndex,
		Hashes:    proof.Hashes,
	}
	proofID := "proof:" + rec.RequestID.String()
	rec.Integrity.InclusionProofRef = fmt.Sprintf("/v1/proofs/%s", proofID)

	if err := record.Validate(&rec); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid decision record: %v", err)
	}

	// Sign
	fullPayload, err := json.Marshal(&rec)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshaling record: %v", err)
	}

	env, err := signer.SignEnvelope(ctx, fullPayload, s.signer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "signing record: %v", err)
	}

	// Store
	stored := &store.StoredRecord{
		RequestID:          rec.RequestID,
		TenantID:           rec.Identity.TenantID,
		Timestamp:          rec.Timestamp,
		RecordHash:         recordHash,
		PreviousRecordHash: rec.Integrity.PreviousRecordHash,
		Envelope:           env,
		MerkleLeafIndex:    leafIndex,
	}

	seq, err := s.store.Append(ctx, stored)
	if err != nil {
		if err == store.ErrDuplicateRequestID {
			return nil, status.Error(codes.AlreadyExists, "duplicate request_id")
		}
		return nil, status.Errorf(codes.Internal, "storing record: %v", err)
	}

	// Persist proof (best-effort)
	if proofErr := s.store.SaveProof(ctx, &store.StoredProof{
		ProofID:   proofID,
		RequestID: rec.RequestID,
		Proof:     proof,
	}); proofErr != nil {
		s.logger.Warn("failed to persist inclusion proof", "request_id", rec.RequestID.String(), "error", proofErr)
	}

	return &vaolv1.AppendRecordResponse{
		RequestId:         rec.RequestID.String(),
		SequenceNumber:    seq,
		RecordHash:        recordHash,
		MerkleRoot:        merkleRoot,
		MerkleTreeSize:    treeSize,
		InclusionProof:    goProofToProto(proof),
		Timestamp:         timestamppb.New(rec.Timestamp),
		InclusionProofRef: rec.Integrity.InclusionProofRef,
	}, nil
}

func (s *LedgerServer) GetRecord(ctx context.Context, req *vaolv1.GetRecordRequest) (*vaolv1.GetRecordResponse, error) {
	if req.RequestId == "" && req.SequenceNumber == 0 {
		return nil, status.Error(codes.InvalidArgument, "request_id or sequence_number is required")
	}

	var stored *store.StoredRecord
	var err error

	if req.RequestId != "" {
		reqID, parseErr := uuid.Parse(req.RequestId)
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid request_id: %v", parseErr)
		}
		stored, err = s.store.GetByRequestID(ctx, reqID)
	} else {
		stored, err = s.store.GetBySequence(ctx, req.SequenceNumber)
	}

	if err != nil {
		if err == store.ErrNotFound {
			return nil, status.Error(codes.NotFound, "record not found")
		}
		return nil, status.Errorf(codes.Internal, "retrieving record: %v", err)
	}

	return &vaolv1.GetRecordResponse{
		Record: goStoredRecordToProto(stored),
	}, nil
}

func (s *LedgerServer) ListRecords(req *vaolv1.ListRecordsRequest, stream grpc.ServerStreamingServer[vaolv1.DecisionRecordEnvelope]) error {
	ctx := stream.Context()

	filter := store.ListFilter{
		TenantID: req.TenantId,
		Limit:    int(req.Limit),
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if req.Cursor != "" {
		var cursor int64
		if _, err := fmt.Sscanf(req.Cursor, "%d", &cursor); err == nil {
			filter.Cursor = cursor
		}
	}
	if req.After != nil {
		filter.After = protoTimestampToTime(req.After)
	}
	if req.Before != nil {
		filter.Before = protoTimestampToTime(req.Before)
	}

	records, err := s.store.List(ctx, filter)
	if err != nil {
		return status.Errorf(codes.Internal, "listing records: %v", err)
	}

	for _, sr := range records {
		if err := stream.Send(goStoredRecordToProto(sr)); err != nil {
			return err
		}
	}

	return nil
}

func (s *LedgerServer) GetInclusionProof(ctx context.Context, req *vaolv1.GetInclusionProofRequest) (*vaolv1.InclusionProofResponse, error) {
	if req.RequestId == "" {
		return nil, status.Error(codes.InvalidArgument, "request_id is required")
	}

	reqID, err := uuid.Parse(req.RequestId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request_id: %v", err)
	}

	stored, err := s.store.GetByRequestID(ctx, reqID)
	if err != nil {
		if err == store.ErrNotFound {
			return nil, status.Error(codes.NotFound, "record not found")
		}
		return nil, status.Errorf(codes.Internal, "retrieving record: %v", err)
	}

	// Try stored proof first
	proofID := "proof:" + stored.RequestID.String()
	storedProof, proofErr := s.store.GetProofByID(ctx, proofID)
	if proofErr == nil {
		return &vaolv1.InclusionProofResponse{
			Proof: goProofToProto(storedProof.Proof),
		}, nil
	}

	// Fallback: compute live proof
	treeSize := req.TreeSize
	if treeSize <= 0 {
		treeSize = s.tree.Size()
	}
	proof, err := s.tree.InclusionProof(stored.MerkleLeafIndex, treeSize)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generating proof: %v", err)
	}

	return &vaolv1.InclusionProofResponse{
		Proof: goProofToProto(proof),
	}, nil
}

func (s *LedgerServer) GetProofByID(ctx context.Context, req *vaolv1.GetProofByIDRequest) (*vaolv1.InclusionProofResponse, error) {
	if req.ProofId == "" {
		return nil, status.Error(codes.InvalidArgument, "proof_id is required")
	}

	storedProof, err := s.store.GetProofByID(ctx, req.ProofId)
	if err != nil {
		if err == store.ErrNotFound {
			// Fallback: try to derive request_id from canonical format
			requestIDRaw := strings.TrimPrefix(req.ProofId, "proof:")
			requestID, parseErr := uuid.Parse(requestIDRaw)
			if parseErr != nil {
				return nil, status.Error(codes.NotFound, "proof not found")
			}

			stored, recErr := s.store.GetByRequestID(ctx, requestID)
			if recErr != nil {
				return nil, status.Error(codes.NotFound, "record for proof not found")
			}

			proof, liveErr := s.tree.InclusionProof(stored.MerkleLeafIndex, s.tree.Size())
			if liveErr != nil {
				return nil, status.Errorf(codes.Internal, "generating proof: %v", liveErr)
			}

			return &vaolv1.InclusionProofResponse{
				Proof: goProofToProto(proof),
			}, nil
		}
		return nil, status.Errorf(codes.Internal, "retrieving proof: %v", err)
	}

	return &vaolv1.InclusionProofResponse{
		Proof: goProofToProto(storedProof.Proof),
	}, nil
}

func (s *LedgerServer) GetConsistencyProof(ctx context.Context, req *vaolv1.GetConsistencyProofRequest) (*vaolv1.ConsistencyProofResponse, error) {
	if req.FirstTreeSize < 0 || req.SecondTreeSize < 0 {
		return nil, status.Error(codes.InvalidArgument, "tree sizes must be non-negative")
	}

	proof, err := s.tree.ConsistencyProof(req.FirstTreeSize, req.SecondTreeSize)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "generating consistency proof: %v", err)
	}

	return &vaolv1.ConsistencyProofResponse{
		Proof: goConsistencyProofToProto(proof),
	}, nil
}

func (s *LedgerServer) GetCheckpoint(ctx context.Context, _ *vaolv1.GetCheckpointRequest) (*vaolv1.SignedCheckpoint, error) {
	checkpoint, err := s.store.GetLatestCheckpoint(ctx)
	if err == nil {
		return goCheckpointToProto(checkpoint.Checkpoint), nil
	}

	// Fallback: return live tree state
	size := s.tree.Size()
	root := s.tree.Root()
	return &vaolv1.SignedCheckpoint{
		TreeSize:  size,
		RootHash:  root,
		Timestamp: timestamppb.New(time.Now().UTC()),
	}, nil
}

func (s *LedgerServer) VerifyRecord(ctx context.Context, req *vaolv1.VerifyRecordRequest) (*vaolv1.VerificationResult, error) {
	if req.Envelope == nil {
		return nil, status.Error(codes.InvalidArgument, "envelope is required")
	}

	env := protoEnvelopeToGo(req.Envelope)

	profile := verifier.ProfileBasic
	if req.VerificationProfile != "" {
		switch strings.ToLower(req.VerificationProfile) {
		case "basic":
			profile = verifier.ProfileBasic
		case "strict":
			profile = verifier.ProfileStrict
		case "fips":
			profile = verifier.ProfileFIPS
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unsupported verification profile: %s", req.VerificationProfile)
		}
	}

	result, err := s.verifier.VerifyEnvelopeWithProfile(ctx, env, profile)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verification error: %v", err)
	}

	return goVerifyResultToProto(result), nil
}

func (s *LedgerServer) ExportBundle(req *vaolv1.ExportBundleRequest, stream grpc.ServerStreamingServer[vaolv1.BundleChunk]) error {
	ctx := stream.Context()

	filter := store.ListFilter{
		TenantID: req.TenantId,
		Limit:    1000,
	}
	if req.After != nil {
		filter.After = protoTimestampToTime(req.After)
	}
	if req.Before != nil {
		filter.Before = protoTimestampToTime(req.Before)
	}

	records, err := s.store.List(ctx, filter)
	if err != nil {
		return status.Errorf(codes.Internal, "listing records: %v", err)
	}

	bundleFilter := export.BundleFilter{
		TenantID: req.TenantId,
	}
	bundle := export.NewBundle(bundleFilter)

	for _, stored := range records {
		proofID := "proof:" + stored.RequestID.String()
		var proof *merkle.Proof
		if persistedProof, pErr := s.store.GetProofByID(ctx, proofID); pErr == nil {
			proof = persistedProof.Proof
		} else {
			proof, _ = s.tree.InclusionProof(stored.MerkleLeafIndex, s.tree.Size())
		}
		bundle.AddRecord(export.BundleRecord{
			SequenceNumber: stored.SequenceNumber,
			Envelope:       stored.Envelope,
			InclusionProof: proof,
		})
	}

	if cp, cpErr := s.store.GetLatestCheckpoint(ctx); cpErr == nil {
		bundle.AddCheckpoint(export.BundleCheckpoint{
			Checkpoint:   cp.Checkpoint,
			RekorEntryID: cp.RekorEntryID,
		})
	}

	bundle.Finalize()

	// Serialize to JSON and send in chunks
	data, err := json.Marshal(bundle)
	if err != nil {
		return status.Errorf(codes.Internal, "marshaling bundle: %v", err)
	}

	totalSize := int64(len(data))
	for offset := int64(0); offset < totalSize; offset += exportChunkSize {
		end := offset + exportChunkSize
		if end > totalSize {
			end = totalSize
		}
		chunk := &vaolv1.BundleChunk{
			Data:      data[offset:end],
			TotalSize: totalSize,
			Offset:    offset,
		}
		if err := stream.Send(chunk); err != nil {
			return err
		}
	}

	return nil
}
