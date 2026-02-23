package grpc_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	vaolv1 "github.com/ogulcanaydogan/vaol/gen/vaol/v1"
	"github.com/ogulcanaydogan/vaol/pkg/auth"
	vaolgrpc "github.com/ogulcanaydogan/vaol/pkg/grpc"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/policy"
	"github.com/ogulcanaydogan/vaol/pkg/record"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
	"github.com/ogulcanaydogan/vaol/pkg/verifier"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// testEnv holds all objects needed for a single gRPC integration test.
type testEnv struct {
	client vaolv1.VAOLLedgerClient
	store  *store.MemoryStore
	tree   *merkle.Tree
	signer *signer.Ed25519Signer
	conn   *grpc.ClientConn
	srv    *grpc.Server
}

type testEnvOptions struct {
	authMode     auth.Mode
	authVerifier *auth.Verifier
}

// newTestEnv sets up an in-process gRPC server + client over bufconn.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWithOptions(t, testEnvOptions{})
}

func newTestEnvWithOptions(t *testing.T, opts testEnvOptions) *testEnv {
	t.Helper()

	ms := store.NewMemoryStore()
	tree := merkle.New()
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generating signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	logger := slog.Default()
	cpMu := &sync.Mutex{}
	cpSigner := merkle.NewCheckpointSigner(sig)
	verifierObj := verifier.New(ver)

	cfg := vaolgrpc.Config{
		Addr:    ":0",
		Version: "test",
	}
	if opts.authMode == "" {
		opts.authMode = auth.ModeDisabled
	}

	ls := vaolgrpc.NewLedgerServer(
		cfg, ms, sig, []signer.Verifier{ver}, tree,
		&policy.NoopEngine{}, opts.authMode, opts.authVerifier, verifierObj, cpSigner, cpMu, logger,
	)
	srv := vaolgrpc.NewGRPCServer(ls)

	lis := bufconn.Listen(bufSize)

	go func() {
		if err := srv.Serve(lis); err != nil {
			// bufconn listener is closed when test ends; ignore and exit goroutine.
			return
		}
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}

	t.Cleanup(func() {
		conn.Close()
		srv.GracefulStop()
		lis.Close()
	})

	return &testEnv{
		client: vaolv1.NewVAOLLedgerClient(conn),
		store:  ms,
		tree:   tree,
		signer: sig,
		conn:   conn,
		srv:    srv,
	}
}

func newRequiredAuthTestEnv(t *testing.T, secret string) *testEnv {
	t.Helper()
	authVerifier, err := auth.NewVerifier(auth.Config{
		Mode:        auth.ModeRequired,
		HS256Secret: secret,
	})
	if err != nil {
		t.Fatalf("new auth verifier: %v", err)
	}
	return newTestEnvWithOptions(t, testEnvOptions{
		authMode:     auth.ModeRequired,
		authVerifier: authVerifier,
	})
}

// ctxWithTenant returns a context with the tenant metadata header set.
func ctxWithTenant(tenant string) context.Context {
	md := metadata.Pairs("x-vaol-tenant-id", tenant)
	return metadata.NewOutgoingContext(context.Background(), md)
}

func ctxWithAuthToken(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewOutgoingContext(context.Background(), md)
}

func ctxWithTenantAndAuth(tenant, token string) context.Context {
	md := metadata.Pairs(
		"x-vaol-tenant-id", tenant,
		"authorization", "Bearer "+token,
	)
	return metadata.NewOutgoingContext(context.Background(), md)
}

// mustBuildPayload serializes a minimal valid DecisionRecord JSON.
func mustBuildPayload(t *testing.T) []byte {
	t.Helper()
	return mustBuildPayloadForIdentity(t, "test-tenant", "grpc-test")
}

func mustBuildPayloadForIdentity(t *testing.T, tenant, subject string) []byte {
	t.Helper()
	rec := record.DecisionRecord{
		SchemaVersion: record.SchemaVersion,
		RequestID:     uuid.New(),
		Timestamp:     time.Now().UTC(),
		Identity: record.Identity{
			TenantID:    tenant,
			Subject:     subject,
			SubjectType: "user",
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
			OutputHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			Mode:       "hash_only",
		},
	}
	data, err := json.Marshal(&rec)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return data
}

// --- Tests ---

func TestHealth(t *testing.T) {
	env := newTestEnv(t)

	resp, err := env.client.Health(context.Background(), &vaolv1.HealthRequest{})
	if err != nil {
		t.Fatalf("Health RPC: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status=ok, got %q", resp.Status)
	}
	if resp.Version != "test" {
		t.Errorf("expected version=test, got %q", resp.Version)
	}
	if resp.RecordCount != 0 {
		t.Errorf("expected record_count=0, got %d", resp.RecordCount)
	}
}

func TestAppendRecord(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	payload := mustBuildPayload(t)
	resp, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{
		RawPayload: payload,
	})
	if err != nil {
		t.Fatalf("AppendRecord RPC: %v", err)
	}

	if resp.RequestId == "" {
		t.Error("expected non-empty request_id")
	}
	// MemoryStore is 0-indexed; first record gets sequence 0.
	if resp.SequenceNumber < 0 {
		t.Errorf("expected non-negative sequence, got %d", resp.SequenceNumber)
	}
	if resp.RecordHash == "" {
		t.Error("expected non-empty record_hash")
	}
	if resp.MerkleRoot == "" {
		t.Error("expected non-empty merkle_root")
	}
	if resp.MerkleTreeSize != 1 {
		t.Errorf("expected tree_size=1, got %d", resp.MerkleTreeSize)
	}
	if resp.InclusionProof == nil {
		t.Error("expected non-nil inclusion_proof")
	}

	// Health should now show 1 record
	health, _ := env.client.Health(context.Background(), &vaolv1.HealthRequest{})
	if health.RecordCount != 1 {
		t.Errorf("expected record_count=1 after append, got %d", health.RecordCount)
	}
}

func TestAppendRecordRejectsMissingPayload(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	_, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{})
	if err == nil {
		t.Fatal("expected error for empty request")
	}
}

func TestAppendRecordDuplicateRequestID(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")
	payload := mustBuildPayload(t)

	// First append
	_, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err != nil {
		t.Fatalf("first AppendRecord: %v", err)
	}

	// Second append with same payload (same request_id)
	_, err = env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
}

func TestGetRecord(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	payload := mustBuildPayload(t)
	appendResp, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	// Get by request_id
	getResp, err := env.client.GetRecord(ctx, &vaolv1.GetRecordRequest{
		RequestId: appendResp.RequestId,
	})
	if err != nil {
		t.Fatalf("GetRecord by request_id: %v", err)
	}
	if getResp.Record == nil {
		t.Fatal("expected non-nil record")
	}
	if getResp.Record.RecordHash != appendResp.RecordHash {
		t.Errorf("hash mismatch: got %q, want %q", getResp.Record.RecordHash, appendResp.RecordHash)
	}

	// Get by sequence_number — append a second record so sequence=1 is unambiguous from proto default 0
	payload2 := mustBuildPayload(t)
	appendResp2, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload2})
	if err != nil {
		t.Fatalf("AppendRecord (second): %v", err)
	}

	getResp2, err := env.client.GetRecord(ctx, &vaolv1.GetRecordRequest{
		SequenceNumber: appendResp2.SequenceNumber,
	})
	if err != nil {
		t.Fatalf("GetRecord by sequence: %v", err)
	}
	if getResp2.Record.RecordHash != appendResp2.RecordHash {
		t.Error("sequence lookup returned different record")
	}
}

func TestGetRecordNotFound(t *testing.T) {
	env := newTestEnv(t)
	_, err := env.client.GetRecord(context.Background(), &vaolv1.GetRecordRequest{
		RequestId: uuid.New().String(),
	})
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
}

func TestListRecords(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	// Append 3 records
	for i := 0; i < 3; i++ {
		payload := mustBuildPayload(t)
		if _, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload}); err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
	}

	stream, err := env.client.ListRecords(ctx, &vaolv1.ListRecordsRequest{
		TenantId: "test-tenant",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	var records []*vaolv1.DecisionRecordEnvelope
	for {
		rec, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("stream recv: %v", err)
		}
		records = append(records, rec)
	}

	if len(records) != 3 {
		t.Errorf("expected 3 streamed records, got %d", len(records))
	}
}

func TestGetInclusionProof(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	payload := mustBuildPayload(t)
	appendResp, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	proofResp, err := env.client.GetInclusionProof(ctx, &vaolv1.GetInclusionProofRequest{
		RequestId: appendResp.RequestId,
	})
	if err != nil {
		t.Fatalf("GetInclusionProof: %v", err)
	}
	if proofResp.Proof == nil {
		t.Fatal("expected non-nil proof")
	}
	if proofResp.Proof.RootHash == "" {
		t.Error("expected non-empty root_hash in proof")
	}
}

func TestGetProofByID(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	payload := mustBuildPayload(t)
	appendResp, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	proofID := "proof:" + appendResp.RequestId
	proofResp, err := env.client.GetProofByID(ctx, &vaolv1.GetProofByIDRequest{
		ProofId: proofID,
	})
	if err != nil {
		t.Fatalf("GetProofByID: %v", err)
	}
	if proofResp.Proof == nil {
		t.Fatal("expected non-nil proof")
	}
}

func TestGetConsistencyProof(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	// Append 3 records to get a tree of size 3
	for i := 0; i < 3; i++ {
		payload := mustBuildPayload(t)
		if _, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload}); err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
	}

	// Consistency proof from size 1 to 3
	resp, err := env.client.GetConsistencyProof(ctx, &vaolv1.GetConsistencyProofRequest{
		FirstTreeSize:  1,
		SecondTreeSize: 3,
	})
	if err != nil {
		t.Fatalf("GetConsistencyProof: %v", err)
	}
	if resp.Proof == nil {
		t.Fatal("expected non-nil consistency proof")
	}
	if resp.Proof.SecondRootHash == "" {
		t.Error("expected non-empty second_root_hash")
	}
}

func TestGetCheckpoint(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	// With no records, checkpoint should still return (live fallback)
	resp, err := env.client.GetCheckpoint(ctx, &vaolv1.GetCheckpointRequest{})
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if resp.TreeSize != 0 {
		t.Errorf("expected tree_size=0, got %d", resp.TreeSize)
	}

	// Append a record and verify checkpoint reflects it
	payload := mustBuildPayload(t)
	if _, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload}); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	resp, err = env.client.GetCheckpoint(ctx, &vaolv1.GetCheckpointRequest{})
	if err != nil {
		t.Fatalf("GetCheckpoint after append: %v", err)
	}
	if resp.TreeSize != 1 {
		t.Errorf("expected tree_size=1 after append, got %d", resp.TreeSize)
	}
}

func TestVerifyRecord(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	// Append first
	payload := mustBuildPayload(t)
	appendResp, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	// Get the stored record to obtain the signed envelope
	getResp, err := env.client.GetRecord(ctx, &vaolv1.GetRecordRequest{
		RequestId: appendResp.RequestId,
	})
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	// Verify
	verifyResp, err := env.client.VerifyRecord(ctx, &vaolv1.VerifyRecordRequest{
		Envelope:            getResp.Record.Envelope,
		VerificationProfile: "basic",
	})
	if err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
	if !verifyResp.Valid {
		t.Errorf("expected valid=true, got false. error=%s", verifyResp.Error)
		for _, check := range verifyResp.Checks {
			t.Logf("  check %s: passed=%v error=%s", check.Name, check.Passed, check.Error)
		}
	}
}

func TestExportBundle(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	// Append 2 records
	for i := 0; i < 2; i++ {
		payload := mustBuildPayload(t)
		if _, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload}); err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
	}

	stream, err := env.client.ExportBundle(ctx, &vaolv1.ExportBundleRequest{
		TenantId: "test-tenant",
	})
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	var chunks [][]byte
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("stream recv: %v", err)
		}
		chunks = append(chunks, chunk.Data)
	}

	if len(chunks) == 0 {
		t.Fatal("expected at least one bundle chunk")
	}

	// Reassemble and parse
	var assembled []byte
	for _, c := range chunks {
		assembled = append(assembled, c...)
	}

	var bundle map[string]interface{}
	if err := json.Unmarshal(assembled, &bundle); err != nil {
		t.Fatalf("failed to parse reassembled bundle: %v", err)
	}

	if bundle["version"] == nil {
		t.Error("expected version in bundle")
	}
}

func TestTenantMismatch(t *testing.T) {
	env := newTestEnv(t)
	// Set gRPC metadata tenant to "tenant-a"
	ctx := ctxWithTenant("tenant-a")

	// Build payload with tenant_id = "tenant-b"
	rec := record.DecisionRecord{
		SchemaVersion: record.SchemaVersion,
		RequestID:     uuid.New(),
		Timestamp:     time.Now().UTC(),
		Identity: record.Identity{
			TenantID:    "tenant-b",
			Subject:     "test",
			SubjectType: "user",
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
			OutputHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			Mode:       "hash_only",
		},
	}
	payload, _ := json.Marshal(&rec)

	_, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
	if err == nil {
		t.Fatal("expected tenant mismatch error, got nil")
	}
}

func TestHashChainIntegrity(t *testing.T) {
	env := newTestEnv(t)
	ctx := ctxWithTenant("test-tenant")

	// Append 3 records
	var responses []*vaolv1.AppendRecordResponse
	for i := 0; i < 3; i++ {
		payload := mustBuildPayload(t)
		resp, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{RawPayload: payload})
		if err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
		responses = append(responses, resp)
	}

	// Verify tree sizes are monotonically increasing
	for i := 1; i < len(responses); i++ {
		if responses[i].MerkleTreeSize <= responses[i-1].MerkleTreeSize {
			t.Errorf("tree size did not increase: %d -> %d", responses[i-1].MerkleTreeSize, responses[i].MerkleTreeSize)
		}
	}

	// Verify each record hash is unique
	hashes := make(map[string]bool)
	for _, r := range responses {
		if hashes[r.RecordHash] {
			t.Errorf("duplicate record hash: %s", r.RecordHash)
		}
		hashes[r.RecordHash] = true
	}
}

func TestAuthRequiredDenyMissingToken(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	ctx := ctxWithTenant("tenant-a")

	_, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-a"),
	})
	assertStatusCodeAndMessage(t, err, codes.Unauthenticated, "authentication failed")
}

func TestAuthRequiredDenyInvalidToken(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	ctx := ctxWithTenantAndAuth("tenant-a", "invalid.jwt.token")

	_, err := env.client.AppendRecord(ctx, &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-a"),
	})
	assertStatusCodeAndMessage(t, err, codes.Unauthenticated, "authentication failed")
}

func TestAuthRequiredAllowValidToken(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	token := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	resp, err := env.client.AppendRecord(ctxWithAuthToken(token), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "", ""),
	})
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	reqID, err := uuid.Parse(resp.RequestId)
	if err != nil {
		t.Fatalf("parse request id: %v", err)
	}
	stored, err := env.store.GetByRequestID(context.Background(), reqID)
	if err != nil {
		t.Fatalf("load stored record: %v", err)
	}
	payload, err := signer.ExtractPayload(stored.Envelope)
	if err != nil {
		t.Fatalf("extract payload: %v", err)
	}
	var rec record.DecisionRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	if rec.Identity.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", rec.Identity.TenantID)
	}
	if rec.Identity.Subject != "svc-a" {
		t.Fatalf("expected svc-a subject, got %q", rec.Identity.Subject)
	}
	if rec.AuthContext == nil {
		t.Fatal("expected auth_context to be populated")
	}
	if rec.AuthContext.Subject != "svc-a" {
		t.Fatalf("expected auth_context.subject=svc-a, got %q", rec.AuthContext.Subject)
	}
	if rec.AuthContext.TokenHash == "" {
		t.Fatal("expected auth_context.token_hash")
	}
}

func TestAppendRecordDenyTenantMismatchWithClaims(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	token := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	_, err := env.client.AppendRecord(ctxWithAuthToken(token), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-b", "svc-a"),
	})
	assertStatusCodeAndMessage(t, err, codes.PermissionDenied, "tenant mismatch")
}

func TestAppendRecordDenySubjectMismatchWithClaims(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	token := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	_, err := env.client.AppendRecord(ctxWithAuthToken(token), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-b"),
	})
	assertStatusCodeAndMessage(t, err, codes.PermissionDenied, "subject mismatch")
}

func TestGetRecordDenyCrossTenant(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	tokenA := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")
	tokenB := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-b",
		"tenant_id": "tenant-b",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	appendResp, err := env.client.AppendRecord(ctxWithAuthToken(tokenA), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-a"),
	})
	if err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	_, err = env.client.GetRecord(ctxWithAuthToken(tokenB), &vaolv1.GetRecordRequest{
		RequestId: appendResp.RequestId,
	})
	assertStatusCodeAndMessage(t, err, codes.PermissionDenied, "tenant mismatch")
}

func TestListRecordsForcedClaimTenantWhenEmpty(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	tokenA := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")
	tokenB := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-b",
		"tenant_id": "tenant-b",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	if _, err := env.client.AppendRecord(ctxWithAuthToken(tokenA), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-a"),
	}); err != nil {
		t.Fatalf("append tenant-a: %v", err)
	}
	if _, err := env.client.AppendRecord(ctxWithAuthToken(tokenB), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-b", "svc-b"),
	}); err != nil {
		t.Fatalf("append tenant-b: %v", err)
	}

	stream, err := env.client.ListRecords(ctxWithAuthToken(tokenA), &vaolv1.ListRecordsRequest{
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	var records []*vaolv1.DecisionRecordEnvelope
	for {
		rec, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			t.Fatalf("stream recv: %v", recvErr)
		}
		records = append(records, rec)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly one tenant-scoped record, got %d", len(records))
	}
	if records[0].TenantId != "tenant-a" {
		t.Fatalf("expected tenant-a record, got %q", records[0].TenantId)
	}
}

func TestExportBundleDenyCrossTenant(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	tokenA := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")
	tokenB := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-b",
		"tenant_id": "tenant-b",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	if _, err := env.client.AppendRecord(ctxWithAuthToken(tokenA), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-a"),
	}); err != nil {
		t.Fatalf("append tenant-a: %v", err)
	}

	stream, err := env.client.ExportBundle(ctxWithAuthToken(tokenB), &vaolv1.ExportBundleRequest{
		TenantId: "tenant-a",
	})
	if err == nil {
		_, err = stream.Recv()
	}
	assertStatusCodeAndMessage(t, err, codes.PermissionDenied, "tenant mismatch")
}

func TestGetProofByIDDenyCrossTenant(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	tokenA := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-a",
		"tenant_id": "tenant-a",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")
	tokenB := mustMakeHS256Token(t, map[string]any{
		"sub":       "svc-b",
		"tenant_id": "tenant-b",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, "test-secret")

	appendResp, err := env.client.AppendRecord(ctxWithAuthToken(tokenA), &vaolv1.AppendRecordRequest{
		RawPayload: mustBuildPayloadForIdentity(t, "tenant-a", "svc-a"),
	})
	if err != nil {
		t.Fatalf("append tenant-a: %v", err)
	}

	_, err = env.client.GetProofByID(ctxWithAuthToken(tokenB), &vaolv1.GetProofByIDRequest{
		ProofId: "proof:" + appendResp.RequestId,
	})
	assertStatusCodeAndMessage(t, err, codes.PermissionDenied, "tenant mismatch")
}

func TestHealthAllowedWithoutAuthWhenAuthRequired(t *testing.T) {
	env := newRequiredAuthTestEnv(t, "test-secret")
	resp, err := env.client.Health(context.Background(), &vaolv1.HealthRequest{})
	if err != nil {
		t.Fatalf("Health RPC: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected ok status, got %q", resp.Status)
	}
}

func mustMakeHS256Token(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertStatusCodeAndMessage(t *testing.T, err error, wantCode codes.Code, wantMsgFragment string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected gRPC error code=%s", wantCode.String())
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != wantCode {
		t.Fatalf("expected code=%s got=%s (msg=%q)", wantCode.String(), st.Code().String(), st.Message())
	}
	if wantMsgFragment != "" && !strings.Contains(st.Message(), wantMsgFragment) {
		t.Fatalf("expected message containing %q, got %q", wantMsgFragment, st.Message())
	}
}
