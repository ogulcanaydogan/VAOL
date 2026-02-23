package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ogulcanaydogan/vaol/pkg/api"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

var errStartupStoreUnsupported = errors.New("startup test store: unsupported operation")

type startupSequenceStore struct {
	records    []*store.StoredRecord
	checkpoint *store.StoredCheckpoint
}

func newStartupSequenceStore(records []*store.StoredRecord, checkpoint *store.StoredCheckpoint) *startupSequenceStore {
	cp := make([]*store.StoredRecord, len(records))
	for i, rec := range records {
		dup := *rec
		cp[i] = &dup
	}
	sort.Slice(cp, func(i, j int) bool {
		return cp[i].SequenceNumber < cp[j].SequenceNumber
	})
	return &startupSequenceStore{records: cp, checkpoint: checkpoint}
}

func (s *startupSequenceStore) Append(_ context.Context, _ *store.StoredRecord) (int64, error) {
	return 0, errStartupStoreUnsupported
}

func (s *startupSequenceStore) GetByRequestID(_ context.Context, requestID uuid.UUID) (*store.StoredRecord, error) {
	for _, rec := range s.records {
		if rec.RequestID == requestID {
			dup := *rec
			return &dup, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *startupSequenceStore) GetBySequence(_ context.Context, seq int64) (*store.StoredRecord, error) {
	for _, rec := range s.records {
		if rec.SequenceNumber == seq {
			dup := *rec
			return &dup, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *startupSequenceStore) GetLatest(_ context.Context) (*store.StoredRecord, error) {
	if len(s.records) == 0 {
		return nil, store.ErrNotFound
	}
	dup := *s.records[len(s.records)-1]
	return &dup, nil
}

func (s *startupSequenceStore) List(_ context.Context, filter store.ListFilter) ([]*store.StoredRecord, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	out := make([]*store.StoredRecord, 0, limit)
	for _, rec := range s.records {
		if filter.Cursor > 0 && rec.SequenceNumber <= filter.Cursor {
			continue
		}
		dup := *rec
		out = append(out, &dup)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (s *startupSequenceStore) Count(_ context.Context) (int64, error) {
	return int64(len(s.records)), nil
}

func (s *startupSequenceStore) PutEncryptedPayload(_ context.Context, _ *store.EncryptedPayload) error {
	return errStartupStoreUnsupported
}

func (s *startupSequenceStore) GetEncryptedPayload(_ context.Context, _ uuid.UUID) (*store.EncryptedPayload, error) {
	return nil, store.ErrNotFound
}

func (s *startupSequenceStore) DeleteExpiredEncryptedPayloads(
	_ context.Context,
	_ time.Time,
	_ int,
	_ string,
) ([]*store.PayloadTombstone, error) {
	return nil, errStartupStoreUnsupported
}

func (s *startupSequenceStore) RotateEncryptionKeyMetadata(_ context.Context, _, _ string, _ int) (int64, error) {
	return 0, errStartupStoreUnsupported
}

func (s *startupSequenceStore) ListPayloadTombstones(_ context.Context, _ string, _ int) ([]*store.PayloadTombstone, error) {
	return nil, nil
}

func (s *startupSequenceStore) SaveKeyRotationEvent(_ context.Context, _ *store.KeyRotationEvent) error {
	return errStartupStoreUnsupported
}

func (s *startupSequenceStore) ListKeyRotationEvents(_ context.Context, _ int) ([]*store.KeyRotationEvent, error) {
	return nil, nil
}

func (s *startupSequenceStore) SaveProof(_ context.Context, _ *store.StoredProof) error {
	return errStartupStoreUnsupported
}

func (s *startupSequenceStore) GetProofByID(_ context.Context, _ string) (*store.StoredProof, error) {
	return nil, store.ErrNotFound
}

func (s *startupSequenceStore) SaveCheckpoint(_ context.Context, checkpoint *store.StoredCheckpoint) error {
	s.checkpoint = checkpoint
	return nil
}

func (s *startupSequenceStore) GetLatestCheckpoint(_ context.Context) (*store.StoredCheckpoint, error) {
	if s.checkpoint == nil {
		return nil, store.ErrNotFound
	}
	cp := *s.checkpoint
	return &cp, nil
}

func (s *startupSequenceStore) Close() error {
	return nil
}

func TestServerStartupRebuildWithNonZeroSequenceNumbers(t *testing.T) {
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	records := []*store.StoredRecord{
		makeStartupStoredRecord(t, 1, mustHashString(t, "record-1"), 0),
		makeStartupStoredRecord(t, 2, mustHashString(t, "record-2"), 1),
	}
	st := newStartupSequenceStore(records, nil)

	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}

	assertStartupHealthTreeSize(t, srv, 2)
}

func TestServerStartupRebuildEmptyLedger(t *testing.T) {
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	st := newStartupSequenceStore(nil, nil)
	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}

	assertStartupHealthTreeSize(t, srv, 0)
}

func TestServerStartupRejectsCheckpointTreeSizeMismatch(t *testing.T) {
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	records := []*store.StoredRecord{
		makeStartupStoredRecord(t, 1, mustHashString(t, "record-mismatch"), 0),
	}
	cp := &store.StoredCheckpoint{
		TreeSize: 2,
		RootHash: mustHashString(t, "invalid-root"),
		Checkpoint: &merkle.Checkpoint{
			TreeSize: 2,
			RootHash: mustHashString(t, "invalid-root"),
		},
	}
	st := newStartupSequenceStore(records, cp)

	cfg := api.DefaultConfig()
	cfg.FailOnStartupCheck = true
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if srv.StartupError() == nil {
		t.Fatal("expected startup error for checkpoint tree size mismatch, got nil")
	}
	if !strings.Contains(srv.StartupError().Error(), "checkpoint tree_size") {
		t.Fatalf("unexpected startup error: %v", srv.StartupError())
	}
}

func TestServerStartupAcceptsValidSignedCheckpoint(t *testing.T) {
	ctx := context.Background()

	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	records := []*store.StoredRecord{
		makeStartupStoredRecord(t, 1, mustHashString(t, "valid-checkpoint-1"), 0),
		makeStartupStoredRecord(t, 2, mustHashString(t, "valid-checkpoint-2"), 1),
	}
	tree := merkle.New()
	for _, rec := range records {
		tree.Append([]byte(rec.RecordHash))
	}
	cp, err := merkle.NewCheckpointSigner(sig).SignCheckpoint(ctx, tree)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	st := newStartupSequenceStore(records, &store.StoredCheckpoint{
		TreeSize:   cp.TreeSize,
		RootHash:   cp.RootHash,
		Checkpoint: cp,
	})

	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}

	assertStartupHealthTreeSize(t, srv, 2)
}

func TestServerStartupRejectsAnchorContinuityMismatch(t *testing.T) {
	ctx := context.Background()

	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	records := []*store.StoredRecord{
		makeStartupStoredRecord(t, 1, mustHashString(t, "anchor-check-1"), 0),
	}
	tree := merkle.New()
	for _, rec := range records {
		tree.Append([]byte(rec.RecordHash))
	}
	cp, err := merkle.NewCheckpointSigner(sig).SignCheckpoint(ctx, tree)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	cp.RekorEntryID = "local:sha256:deadbeef"
	st := newStartupSequenceStore(records, &store.StoredCheckpoint{
		TreeSize:     cp.TreeSize,
		RootHash:     cp.RootHash,
		Checkpoint:   cp,
		RekorEntryID: cp.RekorEntryID,
	})

	cfg := api.DefaultConfig()
	cfg.AnchorMode = "local"
	cfg.AnchorContinuityRequired = true
	cfg.FailOnStartupCheck = true
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if srv.StartupError() == nil {
		t.Fatal("expected startup error for anchor continuity mismatch, got nil")
	}
	if !strings.Contains(srv.StartupError().Error(), "anchor continuity") {
		t.Fatalf("unexpected startup error: %v", srv.StartupError())
	}
}

func TestServerStartupRejectsInvalidVerificationRevocationsFile(t *testing.T) {
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	tmpDir := t.TempDir()
	revocationsPath := tmpDir + "/revocations.json"
	if err := os.WriteFile(revocationsPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := api.DefaultConfig()
	cfg.RebuildOnStart = false
	cfg.VerificationRevocationsFile = revocationsPath

	srv := api.NewServer(cfg, newStartupSequenceStore(nil, nil), sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if srv.StartupError() == nil {
		t.Fatal("expected startup error for invalid verification revocations file, got nil")
	}
	if !strings.Contains(srv.StartupError().Error(), "applying verification revocations") {
		t.Fatalf("unexpected startup error: %v", srv.StartupError())
	}
}

func TestServerStartupAcceptsAnchorContinuityLocal(t *testing.T) {
	ctx := context.Background()

	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	records := []*store.StoredRecord{
		makeStartupStoredRecord(t, 1, mustHashString(t, "anchor-ok-1"), 0),
	}
	tree := merkle.New()
	for _, rec := range records {
		tree.Append([]byte(rec.RecordHash))
	}
	cp, err := merkle.NewCheckpointSigner(sig).SignCheckpoint(ctx, tree)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	anchorID, err := (&merkle.HashAnchorClient{}).Anchor(ctx, cp)
	if err != nil {
		t.Fatalf("Hash anchor: %v", err)
	}
	cp.RekorEntryID = anchorID
	st := newStartupSequenceStore(records, &store.StoredCheckpoint{
		TreeSize:     cp.TreeSize,
		RootHash:     cp.RootHash,
		Checkpoint:   cp,
		RekorEntryID: anchorID,
	})

	cfg := api.DefaultConfig()
	cfg.AnchorMode = "local"
	cfg.AnchorContinuityRequired = true
	cfg.FailOnStartupCheck = true
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}
}

func TestServerStartupRebuildWithSparseSequenceNumbersAndCheckpoint(t *testing.T) {
	ctx := context.Background()

	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	const totalRecords = 650 // exceeds rebuild page size to exercise pagination
	records := make([]*store.StoredRecord, 0, totalRecords)
	tree := merkle.New()

	seq := int64(1000)
	for i := 0; i < totalRecords; i++ {
		recordHash := mustHashString(t, fmt.Sprintf("sparse-seq-%03d", i))
		rec := makeStartupStoredRecord(t, seq, recordHash, int64(i))
		records = append(records, rec)
		tree.Append([]byte(recordHash))
		seq += 2
	}

	cp, err := merkle.NewCheckpointSigner(sig).SignCheckpoint(ctx, tree)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}

	st := newStartupSequenceStore(records, &store.StoredCheckpoint{
		TreeSize:   cp.TreeSize,
		RootHash:   cp.RootHash,
		Checkpoint: cp,
	})

	cfg := api.DefaultConfig()
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if err := srv.StartupError(); err != nil {
		t.Fatalf("unexpected startup error: %v", err)
	}

	assertStartupHealthTreeSize(t, srv, totalRecords)
}

func TestServerStartupRejectsDuplicateSequenceTamper(t *testing.T) {
	sig, err := signer.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("GenerateEd25519Signer: %v", err)
	}
	ver := signer.NewEd25519Verifier(sig.PublicKey())

	records := []*store.StoredRecord{
		makeStartupStoredRecord(t, 42, mustHashString(t, "dup-seq-a"), 0),
		makeStartupStoredRecord(t, 42, mustHashString(t, "dup-seq-b"), 1),
	}
	st := newStartupSequenceStore(records, nil)

	cfg := api.DefaultConfig()
	cfg.FailOnStartupCheck = true
	srv := api.NewServer(cfg, st, sig, []signer.Verifier{ver}, merkle.New(), nil, slog.Default())
	if srv.StartupError() == nil {
		t.Fatal("expected startup error for duplicate/tampered sequence numbers, got nil")
	}
	if !strings.Contains(srv.StartupError().Error(), "non-increasing sequence during rebuild") {
		t.Fatalf("unexpected startup error: %v", srv.StartupError())
	}
}

func makeStartupStoredRecord(t *testing.T, seq int64, recordHash string, leafIndex int64) *store.StoredRecord {
	t.Helper()
	rec := makeTestStoredRecordForAuthTests(t)
	rec.SequenceNumber = seq
	rec.RecordHash = recordHash
	rec.MerkleLeafIndex = leafIndex
	return rec
}

func assertStartupHealthTreeSize(t *testing.T, srv *api.Server, expectedTreeSize int64) {
	t.Helper()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp := mustGet(t, ts.URL+"/v1/health")
	defer resp.Body.Close()

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}

	treeSize, ok := health["tree_size"].(float64)
	if !ok {
		t.Fatalf("unexpected tree_size type: %T", health["tree_size"])
	}
	if int64(treeSize) != expectedTreeSize {
		t.Fatalf("expected tree_size=%d, got %v", expectedTreeSize, health["tree_size"])
	}
}
