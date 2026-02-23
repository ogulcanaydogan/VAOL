package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ogulcanaydogan/vaol/pkg/auth"
	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/store"
)

func (s *Server) authenticateRequest(r *http.Request) (*auth.Claims, error) {
	if s.authVerifier == nil {
		return nil, nil
	}
	return s.authVerifier.VerifyAuthorization(r.Context(), r.Header.Get("Authorization"))
}

func (s *Server) rebuildMerkleTreeFromStore(ctx context.Context) error {
	if s.store == nil {
		return nil
	}

	rebuilt, err := s.rebuildMerkleTreeFromPersistentLeaves(ctx)
	usedPersistentLeaves := err == nil
	if err != nil {
		switch {
		case errors.Is(err, errMerkleLeafStoreUnavailable), errors.Is(err, errNoPersistedMerkleLeaves):
		default:
			s.logger.Warn("persistent Merkle leaf restore failed; falling back to record traversal", "error", err)
		}
		rebuilt, err = s.rebuildMerkleTreeFromRecords(ctx)
		if err != nil {
			return err
		}
	} else {
		s.logger.Info("rebuilt Merkle tree from persisted leaf state", "tree_size", rebuilt.Size())
	}

	if err := s.validateRebuiltMerkleTree(ctx, rebuilt); err != nil {
		if !usedPersistentLeaves {
			return err
		}
		s.logger.Warn("persisted Merkle leaf state validation failed; falling back to record traversal", "error", err)
		rebuilt, err = s.rebuildMerkleTreeFromRecords(ctx)
		if err != nil {
			return err
		}
		if err := s.validateRebuiltMerkleTree(ctx, rebuilt); err != nil {
			return err
		}
	}

	s.tree = rebuilt
	return nil
}

var (
	errMerkleLeafStoreUnavailable = errors.New("store does not implement MerkleLeafStore")
	errNoPersistedMerkleLeaves    = errors.New("no persisted Merkle leaves found")
)

func (s *Server) rebuildMerkleTreeFromRecords(ctx context.Context) (*merkle.Tree, error) {
	rebuilt := merkle.New()
	const pageSize = 500
	cursor := int64(-1)

	for {
		records, err := s.store.List(ctx, store.ListFilter{
			Limit:  pageSize,
			Cursor: cursor,
		})
		if err != nil {
			return nil, fmt.Errorf("listing records during rebuild: %w", err)
		}

		if len(records) == 0 {
			break
		}

		for _, rec := range records {
			if rec.SequenceNumber <= cursor {
				return nil, fmt.Errorf("non-increasing sequence during rebuild: cursor=%d seq=%d", cursor, rec.SequenceNumber)
			}

			idx := rebuilt.Append([]byte(rec.RecordHash))
			if rec.MerkleLeafIndex != idx {
				return nil, fmt.Errorf(
					"merkle leaf index mismatch at seq=%d: stored=%d rebuilt=%d",
					rec.SequenceNumber,
					rec.MerkleLeafIndex,
					idx,
				)
			}

			cursor = rec.SequenceNumber
		}

		if len(records) < pageSize {
			break
		}
	}

	return rebuilt, nil
}

func (s *Server) rebuildMerkleTreeFromPersistentLeaves(ctx context.Context) (*merkle.Tree, error) {
	leafStore, ok := s.store.(store.MerkleLeafStore)
	if !ok {
		return nil, errMerkleLeafStoreUnavailable
	}

	leafCount, err := leafStore.CountMerkleLeaves(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting persisted Merkle leaves: %w", err)
	}
	if leafCount == 0 {
		return nil, errNoPersistedMerkleLeaves
	}

	const pageSize = 1000
	cursor := int64(-1)
	expectedLeafIndex := int64(0)
	persistedLeafHashes := make([][]byte, 0, leafCount)

	for {
		leaves, err := leafStore.ListMerkleLeaves(ctx, cursor, pageSize)
		if err != nil {
			return nil, fmt.Errorf("listing persisted Merkle leaves: %w", err)
		}
		if len(leaves) == 0 {
			break
		}

		for _, leaf := range leaves {
			if leaf.LeafIndex != expectedLeafIndex {
				return nil, fmt.Errorf("non-contiguous leaf index during restore: expected=%d got=%d", expectedLeafIndex, leaf.LeafIndex)
			}

			expectedLeafHash := vaolcrypto.BytesToHash(vaolcrypto.MerkleLeafHash([]byte(leaf.RecordHash)))
			if leaf.LeafHash != expectedLeafHash {
				return nil, fmt.Errorf("persisted leaf hash mismatch at index=%d", leaf.LeafIndex)
			}

			leafBytes, err := vaolcrypto.HashToBytes(leaf.LeafHash)
			if err != nil {
				return nil, fmt.Errorf("decoding persisted leaf hash at index=%d: %w", leaf.LeafIndex, err)
			}
			persistedLeafHashes = append(persistedLeafHashes, leafBytes)

			cursor = leaf.LeafIndex
			expectedLeafIndex++
		}

		if len(leaves) < pageSize {
			break
		}
	}

	if int64(len(persistedLeafHashes)) != leafCount {
		return nil, fmt.Errorf("persisted leaf count mismatch: listed=%d counted=%d", len(persistedLeafHashes), leafCount)
	}

	return merkle.NewFromLeaves(persistedLeafHashes), nil
}

func (s *Server) validateRebuiltMerkleTree(ctx context.Context, rebuilt *merkle.Tree) error {
	count, err := s.store.Count(ctx)
	if err != nil {
		return fmt.Errorf("counting stored records: %w", err)
	}
	if rebuilt.Size() != count {
		return fmt.Errorf("rebuild count mismatch: tree_size=%d record_count=%d", rebuilt.Size(), count)
	}

	cp, err := s.store.GetLatestCheckpoint(ctx)
	if err != nil {
		if err == store.ErrNotFound {
			return nil
		}
		return fmt.Errorf("loading latest checkpoint: %w", err)
	}
	if cp == nil || cp.Checkpoint == nil {
		return fmt.Errorf("latest checkpoint is nil")
	}

	if cp.TreeSize > rebuilt.Size() {
		return fmt.Errorf("checkpoint tree_size=%d exceeds rebuilt tree size=%d", cp.TreeSize, rebuilt.Size())
	}
	rootAt, err := rebuilt.RootAt(cp.TreeSize)
	if err != nil {
		return fmt.Errorf("computing rebuilt root at checkpoint size: %w", err)
	}
	if rootAt != cp.RootHash {
		return fmt.Errorf("checkpoint root mismatch: checkpoint=%s rebuilt=%s", cp.RootHash, rootAt)
	}

	// If a verifier is available, also verify checkpoint signature.
	if len(s.verifiers) > 0 {
		if err := merkle.VerifyCheckpoint(ctx, cp.Checkpoint, s.verifiers[0]); err != nil {
			return fmt.Errorf("checkpoint signature verification failed: %w", err)
		}
	}
	if err := s.verifyCheckpointAnchorContinuity(ctx, cp); err != nil {
		return fmt.Errorf("checkpoint anchor continuity check failed: %w", err)
	}
	s.lastCheckpointAt = cp.Checkpoint.Timestamp

	return nil
}

func (s *Server) verifyCheckpointAnchorContinuity(ctx context.Context, cp *store.StoredCheckpoint) error {
	if !s.config.AnchorContinuityRequired {
		return nil
	}
	if cp == nil || cp.Checkpoint == nil {
		return fmt.Errorf("checkpoint is nil")
	}

	entryID := strings.TrimSpace(cp.RekorEntryID)
	if entryID == "" {
		entryID = strings.TrimSpace(cp.Checkpoint.RekorEntryID)
	}
	if entryID == "" {
		return fmt.Errorf("checkpoint missing anchor entry id")
	}

	if cp.Checkpoint.RekorEntryID != "" && cp.RekorEntryID != "" && cp.Checkpoint.RekorEntryID != cp.RekorEntryID {
		return fmt.Errorf("checkpoint anchor entry mismatch: checkpoint=%q stored=%q", cp.Checkpoint.RekorEntryID, cp.RekorEntryID)
	}

	verifier, ok := s.anchorClient.(merkle.AnchorContinuityVerifier)
	if !ok {
		return fmt.Errorf("configured anchor client does not support continuity verification")
	}

	cpCopy := *cp.Checkpoint
	cpCopy.RekorEntryID = entryID
	if err := verifier.VerifyCheckpoint(ctx, &cpCopy, entryID); err != nil {
		return err
	}
	return nil
}
