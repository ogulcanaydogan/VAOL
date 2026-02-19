package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/yapay-ai/vaol/pkg/auth"
	"github.com/yapay-ai/vaol/pkg/merkle"
	"github.com/yapay-ai/vaol/pkg/store"
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

	count, err := s.store.Count(ctx)
	if err != nil {
		return fmt.Errorf("counting stored records: %w", err)
	}

	rebuilt := merkle.New()
	for seq := int64(0); seq < count; seq++ {
		rec, err := s.store.GetBySequence(ctx, seq)
		if err != nil {
			return fmt.Errorf("loading record sequence %d during rebuild: %w", seq, err)
		}
		idx := rebuilt.Append([]byte(rec.RecordHash))
		if rec.MerkleLeafIndex != idx {
			return fmt.Errorf("merkle leaf index mismatch at seq=%d: stored=%d rebuilt=%d", seq, rec.MerkleLeafIndex, idx)
		}
	}

	cp, err := s.store.GetLatestCheckpoint(ctx)
	if err != nil {
		if err != store.ErrNotFound {
			return fmt.Errorf("loading latest checkpoint: %w", err)
		}
		s.tree = rebuilt
		return nil
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
	s.lastCheckpointAt = cp.Checkpoint.Timestamp

	s.tree = rebuilt
	return nil
}
