package merkle

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yapay-ai/vaol/pkg/signer"
)

// CheckpointSigner creates signed Merkle checkpoints.
type CheckpointSigner struct {
	signer signer.Signer
}

// NewCheckpointSigner creates a new CheckpointSigner.
func NewCheckpointSigner(s signer.Signer) *CheckpointSigner {
	return &CheckpointSigner{signer: s}
}

// SignCheckpoint creates a signed checkpoint for the tree at its current state.
func (cs *CheckpointSigner) SignCheckpoint(ctx context.Context, tree *Tree) (*Checkpoint, error) {
	size := tree.Size()
	root := tree.Root()

	cp := &Checkpoint{
		TreeSize:  size,
		RootHash:  root,
		Timestamp: time.Now().UTC(),
	}

	payload, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("marshaling checkpoint: %w", err)
	}

	sig, err := cs.signer.Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("signing checkpoint: %w", err)
	}

	cp.Signature = sig.Sig
	return cp, nil
}

// VerifyCheckpoint verifies a signed checkpoint.
func VerifyCheckpoint(ctx context.Context, cp *Checkpoint, verifier signer.Verifier) error {
	sig := cp.Signature
	rekorEntryID := cp.RekorEntryID
	cp.Signature = ""
	cp.RekorEntryID = ""
	defer func() {
		cp.Signature = sig
		cp.RekorEntryID = rekorEntryID
	}()

	payload, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("marshaling checkpoint for verification: %w", err)
	}

	dssSig := signer.Signature{
		KeyID: verifier.KeyID(),
		Sig:   sig,
	}

	return verifier.Verify(ctx, payload, dssSig)
}
