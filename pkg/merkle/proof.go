package merkle

import (
	"encoding/json"
	"fmt"
	"time"

	vaolcrypto "github.com/yapay-ai/vaol/pkg/crypto"
)

// ProofType distinguishes between inclusion and consistency proofs.
type ProofType string

const (
	ProofTypeInclusion   ProofType = "inclusion"
	ProofTypeConsistency ProofType = "consistency"
)

// Proof represents a Merkle proof (inclusion or consistency).
type Proof struct {
	ProofType  ProofType `json:"proof_type"`
	LeafIndex  int64     `json:"leaf_index"`
	TreeSize   int64     `json:"tree_size"`
	RootHash   string    `json:"root_hash"`
	Hashes     []string  `json:"hashes"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

// Checkpoint is a signed snapshot of the tree state at a point in time.
type Checkpoint struct {
	TreeSize  int64     `json:"tree_size"`
	RootHash  string    `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
	Signature string    `json:"signature,omitempty"`
	RekorEntryID string `json:"rekor_entry_id,omitempty"`
}

// VerifyInclusion verifies that a leaf hash is included in a tree with the given root.
func VerifyInclusion(leafData []byte, proof *Proof) error {
	if proof.ProofType != ProofTypeInclusion {
		return fmt.Errorf("expected inclusion proof, got %s", proof.ProofType)
	}

	leafHash := vaolcrypto.MerkleLeafHash(leafData)
	computedRoot, err := rootFromInclusionProof(leafHash, proof.LeafIndex, proof.TreeSize, proof.Hashes)
	if err != nil {
		return fmt.Errorf("computing root from proof: %w", err)
	}

	computedRootStr := vaolcrypto.BytesToHash(computedRoot)
	if computedRootStr != proof.RootHash {
		return fmt.Errorf("inclusion proof invalid: computed root %s != expected %s", computedRootStr, proof.RootHash)
	}

	return nil
}

// rootFromInclusionProof computes the expected root from a leaf and its inclusion proof path.
func rootFromInclusionProof(leafHash []byte, leafIndex, treeSize int64, hashes []string) ([]byte, error) {
	if treeSize <= 0 {
		return nil, fmt.Errorf("tree size must be positive")
	}
	if leafIndex < 0 || leafIndex >= treeSize {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, treeSize)
	}

	proofHashes := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := vaolcrypto.HashToBytes(h)
		if err != nil {
			return nil, fmt.Errorf("decoding proof hash %d: %w", i, err)
		}
		proofHashes[i] = b
	}

	return recomputeRoot(leafHash, leafIndex, treeSize, proofHashes)
}

func recomputeRoot(hash []byte, index, size int64, path [][]byte) ([]byte, error) {
	if size == 1 {
		if len(path) != 0 {
			return nil, fmt.Errorf("excess proof hashes for single-leaf tree")
		}
		return hash, nil
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("insufficient proof hashes")
	}

	k := largestPowerOf2LessThan(size)
	sibling := path[len(path)-1]
	remaining := path[:len(path)-1]

	if index < k {
		subRoot, err := recomputeRoot(hash, index, k, remaining)
		if err != nil {
			return nil, err
		}
		return vaolcrypto.MerkleNodeHash(subRoot, sibling), nil
	}
	subRoot, err := recomputeRoot(hash, index-k, size-k, remaining)
	if err != nil {
		return nil, err
	}
	return vaolcrypto.MerkleNodeHash(sibling, subRoot), nil
}

// MarshalJSON provides custom JSON serialization for proofs.
func (p *Proof) MarshalJSON() ([]byte, error) {
	type Alias Proof
	return json.Marshal((*Alias)(p))
}
