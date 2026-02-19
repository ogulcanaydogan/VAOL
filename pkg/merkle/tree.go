// Package merkle implements an RFC 6962-style append-only Merkle tree
// for the VAOL tamper-evident log.
package merkle

import (
	"fmt"
	"math/bits"
	"sync"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

// Tree is an in-memory append-only Merkle tree.
// It stores leaf hashes and computes interior nodes on demand.
// Thread-safe for concurrent reads; writes must be serialized.
type Tree struct {
	mu     sync.RWMutex
	leaves [][]byte // leaf hashes (after LeafHash)
}

// New creates an empty Merkle tree.
func New() *Tree {
	return &Tree{
		leaves: make([][]byte, 0, 1024),
	}
}

// NewFromLeaves reconstructs a tree from existing leaf hashes.
func NewFromLeaves(leaves [][]byte) *Tree {
	cp := make([][]byte, len(leaves))
	copy(cp, leaves)
	return &Tree{leaves: cp}
}

// Append adds a new entry to the tree. The data is first hashed using
// the RFC 6962 leaf hash function (SHA-256(0x00 || data)).
// Returns the leaf index.
func (t *Tree) Append(data []byte) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	leaf := vaolcrypto.MerkleLeafHash(data)
	idx := int64(len(t.leaves))
	t.leaves = append(t.leaves, leaf)
	return idx
}

// Size returns the number of leaves in the tree.
func (t *Tree) Size() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return int64(len(t.leaves))
}

// Root computes the Merkle tree root hash.
// Returns the zero hash for an empty tree.
func (t *Tree) Root() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.rootAt(int64(len(t.leaves)))
}

// RootAt computes the root hash for the tree at a given size.
func (t *Tree) RootAt(size int64) (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if size < 0 || size > int64(len(t.leaves)) {
		return "", fmt.Errorf("invalid tree size: %d (current: %d)", size, len(t.leaves))
	}
	return t.rootAt(size), nil
}

func (t *Tree) rootAt(size int64) string {
	if size == 0 {
		return vaolcrypto.ZeroHash
	}
	root := computeRoot(t.leaves[:size])
	return vaolcrypto.BytesToHash(root)
}

// InclusionProof generates a Merkle inclusion proof for the leaf at the given
// index in a tree of the given size.
func (t *Tree) InclusionProof(leafIndex, treeSize int64) (*Proof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if leafIndex < 0 || leafIndex >= treeSize {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, treeSize)
	}
	if treeSize > int64(len(t.leaves)) {
		return nil, fmt.Errorf("tree size %d exceeds current size %d", treeSize, len(t.leaves))
	}

	path := inclusionPath(t.leaves[:treeSize], leafIndex)
	hashes := make([]string, len(path))
	for i, h := range path {
		hashes[i] = vaolcrypto.BytesToHash(h)
	}

	return &Proof{
		ProofType: ProofTypeInclusion,
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
		RootHash:  t.rootAt(treeSize),
		Hashes:    hashes,
	}, nil
}

// ConsistencyProof generates a proof that the tree at oldSize is a prefix
// of the tree at newSize.
func (t *Tree) ConsistencyProof(oldSize, newSize int64) (*Proof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if oldSize < 0 || oldSize > newSize {
		return nil, fmt.Errorf("invalid sizes: old=%d, new=%d", oldSize, newSize)
	}
	if newSize > int64(len(t.leaves)) {
		return nil, fmt.Errorf("new size %d exceeds current size %d", newSize, len(t.leaves))
	}
	if oldSize == 0 {
		return &Proof{
			ProofType: ProofTypeConsistency,
			TreeSize:  newSize,
			RootHash:  t.rootAt(newSize),
			Hashes:    []string{},
		}, nil
	}

	path := consistencyPath(t.leaves[:newSize], oldSize)
	hashes := make([]string, len(path))
	for i, h := range path {
		hashes[i] = vaolcrypto.BytesToHash(h)
	}

	return &Proof{
		ProofType: ProofTypeConsistency,
		LeafIndex: oldSize,
		TreeSize:  newSize,
		RootHash:  t.rootAt(newSize),
		Hashes:    hashes,
	}, nil
}

// LeafHash returns the stored leaf hash at the given index.
func (t *Tree) LeafHash(index int64) (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if index < 0 || index >= int64(len(t.leaves)) {
		return "", fmt.Errorf("leaf index %d out of range [0, %d)", index, len(t.leaves))
	}
	return vaolcrypto.BytesToHash(t.leaves[index]), nil
}

// computeRoot computes the Merkle root of a slice of leaf hashes.
func computeRoot(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		return nil
	}
	if n == 1 {
		result := make([]byte, len(leaves[0]))
		copy(result, leaves[0])
		return result
	}

	// Split at the largest power of 2 less than n
	k := largestPowerOf2LessThan(int64(n))
	left := computeRoot(leaves[:k])
	right := computeRoot(leaves[k:])
	return vaolcrypto.MerkleNodeHash(left, right)
}

// inclusionPath computes the audit path for leaf at index in a tree of given leaves.
func inclusionPath(leaves [][]byte, index int64) [][]byte {
	n := int64(len(leaves))
	if n <= 1 {
		return nil
	}

	k := largestPowerOf2LessThan(n)
	if index < k {
		path := inclusionPath(leaves[:k], index)
		rightRoot := computeRoot(leaves[k:])
		return append(path, rightRoot)
	}
	path := inclusionPath(leaves[k:], index-k)
	leftRoot := computeRoot(leaves[:k])
	return append(path, leftRoot)
}

// consistencyPath computes the consistency proof between two tree sizes.
func consistencyPath(leaves [][]byte, oldSize int64) [][]byte {
	n := int64(len(leaves))
	if oldSize == n {
		return nil
	}
	if oldSize == 0 {
		return nil
	}

	k := largestPowerOf2LessThan(n)
	if oldSize <= k {
		path := consistencyPath(leaves[:k], oldSize)
		rightRoot := computeRoot(leaves[k:])
		return append(path, rightRoot)
	}
	path := consistencyPath(leaves[k:], oldSize-k)
	leftRoot := computeRoot(leaves[:k])
	return append(path, leftRoot)
}

// largestPowerOf2LessThan returns the largest power of 2 that is strictly less than n.
func largestPowerOf2LessThan(n int64) int64 {
	if n <= 1 {
		return 0
	}
	return 1 << (bits.Len64(uint64(n-1)) - 1)
}
