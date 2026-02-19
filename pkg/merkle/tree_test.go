package merkle

import (
	"fmt"
	"testing"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

func TestNewTreeEmpty(t *testing.T) {
	tree := New()
	if tree.Size() != 0 {
		t.Errorf("Size() = %d, want 0", tree.Size())
	}
	if tree.Root() != vaolcrypto.ZeroHash {
		t.Errorf("Root() = %q, want zero hash", tree.Root())
	}
}

func TestAppendSingleLeaf(t *testing.T) {
	tree := New()
	idx := tree.Append([]byte("leaf-0"))
	if idx != 0 {
		t.Errorf("first leaf index = %d, want 0", idx)
	}
	if tree.Size() != 1 {
		t.Errorf("Size() = %d, want 1", tree.Size())
	}
	root := tree.Root()
	if root == vaolcrypto.ZeroHash {
		t.Error("root of non-empty tree should not be zero hash")
	}
}

func TestAppendMultipleLeaves(t *testing.T) {
	tree := New()
	for i := 0; i < 10; i++ {
		idx := tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
		if idx != int64(i) {
			t.Errorf("leaf %d: index = %d, want %d", i, idx, i)
		}
	}
	if tree.Size() != 10 {
		t.Errorf("Size() = %d, want 10", tree.Size())
	}
}

func TestRootDeterministic(t *testing.T) {
	tree1 := New()
	tree2 := New()
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("leaf-%d", i))
		tree1.Append(data)
		tree2.Append(data)
	}
	if tree1.Root() != tree2.Root() {
		t.Error("trees with same leaves should have same root")
	}
}

func TestRootChangesWithNewLeaf(t *testing.T) {
	tree := New()
	tree.Append([]byte("leaf-0"))
	root1 := tree.Root()
	tree.Append([]byte("leaf-1"))
	root2 := tree.Root()
	if root1 == root2 {
		t.Error("root should change when a new leaf is appended")
	}
}

func TestRootDifferentData(t *testing.T) {
	tree1 := New()
	tree1.Append([]byte("data-A"))
	tree2 := New()
	tree2.Append([]byte("data-B"))
	if tree1.Root() == tree2.Root() {
		t.Error("trees with different leaves should have different roots")
	}
}

func TestRootAt(t *testing.T) {
	tree := New()
	roots := make([]string, 0)
	for i := 0; i < 5; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
		roots = append(roots, tree.Root())
	}

	// Verify RootAt returns same roots
	for i := int64(1); i <= 5; i++ {
		root, err := tree.RootAt(i)
		if err != nil {
			t.Fatalf("RootAt(%d) error: %v", i, err)
		}
		if root != roots[i-1] {
			t.Errorf("RootAt(%d) = %s, want %s", i, root, roots[i-1])
		}
	}
}

func TestRootAtInvalid(t *testing.T) {
	tree := New()
	tree.Append([]byte("leaf"))
	_, err := tree.RootAt(5)
	if err == nil {
		t.Error("RootAt with size > current should fail")
	}
	_, err = tree.RootAt(-1)
	if err == nil {
		t.Error("RootAt with negative size should fail")
	}
}

func TestInclusionProofSingleLeaf(t *testing.T) {
	tree := New()
	tree.Append([]byte("only-leaf"))

	proof, err := tree.InclusionProof(0, 1)
	if err != nil {
		t.Fatalf("InclusionProof error: %v", err)
	}
	if proof.ProofType != ProofTypeInclusion {
		t.Errorf("ProofType = %s, want inclusion", proof.ProofType)
	}
	if proof.LeafIndex != 0 {
		t.Errorf("LeafIndex = %d, want 0", proof.LeafIndex)
	}
	if len(proof.Hashes) != 0 {
		t.Errorf("single-leaf proof should have 0 hashes, got %d", len(proof.Hashes))
	}

	// Verify the proof
	err = VerifyInclusion([]byte("only-leaf"), proof)
	if err != nil {
		t.Errorf("VerifyInclusion failed: %v", err)
	}
}

func TestInclusionProofMultipleLeaves(t *testing.T) {
	tree := New()
	leaves := []string{"leaf-0", "leaf-1", "leaf-2", "leaf-3", "leaf-4", "leaf-5", "leaf-6", "leaf-7"}
	for _, l := range leaves {
		tree.Append([]byte(l))
	}

	// Verify inclusion proof for every leaf
	treeSize := tree.Size()
	for i, l := range leaves {
		proof, err := tree.InclusionProof(int64(i), treeSize)
		if err != nil {
			t.Fatalf("leaf %d: InclusionProof error: %v", i, err)
		}

		err = VerifyInclusion([]byte(l), proof)
		if err != nil {
			t.Errorf("leaf %d: VerifyInclusion failed: %v", i, err)
		}
	}
}

func TestInclusionProofNonPowerOf2(t *testing.T) {
	tree := New()
	for i := 0; i < 5; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	// Verify all leaves
	for i := int64(0); i < 5; i++ {
		proof, err := tree.InclusionProof(i, 5)
		if err != nil {
			t.Fatalf("leaf %d: InclusionProof error: %v", i, err)
		}
		err = VerifyInclusion([]byte(fmt.Sprintf("leaf-%d", i)), proof)
		if err != nil {
			t.Errorf("leaf %d: VerifyInclusion failed: %v", i, err)
		}
	}
}

func TestInclusionProofInvalidIndex(t *testing.T) {
	tree := New()
	tree.Append([]byte("leaf"))

	_, err := tree.InclusionProof(1, 1)
	if err == nil {
		t.Error("should fail for index >= treeSize")
	}
	_, err = tree.InclusionProof(-1, 1)
	if err == nil {
		t.Error("should fail for negative index")
	}
}

func TestVerifyInclusionRejectsWrongData(t *testing.T) {
	tree := New()
	tree.Append([]byte("correct-data"))

	proof, _ := tree.InclusionProof(0, 1)
	err := VerifyInclusion([]byte("wrong-data"), proof)
	if err == nil {
		t.Error("VerifyInclusion should reject wrong data")
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := New()
	for i := 0; i < 4; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	oldRoot := tree.Root()
	oldSize := tree.Size()

	for i := 4; i < 8; i++ {
		tree.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	proof, err := tree.ConsistencyProof(oldSize, tree.Size())
	if err != nil {
		t.Fatalf("ConsistencyProof error: %v", err)
	}
	if proof.ProofType != ProofTypeConsistency {
		t.Errorf("ProofType = %s, want consistency", proof.ProofType)
	}

	_ = oldRoot // consistency proof verification would use this
}

func TestLeafHash(t *testing.T) {
	tree := New()
	tree.Append([]byte("test-leaf"))
	hash, err := tree.LeafHash(0)
	if err != nil {
		t.Fatalf("LeafHash error: %v", err)
	}
	if hash == "" {
		t.Error("LeafHash should not be empty")
	}
}

func TestLeafHashInvalidIndex(t *testing.T) {
	tree := New()
	_, err := tree.LeafHash(0)
	if err == nil {
		t.Error("LeafHash on empty tree should fail")
	}
}

func TestNewFromLeaves(t *testing.T) {
	// Build original tree
	tree1 := New()
	for i := 0; i < 5; i++ {
		tree1.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}

	// Reconstruct from leaves
	leaves := make([][]byte, 5)
	for i := int64(0); i < 5; i++ {
		h, _ := tree1.LeafHash(i)
		b, _ := vaolcrypto.HashToBytes(h)
		leaves[i] = b
	}
	tree2 := NewFromLeaves(leaves)

	if tree1.Root() != tree2.Root() {
		t.Error("reconstructed tree should have same root")
	}
}

func TestLargestPowerOf2LessThan(t *testing.T) {
	tests := []struct {
		n    int64
		want int64
	}{
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{8, 4},
		{9, 8},
		{16, 8},
		{17, 16},
	}
	for _, tt := range tests {
		got := largestPowerOf2LessThan(tt.n)
		if got != tt.want {
			t.Errorf("largestPowerOf2LessThan(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

// Benchmark append + root computation
func BenchmarkTreeAppend(b *testing.B) {
	tree := New()
	for i := 0; i < b.N; i++ {
		tree.Append([]byte(fmt.Sprintf("bench-leaf-%d", i)))
	}
}

func BenchmarkTreeRoot(b *testing.B) {
	tree := New()
	for i := 0; i < 10000; i++ {
		tree.Append([]byte(fmt.Sprintf("bench-leaf-%d", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Root()
	}
}

func BenchmarkInclusionProof(b *testing.B) {
	tree := New()
	for i := 0; i < 10000; i++ {
		tree.Append([]byte(fmt.Sprintf("bench-leaf-%d", i)))
	}
	size := tree.Size()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tree.InclusionProof(int64(i%10000), size); err != nil {
			b.Fatalf("InclusionProof failed: %v", err)
		}
	}
}
