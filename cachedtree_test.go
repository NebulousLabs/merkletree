package merkletree

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestCachedTreeConstruction checks that a CachedTree will correctly build to
// the same merkle root as the Tree when using caches at various heights and
// lengths.
func TestCachedTreeConstruction(t *testing.T) {
	arbData := [][]byte{
		[]byte{1},
		[]byte{2},
		[]byte{3},
		[]byte{4},
		[]byte{5},
		[]byte{6},
		[]byte{7},
		[]byte{8},
	}

	// Test that a CachedTree with no elements will return the same value as a
	// tree with no elements.
	tree := New(sha256.New())
	cachedTree := NewCachedTree(sha256.New())
	if bytes.Compare(tree.Root(), cachedTree.Root()) != 0 {
		t.Error("empty Tree and empty CachedTree do not match")
	}

	// Try comparing the root of a cached tree with one element, where the
	// cache height is 1.
	tree.Reset()
	cachedTree.Reset()
	tree.Push(arbData[0])
	subRoot := tree.Root()
	cachedTree.Push(subRoot)
	if bytes.Compare(tree.Root(), cachedTree.Root()) != 0 {
		t.Error("naive 1-height Tree and CachedTree do not match")
	}

	// Try comparing the root of a cached tree where the cache height is 0, and
	// there are 2 cached elements.
	tree.Reset()
	cachedTree.Reset()
	// Create 2 subtrees, one for caching each element.
	subTree1 := New(sha256.New())
	subTree2 := New(sha256.New())
	subTree1.Push(arbData[0])
	subTree2.Push(arbData[1])
	// Pushed the cached roots into the cachedTree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	// Create a tree from the original elements.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	if bytes.Compare(tree.Root(), cachedTree.Root()) != 0 {
		t.Error("adding 2 len cacheing is causing problems")
	}

	// Try comparing the root of a cached tree where the cache height is 0, and
	// there are 3 cached elements.
	tree.Reset()
	subTree1.Reset()
	subTree2.Reset()
	cachedTree.Reset()
	// Create 3 subtrees, one for caching each element.
	subTree3 := New(sha256.New())
	subTree1.Push(arbData[0])
	subTree2.Push(arbData[1])
	subTree3.Push(arbData[2])
	// Pushed the cached roots into the cachedTree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree3.Root())
	// Create a tree from the original elements.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	if bytes.Compare(tree.Root(), cachedTree.Root()) != 0 {
		t.Error("adding 3 len cacheing is causing problems")
	}

	// Try comparing the root of a cached tree where the cache height is 1, and
	// there is 1 cached element.
	tree.Reset()
	subTree1.Reset()
	cachedTree.Reset()
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	// Supply the cached roots to the cached tree.
	cachedTree.Push(subTree1.Root())
	// Compare against a formally built tree.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	if bytes.Compare(cachedTree.Root(), tree.Root()) != 0 {
		t.Error("comparison has failed")
	}

	// Mirror the above test, but attempt a mutation, which should cause a
	// failure.
	tree.Reset()
	subTree1.Reset()
	cachedTree.Reset()
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	// Supply the cached roots to the cached tree.
	cachedTree.Push(subTree1.Root())
	// Compare against a formally built tree.
	tree.Push(arbData[1]) // Intentional mistake.
	tree.Push(arbData[1])
	if bytes.Compare(cachedTree.Root(), tree.Root()) == 0 {
		t.Error("comparison has succeeded despite mutation")
	}

	// Try comparing the root of a cached tree where the cache height is 2, and
	// there are 5 cached elements.
	tree.Reset()
	subTree1.Reset()
	subTree2.Reset()
	cachedTree.Reset()
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree1.Push(arbData[2])
	subTree1.Push(arbData[3])
	subTree2.Push(arbData[4])
	subTree2.Push(arbData[5])
	subTree2.Push(arbData[6])
	subTree2.Push(arbData[7])
	// Supply the cached roots to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	// Compare against a formally built tree.
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			tree.Push(arbData[j])
		}
	}
	for i := 4; i < 8; i++ {
		tree.Push(arbData[i])
	}
	if bytes.Compare(cachedTree.Root(), tree.Root()) != 0 {
		t.Error("comparison has failed")
	}

	// Mirror the above test, but attempt a mutation, which should cause an
	// error.
	tree.Reset()
	subTree1.Reset()
	subTree2.Reset()
	cachedTree.Reset()
	// Build the subtrees to get the cached roots.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree1.Push(arbData[2])
	subTree1.Push(arbData[3])
	subTree2.Push(arbData[4])
	subTree2.Push(arbData[5])
	subTree2.Push(arbData[6])
	subTree2.Push(arbData[6]) // Intentional mistake.
	// Supply the cached roots to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	// Compare against a formally built tree.
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			tree.Push(arbData[j])
		}
	}
	for i := 4; i < 8; i++ {
		tree.Push(arbData[i])
	}
	if bytes.Compare(cachedTree.Root(), tree.Root()) == 0 {
		t.Error("comparison has succeeded despite mutation")
	}

	// Try proving on an uninitialized cached tree.
	cachedTree.Reset()
	_, proofSet, _, _ := cachedTree.Prove(nil, 0, 0)
	if proofSet != nil {
		t.Error("proving an empty set resulted in a valid proof?")
	}

	// Now try using the cached tree to create proofs. Start with cache height
	// of 0.
	tree.Reset()
	subTree1.Reset()
	err := subTree1.SetIndex(0)
	if err != nil {
		t.Fatal(err)
	}
	cachedTree.Reset()
	err = cachedTree.SetIndex(0)
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtree.
	subTree1.Push(arbData[0])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	root := tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ := subTree1.Prove()
	_, proofSet, proofIndex, numLeaves := cachedTree.Prove(subTreeProofSet, 0, 0)
	if !VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("naive proof was unsuccessful")
	}
	// Try to set the index on a cached tree before it is reset.
	err = cachedTree.SetIndex(2)
	if err == nil {
		t.Error("supposed to see error")
	}

	// Try creating a cached proof with cache height 1, 2 cached nodes, index
	// 1.
	tree.Reset()
	subTree1.Reset()
	err = subTree1.SetIndex(1) // subtree index 0-1, corresponding to index 1.
	if err != nil {
		t.Fatal(err)
	}
	subTree2.Reset()
	cachedTree.Reset()
	err = cachedTree.SetIndex(0) // cached tree index 0.
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree2.Push(arbData[2])
	subTree2.Push(arbData[3])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	tree.Push(arbData[3])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree1.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet, 1, 1)
	if !VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}

	// Try creating a cached proof with cache height 0, 7 cached nodes, index
	// 0.
	tree.Reset()
	subTree1.Reset()
	err = subTree1.SetIndex(0) // subtree index 0-0, corresponding to index 0.
	if err != nil {
		t.Fatal(err)
	}
	subTree2.Reset()
	subTree3.Reset()
	cachedTree.Reset()
	err = cachedTree.SetIndex(0) // cached tree index 0.
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree2.Push(arbData[1])
	subTree3.Push(arbData[2])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree3.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[1])
	tree.Push(arbData[1])
	tree.Push(arbData[1])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree1.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet, 0, 0)
	if !VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}

	// Try creating a cached proof with cache height 0, 3 cached nodes, index
	// 2.
	tree.Reset()
	subTree1.Reset()
	subTree2.Reset()
	subTree3.Reset()
	err = subTree3.SetIndex(0) // subtree index 2-0, corresponding to index 2.
	if err != nil {
		t.Fatal(err)
	}
	subTree2.Reset()
	cachedTree.Reset()
	err = cachedTree.SetIndex(2) // cached tree index 2.
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree2.Push(arbData[1])
	subTree3.Push(arbData[2])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree3.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree3.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet, 0, 0)
	if !VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}

	// Mirror the above test, but with a mutation, causing an error.
	tree.Reset()
	subTree1.Reset()
	err = subTree1.SetIndex(1) // subtree index 0-1, corresponding to index 1.
	if err != nil {
		t.Fatal(err)
	}
	subTree2.Reset()
	cachedTree.Reset()
	err = cachedTree.SetIndex(0) // cached tree index 0.
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree2.Push(arbData[2])
	subTree2.Push(arbData[3])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	tree.Push(arbData[3])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree1.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet, 0, 1) // Intentional mistake.
	if VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was successful, despite intentional mistake")
	}

	// Try creating a cached proof with cache height 2, 3 cached nodes, index
	// 6.
	tree.Reset()
	subTree1.Reset()
	subTree2.Reset()
	err = subTree2.SetIndex(2) // subtree index 1-2, corresponding to index 6.
	if err != nil {
		t.Fatal(err)
	}
	subTree3.Reset()
	cachedTree.Reset()
	err = cachedTree.SetIndex(1) // cached tree index 1.
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree1.Push(arbData[2])
	subTree1.Push(arbData[3])
	subTree2.Push(arbData[4])
	subTree2.Push(arbData[5])
	subTree2.Push(arbData[6])
	subTree2.Push(arbData[7])
	subTree3.Push(arbData[1])
	subTree3.Push(arbData[3])
	subTree3.Push(arbData[5])
	subTree3.Push(arbData[7])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree3.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	tree.Push(arbData[3])
	tree.Push(arbData[4])
	tree.Push(arbData[5])
	tree.Push(arbData[6])
	tree.Push(arbData[7])
	tree.Push(arbData[1])
	tree.Push(arbData[3])
	tree.Push(arbData[5])
	tree.Push(arbData[7])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree2.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet, 2, 2)
	if !VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("proof was unsuccessful")
	}

	// Mirror the above test, but with an intentional mutation to cause a failure.
	tree.Reset()
	subTree1.Reset()
	subTree2.Reset()
	err = subTree2.SetIndex(2) // subtree index 1-2, corresponding to index 6.
	if err != nil {
		t.Fatal(err)
	}
	subTree3.Reset()
	cachedTree.Reset()
	err = cachedTree.SetIndex(1) // cached tree index 1.
	if err != nil {
		t.Fatal(err)
	}
	// Build the subtrees.
	subTree1.Push(arbData[0])
	subTree1.Push(arbData[1])
	subTree1.Push(arbData[2])
	subTree1.Push(arbData[3])
	subTree2.Push(arbData[4])
	subTree2.Push(arbData[5])
	subTree2.Push(arbData[6])
	subTree2.Push(arbData[7])
	subTree3.Push(arbData[1])
	subTree3.Push(arbData[3])
	subTree3.Push(arbData[5])
	subTree3.Push(arbData[7])
	// Supply the cached root to the cached tree.
	cachedTree.Push(subTree1.Root())
	cachedTree.Push(subTree2.Root())
	cachedTree.Push(subTree3.Root())
	// Get the root from the tree, to have certainty about integrity.
	tree.Push(arbData[0])
	tree.Push(arbData[1])
	tree.Push(arbData[2])
	tree.Push(arbData[3])
	tree.Push(arbData[4])
	tree.Push(arbData[5])
	tree.Push(arbData[6])
	tree.Push(arbData[7])
	tree.Push(arbData[1])
	tree.Push(arbData[3])
	tree.Push(arbData[5])
	tree.Push(arbData[7])
	root = tree.Root()
	// Construct the proofs.
	_, subTreeProofSet, _, _ = subTree2.Prove()
	_, proofSet, proofIndex, numLeaves = cachedTree.Prove(subTreeProofSet, 1, 2) // Intentional mistake.
	if VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves) {
		t.Error("naive proof was unsuccessful")
	}
}
