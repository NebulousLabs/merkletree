package merkletree

import (
	"hash"
)

// A CachedTree will take the cached nodes of a merkle tree and use them to
// build roots and create proofs of a larger tree. Because the cached tree is
// taking nodes instead of leaves, significantly less hashing is required to
// produce the root and proofs. This is particularly useful if the contents of
// a cached tree have been altered. The components of the cached tree that
// changed can be updated and must be hashed in full, but the components of the
// cached tree that did not change do not need to be updated or hashed. All
// elements added to the cached tree must be at the same height, meaning that
// the original Tree must have a number of leaves that is a factor of the
// number of leaves per cached node.
type CachedTree struct {
	Tree
}

// NewCachedTree initializes a CachedTree with a hash object, which will be
// used when hashing the input. The hash must match the hash that was used in
// the original tree.
func NewCachedTree(h hash.Hash) *CachedTree {
	return &CachedTree{
		Tree: Tree{
			hash: h,

			cachedTree: true,
		},
	}
}

// Prove will create a proof that a data element of a cached tree is a part of
// the merkle root of the cached tree. Because the tree is cached, additional
// infomration is needed to create the proof. A proof that the element is in
// the corresponding subtree is needed, the index of the elmeent within the
// subtree is needed, and the height of the cached node is needed.
func (ct *CachedTree) Prove(cachedProofSet [][]byte, cachedProofIndex, cachedNodeHeight uint64) (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	// Determine the proof index within the full tree, and the number of leaves
	// within the full tree.
	leavesPerCachedNode := uint64(1) << cachedNodeHeight
	proofIndex = cachedProofIndex + (ct.proofIndex * leavesPerCachedNode)
	numLeaves = leavesPerCachedNode * ct.currentIndex

	// Get the proof set tail, which is generated based entirely on cached
	// nodes.
	merkleRoot, proofSetTail, _, _ := ct.Tree.Prove()
	if len(proofSetTail) < 1 {
		// The proof was invalid, return 'nil' for the proof set but accurate
		// values for everything else.
		return merkleRoot, nil, proofIndex, numLeaves
	}

	// The full proof set is going to be the input cachedProofSet combined with
	// the tail proof set. The one caveat is that the tail proof set has an
	// extra piece of data at the first element - the verifier will assume that
	// this data exists and therefore it needs to be ommitted from the proof
	// set.
	proofSet = append(cachedProofSet, proofSetTail[1:]...)
	return merkleRoot, proofSet, proofIndex, numLeaves
}
