package merkletree

import (
	"errors"
	"hash"
)

// A CachedTree can be used to build Merkle roots and proofs from the cached
// Merkle roots of smaller blocks of data. Each CachedTree has a height,
// meaning every element added to the CachedTree is the root of a full Merkle
// tree containing 2^height leaves.
type CachedTree struct {
	cachedNodeHeight             uint64
	trueProofBegin, trueProofEnd uint64
	cachedBegin, cachedEnd       uint64
	Tree
}

// NewCachedTree initializes a CachedTree with a hash object, which will be
// used when hashing the input.
func NewCachedTree(h hash.Hash, cachedNodeHeight uint64) *CachedTree {
	return &CachedTree{
		cachedNodeHeight: cachedNodeHeight,

		Tree: Tree{
			hash: h,

			cachedTree: true,
		},
	}
}

// Prove will create a proof that the leaf at the indicated index is a part of
// the data represented by the Merkle root of the Cached Tree. The CachedTree
// needs the proof set proving that the index or slice belongs to the cached
// element in order to create a correct proof. If SetSlice was called on a slice
// covering multiple cached elements (which means all affected cached elements
// must be covered entirely), cachedProofSet is concatenation of proofs of
// cached elements. After proof is called, the CachedTree is unchanged, and
// can receive more elements.
// Use VerifyProof or VerifyProofOfSlice to verify proofSet returned by this method.
func (ct *CachedTree) Prove(cachedProofSet [][]byte) (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	// Determine the proof index within the full tree, and the number of leaves
	// within the full tree.
	leavesPerCachedNode := uint64(1) << ct.cachedNodeHeight
	numLeaves = leavesPerCachedNode * ct.currentIndex

	cut := ct.cachedEnd - ct.cachedBegin

	// Get the proof set tail, which is generated based entirely on cached
	// nodes.
	merkleRoot, proofSetTail, _, _ := ct.Tree.Prove()
	if len(proofSetTail) < int(cut) {
		// The proof was invalid, return 'nil' for the proof set but accurate
		// values for everything else.
		return merkleRoot, nil, ct.trueProofBegin, numLeaves
	}

	// The full proof set is going to be the input cachedProofSet combined with
	// the tail proof set. The one caveat is that the tail proof set has an
	// extra piece of data at the first element - the verifier will assume that
	// this data exists and therefore it needs to be omitted from the proof
	// set.
	proofSet = append(cachedProofSet, proofSetTail[cut:]...)
	return merkleRoot, proofSet, ct.trueProofBegin, numLeaves
}

// ProveCached will create a proof of cached element values.
// SetSlice must be called on a slice of leaves belonging to entire
// cached elements.
// Use VerifyProofOfCachedElements to verify proofSet returned by this method.
func (ct *CachedTree) ProveCached() (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	// Determine the proof index within the full tree, and the number of leaves
	// within the full tree.
	leavesPerCachedNode := uint64(1) << ct.cachedNodeHeight
	numLeaves = leavesPerCachedNode * ct.currentIndex

	// Get the proof set, which is generated based entirely on cached nodes.
	merkleRoot, proofSet, _, _ = ct.Tree.Prove()
	if len(proofSet) < 1 {
		// The proof was invalid, return 'nil' for the proof set but accurate
		// values for everything else.
		return merkleRoot, nil, ct.trueProofBegin, numLeaves
	}
	if (ct.trueProofEnd-ct.trueProofBegin)%(1<<ct.cachedNodeHeight) != 0 {
		// SetIndex was called or SetSlice for a part of one cached element.
		return merkleRoot, nil, ct.trueProofBegin, numLeaves
	}
	return merkleRoot, proofSet, ct.trueProofBegin, numLeaves
}

// SetIndex will inform the CachedTree of the index of the leaf for which a
// storage proof is being created. The index should be the index of the actual
// leaf, and not the index of the cached element containing the leaf. SetIndex
// or SetSlice must be called on empty CachedTree.
func (ct *CachedTree) SetIndex(i uint64) error {
	return ct.SetSlice(i, i+1)
}

// SetSlice will inform the CachedTree of the slice of leafs for which a
// storage proof is being created. Indices should be the indices of the actual
// leafs, and not the indices of the cached elements containing the leafs.
// SetIndex or SetSlice must be called on empty CachedTree.
// If SetSlice was called on a slice covering multiple cached elements, then
// all affected cached elements must be covered entirely.
func (ct *CachedTree) SetSlice(proofBegin, proofEnd uint64) error {
	if ct.head != nil {
		return errors.New("cannot call SetIndex or SetSlice on Tree if Tree has not been reset")
	}
	ct.trueProofBegin = proofBegin
	ct.trueProofEnd = proofEnd
	ct.cachedBegin = proofBegin / (1 << ct.cachedNodeHeight)
	ct.cachedEnd = (proofEnd-1)/(1<<ct.cachedNodeHeight) + 1
	if ct.cachedEnd != ct.cachedBegin+1 {
		if proofBegin%(1<<ct.cachedNodeHeight) != 0 || proofEnd%(1<<ct.cachedNodeHeight) != 0 {
			return errors.New("cannot call SetSlice affecting multiple cached elements and not covering entire cached elements")
		}
	}
	return ct.Tree.SetSlice(ct.cachedBegin, ct.cachedEnd)
}
