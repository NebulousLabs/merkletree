package merkletree

import (
	"errors"
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
type CachedTree Tree

// joinSubTrees combines two equal sized subTrees into a larger subTree.
func (ct *CachedTree) joinSubTrees(a, b *subTree) *subTree {
	if DEBUG {
		if b.next != a {
			panic("invalid subtree join - 'a' is not paired with 'b'")
		}
		if a.height < b.height {
			panic("invalid subtree presented - height mismatch")
		}
	}

	return &subTree{
		next:   a.next,
		height: a.height + 1,
		sum:    nodeSum(ct.hash, a.sum, b.sum),
	}
}

// NewCachedTree initializes a CachedTree with a hash object, which will be
// used when hashing the input. The hash must match the hash that was used in
// the original tree.
func NewCachedTree(h hash.Hash) *CachedTree {
	return &CachedTree{
		hash: h,
	}
}

// Reset returns the tree to its inital, empty state.
func (ct *CachedTree) Reset() {
	ct.head = nil
	ct.currentIndex = 0
	ct.proofIndex = 0
	ct.proofSet = nil
}

// SetIndex must be called on an empty CachedTree. The index should point to
// the subtree that contains the data which is being proven to be a part of the
// tree.
func (ct *CachedTree) SetIndex(i uint64) error {
	if ct.head != nil {
		return errors.New("cannot call SetIndex on Tree if Tree has not been reset")
	}
	ct.proofIndex = i
	return nil
}

// Push adds a cached node to the tree.
func (ct *CachedTree) Push(data []byte) {
	// If this index is the index of the proof, add the data as a placeholder.
	// Though the data is not actually used when forming a proof, it is
	// inserted as a placeholder so that the logic for combining trees and
	// adding elements to the proof set can be the same logic as in standard
	// tree implementation. This has an added bonus of simplifying some edge
	// cases regarding determining when to add elements to the proof set.
	if ct.currentIndex == ct.proofIndex {
		ct.proofSet = append(ct.proofSet, data)
	}

	// Add the cached node at a subTree of height 0. Because this is a cached
	// node, it does not need to be hashed before being added to a subTree.
	ct.head = &subTree{
		next:   ct.head,
		height: 0,
		sum:    data,
	}

	// Insert the subTree into the Tree. As long as the height of the next
	// subTree is the same as the height of the current subTree, the two will
	// be combined into a single subTree of height n+1.
	for ct.head.next != nil && ct.head.height == ct.head.next.height {
		// Before combining subtrees, check whether one of the subtree hashes
		// needs to be added to the proof set. This is going to be true IFF the
		// subtrees being combined are one height higher than the previous
		// subtree added to the proof set. The height of the previous subtree
		// added to the proof set is equal to len(t.proofSet)-1.
		if ct.head.height == len(ct.proofSet)-1 {
			// One of the subtrees needs to be added to the proof set. The
			// subtree that needs to be added is the subtree that does not
			// contain the proofIndex. Because the subtrees being compared are
			// the smallest and rightmost trees in the Tree, this can be
			// determined by rounding the currentIndex down to the number of
			// nodes in the subtree and comparing that index to the proofIndex.
			leaves := uint64(1 << uint(ct.head.height))
			mid := (ct.currentIndex / leaves) * leaves
			if ct.proofIndex < mid {
				ct.proofSet = append(ct.proofSet, ct.head.sum)
			} else {
				ct.proofSet = append(ct.proofSet, ct.head.next.sum)
			}

			// Sanity check - the proofIndex should never be less than the
			// midpoint minus the number of leaves in each subtree.
			if DEBUG {
				if ct.proofIndex < mid-leaves {
					panic("proof being added with weird values")
				}
			}
		}

		// Join the two subTrees into one subTree with a greater height. Then
		// compare the new subTree to the next subTree.
		ct.head = ct.joinSubTrees(ct.head.next, ct.head)
	}
	ct.currentIndex++

	// Sanity check - From head to tail of the stack, the height should be
	// strictly increasing.
	if DEBUG {
		current := ct.head
		height := current.height
		for current.next != nil {
			current = current.next
			if current.height <= height {
				panic("subtrees are out of order")
			}
			height = current.height
		}
	}
}

// Root returns the Merkle root of the data that has been pushed into the
// CachedTree. The Root should be identical to the root that would be provided
// had the original data been fed directly into a Tree.
func (ct *CachedTree) Root() []byte {
	// If the Tree is empty, return the hash of the empty string.
	if ct.head == nil {
		return sum(ct.hash, nil)
	}

	// The root is formed by hashing together subTrees in order from least in
	// height to greatest in height. The taller subtree is the first subtree in
	// the join.
	current := ct.head
	for current.next != nil {
		current = ct.joinSubTrees(current.next, current)
	}
	return current.sum
}

// Prove will create a proof that a data element of a cached tree is a part of
// the merkle root of the cached tree. Because the tree is cached, additional
// infomration is needed to create the proof. A proof that the element is in
// the corresponding subtree is needed, the index of the elmeent within the
// subtree is needed, and the height of the cached node is needed.
func (ct *CachedTree) Prove(cachedProofSet [][]byte, cachedProofIndex, cachedNodeHeight uint64) (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	// Return nil if the CachedTree is empty, or if the proofIndex hasn't yet
	// been reached.
	if ct.head == nil || len(ct.proofSet) == 0 {
		return ct.Root(), nil, ct.proofIndex, ct.currentIndex
	}
	proofSet = ct.proofSet

	// The set of subtrees must now be collapsed into a single root. The proof
	// set already contains all of the elements that are members of a complete
	// subtree. Of what remains, there will be at most 1 element provided from
	// a sibling on the right, and all of the other proofs will be provided
	// from a sibling on the left. This results from the way orphans are
	// treated. All subtrees smaller than the subtree containing the proofIndex
	// will be combined into a single subtree that gets combined with the
	// proofIndex subtree as a single right sibling. All subtrees larger than
	// the subtree containing the proofIndex will be combined with the subtree
	// containing the proof index as left siblings.

	// Start at the smallest subtree and combine it with larger subtrees until
	// it would be combining with the subtree that contains the proof index. We
	// can recognize the subtree containing the proof index because the height
	// of that subtree will be one less than the current length of the proof
	// set.
	current := ct.head
	for current.next != nil && current.next.height < len(proofSet)-1 {
		current = ct.joinSubTrees(current.next, current)
	}

	// Sanity check - check that either 'current' or 'current.next' is the
	// subtree containing the proof index.
	if DEBUG {
		if current.height != len(ct.proofSet)-1 && (current.next != nil && current.next.height != len(ct.proofSet)-1) {
			panic("could not find the subtree containing the proof index")
		}
	}

	// If the current subtree is not the subtree containing the proof index,
	// then it must be an aggregate subtree that is to the right of the subtree
	// containing the proof index, and the next subtree is the subtree
	// containing the proof index.
	if current.next != nil && current.next.height == len(proofSet)-1 {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}

	// The current subtree must be the subtre containing the proof index. This
	// subtree does not need an entry, as the entry was created during the
	// construction of the Tree. Instead, skip to the next subtree.
	current = current.next

	// All remaning subtrees will be added to the proof set as a left sibling,
	// completeing the proof set.
	for current != nil {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}

	// The proof for the node in the cached tree has been created, now it must
	// be combined with the proof for the cached node that was being proven on,
	// and then the index and numLeaves must be updated so that the proof
	// returned is a fully valid proof independent of any knowledge of
	// cacheing.

	// Exclude the cached data piece from the full proof set, the verifier will
	// automatically compute it from the earlier parts of the proof set.
	fullProofSet := append(cachedProofSet, proofSet[1:]...)
	leavesPerCachedNode := uint64(1) << cachedNodeHeight
	fullProofIndex := cachedProofIndex + (ct.proofIndex * leavesPerCachedNode)
	fullNumLeaves := leavesPerCachedNode * ct.currentIndex

	return ct.Root(), fullProofSet, fullProofIndex, fullNumLeaves
}
