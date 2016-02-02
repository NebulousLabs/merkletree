// Package merkletree provides tools for calculating the Merkle root of a
// dataset, for creating a proof that a piece of data is in a Merkle tree of a
// given root, and for verifying proofs that a piece of data is in a Merkle
// tree of a given root. The tree is implemented according to the specification
// for Merkle trees provided in RFC 6962.
//
// As a recent addition, package merkletree also supports building roots and
// proofs from cached merkle trees. A cached merkle tree will saves all of the
// nodes at some height, such as height 16. While this incurs a linear storage
// cost in the size of the data, it prevents having to rehash the data any time
// some portion of the data changes or anytime that a proof needs to be
// created. The computational savings are often great enough to justify the
// storage tradeoff.
package merkletree

import (
	"bytes"
	"errors"
	"hash"
)

// A Tree takes data as leaves and returns the Merkle root. Each call to 'Push'
// adds one leaf to the Merkle tree. Calling 'Root' returns the Merkle root.
// The Tree also constructs proof that a single leaf is a part of the tree. The
// leaf can be chosen with 'SetIndex'. The memory footprint of Tree grows in
// O(log(n)) in the number of leaves.
type Tree struct {
	// The Tree is stored as a stack of subtrees. Each subtree has a height,
	// and is the Merkle root of 2^height leaves. A Tree with 11 nodes is
	// represented as a subtree of height 3 (8 nodes), a subtree of height 1 (2
	// nodes), and a subtree of height 0 (1 node). Head points to the smallest
	// tree. When a new leaf is inserted, it is inserted as a subtree of height
	// 0. If there is another subtree of the same height, both can be removed,
	// combined, and then inserted as a subtree of height n + 1.
	head *subTree
	hash hash.Hash

	// Helper variables used to construct proofs that the data at 'proofIndex'
	// is in the Merkle tree. The proofSet is constructed as elements are being
	// added to the tree. The first element of the proof set is the original
	// data used to create the leaf at index 'proofIndex'.
	currentIndex uint64
	proofIndex   uint64
	proofSet     [][]byte
}

// A subTree contains the Merkle root of a complete (2^height leaves) subTree
// of the Tree. 'sum' is the Merkle root of the subTree. If 'next' is not nil,
// it will be a tree with a higher height.
type subTree struct {
	next   *subTree
	height int
	sum    []byte
}

// sum returns the hash of the input data using the specified algorithm.
func sum(h hash.Hash, data []byte) []byte {
	if data == nil {
		return nil
	}

	_, err := h.Write(data)
	if err != nil {
		// Result will not be correct if the hash is throwing an error when
		// it's supposed to be checksumming data.
		panic(err)
	}
	result := h.Sum(nil)
	h.Reset()
	return result
}

// leafSum returns the hash created from data inserted to form a leaf. Leaf
// sums are calculated using:
//		Hash( 0x00 || data)
func leafSum(h hash.Hash, data []byte) []byte {
	return sum(h, append([]byte{0}, data...))
}

// nodeSum returns the hash created from two sibling nodes being combined into
// a parent node. Node sums are calculated using:
//		Hash( 0x01 || left sibling sum || right sibling sum)
func nodeSum(h hash.Hash, a, b []byte) []byte {
	return sum(h, append(append([]byte{1}, a...), b...))
}

// joinSubTrees combines two equal sized subTrees into a larger subTree.
func joinSubTrees(h hash.Hash, a, b *subTree) *subTree {
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
		sum:    nodeSum(h, a.sum, b.sum),
	}
}

// New initializes a Tree with a hash object, which will be used when hashing
// the input.
func New(h hash.Hash) *Tree {
	return &Tree{
		hash: h,
	}
}

// Reset returns the tree to its inital, empty state.
func (t *Tree) Reset() {
	t.head = nil
	t.currentIndex = 0
	t.proofIndex = 0
	t.proofSet = nil
}

// SetIndex must be called on an empty Tree. Trees can be emptied by calling
// Reset.
func (t *Tree) SetIndex(i uint64) error {
	if t.head != nil {
		return errors.New("cannot call SetIndex on Tree if Tree has not been reset")
	}
	t.proofIndex = i
	return nil
}

// Push adds a leaf to the tree by hashing the input and then inserting the
// result as a leaf.
func (t *Tree) Push(data []byte) {
	// The first element of a proof is the data at the proof index. If this
	// data is being inserted at the proof index, it is added to the proof set.
	if t.currentIndex == t.proofIndex {
		t.proofSet = append(t.proofSet, data)
	}

	// Hash the data to create a subtree of height 0.
	t.head = &subTree{
		next:   t.head,
		height: 0,
		sum:    leafSum(t.hash, data),
	}

	// Insert the subTree into the Tree. As long as the height of the next
	// subTree is the same as the height of the current subTree, the two will
	// be combined into a single subTree of height n+1.
	for t.head.next != nil && t.head.height == t.head.next.height {
		// Before combining subtrees, check whether one of the subtree hashes
		// needs to be added to the proof set. This is going to be true IFF the
		// subtrees being combined are one height higher than the previous
		// subtree added to the proof set. The height of the previous subtree
		// added to the proof set is equal to len(t.proofSet) - 1.
		if t.head.height == len(t.proofSet)-1 {
			// One of the subtrees needs to be added to the proof set. The
			// subtree that needs to be added is the subtree that does not
			// contain the proofIndex. Because the subtrees being compared are
			// the smallest and rightmost trees in the Tree, this can be
			// determined by rounding the currentIndex down to the number of
			// nodes in the subtree and comparing that index to the proofIndex.
			leaves := uint64(1 << uint(t.head.height))
			mid := (t.currentIndex / leaves) * leaves
			if t.proofIndex < mid {
				t.proofSet = append(t.proofSet, t.head.sum)
			} else {
				t.proofSet = append(t.proofSet, t.head.next.sum)
			}

			// Sanity check - the proofIndex should never be less than the
			// midpoint minus the number of leaves in each subtree.
			if DEBUG {
				if t.proofIndex < mid-leaves {
					panic("proof being added with weird values")
				}
			}
		}

		// Join the two subTrees into one subTree with a greater height. Then
		// compare the new subTree to the next subTree.
		t.head = joinSubTrees(t.hash, t.head.next, t.head)
	}
	t.currentIndex++

	// Sanity check - From head to tail of the stack, the height should be
	// strictly increasing.
	if DEBUG {
		current := t.head
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

// Root returns the Merkle root of the data that has been pushed into the Tree.
func (t *Tree) Root() []byte {
	// If the Tree is empty, return the hash of the empty string.
	if t.head == nil {
		return sum(t.hash, nil)
	}

	// The root is formed by hashing together subTrees in order from least in
	// height to greatest in height. The taller subtree is the first subtree in
	// the join.
	current := t.head
	for current.next != nil {
		current = joinSubTrees(t.hash, current.next, current)
	}
	return current.sum
}

// Prove returns a proof that the data at index 'proofIndex' is an element in
// the current Tree. The proof will be invalid if any more elements are added
// to the tree after calling Prove. The tree is left unaltered.
func (t *Tree) Prove() (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	// Return nil if the Tree is empty, or if the proofIndex hasn't yet been
	// reached.
	if t.head == nil || len(t.proofSet) == 0 {
		return t.Root(), nil, t.proofIndex, t.currentIndex
	}
	proofSet = t.proofSet

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
	current := t.head
	for current.next != nil && current.next.height < len(proofSet)-1 {
		current = joinSubTrees(t.hash, current.next, current)
	}

	// Sanity check - check that either 'current' or 'current.next' is the
	// subtree containing the proof index.
	if DEBUG {
		if current.height != len(t.proofSet)-1 && (current.next != nil && current.next.height != len(t.proofSet)-1) {
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
	return t.Root(), proofSet, t.proofIndex, t.currentIndex
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func VerifyProof(h hash.Hash, merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) bool {
	// Return false for nonsense input. A switch statement is used so that the
	// cover tool will reveal if a case is not covered by the test suite. This
	// would not be possible using a single if statement due to the limitations
	// of the cover tool.
	switch {
	case merkleRoot == nil:
		return false
	case proofIndex >= numLeaves:
		return false
	}

	// In a Merkle tree, every node except the root node has a sibling.
	// Combining the two siblings in the correct order will create the parent
	// node. Each of the remaining hashes in the proof set is a sibling to a
	// node that can be built from all of the previous elements of the proof
	// set. The next node is built by taking:
	//
	//		H(0x01 || sibling A || sibling B)
	//
	// The difficulty of the algorithm lies in determining whether the supplied
	// hash is sibling A or sibling B. This information can be determined by
	// using the proof index and the total number of leaves in the tree.
	//
	// A pair of two siblings forms a subtree. The subtree is complete if it
	// has 1 << height total leaves. When the subtree is complete, the position
	// of the proof index within the subtree can be determined by looking at
	// the bounds of the subtree and determining if the proof index is in the
	// first or second half of the subtree.
	//
	// When the subtree is not complete, either 1 or 0 of the remaining hashes
	// will be sibling B. All remaining hashes after that will be sibling A.
	// This is true because of the way that orphans are merged into the Merkle
	// tree - an orphan at height n is elevated to height n + 1, and only
	// hashed when it is no longer an orphan. Each subtree will therefore merge
	// with at most 1 orphan to the right before becoming an orphan itself.
	// Orphan nodes are always merged with larger subtrees to the left.
	//
	// One vulnerability with the proof verification is that the proofSet may
	// not be long enough. Before looking at an element of proofSet, a check
	// needs to be made that the element exists.

	// The first element of the set is the original data. A sibling at height 1
	// is created by getting the leafSum of the original data.
	height := 0
	if len(proofSet) <= height {
		return false
	}
	sum := leafSum(h, proofSet[height])
	height++

	// While the current subtree (of height 'height') is complete, determine
	// the position of the next sibling using the complete subtree algorithm.
	// 'stableEnd' tells us the ending index of the last full subtree. It gets
	// initialized to 'proofIndex' because the first full subtree was the
	// subtree of height 1, created above (and had an ending index of
	// 'proofIndex').
	stableEnd := proofIndex
	for {
		// Determine if the subtree is complete. This is accomplished by
		// rounding down the proofIndex to the nearest 1 << 'height', adding 1
		// << 'height', and comparing the result to the number of leaves in the
		// Merkle tree.
		subTreeStartIndex := (proofIndex / (1 << uint(height))) * (1 << uint(height)) // round down to the nearest 1 << height
		subTreeEndIndex := subTreeStartIndex + (1 << (uint(height))) - 1              // subtract 1 because the start index is inclusive
		if subTreeEndIndex >= numLeaves {
			// If the Merkle tree does not have a leaf at index
			// 'subTreeEndIndex', then the subtree of the current height is not
			// a complete subtree.
			break
		}
		stableEnd = subTreeEndIndex

		// Determine if the proofIndex is in the first or the second half of
		// the subtree.
		if len(proofSet) <= height {
			return false
		}
		if proofIndex-subTreeStartIndex < 1<<uint(height-1) {
			sum = nodeSum(h, sum, proofSet[height])
		} else {
			sum = nodeSum(h, proofSet[height], sum)
		}
		height++
	}

	// Determine if the next hash belongs to an orphan that was elevated. This
	// is the case IFF 'stableEnd' (the last index of the largest full subtree)
	// is equal to the number of leaves in the Merkle tree.
	if stableEnd != numLeaves-1 {
		if len(proofSet) <= height {
			return false
		}
		sum = nodeSum(h, sum, proofSet[height])
		height++
	}

	// All remaining elements in the proof set will belong to a left sibling.
	for height < len(proofSet) {
		sum = nodeSum(h, proofSet[height], sum)
		height++
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	if bytes.Compare(sum, merkleRoot) == 0 {
		return true
	}
	return false
}
