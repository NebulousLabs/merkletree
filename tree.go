package merkletree

import (
	"errors"
	"hash"
)

// A Tree takes data as leaves and returns the Merkle root. Each call to 'Push'
// adds one leaf to the Merkle tree. Calling 'Root' returns the Merkle root.
// The Tree also constructs proof that a single leaf or a slice of leaves is
// a part of the tree. The leaf can be chosen with 'SetIndex'. The slice can
// be chosen with 'SetSlice'. The memory footprint of Tree grows in O(log(n))
// in the number of leaves.
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

	// Helper variables used to construct proofs that the data at slice from
	// 'proofBegin' to 'proofEnd' (a single leaf if a slice of length 1)
	// is in the Merkle tree. The proofSet is constructed as elements are being
	// added to the tree. The first elements of the proof set are the original
	// data used to create the leaf at indices from 'proofBegin' to 'proofEnd'.
	currentIndex         uint64
	proofBegin, proofEnd uint64
	lader                [][][]byte
	bases                [][]byte

	// The cachedTree flag indicates that the tree is cached, meaning that
	// different code is used in 'Push' for creating a new head subtree. Adding
	// this flag is somewhat gross, but eliminates needing to duplicate the
	// entire 'Push' function when writing the cached tree.
	cachedTree bool
}

// A subTree contains the Merkle root of a complete (2^height leaves) subTree
// of the Tree. 'sum' is the Merkle root of the subTree. If 'next' is not nil,
// it will be a tree with a higher height.
type subTree struct {
	next       *subTree
	height     int // Int is okay because a height over 300 is physically unachievable.
	begin, end uint64
	sum        []byte
}

func (s *subTree) contains(t *Tree) bool {
	return (s.begin <= t.proofBegin && t.proofBegin < s.end) ||
		(t.proofBegin <= s.begin && s.begin < t.proofEnd)
}

// sum returns the hash of the input data using the specified algorithm.
func sum(h hash.Hash, data ...[]byte) []byte {
	h.Reset()
	for _, d := range data {
		// the Hash interface specifies that Write never returns an error
		_, _ = h.Write(d)
	}
	return h.Sum(nil)
}

// leafSum returns the hash created from data inserted to form a leaf. Leaf
// sums are calculated using:
//		Hash(0x00 || data)
func leafSum(h hash.Hash, data []byte) []byte {
	return sum(h, []byte{0}, data)
}

// nodeSum returns the hash created from two sibling nodes being combined into
// a parent node. Node sums are calculated using:
//		Hash(0x01 || left sibling sum || right sibling sum)
func nodeSum(h hash.Hash, a, b []byte) []byte {
	return sum(h, []byte{1}, a, b)
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
		if a.end != b.begin {
			panic("the subtrees are not adjacent")
		}
	}

	return &subTree{
		next:   a.next,
		height: a.height + 1,
		begin:  a.begin,
		end:    b.end,
		sum:    nodeSum(h, a.sum, b.sum),
	}
}

// proofLader stores hashes that are proof parts.
// proofLader[height] is the list of hashes of subtrees
// of height 'height' in the correct order.
type proofLader [][][]byte

// addToLader returns new proofLader with one new element.
func addToLader(lader proofLader, height int, proof []byte) proofLader {
	for len(lader) <= height {
		lader = append(lader, nil)
	}
	lader[height] = append(lader[height], proof)
	return lader
}

// cloneLader returns deep copy of proofLader.
func cloneLader(lader proofLader) proofLader {
	lader2 := make(proofLader, len(lader))
	for i, step := range lader {
		step2 := make([][]byte, len(step))
		copy(step2, step)
		lader2[i] = step2
	}
	return lader2
}

// foldLader converts proofLader to the tail of the proof.
// To generate a valid proof, concatenate data from the target slice
// (one element of the target slice = one element in the proof) with
// the output of foldLader.
func foldLader(lader proofLader) [][]byte {
	var proofs [][]byte
	for _, step := range lader {
		if len(step) > 2 {
			panic("More than 2 proofs of same height in proofSet")
		}
		for _, proof := range step {
			proofs = append(proofs, proof)
		}
	}
	return proofs
}

// New creates a new Tree. The provided hash will be used for all hashing
// operations within the Tree.
func New(h hash.Hash) *Tree {
	return &Tree{
		hash:       h,
		proofBegin: 0,
		proofEnd:   1,
	}
}

// Prove creates a proof that the leaf at the established index (established by
// SetIndex) or the slice of leaves (established by SetSlice) belongs to the
// Merkle tree. Prove will return a nil proof set if used incorrectly.
// Prove does not modify the Tree.
func (t *Tree) Prove() (merkleRoot []byte, proofSet [][]byte, proofBegin uint64, numLeaves uint64) {
	// Return nil if the Tree is empty, or if the proofEnd hasn't yet been
	// reached.
	if t.head == nil || t.currentIndex < t.proofEnd {
		return t.Root(), nil, t.proofBegin, t.currentIndex
	}
	proofSet = make([][]byte, len(t.bases))
	copy(proofSet, t.bases)

	// The set of subtrees must now be collapsed into a single root.
	// Unlike Push, now we ignore previous height of the right subtree,
	// because we have to collapse all leaves anyway.
	// All needed hashes are added to the ladder.
	current := t.head
	lader := cloneLader(t.lader)
	for current.next != nil {
		// The left subtree is higher or equal to the right subtree.
		// If the right subtree is incomplete, its height is considered
		// to be equal to its left sibling.
		height := current.next.height
		if current.contains(t) && !current.next.contains(t) {
			lader = addToLader(lader, height, current.next.sum)
		} else if !current.contains(t) && current.next.contains(t) {
			lader = addToLader(lader, height, current.sum)
		}

		current = joinSubTrees(t.hash, current.next, current)
	}
	proofSet = append(proofSet, foldLader(lader)...)

	// Sanity check - check that either 'current' or 'current.next' is the
	// subtree containing the proof slice.
	if DEBUG {
		if !current.contains(t) && !current.next.contains(t) {
			panic("could not find the subtree containing the proof slice")
		}
	}
	return t.Root(), proofSet, t.proofBegin, t.currentIndex
}

// Push will add data to the set, building out the Merkle tree and Root. The
// tree does not remember all elements that are added, instead only keeping the
// log(n) elements that are necessary to build the Merkle root and keeping the
// log(n) elements necessary to build a proof that a piece of data is in the
// Merkle tree.
func (t *Tree) Push(data []byte) {
	// The first element of a proof is the data at the proof index. If this
	// data is being inserted at the proof index, it is added to the proof set.
	if t.proofBegin <= t.currentIndex && t.currentIndex < t.proofEnd {
		t.bases = append(t.bases, data)
	}

	// Hash the data to create a subtree of height 0. The sum of the new node
	// is going to be the data for cached trees, and is going to be the result
	// of calling leafSum() on the data for standard trees. Doing a check here
	// prevents needing to duplicate the entire 'Push' function for the trees.
	t.head = &subTree{
		next:   t.head,
		height: 0,
		begin:  t.currentIndex,
		end:    t.currentIndex + 1,
	}
	if t.cachedTree {
		t.head.sum = data
	} else {
		t.head.sum = leafSum(t.hash, data)
	}

	// Insert the subTree into the Tree. As long as the height of the next
	// subTree is the same as the height of the current subTree, the two will
	// be combined into a single subTree of height n+1.
	for t.head.next != nil && t.head.height == t.head.next.height {
		// Before combining subtrees, check whether one of the subtree hashes
		// needs to be added to the proof set. This is going to be true IFF
		// one of the subtrees being combined overlaps with the target slice
		// and another does not.
		var proof []byte
		if t.head.contains(t) && !t.head.next.contains(t) {
			proof = t.head.next.sum
		} else if !t.head.contains(t) && t.head.next.contains(t) {
			proof = t.head.sum
		}

		if proof != nil {
			t.lader = addToLader(t.lader, t.head.height, proof)
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

// Root returns the Merkle root of the data that has been pushed.
func (t *Tree) Root() []byte {
	// If the Tree is empty, return nil.
	if t.head == nil {
		return nil
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

// SetIndex will tell the Tree to create a storage proof for the leaf at the
// input index. SetIndex must be called on an empty tree.
func (t *Tree) SetIndex(i uint64) error {
	return t.SetSlice(i, i+1)
}

// SetSlice will tell the Tree to create a storage proof for the leaves
// within the slice [begin, end). SetSlice must be called on an empty tree.
func (t *Tree) SetSlice(begin, end uint64) error {
	if t.head != nil {
		return errors.New("cannot call SetIndex or SetSlice on Tree if Tree has not been reset")
	}
	t.proofBegin = begin
	t.proofEnd = end
	return nil
}
