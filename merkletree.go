// merkletree provides tools for calculating the Merkle root of a dataset, for
// creating a proof that a piece of data is in a Merkle tree of a given root,
// and for verifying proofs that a piece of data is in a Merkle tree of a given
// root. The tree is implemented according to the specification for Merkle
// trees provided in RFC 6962.
package merkletree

import (
	"bytes"
	"errors"
	"hash"
)

// A Tree takes data as leaves and returns the merkle root. Each call to 'Push'
// adds one leaf to the merkle tree. Calling 'Root' returns the Merkle root.
// The Tree also constructs proof that a single leaf is a part of the tree. The
// leaf can be chosen with 'SetIndex'. The memory footprint of Tree grows in
// O(log(n)) in the number of leaves.
type Tree struct {
	head *subTree
	hash hash.Hash

	// Helper variables used to construct proofs that the data at 'proofIndex'
	// is in the merkle tree.
	currentIndex uint64
	proofIndex   uint64
	proofSet     [][]byte
}

// A subTree contains the merkle root of a complete (2^n leaves) subTree of
// the Tree. 'sum' is the Merkle root of the subTree. If 'next' is not nil, it
// will be a tree with a higher height.
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

	h.Write(data)
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
func (t *Tree) joinSubTrees(a, b *subTree) *subTree {
	if DEBUG {
		if b.next != a {
			panic("invalid subtree join - 'a' is not paried with 'b'")
		}
		if a.height < b.height {
			panic("invalid subtree presented - height mismatch")
		}
	}

	return &subTree{
		next:   a.next,
		height: a.height + 1,
		sum:    nodeSum(t.hash, a.sum, b.sum),
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

// SetIndex resets the tree, and then sets the index for which a proof that the
// element is in the Tree will be built.
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
	// The first element of a proof is the original data at a leaf. If the
	// current index is the index for which we are creating a proof, save the
	// data.
	if t.currentIndex == t.proofIndex {
		t.proofSet = append(t.proofSet, data)
	}

	// A node of height 1 is created by grabbing the leafSum of the data.
	current := &subTree{
		next:   t.head,
		height: 1,
		sum:    leafSum(t.hash, data),
	}

	// Check the height of the next subTree. If the height of the next subTree
	// is the same as the height of the current subTree, combine the two
	// subTrees to create a subTree with a height that is 1 greater.
	for t.head != nil && current.height == t.head.height {
		// When creating a proof for a specific index, you need to collect one
		// hash at each height of the tree, and that hash will be found in the
		// same subTree as the initial leaf. Before we hit that index, this
		// logic will be ignored because len(proofSet) will be 0. After we hit
		// that index, len(proofSet) will be one. From that point forward,
		// every time there are two subTrees (the current one and the previous
		// one) that have a height equal to len(proofSet) we will need to grab
		// one of the roots and add it to the proof set.
		if current.height == len(t.proofSet) {
			// Either the root of the current subTree or the root of the
			// previous subTree needs to be added to the proof set. We want to
			// grab the root of the subTree that does not contain
			// 't.proofIndex'. We do this by finding the starting index of the
			// current subTree and comparing it to 't.proofIndex'.
			//
			// The start of the first subTree can be determined by rounding
			// the currentIndex down to the nearest (2^height). This represents
			// the combined size of the two trees, as a tree of height 1 was
			// built from only 1 leaf.
			combinedSize := uint64(1 << uint(current.height))
			previousStart := (t.currentIndex / combinedSize) * combinedSize
			currentStart := previousStart + (combinedSize / 2)
			if t.proofIndex < currentStart {
				t.proofSet = append(t.proofSet, current.sum)
			} else {
				t.proofSet = append(t.proofSet, t.head.sum)
			}
		}

		// Join the two subTrees into one subTree with a greater height. Then
		// compare the new subTree to the next subTree.
		current = t.joinSubTrees(t.head, current)
		t.head = t.head.next
	}

	// Add the subTree to the top of the stack.
	t.head = current
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
// As specified in RFC6962, and emtpy tree will return the hash of an empty
// string.
func (t *Tree) Root() []byte {
	// If the Tree is empty, return the hash of the empty string.
	if t.head == nil {
		return sum(t.hash, nil)
	}

	// The root is formed by hashing together subTrees in order from least in
	// height to greatest in height. To preserve the ordering specified in
	// RFC6962, the taller subTree needs to be the first argument of 'join'.
	current := t.head
	for current.next != nil {
		current = t.joinSubTrees(current.next, current)
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

	// The hashes have already been provided for the largest complete subTree
	// that contains 't.ProveIndex'. If 't.CurrentIndex' is a power of two, we
	// are already finshed. Otherwise, two sets of hashes remain which need to
	// be added to the proof. The first is the hashes of the smaller subTrees.
	// All of the smaller subTrees need to be combined, and then that hash
	// needs to be saved. The second is the larger subTrees. The root of each
	// of the larger subTrees needs to be saved. The subTree with the proof
	// index will have a height equal to the current length of the proof set.

	// Iterate through all of the smaller subTrees and combine them.
	current := t.head
	for current.next != nil && current.next.height < len(proofSet) {
		current = t.joinSubTrees(current.next, current)
	}
	sum := current.sum

	// If the current subTree is the last subTree before the subTree containing
	// the proof index, add the root of the subTree to the proof set.
	if current.next != nil && current.next.height == len(proofSet) {
		proofSet = append(proofSet, sum)
		current = current.next
	}

	// The subTree containing the proof index needs to be skipped.
	current = current.next

	// Now add the roots of all subTrees that are larger than the subTree
	// containing the proof index.
	for current != nil {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}
	return t.Root(), proofSet, t.proofIndex, t.currentIndex
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or merkle root is nil, and if
// 'numLeaves' equals 0.
func VerifyProof(h hash.Hash, merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) bool {
	// Return false for nonsense input.
	switch {
	case merkleRoot == nil:
		return false
	case numLeaves == 0:
		return false
	}

	// In a merkle tree, every node except the root node has a sibling.
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

		// Sanity check - the proof index should be between the start and end
		// index of the subtree (inclusive).
		if DEBUG {
			if proofIndex < subTreeStartIndex {
				panic("weird proof verifying")
			}
			if proofIndex > subTreeEndIndex {
				panic("weird proof verifying")
			}
		}

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
	// is equal to the number of leaves in the merkle tree.
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
	} else {
		return false
	}
}
