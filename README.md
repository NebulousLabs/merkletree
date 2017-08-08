# merkletree

merkletree is a Go package for working with [Merkle
trees](http://en.wikipedia.org/wiki/Merkle_tree). Specifically, this package is
designed to facilitate the generation and verification of "Merkle proofs" —
cryptographic proofs that a given subset of data "belongs" to a larger set.
BitTorrent, for example, requires downloading many small pieces of a file from
many untrusted peers; Merkle proofs allow the downloader to verify that each
piece is part of the full file.

When sha256 is used as the hashing algorithm, the implementation matches the
merkle tree described in RFC 6962, 'Certificate Transparency'.

## Usage

```go
package main

import (
    "crypto/sha256"
    "os"

    "github.com/NebulousLabs/merkletree"
)

// All error checking is ignored in the following examples.
func main() {
	// Example 1: Get the merkle root of a file.
	segmentSize := 4096 // bytes per leaf
	file, _ := os.Open("myfile")
	merkleRoot, _ := merkletree.ReaderRoot(file, sha256.New(), segmentSize)

	// Example 2: Build and verify a proof that the element at segment 7 is in
	// the merkle root.
	file.Seek(0, 0) // Offset needs to be set back to 0.
	proofIndex := uint64(7)
	merkleRoot, proof, numLeaves, _ := merkletree.BuildReaderProof(file, sha256.New(), segmentSize, proofIndex)
	verified := merkletree.VerifyProof(sha256.New(), merkleRoot, proof, proofIndex, numLeaves)

	// Example 3: Using a Tree to build a merkle tree and get a proof for a
	// specific index for non-file objects.
	tree := merkletree.New(sha256.New())
	tree.SetIndex(1)
	tree.Push([]byte("an object - the tree will hash the data after it is pushed"))
	tree.Push([]byte("another object"))
	// The merkle root could be obtained by calling tree.Root(), but will also
	// be provided by tree.Prove()
	merkleRoot, proof, proofIndex, numLeaves = tree.Prove()

	////////////////////////////////////////////////////
	/// Next group of examples deal with cached trees //
	////////////////////////////////////////////////////

	// Example 4: Creating a cached set of Merkle roots and then using them in
	// a cached tree. The cached tree is height 1, meaning that all elements of
	// the cached tree will be Merkle roots of data with 2 leaves.
	cachedTree := merkletree.NewCachedTree(sha256.New(), 1)
	subtree1 := merkletree.New(sha256.New())
	subtree1.Push([]byte("first leaf, first subtree"))
	subtree1.Push([]byte("second leaf, first subtree"))
	subtree2 := merkletree.New(sha256.New())
	subtree2.Push([]byte("first leaf, second subtree"))
	subtree2.Push([]byte("second leaf, second subtree"))
	// Using the cached tree, build the merkle root of the 4 leaves.
	cachedTree.Push(subtree1.Root())
	cachedTree.Push(subtree2.Root())
	collectiveRoot := cachedTree.Root()

	// Example 5: Modify the data pushed into subtree 2 and create the Merkle
	// root, without needing to rehash the data in any other subtree.
	revisedSubtree2 := merkletree.New(sha256.New())
	revisedSubtree2.Push([]byte("first leaf, second subtree"))
	revisedSubtree2.Push([]byte("second leaf, second subtree, revised"))
	// Using the cached tree, build the merkle root of the 4 leaves - without
	// needing to rehash any of the data in subtree1.
	cachedTree = merkletree.NewCachedTree(sha256.New(), 1)
	cachedTree.Push(subtree1.Root())
	cachedTree.Push(revisedSubtree2.Root())
	revisedRoot := cachedTree.Root()

	// Exapmle 6: Create a proof that leaf 3 (index 2) of the revised root,
	// found in revisedSubtree2 (at index 0 of the revised subtree), is a part of
	// the cached set. This is a two stage process - first we must get a proof
	// that the leaf is a part of revisedSubtree2, and then we must get provide
	// that proof as input to the cached tree prover.
	cachedTree = merkletree.NewCachedTree(sha256.New(), 1)
	cachedTree.SetIndex(2) // leaf at index 2, or the third element which gets inserted.
	revisedSubtree2 = merkletree.New(sha256.New())
	revisedSubtree2.SetIndex(0)
	revisedSubtree2.Push([]byte("first leaf, second subtree"))
	revisedSubtree2.Push([]byte("second leaf, second subtree, revised"))
	_, subtreeProof, _, _ := revisedSubtree2.Prove()
	// Now we can create the full proof for the cached tree, without having to
	// rehash any of the elements from subtree1.
	_, fullProof, _, _ := cachedTree.Prove(subtreeProof)

	////////////////////////////////////////////////////////
	/// Next group of examples deal with proofs of slices //
	////////////////////////////////////////////////////////

	// Example 7: Using a Tree to build a merkle tree and get a proof for a
	// specific slice for non-file objects.
	tree = merkletree.New(sha256.New())
	tree.SetSlice(1, 3) // Objects 1 and 2.
	tree.Push([]byte("an object - the tree will hash the data after it is pushed"))
	tree.Push([]byte("the first part of the slice"))
	tree.Push([]byte("the second part of the slice"))
	tree.Push([]byte("another object"))
	merkleRoot, proof, _, numLeaves = tree.Prove()
	verified = merkletree.VerifyProofOfSlice(sha256.New(), merkleRoot, proof, 1, 3, numLeaves)

	// Example 8: Build and verify a proof that the elements at segments 5-10
	// are in the merkle root. The proof starts with the elements themselves.
	file.Seek(0, 0) // Offset needs to be set back to 0.
	proofBegin := uint64(5)
	proofEnd := uint64(10) + 1
	merkleRoot, proof, numLeaves, _ = merkletree.BuildReaderProofSlice(file, sha256.New(), segmentSize, proofBegin, proofEnd)
	verified = merkletree.VerifyProofOfSlice(sha256.New(), merkleRoot, proof, proofBegin, proofEnd, numLeaves)

	// Example 9: Cached tree of height 2, with proof slice entirely inside
	// one cached subtree.
	cachedTree = merkletree.NewCachedTree(sha256.New(), 2)
	cachedTree.SetSlice(5, 7)
	subtree1 = merkletree.New(sha256.New())
	subtree1.Push([]byte("first leaf, first subtree"))
	subtree1.Push([]byte("second leaf, first subtree"))
	subtree1.Push([]byte("third leaf, first subtree"))
	subtree1.Push([]byte("fourth leaf, first subtree"))
	subtree2 = merkletree.New(sha256.New())
	subtree2.SetSlice(1, 3)
	subtree2.Push([]byte("first leaf, second subtree"))
	subtree2.Push([]byte("second leaf, second subtree")) // in proof slice
	subtree2.Push([]byte("third leaf, second subtree")) // in proof slice
	subtree2.Push([]byte("fourth leaf, second subtree"))
	cachedTree.Push(subtree1.Root())
	cachedTree.Push(subtree2.Root())
	_, subtreeProof, _, _ = subtree2.Prove()
	// Now we can create the full proof for the cached tree, without having to
	// rehash any of the elements from subtree1.
	merkleRoot, fullProof, _, numLeaves = cachedTree.Prove(subtreeProof)
	verified = merkletree.VerifyProofOfSlice(sha256.New(), merkleRoot, fullProof, 1, 3, numLeaves)

	// Example 10: Cached tree of height 1, with proof slice consisting
	// of several full subtrees.
	cachedTree = merkletree.NewCachedTree(sha256.New(), 1)
	cachedTree.SetSlice(2, 6)
	subtree1 = merkletree.New(sha256.New())
	subtree1.Push([]byte("first leaf, first subtree"))
	subtree1.Push([]byte("second leaf, first subtree"))
	subtree2 = merkletree.New(sha256.New())
	subtree2.SetSlice(0, 2)
	subtree2.Push([]byte("first leaf, second subtree")) // in proof slice
	subtree2.Push([]byte("second leaf, second subtree")) // in proof slice
	subtree3 := merkletree.New(sha256.New())
	subtree3.SetSlice(0, 2)
	subtree3.Push([]byte("first leaf, third subtree")) // in proof slice
	subtree3.Push([]byte("second leaf, third subtree")) // in proof slice
	subtree4 := merkletree.New(sha256.New())
	subtree4.Push([]byte("first leaf, fourth subtree"))
	subtree4.Push([]byte("second leaf, fourth subtree"))
	cachedTree.Push(subtree1.Root())
	cachedTree.Push(subtree2.Root())
	cachedTree.Push(subtree2.Root())
	cachedTree.Push(subtree4.Root())
	_, subtreeProof1, _, _ := subtree2.Prove()
	_, subtreeProof2, _, _ := subtree3.Prove()
	subtreeProof = append(subtreeProof1, subtreeProof2...)
	merkleRoot, fullProof, _, numLeaves = cachedTree.Prove(subtreeProof)
	verified = merkletree.VerifyProofOfSlice(sha256.New(), merkleRoot, fullProof, 2, 6, numLeaves)

	_ = verified
	_ = collectiveRoot
	_ = revisedRoot
	_ = fullProof
}
```

For more extensive documentation, refer to the
[godoc](http://godoc.org/github.com/NebulousLabs/merkletree).

## Notes

This implementation does not retain the entire Merkle tree in memory. Rather,
as each new leaf is added to the tree, is it pushed onto a stack as a "subtree
of depth 1." If the next element on the stack also has depth 1, the two are
combined into a "subtree of depth 2." This process continues until no adjacent
elements on the stack have the same depth. (For a nice visual representation of
this, play a round of [2048](http://gabrielecirulli.github.io/2048).) This
gives a space complexity of O(log(n)), making this implementation suitable for
generating Merkle proofs on very large files. (It is not as suitable for
generating "batches" of many Merkle proofs on the same file.)

Different Merkle tree implementations handle "orphan" leaves in different ways.
Our trees conform to the diagrams below; orphan leaves are not duplicated or
hashed multiple times.
```
     ┌───┴──┐       ┌────┴───┐         ┌─────┴─────┐
  ┌──┴──┐   │    ┌──┴──┐     │      ┌──┴──┐     ┌──┴──┐
┌─┴─┐ ┌─┴─┐ │  ┌─┴─┐ ┌─┴─┐ ┌─┴─┐  ┌─┴─┐ ┌─┴─┐ ┌─┴─┐   │
   (5-leaf)         (6-leaf)             (7-leaf)
```

When using the Reader functions (ReaderRoot and BuildReaderProof), the last
segment will not be padded if there are not 'segmentSize' bytes remaining.

## Format of proof

### What is included to the proof

A proof is a slice of slices of bytes. It begins with the leave data,
then hashes of subtrees follow. Combining all leaves which are covered in
these two groups (as leaves from the beginning of the proof or as leaves
from the subtrees whose hashes constitute the second part of the proof)
we get all leaves of the tree and each leave presents once.

Example. Proof built in a tree of 5 leaves for element at index 2:

```
     ┌───┴──*
  *──┴──┐   │
┌─┴─┐ ┌─┴─* │
0   1 2   3 4
      *
```

Parts of the proof are marked with asterisks (*).

If we build a proof for a slice, the rule is the same: first include all
leaves from the target slice, then add hashes of all subtrees so that
together with the target slice they cover all leaves, once.

Example. Proof built in a tree of 7 leaves for the slice [2, 5).

```
     ┌─────┴─────┐
  *──┴──┐     ┌──┴──*
┌─┴─┐ ┌─┴─┐ ┌─┴─*   │
0   1 2   3 4   5   6
      *   * *
```

Example. Proof built in a tree of 7 leaves for the slice [3, 5).

```
     ┌─────┴─────┐
  *──┴──┐     ┌──┴──*
┌─┴─┐ *─┴─┐ ┌─┴─*   │
0   1 2   3 4   5   6
          * *
```

### The order of stuff in the proof

The proof starts with the data items. For a proof of one element
it is the element itself (one item in the main proof slice).
In case of slice the data is represented as multiple items in the main
proof slice, in the order of occurrence in the source data.

Hashes of subtrees (constituting the second half of a proof) are sorted
by height (ascending), then by occurrence in the source data. The height
of an orphan subtree is equal to the height of its parent minus one.

Some examples of how parts of proofs are ordered. A number corresponds
to the place of this leave or subtree hash in the proof.

```
     ┌────┴───┐
  5──┴──┐     │
┌─┴─┐ 3─┴─┐ ┌─┴─4
          1 2
```

```
     ┌────┴───4
  ┌──┴──┐     │
3─┴─┐ ┌─┴─┐ ┌─┴─┐
    1 2   3
```

```
     ┌────┴───┐
  5──┴──┐     │
┌─┴─┐ ┌─┴─┐ ┌─┴─┐
      1   2 3   4
```
