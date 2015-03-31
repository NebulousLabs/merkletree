merkletree
----------

merkletree is a Go package for working with [Merkle
trees](http://en.wikipedia.org/wiki/Merkle_tree). Specifically, this package is
designed to facilitate the generation and verification of "Merkle proofs" —
cryptographic proofs that a given subset of data "belongs" to a larger set.
BitTorrent, for example, requires downloading many small pieces of a file from
many untrusted peers; Merkle proofs allow the downloader to verify that each
piece is part of the full file.

Usage
-----

```go
package main

import (
    "crypto/sha256"
    "log"
    "os"

    "github.com/NebulousLabs/merkletree"
)

// All error checking is ignored in the following examples.
func main() {
	// Example 1: Using the reader functions to get the merkle root of a file.
	segmentSize := 4096 // bytes per leaf
    file, _ := os.Open("myfile")
	merkleRoot, _ := merkleTree.ReaderRoot(file, sha256.New(), segmentSize)


	// Example 2: Using the reader functions to build a proof that the segment
	// at index 7 is in the file with the root 'merkleRoot', and then verifying
	// that proof. Note that BuildReaderProof will actually return the merkle
	// root of the file as the first return value.
	file.Seek(0, 0)
    proofIndex := uint64(7)
    _, proof, numLeaves, _ := merkletree.BuildReaderProof(file, sha256.New(), segmentSize, proofIndex)

	// Verify that the proof is correct, given the merkle root of the file, the
	proof, the index of the segment being proven, and the number of leaves in
	the merkle tree.
    verified := VerifyProof(sha256.New(), merkleRoot, proof, proofIndex, numLeaves)

	// Example 3: Using a Tree to build a merkle tree and get a proof for a
	// specific index for non-file objects.
	tree := merkletree.New(sha256.New())
	tree.SetIndex(1) // error is ignored
	tree.Push([]byte("object 1 - the tree will do the hashing, just push a byte slice"))
	tree.Push([]byte("object 2 - if using data structures, you may need to use something like json.Marshal()"))
	tree.Push([]byte("another object"))
	merkleRoot, proof, proofIndex, numLeaves := tree.Prove()
	// calling tree.Prove() will return the merkleRoot, the proof, the
	// proveIndex (1 in this case), and the total number of leaves in the tree (3
	// in this case). The proof is for the leaf at index 1: "object 2...". The
	// proof will be invalid if another object is added to the tree.
}
```

For more extensive documentation, refer to the
[godoc](http://godoc.org/github.com/NebulousLabs/merkletree).

Notes
-----

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
segment will be padded with 0's if there are not enough bytes.
