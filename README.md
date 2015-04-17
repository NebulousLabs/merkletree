merkletree
----------

merkletree is a Go package for working with [Merkle
trees](http://en.wikipedia.org/wiki/Merkle_tree). Specifically, this package is
designed to facilitate the generation and verification of "Merkle proofs" —
cryptographic proofs that a given subset of data "belongs" to a larger set.
BitTorrent, for example, requires downloading many small pieces of a file from
many untrusted peers; Merkle proofs allow the downloader to verify that each
piece is part of the full file.

When sha256 is used as the hashing algorithm, the implementation matches the
merkle tree described in RFC 6962, 'Certificate Transparency'.

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
	// Example 1: Get the merkle root of a file.
	segmentSize := 4096 // bytes per leaf
	file, _ := os.Open("myfile")
	merkleRoot, _ := merkleTree.ReaderRoot(file, sha256.New(), segmentSize)

	// Example 2: Build and verify a proof that the element at segment 7 is in
	// the merkle root.
	file.Seek(0, 0) // Offset needs to be set back to 0.
	proofIndex := uint64(7)
	merkleRoot, proof, numLeaves, _ := merkletree.BuildReaderProof(file, sha256.New(), segmentSize, proofIndex)
	verified := VerifyProof(sha256.New(), merkleRoot, proof, proofIndex, numLeaves)

	// Example 3: Using a Tree to build a merkle tree and get a proof for a
	// specific index for non-file objects.
	tree := merkletree.New(sha256.New())
	tree.SetIndex(1)
	tree.Push([]byte("an object - the tree will hash the data after it is pushed"))
	tree.Push([]byte("another object"))
	merkleRoot, proof, proofIndex, numLeaves := tree.Prove()
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
segment will not be padded if there are not 'segmentSize' bytes remaining.
