merkletree
----------

merkletree is a Go package for working with [Merkle trees](http://en.wikipedia.org/wiki/Merkle_tree). Specifically, this package is designed to facilitate the generation and verification of "Merkle proofs" — cryptographic proofs that a given subset of data "belongs" to a larger set. BitTorrent, for example, requires downloading many small pieces of a file from many untrusted peers; Merkle proofs allow the downloader to verify that each piece is part of the full file.

Usage
-----

```go
package main

import (
    "crypto/sha256"
    "log"
    "os"

    . "github.com/NebulousLabs/merkletree"
)

const segmentSize = 64 // in bytes

func main() {
    file, err := os.Open("myfile")
    if err != nil {
        log.Fatal(err)
    }
    // build proof for index 7
    proofIndex := uint64(7)
    root, proofSet, numLeaves, err := BuildReaderProof(file, sha256.New(), segmentSize, proofIndex)
    if err != nil {
        log.Fatal(err)
    }
    // verify proof
    verified := VerifyProof(sha256.New(), root, proofSet, proofIndex, numLeaves)
    if !verified {
        log.Fatal("verification failed!")
    }
}
```

For more extensive documentation, refer to the [godoc](http://godoc.org/github.com/NebulousLabs/merkletree).

Notes
-----

This implementation does not retain the entire Merkle tree in memory. Rather, as each new leaf is added to the tree, is it pushed onto a stack as a "subtree of depth 1." If the next element on the stack also has depth 1, the two are combined into a "subtree of depth 2." This process continues until no adjacent elements on the stack have the same depth. (For a nice visual representation of this, play a round of [2048](http://gabrielecirulli.github.io/2048).) This gives a space complexity of O(log(n)), making this implementation suitable for generating Merkle proofs on very large files. (It is not as suitable for generating "batches" of many Merkle proofs on the same file, though this is an eventual goal.)

Different Merkle tree implementations handle "orphan" leaves in different ways. Our trees conform to the diagrams below; orphan leaves are not duplicated or hashed multiple times. While this introduces some ugly edge cases in the proof logic, the efficiency gains are worth it.
```
     ┌───┴──┐       ┌────┴───┐         ┌─────┴─────┐
  ┌──┴──┐   │    ┌──┴──┐     │      ┌──┴──┐     ┌──┴──┐
┌─┴─┐ ┌─┴─┐ │  ┌─┴─┐ ┌─┴─┐ ┌─┴─┐  ┌─┴─┐ ┌─┴─┐ ┌─┴─┐   │
   (5-leaf)         (6-leaf)             (7-leaf)
```
