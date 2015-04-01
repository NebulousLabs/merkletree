package merkletree

import (
	"hash"
	"io"
)

// readIntoTree will read segments of size 'segmentSize' and push them into the
// tree until EOF is reached.
func readIntoTree(t *Tree, r io.Reader, segmentSize int) error {
	for {
		segment := make([]byte, segmentSize)
		n, readErr := io.ReadFull(r, segment)
		if readErr == io.EOF {
			// All data has been read.
			break
		} else if readErr == io.ErrUnexpectedEOF {
			// This is the last segment, and there aren't enough bytes to fill
			// the entire segment. Note that the next call will return io.EOF.
			segment = segment[:n]
		} else if readErr != nil {
			return readErr
		}
		t.Push(segment)
	}
	return nil
}

// ReaderRoot returns the Merkle root of the data read from the reader, where
// each leaf is 'segmentSize' long and 'h' is used as the hashing function. All
// leaves will be 'segmentSize' bytes, the last leaf may have extra zeros.
func ReaderRoot(r io.Reader, h hash.Hash, segmentSize int) (root []byte, err error) {
	tree := New(h)
	err = readIntoTree(tree, r, segmentSize)
	if err != nil {
		return
	}
	root = tree.Root()
	return
}

// BuildReaderProof returns a proof that certain data is in the merkle tree
// created by the data in the reader. The merkle root, set of proofs, and the
// number of leaves in the Merkle tree are all returned.
func BuildReaderProof(r io.Reader, h hash.Hash, segmentSize int, index uint64) (root []byte, proofSet [][]byte, numLeaves uint64, err error) {
	tree := New(h)
	tree.SetIndex(index)
	err = readIntoTree(tree, r, segmentSize)
	if err != nil {
		return
	}
	root, proofSet, _, numLeaves = tree.Prove()
	return
}
