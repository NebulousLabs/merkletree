package merkletree

import (
	"errors"
	"hash"
	"io"
)

// ReadAll will read segments of size 'segmentSize' and push them into the tree
// until EOF is reached. Success will return 'err == nil', not 'err == EOF'. No
// padding is added to the data, so the last element may be smaller than
// 'segmentSize'.
func (t *Tree) ReadAll(r io.Reader, segmentSize int) error {
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
// leaves will be 'segmentSize' bytes except the last leaf, which will not be
// padded out if there are not enough bytes remaining in the reader.
func ReaderRoot(r io.Reader, h hash.Hash, segmentSize int) ([]byte, error) {
	if segmentSize == 0 {
		return nil, errors.New("segment size must be nonzero")
	}
	nodes := make([][]byte, 64)      // very unlikely to need more than 64 nodes
	buf := make([]byte, segmentSize) // scratch space for reading and hashing
	for {
		// hash next segment
		h.Reset()
		_, _ = h.Write(leafHashPrefix)
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			// ignore EOF errors because a partially-full segment is okay
			return nil, err
		} else if n == 0 {
			break
		}
		_, _ = h.Write(buf[:n])
		sum := h.Sum(buf[:0])

		// merge nodes of adjacent height until we reach a gap, and insert
		// the new hash into the gap
		for i := 0; ; i++ {
			if i == len(nodes) {
				// we ran out of nodes; append a new one
				nodes = append(nodes, nil)
			}
			if len(nodes[i]) == 0 {
				// found a gap; insert hash and proceed to next segment
				nodes[i] = append(nodes[i], sum...)
				break
			}

			// join hashes
			h.Reset()
			_, _ = h.Write(nodeHashPrefix)
			_, _ = h.Write(nodes[i])
			_, _ = h.Write(sum)
			sum = h.Sum(buf[:0])
			// clear the old hash
			nodes[i] = nodes[i][:0]
		}
	}

	// filter out empty nodes
	nonEmpty := nodes[:0]
	for _, node := range nodes {
		if len(node) != 0 {
			nonEmpty = append(nonEmpty, node)
		}
	}
	// combine remaining nodes
	if len(nonEmpty) == 0 {
		return nil, nil
	}
	root := nonEmpty[0]
	for _, node := range nonEmpty[1:] {
		h.Reset()
		_, _ = h.Write(nodeHashPrefix)
		_, _ = h.Write(node)
		_, _ = h.Write(root)
		root = h.Sum(buf[:0])
	}
	return root, nil
}

// BuildReaderProof returns a proof that certain data is in the merkle tree
// created by the data in the reader. The merkle root, set of proofs, and the
// number of leaves in the Merkle tree are all returned. All leaves will we
// 'segmentSize' bytes except the last leaf, which will not be padded out if
// there are not enough bytes remaining in the reader.
func BuildReaderProof(r io.Reader, h hash.Hash, segmentSize int, index uint64) (root []byte, proofSet [][]byte, numLeaves uint64, err error) {
	tree := New(h)
	err = tree.SetIndex(index)
	if err != nil {
		// This code should be unreachable - SetIndex will only return an error
		// if the tree is not empty, and yet the tree should be empty at this
		// point.
		panic(err)
	}
	err = tree.ReadAll(r, segmentSize)
	if err != nil {
		return
	}
	root, proofSet, _, numLeaves = tree.Prove()
	if len(proofSet) == 0 {
		err = errors.New("index was not reached while creating proof")
		return
	}
	return
}
