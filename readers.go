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
	// Implementation:
	//
	// Calculating a Merkle root is analogous to binary addition. In binary,
	// adding two bits at position n produces one bit at position n+1.
	// Likewise, we can "add" two hashes at height n in a Merkle tree to
	// produce a hash at height n+1.
	//
	// By exploiting this isomorphism, we can calculate the root of a Merkle
	// tree in log(n) space. We represent the tree as a slice of hashes, with
	// each index corresponding to a height in the tree. Each time we hash a
	// segment, we "add" it to the 0-index of our slice of hashes. If there is
	// already a hash at index 0, we combine the hashes and carry this "sum"
	// into the next index, clearing index 0. If that index is occupied, we
	// continue summing and carrying until a gap is reached. Thus, after we
	// have processed 8 segments, the first 3 indices will be empty, and the
	// fourth will contain the Merkle root of the segments. This is analogous
	// to the binary string 0001 (little-endian).
	//
	// Once we have finished reading and processing segments, the tree may not
	// be perfectly balanced, i.e. the slice of hashes will have more than one
	// hash. To calculate the final Merkle root, we simply join each of the
	// remaining hashes in order until one remains.

	if segmentSize == 0 {
		return nil, errors.New("segment size must be nonzero")
	}
	// The total number of nodes required is log2(n/segmentSize), where n is
	// the number of bytes read from r. It is highly unlikely that we will
	// need more than 64 nodes, but if we do, more are appended as needed.
	nodes := make([][]byte, 64)
	// Preallocate scratch space for reading and hashing. Unfortunately, the
	// hash.Hash interface does not expose the length of its checksums, so we
	// preallocate by hashing the empty string.
	buf := make([]byte, segmentSize)
	sum := h.Sum(nil)
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
		sum = h.Sum(sum[:0])

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
			sum = h.Sum(sum[:0])
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
		root = h.Sum(root[:0])
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
