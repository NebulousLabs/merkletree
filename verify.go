package merkletree

import (
	"bytes"
	"hash"
)

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func VerifyProof(h hash.Hash, merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) bool {
	return VerifyProofOfSlice(h, merkleRoot, proofSet, proofIndex, proofIndex+1, numLeaves)
}

// VerifyProofOfSlice takes a Merkle root, a proofSet, and the slice and returns
// true if the first proofEnd-proofBegin elements of the proof set are leaves
// of data in the Merkle root. False is returned if the proof set or Merkle
// root is nil, and if 'numLeaves' equals 0. Can be used with proofs returned
// by Tree.Prove and CachedTree.Prove.
func VerifyProofOfSlice(h hash.Hash, merkleRoot []byte, proofSet [][]byte, proofBegin, proofEnd, numLeaves uint64) bool {
	// Return false for nonsense input.
	if merkleRoot == nil {
		return false
	}
	if proofBegin >= proofEnd {
		return false
	}
	if proofEnd > numLeaves {
		return false
	}

	// Create the list of hashes on the level of leaves.
	var sums [][]byte
	for i := proofBegin; i < proofEnd; i++ {
		if len(proofSet) == 0 {
			return false
		}
		sums = append(sums, leafSum(h, proofSet[0]))
		proofSet = proofSet[1:]
	}

	// Each iteration of the loop below corresponds to height increment.
	// The following variables are updated: proofBegin, proofEnd, numLeaves,
	// sums. Sums is the list of hashes involving the original data on the
	// current level. The indices (proofBegin, proofEnd, numLeaves) have the
	// same meaning but on levels > 1.

	for numLeaves > 1 {
		if proofBegin%2 == 1 {
			//  Example: addition of % on level <-
			//      ┌───┴──┐
			//   %──┴──*   │ <-
			// ┌─┴─┐ ┌─┴─┐ │
			//       *   *
			if len(proofSet) == 0 {
				return false
			}
			left := proofSet[0]
			proofSet = proofSet[1:]
			sums = append([][]byte{left}, sums...)
			proofBegin -= 1
		}
		if len(sums)%2 == 1 && proofEnd < numLeaves {
			//  Example: addition of % on level <-
			//      ┌───┴──┐
			//   *──┴──%   │ <-
			// ┌─┴─┐ ┌─┴─┐ │
			// *   *
			if len(proofSet) == 0 {
				return false
			}
			right := proofSet[0]
			proofSet = proofSet[1:]
			sums = append(sums, right)
			proofEnd += 1
		}
		var sums2 [][]byte
		for len(sums) >= 2 {
			left, right := sums[0], sums[1]
			sums = sums[2:]
			sums2 = append(sums2, nodeSum(h, left, right))
		}
		if len(sums) == 1 {
			sums2 = append(sums2, sums[0])
		}
		sums = sums2
		proofBegin /= 2
		// proofEnd and numLeaves need +1 because they are not inclusive.
		proofEnd = (proofEnd + 1) / 2
		numLeaves = (numLeaves + 1) / 2
	}

	if len(proofSet) != 0 {
		return false
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	return bytes.Compare(sums[0], merkleRoot) == 0
}
