package merkletree

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestReaderRoot calls ReaderRoot on a manually crafted dataset
// and checks the output.
func TestReaderRoot(t *testing.T) {
	mt := CreateMerkleTester(t)
	bytes8 := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	reader := bytes.NewReader(bytes8)
	root, err := ReaderRoot(reader, sha256.New(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(root, mt.roots[8]) != 0 {
		t.Error("ReaderRoot returned the wrong root")
	}
}

// TestReaderRootPadding passes ReaderRoot a reader that has too few bytes to
// fill the last segment. The segment should not be padded out.
func TestReaderRootPadding(t *testing.T) {
	bytes1 := []byte{1}
	reader := bytes.NewReader(bytes1)
	root, err := ReaderRoot(reader, sha256.New(), 2)
	if err != nil {
		t.Fatal(err)
	}

	expectedRoot := sum(sha256.New(), []byte{0, 1})
	if bytes.Compare(root, expectedRoot) != 0 {
		t.Error("ReaderRoot returned the wrong root")
	}

	bytes3 := []byte{1, 2, 3}
	reader = bytes.NewReader(bytes3)
	root, err = ReaderRoot(reader, sha256.New(), 2)
	if err != nil {
		t.Fatal(err)
	}

	baseLeft := sum(sha256.New(), []byte{0, 1, 2})
	baseRight := sum(sha256.New(), []byte{0, 3})
	expectedRoot = sum(sha256.New(), append(append([]byte{1}, baseLeft...), baseRight...))
	if bytes.Compare(root, expectedRoot) != 0 {
		t.Error("ReaderRoot returned the wrong root")
	}
}

// TestBuildReaderProof calls BuildReaderProof on a manually crafted dataset
// and checks the output.
func TestBuilReaderProof(t *testing.T) {
	mt := CreateMerkleTester(t)
	bytes7 := []byte{0, 1, 2, 3, 4, 5, 6}
	reader := bytes.NewReader(bytes7)
	root, proofSet, numLeaves, err := BuildReaderProof(reader, sha256.New(), 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(root, mt.roots[7]) != 0 {
		t.Error("BuildReaderProof returned the wrong root")
	}
	if len(proofSet) != len(mt.proofSets[7][5]) {
		t.Fatal("BuildReaderProof returned a proof with the wrong length")
	}
	for i := range proofSet {
		if bytes.Compare(proofSet[i], mt.proofSets[7][5][i]) != 0 {
			t.Error("BuildReaderProof returned an incorrect proof")
		}
	}
	if numLeaves != 7 {
		t.Error("BuildReaderProof returned the wrong number of leaves")
	}
}

// TestBuildReaderProofPadding passes BuildReaderProof a reader that has too
// few bytes to fill the last segment. The segment should not be padded out.
func TestBuildReaderProofPadding(t *testing.T) {
	bytes1 := []byte{1}
	reader := bytes.NewReader(bytes1)
	root, proofSet, numLeaves, err := BuildReaderProof(reader, sha256.New(), 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	expectedRoot := sum(sha256.New(), []byte{0, 1})
	if bytes.Compare(root, expectedRoot) != 0 {
		t.Error("ReaderRoot returned the wrong root")
	}
	if len(proofSet) != 1 {
		t.Fatal("proofSet is the incorrect length")
	}
	if bytes.Compare(proofSet[0], []byte{1}) != 0 {
		t.Error("proofSet is incorrect")
	}
	if numLeaves != 1 {
		t.Error("wrong number of leaves returned")
	}
}

// TestBuildReaderProofSlicePadding passes BuildReaderProofSlice a reader that has too
// few bytes to fill the last segment. The segment should not be padded out.
func TestBuildReaderProofSlicePadding(t *testing.T) {
	bytes1 := []byte{1, 2, 3, 4, 5}
	reader := bytes.NewReader(bytes1)
	root, proofSet, numLeaves, err := BuildReaderProofSlice(reader, sha256.New(), 2, 1, 3)
	if err != nil {
		t.Fatal(err)
	}

	base12 := sum(sha256.New(), []byte{0, 1, 2})
	base34 := sum(sha256.New(), []byte{0, 3, 4})
	base5 := sum(sha256.New(), []byte{0, 5})
	node1234 := sum(sha256.New(), append(append([]byte{1}, base12...), base34...))
	expectedRoot := sum(sha256.New(), append(append([]byte{1}, node1234...), base5...))

	if bytes.Compare(root, expectedRoot) != 0 {
		t.Error("ReaderRoot returned the wrong root")
	}
	if len(proofSet) != 3 {
		t.Fatalf("proofSet is the incorrect lenght: %d", len(proofSet))
	}
	if bytes.Compare(proofSet[0], []byte{3, 4}) != 0 {
		t.Error("proofSet is incorrect")
	}
	if bytes.Compare(proofSet[1], []byte{5}) != 0 {
		t.Error("proofSet is incorrect")
	}
	if bytes.Compare(proofSet[2], base12) != 0 {
		t.Error("proofSet is incorrect")
	}
	if numLeaves != 3 {
		t.Error("wrong number of leaves returned")
	}
}

// TestEmptyReader passes an empty reader into BuildReaderProof and BuildReaderProofSlice.
func TestEmptyReader(t *testing.T) {
	_, _, _, err := BuildReaderProof(new(bytes.Reader), sha256.New(), 64, 5)
	if err == nil {
		t.Error(err)
	}
	_, _, _, err = BuildReaderProofSlice(new(bytes.Reader), sha256.New(), 64, 5, 6)
	if err == nil {
		t.Error(err)
	}
}
