package merkletree

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
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
		t.Fatal("proofSet is the incorrect lenght")
	}
	if bytes.Compare(proofSet[0], []byte{1}) != 0 {
		t.Error("proofSet is incorrect")
	}
	if numLeaves != 1 {
		t.Error("wrong number of leaves returned")
	}
}

// TestEmptyReader passes an empty reader into BuildReaderProof.
func TestEmptyReader(t *testing.T) {
	_, _, _, err := BuildReaderProof(new(bytes.Reader), sha256.New(), 64, 5)
	if err == nil {
		t.Error(err)
	}
}

// BenchmarkReader1_1k calculates the Merkle root of a random 1KB slice, using
// a 1-byte segment size and SHA-256. The segment size is intentionally chosen
// to be smaller than the hash.
func BenchmarkReader1_1k(b *testing.B) {
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 1
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// BenchmarkReader64_1k calculates the Merkle root of a random 1KB slice,
// using a 64-byte segment size and SHA-256.
func BenchmarkReader64_1k(b *testing.B) {
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 64
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// BenchmarkReader64_4MB calculates the Merkle root of a random 4MB slice,
// using a 64-byte segment size and SHA-256.
func BenchmarkReader64_4MB(b *testing.B) {
	data := make([]byte, 4*1024*1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 64
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// BenchmarkReader4k_4MB calculates the Merkle root of a random 4MB slice,
// using a 4096-byte segment size and SHA-256.
func BenchmarkReader4k_4MB(b *testing.B) {
	data := make([]byte, 4*1024*1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 4096
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// treeReaderRoot is the old tree-based Merkle root algorithm, preserved for
// benchmarking.
func treeReaderRoot(r io.Reader, h hash.Hash, segmentSize int) (root []byte, err error) {
	tree := New(h)
	err = tree.ReadAll(r, segmentSize)
	if err != nil {
		return
	}
	root = tree.Root()
	return
}

// BenchmarkReaderTree1_1k calculates the Merkle root of a random 1KB slice, using
// a 1-byte segment size and SHA-256. The segment size is intentionally chosen
// to be smaller than the hash.
func BenchmarkReaderTree1_1k(b *testing.B) {
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 1
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = treeReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// BenchmarkReaderTree64_1k calculates the Merkle root of a random 1KB slice,
// using a 64-byte segment size and SHA-256.
func BenchmarkReaderTree64_1k(b *testing.B) {
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 64
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = treeReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// BenchmarkReaderTree64_4MB calculates the Merkle root of a random 4MB slice,
// using a 64-byte segment size and SHA-256.
func BenchmarkReaderTree64_4MB(b *testing.B) {
	data := make([]byte, 4*1024*1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 64
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = treeReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// BenchmarkReaderTree4k_4MB calculates the Merkle root of a random 4MB slice,
// using a 4096-byte segment size and SHA-256.
func BenchmarkReaderTree4k_4MB(b *testing.B) {
	data := make([]byte, 4*1024*1024)
	_, err := rand.Read(data)
	if err != nil {
		b.Fatal(err)
	}
	segmentSize := 4096
	h := sha256.New()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = treeReaderRoot(bytes.NewReader(data), h, segmentSize)
	}
}

// TestReaderMatch tests that the new ReaderRoot algorithm produces results
// identical to the old algorithm.
func TestReaderMatch(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	dataSizes := []int{1, 32, 64, 77, 4096, 5000, 4 * 1024 * 1024}
	segmentSizes := []int{7, 32, 64, 77, 4096, 4 * 1024 * 1024}

	for _, d := range dataSizes {
		for _, s := range segmentSizes {
			data := make([]byte, d)
			_, err := rand.Read(data)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			r1, err := ReaderRoot(bytes.NewReader(data), h, s)
			if err != nil {
				t.Error(err)
			}
			r2, err := treeReaderRoot(bytes.NewReader(data), h, s)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(r1, r2) {
				t.Error("Merkle roots do not match:\n", r1, "\n", r2)
			}
		}
	}
}

// TestReaderBadInputs tests that ReaderRoot properly handles edge-case
// inputs, such as a segment size of zero or a reader containing no data.
func TestReaderBadInputs(t *testing.T) {
	// A reader containing no data should result in a nil root, without an
	// error.
	root, err := ReaderRoot(&bytes.Reader{}, sha256.New(), 64)
	if err != nil {
		t.Error(err)
	} else if root != nil {
		t.Error("root of empty reader should be nil; got", root)
	}

	// A segment size of 0 should return an error.
	_, err = ReaderRoot(bytes.NewReader([]byte("data")), sha256.New(), 0)
	if err == nil {
		t.Error("ReaderRoot should return an error if segment size is zero")
	}
}
