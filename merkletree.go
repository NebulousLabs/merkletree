// Package merkletree provides tools for calculating the Merkle root of a
// dataset, for creating a proof that a piece of data is in a Merkle tree of a
// given root, and for verifying proofs that a piece of data is in a Merkle
// tree of a given root. The tree is implemented according to the specification
// for Merkle trees provided in RFC 6962.
//
// As a recent addition, package merkletree also supports building roots and
// proofs from cached merkle trees. A cached merkle tree will saves all of the
// nodes at some height, such as height 16. While this incurs a linear storage
// cost in the size of the data, it prevents having to rehash the data any time
// some portion of the data changes or anytime that a proof needs to be
// created. The computational savings are often great enough to justify the
// storage tradeoff.
package merkletree
