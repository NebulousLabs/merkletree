merkletree
----------

merkletree is a go package for working with merkle trees. Using the 'Tree' object, you can insert leaves and get back the Merkle root. You can build proofs that data is a member of a Merkle tree, and you can verify proofs that data is a member of a Merkle tree.

Merkle trees are created using a stack of sub-trees that increase in height as you progress through the stack. When building the tree, orphan elements are not duplicated or hashed.

When creating a tree, you can set an index to create a proof that a certain leaf of the tree is a member of the tree. You must chose the index before adding any leaves to the tree, and you can only create 1 proof at a time. This library is not efficient for creating batch proofs.

Any hash that implements the go standard library 'Hash' interface can be used.

Tree shape:

```
     *
     |
   -----
  |     |
 ---    |
|   |   |
+   +   +
```
