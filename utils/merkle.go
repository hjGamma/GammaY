// Original Copyright (c) 2015 Nebulous

// Package merkletree provides Merkle tree and proof following RFC 6962.
//
// From https://gitlab.com/NebulousLabs/merkletree
package utils

import (
	"errors"
	"fmt"
	"hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// A Tree takes data as leaves and returns the Merkle root. Each call to 'Push'
// adds one leaf to the Merkle tree. Calling 'Root' returns the Merkle root.
// The Tree also constructs proof that a single leaf is a part of the tree. The
// leaf can be chosen with 'SetIndex'. The memory footprint of Tree grows in
// O(log(n)) in the number of leaves.
// merkle tree结构，通过push添加叶子节点，返回merkle root
// 并可以通过SetIndex设置索引，返回该索引的merkle proof
type Tree struct {
	// The Tree is stored as a stack of subtrees. Each subtree has a height,
	// and is the Merkle root of 2^height leaves. A Tree with 11 nodes is
	// represented as a subtree of height 3 (8 nodes), a subtree of height 1 (2
	// nodes), and a subtree of height 0 (1 node). Head points to the smallest
	// tree. When a new leaf is inserted, it is inserted as a subtree of height
	// 0. If there is another subtree of the same height, both can be removed,
	// combined, and then inserted as a subtree of height n + 1.
	head *subTree
	hash hash.Hash

	// Helper variables used to construct proofs that the data at 'proofIndex'
	// is in the Merkle tree. The proofSet is constructed as elements are being
	// added to the tree. The first element of the proof set is the original
	// data used to create the leaf at index 'proofIndex'. proofTree indicates
	// if the tree will be used to create a merkle proof.
	//当前已插入的叶子数量，表示叶子索引位置
	currentIndex uint64
	//被证明的叶子索引
	proofIndex uint64
	//构造 Merkle 证明路径时，保存的哈希值数组。每个元素是某一层的兄弟节点哈希值
	proofSet [][]byte
	//是否启用了“构造 Merkle 证明”功能。为 true 时，在插入数据时会记录 proofSet；否则仅构造树，不做证明。
	proofTree bool

	// The cachedTree flag indicates that the tree is cached, meaning that
	// different code is used in 'Push' for creating a new head subtree. Adding
	// this flag is somewhat gross, but eliminates needing to duplicate the
	// entire 'Push' function when writing the cached tree.
	//是否开启缓存优化。为 true 时，插入数据时用不同的方式创建头部子树
	cachedTree bool

	//添加叶子结点用于还原merkle tree
	leaves [][]byte
}

// 子树包含树的完整（2^高叶子）子树的Merkle根。
// “sum”是子树的Merkle根。
// A subTree contains the Merkle root of a complete (2^height leaves) subTree
// of the Tree. 'sum' is the Merkle root of the subTree. If 'next' is not nil,
// it will be a tree with a higher height.
type subTree struct {
	next *subTree
	//- height = 0 的子树代表一个叶子
	// - height = 1 的子树有 2 个叶子
	// - height = 3 的子树有 8 个叶子
	height int // Int is okay because a height over 300 is physically unachievable.
	sum    []byte
}

// 返回输入数据的hash，通过传入满足hash.Hash接口的哈希函数
// sum returns the hash of the input data using the specified algorithm.
func sum(h hash.Hash, data ...[]byte) []byte {

	h.Reset()

	for _, d := range data {
		// the Hash interface specifies that Write never returns an error
		_, err := h.Write(d)
		if err != nil {
			panic(err)
		}
	}
	return h.Sum(nil)
}

// leafSum returns the hash created from data inserted to form a leaf. Leaf
// sums are calculated using:
//
//	Hash(0x00 || data)
//
// 返回叶子节点的hash
func leafSum(h hash.Hash, data []byte) []byte {

	//return sum(h, leafHashPrefix, data)
	return sum(h, data)
}

// nodeSum returns the hash created from two sibling nodes being combined into
// a parent node. Node sums are calculated using:
//
//	Hash(0x01 || left sibling sum || right sibling sum)
//
// 返回两个兄弟节点的hash
func nodeSum(h hash.Hash, a, b []byte) []byte {
	//将a、b合并后拆分

	//return sum(h, nodeHashPrefix, a, b)
	return sum(h, a, b)
}

// joinSubTrees combines two equal sized subTrees into a larger subTree.
func (t *Tree) joinSubTrees(h hash.Hash, a, b *subTree) *subTree {
	// if DEBUG {
	// 	if b.next != a {
	// 		panic("invalid subtree join - 'a' is not paired with 'b'")
	// 	}
	// 	if a.height < b.height {
	// 		panic("invalid subtree presented - height mismatch")
	// 	}
	// }
	if a.height == 0 && b.height == 0 {
		combineSums(a, b)
		t.leaves = append(t.leaves, a.sum)
		t.leaves = append(t.leaves, b.sum)
	}

	return &subTree{
		next:   a.next,
		height: a.height + 1,
		sum:    nodeSum(h, a.sum, b.sum),
	}
}

// New creates a new Tree. The provided hash will be used for all hashing
// operations within the Tree.
func New(h hash.Hash) *Tree {
	return &Tree{
		hash:       h,
		cachedTree: true,
	}
}

// Prove creates a proof that the leaf at the established index (established by
// SetIndex) is an element of the Merkle tree. Prove will return a nil proof
// set if used incorrectly. Prove does not modify the Tree. Prove can only be
// called if SetIndex has been called previously.
// 生成merkle proof
func (t *Tree) Prove() (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	if !t.proofTree {
		panic("wrong usage: can't call prove on a tree if SetIndex wasn't called")
	}

	// Return nil if the Tree is empty, or if the proofIndex hasn't yet been
	// reached.
	if t.head == nil || len(t.proofSet) == 0 {
		return t.Root(), nil, t.proofIndex, t.currentIndex
	}
	proofSet = t.proofSet

	// The set of subtrees must now be collapsed into a single root. The proof
	// set already contains all of the elements that are members of a complete
	// subtree. Of what remains, there will be at most 1 element provided from
	// a sibling on the right, and all of the other proofs will be provided
	// from a sibling on the left. This results from the way orphans are
	// treated. All subtrees smaller than the subtree containing the proofIndex
	// will be combined into a single subtree that gets combined with the
	// proofIndex subtree as a single right sibling. All subtrees larger than
	// the subtree containing the proofIndex will be combined with the subtree
	// containing the proof index as left siblings.

	// Start at the smallest subtree and combine it with larger subtrees until
	// it would be combining with the subtree that contains the proof index. We
	// can recognize the subtree containing the proof index because the height
	// of that subtree will be one less than the current length of the proof
	// set.
	current := t.head

	for current.next != nil && current.next.height < len(proofSet)-1 {
		current = t.joinSubTrees(t.hash, current.next, current)
	}

	// If the current subtree is not the subtree containing the proof index,
	// then it must be an aggregate subtree that is to the right of the subtree
	// containing the proof index, and the next subtree is the subtree
	// containing the proof index.
	if current.next != nil && current.next.height == len(proofSet)-1 {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}

	// The current subtree must be the subtree containing the proof index. This
	// subtree does not need an entry, as the entry was created during the
	// construction of the Tree. Instead, skip to the next subtree.
	current = current.next

	// All remaining subtrees will be added to the proof set as a left sibling,
	// completing the proof set.
	for current != nil {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}
	return t.Root(), proofSet, t.proofIndex, t.currentIndex
}

// Push will add data to the set, building out the Merkle tree and Root. The
// tree does not remember all elements that are added, instead only keeping the
// log(n) elements that are necessary to build the Merkle root and keeping the
// log(n) elements necessary to build a proof that a piece of data is in the
// Merkle tree.
// 接收原始数据作为叶子节点，计算其哈希，插入 Merkle Tree
// 自动判断是否为 proofIndex，记录进 proofSet；
// 自动合并高度相同的子树（通过 joinAllSubTrees()）；
func (t *Tree) Push(data []byte) {
	// The first element of a proof is the data at the proof index. If this
	// data is being inserted at the proof index, it is added to the proof set.
	if t.currentIndex == t.proofIndex {
		t.proofSet = append(t.proofSet, data)
	}

	// Hash the data to create a subtree of height 0. The sum of the new node
	// is going to be the data for cached trees, and is going to be the result
	// of calling leafSum() on the data for standard trees. Doing a check here
	// prevents needing to duplicate the entire 'Push' function for the trees.
	t.head = &subTree{
		next:   t.head,
		height: 0,
	}
	if t.cachedTree {
		t.head.sum = data
	} else {
		t.head.sum = leafSum(t.hash, data)
	}

	// Join subTrees if possible.
	t.joinAllSubTrees()

	// Update the index.
	t.currentIndex++

}

// PushSubTree pushes a cached subtree into the merkle tree. The subtree has to
// be smaller than the smallest subtree in the merkle tree, it has to be
// balanced and it can't contain the element that needs to be proven.  Since we
// can't tell if a subTree is balanced, we can't sanity check for unbalanced
// trees. Therefore an unbalanced tree will cause silent errors, pain and
// misery for the person who wants to debug the resulting error.
// 接收已经预计算好的子树根哈希（sum）和高度，插入 Merkle Tree；
// 一般用于“缓存优化”、“快速恢复”、“拼接历史树”等场景；
// 不再对数据进行哈希，也不会保存到 proofSet；
func (t *Tree) PushSubTree(height int, sum []byte) error {
	// Check if the cached tree that is pushed contains the element at
	// proofIndex. This is not allowed.
	newIndex := t.currentIndex + 1<<uint64(height)
	if t.proofTree && (t.currentIndex == t.proofIndex ||
		(t.currentIndex < t.proofIndex && t.proofIndex < newIndex)) {
		return errors.New("the cached tree shouldn't contain the element to prove")
	}

	// We can only add the cached tree if its depth is <= the depth of the
	// current subtree.
	if t.head != nil && height > t.head.height {
		return fmt.Errorf("can't add a subtree that is larger than the smallest subtree %v > %v", height, t.head.height)
	}

	// Insert the cached tree as the new head.
	t.head = &subTree{
		height: height,
		next:   t.head,
		sum:    sum,
	}

	// Join subTrees if possible.
	t.joinAllSubTrees()

	// Update the index.
	t.currentIndex = newIndex

	return nil
}

// Root returns the Merkle root of the data that has been pushed.
func (t *Tree) Root() []byte {
	// If the Tree is empty, return nil.
	if t.head == nil {
		return nil
	}

	// The root is formed by hashing together subTrees in order from least in
	// height to greatest in height. The taller subtree is the first subtree in
	// the join.
	current := t.head
	for current.next != nil {
		current = t.joinSubTrees(t.hash, current.next, current)
	}
	// Return a copy to prevent leaking a pointer to internal data.
	return append(current.sum[:0:0], current.sum...)
}

func (t *Tree) SetIndex(i uint64) error {
	if t.head != nil {
		return errors.New("cannot call SetIndex on Tree if Tree has not been reset")
	}
	t.proofTree = true
	t.proofIndex = i
	return nil
}

func (t *Tree) joinAllSubTrees() {
	// 防止 proofSet 是空的情况下死循环
	if len(t.proofSet) == 0 {
		for t.head.next != nil && t.head.height == t.head.next.height {
			t.head = t.joinSubTrees(t.hash, t.head.next, t.head)
		}
		return
	}

	for t.head.next != nil && t.head.height == t.head.next.height {
		if t.head.height == len(t.proofSet)-1 {
			leaves := uint64(1 << uint(t.head.height))
			mid := (t.currentIndex / leaves) * leaves
			if t.proofIndex < mid {
				t.proofSet = append(t.proofSet, t.head.sum)
			} else {
				t.proofSet = append(t.proofSet, t.head.next.sum)
			}
		}
		t.head = t.joinSubTrees(t.hash, t.head.next, t.head)
	}
}

func MPC(X2 [32]byte, Y1 []byte) []byte {

	concat := append(X2[:], Y1...)

	return concat
}

func frToBytes32(e *fr.Element) []byte {
	b := e.Bytes() // 返回 []byte（32字节）
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b[:])
		return padded
	}
	return b[:]
}

func combineSums(a, b *subTree) {
	if len(a.sum) != 64 || len(b.sum) != 64 {
		panic("sum should be 64 bytes")
	}

	// 分割出每一部分（32 字节）
	p1a := new(fr.Element).SetBytes(a.sum[:32])
	p2a := new(fr.Element).SetBytes(a.sum[32:])
	p1b := new(fr.Element).SetBytes(b.sum[:32])
	p2b := new(fr.Element).SetBytes(b.sum[32:])

	// 执行加法
	sumA := new(fr.Element).Add(p1a, p1b) // a 的新值
	sumB := new(fr.Element).Add(p2a, p2b) // b 的新值

	// 更新 sum（只保留 32 字节结果）
	a.sum = frToBytes32(sumA)
	fmt.Println("还原hash:", new(fr.Element).SetBytes(a.sum))
	b.sum = frToBytes32(sumB)
	fmt.Println("还原hash:", new(fr.Element).SetBytes(b.sum))
}

func (t *Tree) BuildProof(index uint64) ([][]byte, []byte, error) {
	if index >= uint64(len(t.leaves)) {
		return nil, nil, fmt.Errorf("index out of range")
	}

	// 生成叶子哈希
	leafHashes := make([][]byte, len(t.leaves))
	for i, leaf := range t.leaves {
		leafHashes[i] = leafSum(t.hash, leaf)
	}

	// 构造 proof path
	var proof [][]byte
	i := index
	nodes := leafHashes

	for len(nodes) > 1 {
		var nextLevel [][]byte
		for j := 0; j < len(nodes); j += 2 {
			left := nodes[j]
			var right []byte
			if j+1 < len(nodes) {
				right = nodes[j+1]
			} else {
				right = left
			}

			if uint64(j) == i {
				proof = append(proof, right)
				i = uint64(len(nextLevel))
			} else if uint64(j+1) == i {
				proof = append(proof, left)
				i = uint64(len(nextLevel))
			}

			nextLevel = append(nextLevel, nodeSum(t.hash, left, right))
		}
		nodes = nextLevel
	}

	root := nodes[0]
	return proof, root, nil
}
