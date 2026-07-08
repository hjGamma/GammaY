package utils

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

// SimpleMerkleTree 一个简洁的 Merkle 树实现, 专为 DID 新架构设计
// 使用 SHA-256 哈希, 支持任意长度叶子
type SimpleMerkleTree struct {
	leaves  [][]byte // 叶子数据 (原始)
	hashes  [][]byte // 叶子哈希
	layers  [][][]byte // 各层节点 (layers[0]=叶子哈希层, layers[last]=[root])
	root    []byte
}

// NewSimpleMerkleTree 创建空的 Merkle 树
func NewSimpleMerkleTree() *SimpleMerkleTree {
	return &SimpleMerkleTree{}
}

// hashLeaf 计算叶子哈希: H(0x00 || data)
func hashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// hashNode 计算内部节点哈希: H(0x01 || left || right)
func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Push 添加一个叶子 (原始数据)
func (t *SimpleMerkleTree) Push(data []byte) {
	// 复制避免外部修改
	dup := make([]byte, len(data))
	copy(dup, data)
	t.leaves = append(t.leaves, dup)
	t.hashes = append(t.hashes, hashLeaf(dup))
}

// Build 构建 Merkle 树, 计算 root
// 必须在 Push 完所有叶子后调用
func (t *SimpleMerkleTree) Build() error {
	if len(t.hashes) == 0 {
		return errors.New("no leaves to build tree")
	}

	// 叶子层
	current := make([][]byte, len(t.hashes))
	copy(current, t.hashes)
	t.layers = [][][]byte{current}

	// 自底向上构建
	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			var right []byte
			if i+1 < len(current) {
				right = current[i+1]
			} else {
				// 奇数情况: 复制左节点作为右节点
				right = left
			}
			next = append(next, hashNode(left, right))
		}
		t.layers = append(t.layers, next)
		current = next
	}

	t.root = current[0]
	return nil
}

// Root 返回 Merkle Root
func (t *SimpleMerkleTree) Root() []byte {
	return t.root
}

// LeafHashes 返回所有叶子哈希
func (t *SimpleMerkleTree) LeafHashes() [][]byte {
	return t.hashes
}

// NumLeaves 返回叶子数量
func (t *SimpleMerkleTree) NumLeaves() int {
	return len(t.leaves)
}

// LeafData 返回指定索引的叶子原始数据
func (t *SimpleMerkleTree) LeafData(index int) []byte {
	if index < 0 || index >= len(t.leaves) {
		return nil
	}
	return t.leaves[index]
}

// Proof Merkle 路径证明
type Proof struct {
	LeafIndex  int      // 叶子索引
	LeafHash   []byte   // 叶子哈希
	LeafData   []byte   // 叶子原始数据
	Path       [][]byte // 兄弟节点哈希路径 (从叶到根)
	IsRight    []bool   // 兄弟节点方向: true=兄弟在右, false=兄弟在左
	MerkleRoot []byte   // 根
}

// GenerateProof 为指定叶子生成 Merkle proof
func (t *SimpleMerkleTree) GenerateProof(index int) (*Proof, error) {
	if index < 0 || index >= len(t.hashes) {
		return nil, errors.New("leaf index out of range")
	}
	if len(t.layers) == 0 {
		return nil, errors.New("tree not built yet, call Build() first")
	}

	proof := &Proof{
		LeafIndex:  index,
		LeafHash:   t.hashes[index],
		LeafData:   t.leaves[index],
		MerkleRoot: t.root,
	}

	idx := index
	for layer := 0; layer < len(t.layers)-1; layer++ {
		currentLevel := t.layers[layer]
		var siblingHash []byte
		var siblingIsRight bool

		if idx%2 == 0 {
			// 当前是左节点, 兄弟在右
			siblingIsRight = true
			if idx+1 < len(currentLevel) {
				siblingHash = currentLevel[idx+1]
			} else {
				siblingHash = currentLevel[idx] // 奇数情况, 兄弟是自己
			}
		} else {
			// 当前是右节点, 兄弟在左
			siblingIsRight = false
			siblingHash = currentLevel[idx-1]
		}

		proof.Path = append(proof.Path, siblingHash)
		proof.IsRight = append(proof.IsRight, siblingIsRight)
		idx = idx / 2
	}

	return proof, nil
}

// VerifyProof 验证 Merkle proof
// 静态方法, 只需 proof 和 root 即可验证
func VerifyProof(proof *Proof) bool {
	if proof == nil || len(proof.Path) != len(proof.IsRight) {
		return false
	}

	current := proof.LeafHash
	for i, sibling := range proof.Path {
		if proof.IsRight[i] {
			// 兄弟在右: current = H(current, sibling)
			current = hashNode(current, sibling)
		} else {
			// 兄弟在左: current = H(sibling, current)
			current = hashNode(sibling, current)
		}
	}

	if len(current) != len(proof.MerkleRoot) {
		return false
	}
	for i := range current {
		if current[i] != proof.MerkleRoot[i] {
			return false
		}
	}
	return true
}

// TreeDepth 返回 Merkle 树深度 (叶子层为第 0 层)
func (t *SimpleMerkleTree) TreeDepth() int {
	if len(t.layers) == 0 {
		return 0
	}
	return len(t.layers) - 1
}

// NextPowerOfTwo 返回 >= n 的最小 2 的幂
func NextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len(uint(n-1))
}
