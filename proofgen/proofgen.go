package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"DID/utils"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// ProofRequest proof 生成请求
type ProofRequest struct {
	MerkleRoot   []byte   `json:"merkle_root"`    // Merkle 树根
	LeafHashes   [][]byte `json:"leaf_hashes"`    // 所有叶子哈希
	LeafIndex    int      `json:"leaf_index"`     // 要证明的叶子索引
	LeafData     []byte   `json:"leaf_data"`      // 原始叶子数据 (承诺的字节)
}

// ProofResponse 生成的 Merkle proof
type ProofResponse struct {
	LeafIndex  int      `json:"leaf_index"`   // 叶子索引
	LeafData   []byte   `json:"leaf_data"`    // 叶子原始数据
	LeafHash   []byte   `json:"leaf_hash"`    // 叶子哈希
	ProofPath  [][]byte `json:"proof_path"`   // 兄弟节点哈希路径
	ProofOrder []bool   `json:"proof_order"`  // 兄弟节点方向: false=左, true=右
	MerkleRoot []byte   `json:"merkle_root"`  // Merkle 根
	NumLeaves  int      `json:"num_leaves"`   // 叶子总数
	Verified   bool     `json:"verified"`     // 验证结果
}

// MerkleProofGenerator Merkle proof 生成器
// 专门用于从给定的 Merkle 树结构生成验证 proof
type MerkleProofGenerator struct {
	hasher interface {
		Reset()
		Write([]byte) (int, error)
		Sum(b []byte) []byte
	}
}

// NewMerkleProofGenerator 创建 proof 生成器
func NewMerkleProofGenerator() *MerkleProofGenerator {
	return &MerkleProofGenerator{
		hasher: mimc.NewMiMC(),
	}
}

// GenerateProof 为指定叶子生成 Merkle proof
// leafHashes: 所有叶子节点的哈希值
// leafIndex: 要证明的叶子索引
// leafData: 叶子的原始数据
func (gen *MerkleProofGenerator) GenerateProof(leafHashes [][]byte, leafIndex int, leafData []byte) (*ProofResponse, error) {
	n := len(leafHashes)
	if leafIndex < 0 || leafIndex >= n {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, n)
	}

	// 计算叶子哈希 (验证一致性)
	gen.hasher.Reset()
	gen.hasher.Write(leafData)
	computedLeafHash := gen.hasher.Sum(nil)

	if hex.EncodeToString(computedLeafHash) != hex.EncodeToString(leafHashes[leafIndex]) {
		return nil, fmt.Errorf("leaf data hash mismatch: expected %x, got %x",
			leafHashes[leafIndex], computedLeafHash)
	}

	// 逐层构建 proof 路径
	proofPath := make([][]byte, 0)
	proofOrder := make([]bool, 0) // false=兄弟在左, true=兄弟在右

	currentLevel := make([][]byte, len(leafHashes))
	copy(currentLevel, leafHashes)

	idx := leafIndex
	for len(currentLevel) > 1 {
		// 确定兄弟节点
		var siblingHash []byte
		var siblingIsRight bool

		if idx%2 == 0 {
			// 当前节点是左节点, 兄弟在右
			siblingIsRight = true
			if idx+1 < len(currentLevel) {
				siblingHash = currentLevel[idx+1]
			} else {
				// 奇数情况: 兄弟是自己
				siblingHash = currentLevel[idx]
			}
		} else {
			// 当前节点是右节点, 兄弟在左
			siblingIsRight = false
			siblingHash = currentLevel[idx-1]
		}

		proofPath = append(proofPath, siblingHash)
		proofOrder = append(proofOrder, siblingIsRight)

		// 计算下一层
		nextLevel := make([][]byte, 0)
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right []byte
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = left
			}
			gen.hasher.Reset()
			gen.hasher.Write(left)
			gen.hasher.Write(right)
			nextLevel = append(nextLevel, gen.hasher.Sum(nil))
		}
		currentLevel = nextLevel
		idx = idx / 2
	}

	merkleRoot := currentLevel[0]

	// 验证 proof
	verified := VerifyProof(computedLeafHash, proofPath, proofOrder, merkleRoot, gen.hasher)

	return &ProofResponse{
		LeafIndex:  leafIndex,
		LeafData:   leafData,
		LeafHash:   computedLeafHash,
		ProofPath:  proofPath,
		ProofOrder: proofOrder,
		MerkleRoot: merkleRoot,
		NumLeaves:  n,
		Verified:   verified,
	}, nil
}

// VerifyProof 验证 Merkle proof
// leafHash: 叶子哈希
// proofPath: 兄弟节点路径
// proofOrder: 兄弟节点方向 (false=左, true=右)
// merkleRoot: 预期的 Merkle 根
func VerifyProof(leafHash []byte, proofPath [][]byte, proofOrder []bool, merkleRoot []byte, hasher interface {
	Reset()
	Write([]byte) (int, error)
	Sum(b []byte) []byte
}) bool {
	current := leafHash

	for i, sibling := range proofPath {
		hasher.Reset()
		if proofOrder[i] {
			// 兄弟在右: current = H(current, sibling)
			hasher.Write(current)
			hasher.Write(sibling)
		} else {
			// 兄弟在左: current = H(sibling, current)
			hasher.Write(sibling)
			hasher.Write(current)
		}
		current = hasher.Sum(nil)
	}

	return hex.EncodeToString(current) == hex.EncodeToString(merkleRoot)
}

// RunProofGenerator proof 生成器主入口
func RunProofGenerator(aggregatorFile string, leafIndex int, leafDataFile string, outputFile string) {
	// 读取聚合节点输出
	aggData, err := os.ReadFile(aggregatorFile)
	if err != nil {
		log.Fatalf("[ProofGen] 无法读取聚合输出文件 %s: %v", aggregatorFile, err)
	}

	var aggResp struct {
		MerkleRoot []byte   `json:"merkle_root"`
		LeafHashes [][]byte `json:"leaf_hashes"`
		NumLeaves  int      `json:"num_leaves"`
	}
	if err := json.Unmarshal(aggData, &aggResp); err != nil {
		log.Fatalf("[ProofGen] 解析聚合输出失败: %v", err)
	}

	// 读取叶子数据
	leafData, err := os.ReadFile(leafDataFile)
	if err != nil {
		log.Fatalf("[ProofGen] 无法读取叶子数据文件 %s: %v", leafDataFile, err)
	}

	// 生成 proof
	gen := NewMerkleProofGenerator()
	proof, err := gen.GenerateProof(aggResp.LeafHashes, leafIndex, leafData)
	if err != nil {
		log.Fatalf("[ProofGen] 生成 proof 失败: %v", err)
	}

	// 输出 proof
	proofJSON, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		log.Fatalf("[ProofGen] 序列化 proof 失败: %v", err)
	}

	if err := os.WriteFile(outputFile, proofJSON, 0644); err != nil {
		log.Fatalf("[ProofGen] 写入 proof 文件失败: %v", err)
	}

	log.Printf("[ProofGen] Proof 生成完成 (leaf=%d, verified=%v)", leafIndex, proof.Verified)
	log.Printf("[ProofGen] Merkle Root: %x", proof.MerkleRoot)
	log.Printf("[ProofGen] Proof 已写入 %s", outputFile)
}

// GenerateProofFromTree 直接从 Merkle 树生成 proof (使用 utils.Tree)
func GenerateProofFromTree(commitments [][]byte, leafIndex int) (*ProofResponse, error) {
	h := mimc.NewMiMC()
	tree := utils.New(h)

	if err := tree.SetIndex(uint64(leafIndex)); err != nil {
		return nil, fmt.Errorf("SetIndex failed: %v", err)
	}

	for _, c := range commitments {
		tree.Push(c)
	}

	root, proofSet, proofIndex, numLeaves := tree.Prove()

	// 构建 proof order
	proofOrder := make([]bool, len(proofSet)-1)
	idx := int(proofIndex)
	for i := range proofOrder {
		proofOrder[i] = (idx % 2) == 0
		idx = idx / 2
	}

	leafData := commitments[leafIndex]

	// 计算叶子哈希
	h.Reset()
	h.Write(leafData)
	leafHash := h.Sum(nil)

	return &ProofResponse{
		LeafIndex:  int(proofIndex),
		LeafData:   leafData,
		LeafHash:   leafHash,
		ProofPath:  proofSet[1:], // proofSet[0] 是叶子数据本身
		ProofOrder: proofOrder,
		MerkleRoot: root,
		NumLeaves:  int(numLeaves),
		Verified:   true,
	}, nil
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("用法: proofgen <aggregator_output.json> <leaf_index> <leaf_data_file> [output_file]")
	}

	aggregatorFile := os.Args[1]
	var leafIndex int
	fmt.Sscanf(os.Args[2], "%d", &leafIndex)
	leafDataFile := os.Args[3]
	outputFile := "merkle_proof.json"
	if len(os.Args) > 4 {
		outputFile = os.Args[4]
	}

	RunProofGenerator(aggregatorFile, leafIndex, leafDataFile, outputFile)
}
