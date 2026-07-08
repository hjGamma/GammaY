package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"DID/utils"
)

// AggregatorOutput 聚合节点输出文件格式 (供 proofgen 读取)
type AggregatorOutput struct {
	MerkleRoot []byte   `json:"merkle_root"`
	NumLeaves  int      `json:"num_leaves"`
	LeafHashes [][]byte `json:"leaf_hashes"`
	LeafData   [][]byte `json:"leaf_data"`
}

// ProofResponse 生成的 Merkle proof
type ProofResponse struct {
	LeafIndex  int      `json:"leaf_index"`
	LeafData   []byte   `json:"leaf_data"`
	LeafHash   []byte   `json:"leaf_hash"`
	ProofPath  [][]byte `json:"proof_path"`
	ProofOrder []bool   `json:"proof_order"` // true=兄弟在右, false=兄弟在左
	MerkleRoot []byte   `json:"merkle_root"`
	NumLeaves  int      `json:"num_leaves"`
	Verified   bool     `json:"verified"`
}

// RunProofGenerator proof 生成器主入口
// 从聚合节点输出文件读取 Merkle 树, 为指定叶子生成 proof
// 用法: proofgen <aggregator_output.json> <leaf_index> [output_file]
func RunProofGenerator(aggregatorFile string, leafIndex int, outputFile string) {
	// 读取聚合节点输出
	aggData, err := os.ReadFile(aggregatorFile)
	if err != nil {
		log.Fatalf("[ProofGen] 无法读取聚合输出文件 %s: %v", aggregatorFile, err)
	}

	var agg AggregatorOutput
	if err := json.Unmarshal(aggData, &agg); err != nil {
		log.Fatalf("[ProofGen] 解析聚合输出失败: %v", err)
	}

	if leafIndex < 0 || leafIndex >= len(agg.LeafData) {
		log.Fatalf("[ProofGen] 叶子索引 %d 超出范围 [0, %d)", leafIndex, len(agg.LeafData))
	}

	// 用叶子数据重建 Merkle 树并生成 proof
	tree := utils.NewSimpleMerkleTree()
	for _, leaf := range agg.LeafData {
		tree.Push(leaf)
	}
	if err := tree.Build(); err != nil {
		log.Fatalf("[ProofGen] 重建 Merkle 树失败: %v", err)
	}

	// 验证 root 一致
	if hex.EncodeToString(tree.Root()) != hex.EncodeToString(agg.MerkleRoot) {
		log.Fatalf("[ProofGen] 警告: 重建 root 与聚合输出 root 不一致")
	}

	// 生成 proof
	proof, err := tree.GenerateProof(leafIndex)
	if err != nil {
		log.Fatalf("[ProofGen] 生成 proof 失败: %v", err)
	}

	// 验证 proof
	verified := utils.VerifyProof(proof)

	resp := &ProofResponse{
		LeafIndex:  proof.LeafIndex,
		LeafData:   proof.LeafData,
		LeafHash:   proof.LeafHash,
		ProofPath:  proof.Path,
		ProofOrder: proof.IsRight,
		MerkleRoot: proof.MerkleRoot,
		NumLeaves:  tree.NumLeaves(),
		Verified:   verified,
	}

	// 输出 proof
	proofJSON, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		log.Fatalf("[ProofGen] 序列化 proof 失败: %v", err)
	}

	if err := os.WriteFile(outputFile, proofJSON, 0644); err != nil {
		log.Fatalf("[ProofGen] 写入 proof 文件失败: %v", err)
	}

	log.Printf("[ProofGen] Proof 生成完成 (leaf=%d, verified=%v)", leafIndex, verified)
	log.Printf("[ProofGen] Merkle Root: %x", resp.MerkleRoot)
	log.Printf("[ProofGen] Proof 路径长度: %d", len(resp.ProofPath))
	log.Printf("[ProofGen] Proof 已写入 %s", outputFile)
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("用法: proofgen <aggregator_output.json> <leaf_index> [output_file]")
	}

	aggregatorFile := os.Args[1]
	var leafIndex int
	fmt.Sscanf(os.Args[2], "%d", &leafIndex)
	outputFile := "merkle_proof.json"
	if len(os.Args) > 3 {
		outputFile = os.Args[3]
	}

	RunProofGenerator(aggregatorFile, leafIndex, outputFile)
}
