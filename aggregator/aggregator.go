package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"DID/utils"
)

// AggregatorRequest 聚合节点接收的请求
type AggregatorRequest struct {
	PermutedCommitments [][]byte `json:"permuted_commitments"` // 置换后的承诺 (序列化字节)
}

// AggregatorResponse 聚合节点的响应
type AggregatorResponse struct {
	MerkleRoot []byte   `json:"merkle_root"`   // Merkle 树根
	NumLeaves  int      `json:"num_leaves"`    // 叶子节点数
	LeafHashes [][]byte `json:"leaf_hashes"`   // 所有叶子哈希 (用于后续 proof 生成)
	LeafData   [][]byte `json:"leaf_data"`     // 所有叶子原始数据
}

// BuildMerkleTree 从置换后的承诺构建 Merkle 树 (使用 SimpleMerkleTree)
// 这是单一聚合节点的工作: 接收置换后的承诺, 构建 Merkle 树, 输出 root
func BuildMerkleTree(permutedCommitments [][]byte) (*AggregatorResponse, error) {
	n := len(permutedCommitments)
	if n == 0 {
		return nil, fmt.Errorf("no commitments to aggregate")
	}

	log.Printf("[Aggregator] 接收到 %d 个置换后的承诺", n)

	tree := utils.NewSimpleMerkleTree()

	// 将每个承诺作为叶子插入 Merkle 树
	for _, commitmentBytes := range permutedCommitments {
		tree.Push(commitmentBytes)
	}

	// 构建 Merkle 树
	if err := tree.Build(); err != nil {
		return nil, fmt.Errorf("构建 Merkle 树失败: %v", err)
	}

	root := tree.Root()
	log.Printf("[Aggregator] Merkle Root: %s", hex.EncodeToString(root))

	response := &AggregatorResponse{
		MerkleRoot: root,
		NumLeaves:  tree.NumLeaves(),
		LeafHashes: tree.LeafHashes(),
		LeafData:   permutedCommitments,
	}

	return response, nil
}

// RunAggregator 聚合节点主入口
// 从文件读取置换后的承诺, 构建 Merkle 树, 输出 root
func RunAggregator(inputFile, outputFile string) {
	// 读取置换后的承诺
	jsonData, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("[Aggregator] 无法读取输入文件 %s: %v", inputFile, err)
	}

	var req AggregatorRequest
	if err := json.Unmarshal(jsonData, &req); err != nil {
		log.Fatalf("[Aggregator] 解析输入文件失败: %v", err)
	}

	// 构建 Merkle 树
	resp, err := BuildMerkleTree(req.PermutedCommitments)
	if err != nil {
		log.Fatalf("[Aggregator] 构建 Merkle 树失败: %v", err)
	}

	// 输出结果
	respJSON, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		log.Fatalf("[Aggregator] 序列化结果失败: %v", err)
	}

	if err := os.WriteFile(outputFile, respJSON, 0644); err != nil {
		log.Fatalf("[Aggregator] 写入输出文件失败: %v", err)
	}

	log.Printf("[Aggregator] Merkle Root: %x", resp.MerkleRoot)
	log.Printf("[Aggregator] 结果已写入 %s", outputFile)
}

func main() {
	inputFile := "permuted_commitments.json"
	outputFile := "aggregator_output.json"

	if len(os.Args) > 1 {
		inputFile = os.Args[1]
	}
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	RunAggregator(inputFile, outputFile)
}
