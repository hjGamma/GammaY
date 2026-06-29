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

// AggregatorRequest 聚合节点接收的请求
type AggregatorRequest struct {
	PermutedCommitments [][]byte `json:"permuted_commitments"` // 置换后的承诺 (序列化字节)
}

// AggregatorResponse 聚合节点的响应
type AggregatorResponse struct {
	MerkleRoot   []byte   `json:"merkle_root"`    // Merkle 树根
	NumLeaves    int      `json:"num_leaves"`     // 叶子节点数
	LeafHashes   [][]byte `json:"leaf_hashes"`    // 所有叶子哈希 (用于后续 proof 生成)
	TreeDump     [][]byte `json:"tree_dump"`      // 完整树的节点 (用于 proof 生成)
}

// BuildMerkleTree 从置换后的承诺构建 Merkle 树
// 这是单一聚合节点的工作: 接收置换后的承诺, 构建 Merkle 树, 输出 root
func BuildMerkleTree(permutedCommitments [][]byte) (*AggregatorResponse, error) {
	n := len(permutedCommitments)
	if n == 0 {
		return nil, fmt.Errorf("no commitments to aggregate")
	}

	log.Printf("[Aggregator] 接收到 %d 个置换后的承诺", n)

	// 使用 MiMC 哈希函数
	h := mimc.NewMiMC()
	tree := utils.New(h)

	// 将每个承诺作为叶子插入 Merkle 树
	for _, commitmentBytes := range permutedCommitments {
		tree.Push(commitmentBytes)
	}

	// 计算 Merkle Root
	root := tree.Root()
	log.Printf("[Aggregator] Merkle Root: %s", hex.EncodeToString(root))

	// 收集所有叶子哈希 (用于 proof 生成)
	leafHashes := make([][]byte, n)
	for i, commitmentBytes := range permutedCommitments {
		// 使用与 Push 相同的哈希计算叶子
		h.Reset()
		h.Write(commitmentBytes)
		leafHashes[i] = h.Sum(nil)
	}

	// 构建完整树结构 (用于 proof 生成器)
	treeDump := buildTreeDump(leafHashes, h)

	response := &AggregatorResponse{
		MerkleRoot: root,
		NumLeaves:  n,
		LeafHashes: leafHashes,
		TreeDump:   treeDump,
	}

	return response, nil
}

// buildTreeDump 构建完整 Merkle 树的节点列表 (自底向上)
// 返回每层的节点哈希, treeDump[0] = 叶子层, treeDump[last] = root
func buildTreeDump(leafHashes [][]byte, h interface{ Write([]byte) (int, error); Reset(); Sum(b []byte) []byte }) [][]byte {
	if len(leafHashes) == 0 {
		return nil
	}

	// 合并每层为一个扁平的字节数组
	layers := make([][]byte, 0)
	current := make([]byte, 0)
	for _, lh := range leafHashes {
		current = append(current, lh...)
	}
	layers = append(layers, current)

	// 构建上层
	nodes := leafHashes
	for len(nodes) > 1 {
		nextLevel := make([][]byte, 0)
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right []byte
			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				right = left // 奇数情况复制
			}
			h.Reset()
			h.Write(left)
			h.Write(right)
			nextLevel = append(nextLevel, h.Sum(nil))
		}
		// 扁平化
		flat := make([]byte, 0)
		for _, n := range nextLevel {
			flat = append(flat, n...)
		}
		layers = append(layers, flat)
		nodes = nextLevel
	}

	return layers
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
