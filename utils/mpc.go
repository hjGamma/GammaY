package utils

import (
	"crypto/rand"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// MPCShare 表示一个加法秘密共享分片
// 在加法秘密共享中, 秘密 s = s_1 + s_2 + ... + s_n
type MPCShare struct {
	Index   int        // 分片索引 (0..n-1)
	Share   fr.Element // 分片值
	NodeID  int         // 目标 MPC 节点 ID
}

// AttributeShard 表示服务器发送给 MPC 节点的属性分片
// 包含承诺的重随机化分片和原始承诺
type AttributeShard struct {
	Commitment    bls12381.G1Affine // 原始 Pedersen 承诺 C = m*G + r*H
	ReRandomShare fr.Element         // 重随机化分片 r'_i (r' = Σ r'_i)
	AttributeID   int               // 属性标识
	ServerID      int               // 来源服务器 ID
}

// ClientShard 表示客户端发送给 MPC 节点的分片
// 客户端基于 g 计算新的参数, 并分片发送
type ClientShard struct {
	ClientShare fr.Element // 客户端计算的参数分片
	NodeID      int        // 目标 MPC 节点 ID
}

// ShardSecret 将秘密值 s 分成 n 份加法秘密共享
// 返回 n 个分片, 满足 s = s_1 + s_2 + ... + s_n
func ShardSecret(s fr.Element, n int) []fr.Element {
	shares := make([]fr.Element, n)
	var sum fr.Element
	sum.SetZero()

	// 前 n-1 份随机生成
	for i := 0; i < n-1; i++ {
		shares[i].SetRandom()
		sum.Add(&sum, &shares[i])
	}

	// 第 n 份 = s - (s_1 + s_2 + ... + s_{n-1})
	shares[n-1].Sub(&s, &sum)
	return shares
}

// ReconstructSecret 从分片重构秘密值
// s = s_1 + s_2 + ... + s_n
func ReconstructSecret(shares []fr.Element) fr.Element {
	var s fr.Element
	s.SetZero()
	for i := range shares {
		s.Add(&s, &shares[i])
	}
	return s
}

// ServerComputeShards 服务器端计算流程:
// 1. 生成用户属性 m
// 2. 计算 Pedersen 承诺 C = m*G + r*H
// 3. 将重随机化因子 r' 分成 n 份
// 4. 返回承诺和 n 个分片
func ServerComputeShards(params *CommitmentParams, attr []byte, nShards int, serverID int) ([]AttributeShard, fr.Element, fr.Element) {
	// 将属性映射到标量
	var m fr.Element
	m.SetBytes(attr)

	// 生成随机盲化因子 r
	var r fr.Element
	r.SetRandom()

	// 计算承诺 C = m*G + r*H
	commitment := params.Commit(m, r)

	// 生成重随机化因子 r'
	var rPrime fr.Element
	rPrime.SetRandom()

	// 将 r' 分成 n 份
	shards := ShardSecret(rPrime, nShards)

	// 构造 AttributeShard
	result := make([]AttributeShard, nShards)
	for i := range result {
		result[i] = AttributeShard{
			Commitment:    commitment.C,
			ReRandomShare: shards[i],
			AttributeID:   i,
			ServerID:      serverID,
		}
	}

	return result, m, r
}

// ClientComputeShards 客户端端计算流程:
// 1. 接收服务器发送的生成元 g
// 2. 基于 g 计算新的参数 (这里用 g 的哈希作为新的盲化贡献)
// 3. 将新参数分成 n 份
// 4. 返回 n 个客户端分片
func ClientComputeShards(g bls12381.G1Affine, nShards int) ([]ClientShard, fr.Element) {
	// 将 g 的序列化字节映射到标量, 作为客户端贡献
	gBytes := g.Marshal()
	var clientParam fr.Element
	clientParam.SetBytes(gBytes)

	// 客户端额外添加一个随机因子, 增强随机性
	var extraRand fr.Element
	extraRand.SetRandom()
	clientParam.Add(&clientParam, &extraRand)

	// 将客户端参数分成 n 份
	shards := ShardSecret(clientParam, nShards)

	// 构造 ClientShard
	result := make([]ClientShard, nShards)
	for i := range result {
		result[i] = ClientShard{
			ClientShare: shards[i],
			NodeID:      i,
		}
	}

	return result, clientParam
}

// MPCNode MPC 节点结构, 负责收集分片并执行重随机化
type MPCNode struct {
	NodeID      int
	serverShards map[int][]AttributeShard // 按 serverID 分组的属性分片
	clientShards []ClientShard             // 客户端分片
	params      *CommitmentParams
}

// NewMPCNode 创建 MPC 节点
func NewMPCNode(nodeID int, params *CommitmentParams) *MPCNode {
	return &MPCNode{
		NodeID:       nodeID,
		serverShards: make(map[int][]AttributeShard),
		params:       params,
	}
}

// ReceiveServerShard 接收服务器分片
func (node *MPCNode) ReceiveServerShard(shard AttributeShard) {
	node.serverShards[shard.ServerID] = append(node.serverShards[shard.ServerID], shard)
}

// ReceiveClientShard 接收客户端分片
func (node *MPCNode) ReceiveClientShard(shard ClientShard) {
	node.clientShards = append(node.clientShards, shard)
}

// ComputeReRandomization 单个 MPC 节点计算重随机化贡献
// 对于每个属性, 节点计算: partial = r'_i * H + clientShare_i * H
// 最终所有节点聚合: C' = C + Σ partial_i = m*G + (r + r' + clientParam)*H
func (node *MPCNode) ComputeReRandomization() map[int]bls12381.G1Affine {
	result := make(map[int]bls12381.G1Affine)

	// 获取客户端分片 (本节点对应的分片)
	var clientShare fr.Element
	for _, cs := range node.clientShards {
		if cs.NodeID == node.NodeID {
			clientShare = cs.ClientShare
			break
		}
	}

	// 对每个服务器的每个属性计算重随机化贡献
	for serverID, shards := range node.serverShards {
		for _, shard := range shards {
			// 合并服务器分片和客户端分片
			var combinedShare fr.Element
			combinedShare.Add(&shard.ReRandomShare, &clientShare)

			// 计算 combinedShare * H
			var combinedBI big.Int
			combinedShare.BigInt(&combinedBI)

			var hMul bls12381.G1Affine
			hMul.ScalarMultiplication(&node.params.H, &combinedBI)

			// 添加到该属性的累计贡献
			if existing, ok := result[shard.AttributeID]; ok {
				var summed bls12381.G1Affine
				summed.Add(&existing, &hMul)
				result[shard.AttributeID] = summed
			} else {
				result[shard.AttributeID] = hMul
			}
		}
		_ = serverID
	}

	return result
}

// AggregateReRandomization 聚合所有 MPC 节点的重随机化贡献
// 将原始承诺加上所有节点的贡献, 得到新的重随机化承诺
func AggregateReRandomization(
	originalCommitments map[int]bls12381.G1Affine, // 原始承诺 (按属性ID索引)
	nodeContributions []map[int]bls12381.G1Affine,  // 各节点的贡献
) map[int]bls12381.G1Affine {
	newCommitments := make(map[int]bls12381.G1Affine)

	for attrID, originalC := range originalCommitments {
		newC := originalC
		// 累加所有节点的贡献
		for _, contrib := range nodeContributions {
			if nodeContrib, ok := contrib[attrID]; ok {
				var combined bls12381.G1Affine
				combined.Add(&newC, &nodeContrib)
				newC = combined
			}
		}
		newCommitments[attrID] = newC
	}

	return newCommitments
}

// CollectOriginalCommitments 从服务器分片中收集原始承诺
func CollectOriginalCommitments(allShards [][]AttributeShard) map[int]bls12381.G1Affine {
	commitments := make(map[int]bls12381.G1Affine)
	for _, serverShards := range allShards {
		if len(serverShards) > 0 {
			// 同一服务器的所有分片包含相同承诺, 取第一个
			shard := serverShards[0]
			commitments[shard.AttributeID] = shard.Commitment
		}
	}
	return commitments
}

// ShardBigInt 使用大整数分片 (辅助函数)
func ShardBigInt(s *big.Int, n int, modulus *big.Int) []*big.Int {
	shares := make([]*big.Int, n)
	sum := big.NewInt(0)

	for i := 0; i < n-1; i++ {
		ri, _ := rand.Int(rand.Reader, modulus)
		shares[i] = ri
		sum.Add(sum, ri)
		sum.Mod(sum, modulus)
	}

	last := new(big.Int).Sub(s, sum)
	last.Mod(last, modulus)
	shares[n-1] = last
	return shares
}
