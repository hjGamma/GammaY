package utils

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// 测试 Pedersen 承诺的正确性
func TestPedersenCommitment(t *testing.T) {
	params := SetupPedersen()

	// 属性 m = 42
	var m fr.Element
	m.SetUint64(42)

	// 随机盲化因子 r
	var r fr.Element
	r.SetRandom()

	// 计算承诺 C = m*G + r*H
	commitment := params.Commit(m, r)

	// 验证承诺正确性
	if !params.VerifyCommitment(commitment.C, m, r) {
		t.Fatal("Pedersen 承诺验证失败")
	}

	// 验证不同盲化因子的承诺不相等
	var r2 fr.Element
	r2.SetRandom()
	commitment2 := params.Commit(m, r2)
	if commitment.C.Equal(&commitment2.C) {
		t.Fatal("不同盲化因子应产生不同承诺")
	}

	t.Log("Pedersen 承诺验证通过")
}

// 测试 Pedersen 承诺的同态性质
func TestPedersenHomomorphism(t *testing.T) {
	params := SetupPedersen()

	var m1, m2, r1, r2 fr.Element
	m1.SetUint64(10)
	m2.SetUint64(20)
	r1.SetRandom()
	r2.SetRandom()

	c1 := params.Commit(m1, r1)
	c2 := params.Commit(m2, r2)

	// 同态性质: C(m1+m2, r1+r2) = C(m1,r1) + C(m2,r2)
	var mSum, rSum fr.Element
	mSum.Add(&m1, &m2)
	rSum.Add(&r1, &r2)
	cSum := params.Commit(mSum, rSum)

	var combined bls12381.G1Affine
	combined.Add(&c1.C, &c2.C)

	if !cSum.C.Equal(&combined) {
		t.Fatal("Pedersen 承诺同态性质验证失败")
	}

	t.Log("Pedersen 承诺同态性质验证通过")
}

// 测试重随机化
func TestReRandomization(t *testing.T) {
	params := SetupPedersen()

	var m, r fr.Element
	m.SetUint64(42)
	r.SetRandom()

	commitment := params.Commit(m, r)

	// 重随机化: 添加 r'*H
	var rPrime fr.Element
	rPrime.SetRandom()
	newC := params.ReRandomize(commitment.C, rPrime)

	// 新承诺仍然是对同一属性 m 的承诺
	// C' = m*G + (r+r')*H
	var rNew fr.Element
	rNew.Add(&r, &rPrime)
	if !params.VerifyCommitment(newC, m, rNew) {
		t.Fatal("重随机化后的承诺验证失败")
	}

	// 新承诺应与原承诺不同
	if commitment.C.Equal(&newC) {
		t.Fatal("重随机化后的承诺应与原承诺不同")
	}

	t.Log("重随机化验证通过")
}

// 测试加法秘密共享
func TestSecretSharing(t *testing.T) {
	var secret fr.Element
	secret.SetUint64(12345)

	n := 4 // 4 个分片
	shards := ShardSecret(secret, n)

	// 验证分片数量
	if len(shards) != n {
		t.Fatalf("期望 %d 个分片, 得到 %d", n, len(shards))
	}

	// 重构秘密
	reconstructed := ReconstructSecret(shards)
	if !reconstructed.Equal(&secret) {
		t.Fatal("秘密共享重构失败")
	}

	// 单个分片不应等于秘密
	for i, shard := range shards {
		if shard.Equal(&secret) {
			t.Fatalf("分片 %d 不应等于原始秘密", i)
		}
	}

	t.Log("加法秘密共享验证通过")
}

// 测试 ORP 不经意置换
func TestObliviousPermutation(t *testing.T) {
	params := SetupPedersen()
	n := 8

	// 生成 n 个承诺
	commitments := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		var m, r fr.Element
		m.SetUint64(uint64(i + 1))
		r.SetRandom()
		c := params.Commit(m, r)
		commitments[i] = c.C
	}

	// 生成随机置换
	perm := RandomPermutation(n)

	// 执行不经意置换
	permuted := ObliviousPermute(commitments, perm)

	// 验证置换正确性: permuted[i] 应等于 original[perm.Get()[i]]
	pi := perm.Get()
	for i := 0; i < n; i++ {
		if !permuted[i].Equal(&commitments[pi[i]]) {
			t.Fatalf("置换错误: 位置 %d 期望 %d 的承诺", i, pi[i])
		}
	}

	t.Log("ORP 不经意置换验证通过")
}

// 测试完整流程: 承诺 -> 分片 -> MPC 重随机化 -> 置换
func TestFullPipeline(t *testing.T) {
	params := SetupPedersen()
	nAttributes := 4
	nShards := 4

	// 模拟多个服务器生成属性、承诺、分片
	allShards := make([][]AttributeShard, nAttributes)
	originalCommitments := make(map[int]bls12381.G1Affine)

	for serverID := 0; serverID < nAttributes; serverID++ {
		attr := []byte{byte(serverID + 1)}
		shards, m, r := ServerComputeShards(params, attr, nShards, serverID)

		// 存储原始承诺
		c := params.Commit(m, r)
		originalCommitments[serverID] = c.C
		allShards[serverID] = shards
	}

	// 模拟客户端计算参数分片
	clientShards, _ := ClientComputeShards(params.G, nShards)

	// 模拟 MPC 节点计算
	nodeContributions := make([]map[int]bls12381.G1Affine, nShards)
	for nodeID := 0; nodeID < nShards; nodeID++ {
		node := NewMPCNode(nodeID, params)

		for serverID := 0; serverID < nAttributes; serverID++ {
			node.ReceiveServerShard(allShards[serverID][nodeID])
		}

		node.ReceiveClientShard(clientShards[nodeID])
		nodeContributions[nodeID] = node.ComputeReRandomization()
	}

	// 聚合重随机化
	rerandomized := AggregateReRandomization(originalCommitments, nodeContributions)
	if len(rerandomized) != nAttributes {
		t.Fatalf("期望 %d 个重随机化承诺, 得到 %d", nAttributes, len(rerandomized))
	}

	// 执行 ORP 置换
	perm := RandomPermutation(nAttributes)
	permuted := ObliviousPermute(
		toSlice(rerandomized, nAttributes),
		perm,
	)

	if len(permuted) != nAttributes {
		t.Fatalf("期望 %d 个置换承诺, 得到 %d", nAttributes, len(permuted))
	}

	t.Log("完整流程验证通过")
}

// 辅助函数: 将 map 转为有序 slice
func toSlice(m map[int]bls12381.G1Affine, n int) []bls12381.G1Affine {
	result := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		result[i] = m[i]
	}
	return result
}
