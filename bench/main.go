package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// 基准测试: 测量新架构各阶段的效率
func main() {
	log.SetFlags(0)
	fmt.Println("========================================")
	fmt.Println("DID 新架构效率基准测试")
	fmt.Println("========================================")

	// 测试不同规模
	for _, n := range []int{4, 16, 64, 256, 1024} {
		runBenchmark(n)
	}
}

func runBenchmark(nAttrs int) {
	fmt.Printf("\n--- 规模: %d 个属性 ---\n", nAttrs)
	nShards := 4

	// 阶段 1: Pedersen 承诺计算 (服务器端)
	t0 := time.Now()
	params := utils.SetupPedersen()
	allCommitments := make([]bls12381.G1Affine, nAttrs)
	for i := 0; i < nAttrs; i++ {
		attr := make([]byte, 32)
		rand.Read(attr)
		var m, r fr.Element
		m.SetBytes(attr)
		r.SetRandom()
		c := params.Commit(m, r)
		allCommitments[i] = c.C
	}
	t1 := time.Now()
	fmt.Printf("[阶段1] Pedersen 承诺计算: %v (%d 个)\n", t1.Sub(t0), nAttrs)

	// 阶段 2: 秘密分片
	t0 = time.Now()
	var secret fr.Element
	secret.SetUint64(12345)
	for i := 0; i < nAttrs; i++ {
		utils.ShardSecret(secret, nShards)
	}
	t1 = time.Now()
	fmt.Printf("[阶段2] 秘密分片 (%d 份 × %d 属性): %v\n", nShards, nAttrs, t1.Sub(t0))

	// 阶段 3: MPC 重随机化聚合
	t0 = time.Now()
	rerandomized := make([]bls12381.G1Affine, nAttrs)
	for i := range allCommitments {
		var rPrime fr.Element
		rPrime.SetRandom()
		rerandomized[i] = params.ReRandomize(allCommitments[i], rPrime)
	}
	t1 = time.Now()
	fmt.Printf("[阶段3] MPC 重随机化: %v\n", t1.Sub(t0))

	// 阶段 4: ORP 不经意置换 (Waksman 网络)
	t0 = time.Now()
	perm := utils.RandomPermutation(nAttrs)
	_ = utils.ObliviousPermute(rerandomized, perm)
	t1 = time.Now()
	fmt.Printf("[阶段4] ORP 不经意置换: %v\n", t1.Sub(t0))

	// 阶段 5: Merkle 树构建
	permuted := utils.ObliviousPermute(rerandomized, perm)
	leafData := make([][]byte, nAttrs)
	for i, c := range permuted {
		leafData[i] = c.Marshal()
	}
	t0 = time.Now()
	tree := utils.NewSimpleMerkleTree()
	for _, d := range leafData {
		tree.Push(d)
	}
	tree.Build()
	root := tree.Root()
	t1 = time.Now()
	fmt.Printf("[阶段5] Merkle 树构建: %v (root=%x...)\n", t1.Sub(t0), root[:8])

	// 阶段 6: 生成 Merkle proof
	t0 = time.Now()
	for i := 0; i < nAttrs; i++ {
		proof, _ := tree.GenerateProof(i)
		if !utils.VerifyProof(proof) {
			log.Fatalf("proof %d 验证失败", i)
		}
	}
	t1 = time.Now()
	fmt.Printf("[阶段6] 生成+验证 %d 个 proof: %v\n", nAttrs, t1.Sub(t0))

	fmt.Printf("总耗时: %v\n", t1.Sub(time.Time{}))
}
