package main

// =============================================================================
// 对比基准测试: 纯 Pedersen vs 当前方案(Pedersen+MPC) vs 纯 MPC
//
// 三种方案的 Merkle Tree 计算方式:
//
// 1. 纯 Pedersen:
//    - 权威机构直接计算属性 → Pedersen 承诺: C_i = m_i*G + r_i*H
//    - 中心节点直接用 SHA-256 构建 Merkle Tree
//    - 无任何 MPC 参与, 无通信开销
//
// 2. 当前方案 (Pedersen + MPC 重随机化):
//    - 服务器计算 Pedersen 承诺 + 生成重随机化因子分片
//    - 客户端生成重随机化因子分片
//    - k 个 MPC 节点各做 1 次标量乘法计算贡献
//    - 聚合贡献后得到重随机化承诺
//    - 中心节点用 SHA-256 构建 Merkle Tree
//    - MPC 仅参与重随机化, Merkle Tree 仍为中心计算
//
// 3. 纯 MPC:
//    - 属性秘密分片给 k 个 MPC 节点
//    - 每个节点计算部分承诺: m_j*G + r_j*H (2k 次标量乘法/属性)
//    - 聚合得到完整承诺
//    - Merkle Tree 的每一层哈希均通过 MPC 协议计算
//    - SHA-256 在 MPC 中需 ~22,000-27,000 个 AND 门
//    - 每个 AND 门通过 Beaver 三元组协议实现 (5 次域乘法 + 1 轮通信)
//
// =============================================================================

import (
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ===== MPC 模拟参数 =====
const (
	mpcNodes         = 4      // MPC 节点数 k
	commDelayMs      = 1.0    // 每轮通信延迟 (ms, 数据中心 LAN)
	andGatesLeaf     = 22000  // SHA-256 叶子哈希 (~256bit 输入) 的 AND 门数
	andGatesNode     = 27000  // SHA-256 内部节点哈希 (~512bit 输入) 的 AND 门数
	mpcBatchSize     = 1000   // 每轮批处理的 AND 门数
	mulsPerANDGate   = 5      // 每个 AND 门的域乘法数 (Beaver triple: 1预处理+4在线)
)

// ===== 结果结构 =====
type Result struct {
	Approach   string
	NAttrs     int
	Phase      string
	AvgMs      float64
	MinMs      float64
	MaxMs      float64
	Iterations int
}

// ===== 主函数 =====
func main() {
	log.SetFlags(0)
	fmt.Println("============================================================")
	fmt.Println("  Merkle Tree 计算方案对比: 纯Pedersen vs Pedersen+MPC vs 纯MPC")
	fmt.Println("============================================================")
	fmt.Printf("CPU: %d 核, Go: %s\n", runtime.NumCPU(), runtime.Version())
	fmt.Printf("MPC 节点数: %d, 通信延迟: %.1f ms/轮, 批处理: %d AND门/轮\n\n",
		mpcNodes, commDelayMs, mpcBatchSize)

	// 校准域乘法时间 (用于 MPC 开销估算)
	mulTimeUs := calibrateFieldMul()
	fmt.Printf("域乘法(fr.Mul)校准时间: %.3f μs\n", mulTimeUs)
	fmt.Printf("每个 AND 门 MPC 开销: %.3f μs (计算) + %.3f ms (通信)\n\n",
		mulTimeUs*mulsPerANDGate, commDelayMs/float64(mpcBatchSize))

	attrsList := []int{4, 16, 64, 128, 256, 512}
	iterations := 5

	var allResults []Result
	for _, nAttrs := range attrsList {
		fmt.Printf("====== %d 属性 ======\n", nAttrs)

		// 方案1: 纯 Pedersen
		r1 := runPurePedersen(nAttrs, iterations)
		allResults = append(allResults, r1...)

		// 方案2: 当前方案 (Pedersen + MPC)
		r2 := runCurrentApproach(nAttrs, mpcNodes, iterations)
		allResults = append(allResults, r2...)

		// 方案3: 纯 MPC
		r3 := runPureMPC(nAttrs, mpcNodes, iterations, mulTimeUs)
		allResults = append(allResults, r3...)

		fmt.Println()
	}

	printComparisonTable(allResults)
	writeCSV("/workspace/bench_compare_results.csv", allResults)
}

// ===== 校准: 测量域乘法时间 =====
func calibrateFieldMul() float64 {
	var a, b, c fr.Element
	a.SetRandom()
	b.SetRandom()

	n := 200000
	start := time.Now()
	for i := 0; i < n; i++ {
		c.Mul(&a, &b)
	}
	elapsed := time.Since(start)
	return float64(elapsed.Microseconds()) / float64(n)
}

// =============================================================================
// 方案1: 纯 Pedersen (中心权威直接计算)
// =============================================================================

func runPurePedersen(nAttrs, iterations int) []Result {
	phases := []string{"承诺计算", "Merkle构建", "Proof生成", "Proof验证", "总耗时"}
	timings := make(map[string][]float64)
	for _, p := range phases {
		timings[p] = make([]float64, 0, iterations)
	}

	for iter := 0; iter < iterations; iter++ {
		t := purePedersenRun(nAttrs)
		for _, p := range phases {
			timings[p] = append(timings[p], t[p])
		}
	}

	var results []Result
	for _, phase := range phases {
		tv := timings[phase]
		sort.Float64s(tv)
		avg := avgF(tv)
		results = append(results, Result{"纯Pedersen", nAttrs, phase, avg, tv[0], tv[len(tv)-1], iterations})
		fmt.Printf("  [纯Pedersen]     %-16s %12.2f ms\n", phase, avg)
	}
	return results
}

func purePedersenRun(nAttrs int) map[string]float64 {
	result := make(map[string]float64)
	var t0 time.Time

	// Setup
	params := utils.SetupPedersen()
	attrs := make([][]byte, nAttrs)
	for i := range attrs {
		attrs[i] = make([]byte, 32)
		rand.Read(attrs[i])
	}

	// 1. 承诺计算 (中心, 无 MPC)
	t0 = time.Now()
	commitments := make([]bls12381.G1Affine, nAttrs)
	for i, attr := range attrs {
		var m, r fr.Element
		m.SetBytes(attr)
		r.SetRandom()
		c := params.Commit(m, r)
		commitments[i] = c.C
	}
	result["承诺计算"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 2. Merkle 构建 (中心, SHA-256)
	t0 = time.Now()
	tree := utils.NewSimpleMerkleTree()
	for _, c := range commitments {
		tree.Push(c.Marshal())
	}
	tree.Build()
	_ = tree.Root()
	result["Merkle构建"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 3. Proof 生成
	t0 = time.Now()
	proofs := make([]*utils.Proof, nAttrs)
	for i := 0; i < nAttrs; i++ {
		p, _ := tree.GenerateProof(i)
		proofs[i] = p
	}
	result["Proof生成"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 4. Proof 验证
	t0 = time.Now()
	for i := 0; i < nAttrs; i++ {
		utils.VerifyProof(proofs[i])
	}
	result["Proof验证"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 5. 总耗时
	total := 0.0
	for _, p := range []string{"承诺计算", "Merkle构建", "Proof生成", "Proof验证"} {
		total += result[p]
	}
	result["总耗时"] = total
	return result
}

// =============================================================================
// 方案2: 当前方案 (Pedersen + MPC 重随机化)
// MPC 仅用于重随机化, Merkle Tree 仍为中心计算
// =============================================================================

func runCurrentApproach(nAttrs, nShards, iterations int) []Result {
	phases := []string{"承诺+分片", "MPC重随机化", "Merkle构建", "Proof生成", "Proof验证", "总耗时"}
	timings := make(map[string][]float64)
	for _, p := range phases {
		timings[p] = make([]float64, 0, iterations)
	}

	for iter := 0; iter < iterations; iter++ {
		t := currentApproachRun(nAttrs, nShards)
		for _, p := range phases {
			timings[p] = append(timings[p], t[p])
		}
	}

	var results []Result
	for _, phase := range phases {
		tv := timings[phase]
		sort.Float64s(tv)
		avg := avgF(tv)
		results = append(results, Result{"Pedersen+MPC", nAttrs, phase, avg, tv[0], tv[len(tv)-1], iterations})
		fmt.Printf("  [Pedersen+MPC]   %-16s %12.2f ms\n", phase, avg)
	}
	return results
}

func currentApproachRun(nAttrs, nShards int) map[string]float64 {
	result := make(map[string]float64)
	var t0 time.Time

	// Setup
	params := utils.SetupPedersen()
	attrs := make([][]byte, nAttrs)
	for i := range attrs {
		attrs[i] = make([]byte, 32)
		rand.Read(attrs[i])
	}

	// 1. 服务器处理: 承诺 + 重随机化因子分片
	t0 = time.Now()
	commitments := make([]bls12381.G1Affine, nAttrs)
	for i, attr := range attrs {
		var m, r fr.Element
		m.SetBytes(attr)
		r.SetRandom()
		c := params.Commit(m, r)
		commitments[i] = c.C
	}

	// 生成全局重随机化因子并分片
	var deltaServer fr.Element
	deltaServer.SetRandom()
	serverShares := utils.ShardSecret(deltaServer, nShards)

	// 客户端生成重随机化因子并分片
	var deltaClient fr.Element
	deltaClient.SetRandom()
	clientShares := utils.ShardSecret(deltaClient, nShards)
	result["承诺+分片"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 2. MPC 重随机化 (k 个节点各做 1 次标量乘法)
	t0 = time.Now()
	nodes := make([]*utils.V2MPCNode, nShards)
	for j := 0; j < nShards; j++ {
		nodes[j] = utils.NewV2MPCNode(j, serverShares[j], clientShares[j], params)
	}
	rerandomized := utils.V2ApplyRerandomization(commitments, nodes)

	// 通信开销: 2 轮 (分片分发 + 贡献聚合)
	mpcCommMs := 2.0 * commDelayMs
	result["MPC重随机化"] = float64(time.Since(t0).Microseconds())/1000.0 + mpcCommMs

	// 3. Merkle 构建 (中心, SHA-256)
	t0 = time.Now()
	tree := utils.NewSimpleMerkleTree()
	for _, c := range rerandomized {
		tree.Push(c.Marshal())
	}
	tree.Build()
	_ = tree.Root()
	result["Merkle构建"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 4. Proof 生成
	t0 = time.Now()
	proofs := make([]*utils.Proof, nAttrs)
	for i := 0; i < nAttrs; i++ {
		p, _ := tree.GenerateProof(i)
		proofs[i] = p
	}
	result["Proof生成"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 5. Proof 验证
	t0 = time.Now()
	for i := 0; i < nAttrs; i++ {
		utils.VerifyProof(proofs[i])
	}
	result["Proof验证"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 6. 总耗时
	total := 0.0
	for _, p := range []string{"承诺+分片", "MPC重随机化", "Merkle构建", "Proof生成", "Proof验证"} {
		total += result[p]
	}
	result["总耗时"] = total
	return result
}

// =============================================================================
// 方案3: 纯 MPC (每一步都由 MPC 计算)
// =============================================================================

func runPureMPC(nAttrs, nShards, iterations int, mulTimeUs float64) []Result {
	phases := []string{"MPC承诺计算", "MPC Merkle构建", "Proof生成", "Proof验证", "总耗时"}
	timings := make(map[string][]float64)
	for _, p := range phases {
		timings[p] = make([]float64, 0, iterations)
	}

	for iter := 0; iter < iterations; iter++ {
		t := pureMPCRun(nAttrs, nShards, mulTimeUs)
		for _, p := range phases {
			timings[p] = append(timings[p], t[p])
		}
	}

	var results []Result
	for _, phase := range phases {
		tv := timings[phase]
		sort.Float64s(tv)
		avg := avgF(tv)
		results = append(results, Result{"纯MPC", nAttrs, phase, avg, tv[0], tv[len(tv)-1], iterations})
		fmt.Printf("  [纯MPC]          %-16s %12.2f ms\n", phase, avg)
	}
	return results
}

func pureMPCRun(nAttrs, nShards int, mulTimeUs float64) map[string]float64 {
	result := make(map[string]float64)
	var t0 time.Time

	// Setup
	params := utils.SetupPedersen()
	attrs := make([][]byte, nAttrs)
	for i := range attrs {
		attrs[i] = make([]byte, 32)
		rand.Read(attrs[i])
	}

	// ===== 1. MPC 承诺计算 =====
	// 每个属性:
	//   a. 秘密分片 m 和 r → k 份
	//   b. 每个节点 j 计算: partial_j = m_j*G + r_j*H (2 次标量乘法)
	//   c. 聚合: C = Σ partial_j (k-1 次点加法)
	//   d. 通信: 2 轮/属性 (分片分发 + 部分承诺聚合)
	t0 = time.Now()
	commitments := make([]bls12381.G1Affine, nAttrs)
	for i, attr := range attrs {
		var m, r fr.Element
		m.SetBytes(attr)
		r.SetRandom()

		// a. 秘密分片
		mShares := utils.ShardSecret(m, nShards)
		rShares := utils.ShardSecret(r, nShards)

		// b. 每个节点计算部分承诺 (2k 次标量乘法)
		partials := make([]bls12381.G1Affine, nShards)
		for j := 0; j < nShards; j++ {
			var mBI, rBI big.Int
			mShares[j].BigInt(&mBI)
			rShares[j].BigInt(&rBI)

			var mG, rH, partial bls12381.G1Affine
			mG.ScalarMultiplication(&params.G, &mBI)
			rH.ScalarMultiplication(&params.H, &rBI)
			partial.Add(&mG, &rH)
			partials[j] = partial
		}

		// c. 聚合 (k-1 次点加法)
		var c bls12381.G1Affine
		c = partials[0]
		for j := 1; j < nShards; j++ {
			var tmp bls12381.G1Affine
			tmp.Add(&c, &partials[j])
			c = tmp
		}
		commitments[i] = c
	}
	mpcCommitComputeMs := float64(time.Since(t0).Microseconds()) / 1000.0

	// d. 通信开销: 2 轮/属性 (分片分发 + 部分承诺聚合)
	//   - 分片分发: 服务器 → k 节点 (k * 32 bytes)
	//   - 部分承诺聚合: k 节点 → 聚合者 (k * 48 bytes)
	//   每属性 2 轮, 每轮 1ms
	mpcCommitCommMs := float64(nAttrs*2) * commDelayMs

	result["MPC承诺计算"] = mpcCommitComputeMs + mpcCommitCommMs

	// ===== 2. MPC Merkle 构建 =====
	// 在纯 MPC 中, Merkle Tree 的每一层哈希都通过 MPC 协议计算:
	//   - 叶子层: n 个 SHA-256 (每个 ~22,000 AND 门)
	//   - 内部层: n-1 个 SHA-256 (每个 ~27,000 AND 门)
	//   每个 AND 门通过 Beaver 三元组协议:
	//   - 预处理: 生成三元组 (a, b, c=a*b) → 1 次域乘法
	//   - 在线: 掩码 + 开启 + 重构 → 4 次域乘法 + 1 轮通信
	//   总计: 5 次域乘法 + 1 轮通信/AND门 (批处理)

	// 实际构建 Merkle Tree (用于正确性和 Proof 生成)
	t0 = time.Now()
	tree := utils.NewSimpleMerkleTree()
	for _, c := range commitments {
		tree.Push(c.Marshal())
	}
	tree.Build()
	_ = tree.Root()
	actualHashMs := float64(time.Since(t0).Microseconds()) / 1000.0

	// 模拟 MPC 哈希开销
	leafHashes := nAttrs
	internalHashes := nAttrs - 1
	if internalHashes < 0 {
		internalHashes = 0
	}

	totalANDGates := leafHashes*andGatesLeaf + internalHashes*andGatesNode
	totalFieldMuls := totalANDGates * mulsPerANDGate
	totalCommRounds := (totalANDGates + mpcBatchSize - 1) / mpcBatchSize

	// MPC 计算开销 (域乘法)
	mpcHashComputeMs := float64(totalFieldMuls) * mulTimeUs / 1000.0
	// MPC 通信开销 (每批 1 轮)
	mpcHashCommMs := float64(totalCommRounds) * commDelayMs

	result["MPC Merkle构建"] = actualHashMs + mpcHashComputeMs + mpcHashCommMs

	// 3. Proof 生成 (中心, 从已构建的树生成)
	t0 = time.Now()
	proofs := make([]*utils.Proof, nAttrs)
	for i := 0; i < nAttrs; i++ {
		p, _ := tree.GenerateProof(i)
		proofs[i] = p
	}
	result["Proof生成"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 4. Proof 验证
	t0 = time.Now()
	for i := 0; i < nAttrs; i++ {
		utils.VerifyProof(proofs[i])
	}
	result["Proof验证"] = float64(time.Since(t0).Microseconds()) / 1000.0

	// 5. 总耗时
	total := 0.0
	for _, p := range []string{"MPC承诺计算", "MPC Merkle构建", "Proof生成", "Proof验证"} {
		total += result[p]
	}
	result["总耗时"] = total
	return result
}

// =============================================================================
// 输出与工具函数
// =============================================================================

func avgF(v []float64) float64 {
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func printComparisonTable(results []Result) {
	approaches := []string{"纯Pedersen", "Pedersen+MPC", "纯MPC"}
	attrsList := []int{4, 16, 64, 128, 256, 512}

	// 按 方案×属性数 组织数据
	type key struct {
		approach string
		nAttrs   int
	}
	data := make(map[key]map[string]float64)
	for _, r := range results {
		k := key{r.Approach, r.NAttrs}
		if data[k] == nil {
			data[k] = make(map[string]float64)
		}
		data[k][r.Phase] = r.AvgMs
	}

	fmt.Println("\n============================================================")
	fmt.Println("                    汇总对比表 (平均耗时 ms)")
	fmt.Println("============================================================")

	// --- 总耗时对比 ---
	fmt.Println("\n■ 总耗时对比 (ms)")
	fmt.Printf("%-10s", "属性数")
	for _, a := range approaches {
		fmt.Printf(" %16s", a)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))

	for _, n := range attrsList {
		fmt.Printf("%-10d", n)
		for _, a := range approaches {
			if d, ok := data[key{a, n}]; ok {
				fmt.Printf(" %16.2f", d["总耗时"])
			} else {
				fmt.Printf(" %16s", "N/A")
			}
		}
		fmt.Println()
	}

	// --- 承诺计算对比 ---
	fmt.Println("\n■ 承诺计算阶段对比 (ms)")
	fmt.Printf("%-10s", "属性数")
	for _, a := range approaches {
		fmt.Printf(" %16s", a)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))

	for _, n := range attrsList {
		fmt.Printf("%-10d", n)
		for _, a := range approaches {
			if d, ok := data[key{a, n}]; ok {
				phase := ""
				switch a {
				case "纯Pedersen":
					phase = "承诺计算"
				case "Pedersen+MPC":
					phase = "承诺+分片"
				case "纯MPC":
					phase = "MPC承诺计算"
				}
				if v, ok2 := d[phase]; ok2 {
					fmt.Printf(" %16.2f", v)
				} else {
					fmt.Printf(" %16s", "N/A")
				}
			} else {
				fmt.Printf(" %16s", "N/A")
			}
		}
		fmt.Println()
	}

	// --- Merkle 构建对比 ---
	fmt.Println("\n■ Merkle 构建阶段对比 (ms)")
	fmt.Printf("%-10s", "属性数")
	for _, a := range approaches {
		fmt.Printf(" %16s", a)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))

	for _, n := range attrsList {
		fmt.Printf("%-10d", n)
		for _, a := range approaches {
			if d, ok := data[key{a, n}]; ok {
				phase := ""
				switch a {
				case "纯Pedersen", "Pedersen+MPC":
					phase = "Merkle构建"
				case "纯MPC":
					phase = "MPC Merkle构建"
				}
				if v, ok2 := d[phase]; ok2 {
					fmt.Printf(" %16.2f", v)
				} else {
					fmt.Printf(" %16s", "N/A")
				}
			} else {
				fmt.Printf(" %16s", "N/A")
			}
		}
		fmt.Println()
	}

	// --- 加速比 ---
	fmt.Println("\n■ 加速比 (纯MPC / 纯Pedersen)")
	fmt.Printf("%-10s %16s %16s\n", "属性数", "承诺计算", "Merkle构建")
	fmt.Println(strings.Repeat("-", 44))
	for _, n := range attrsList {
		pedData := data[key{"纯Pedersen", n}]
		mpcData := data[key{"纯MPC", n}]
		if pedData != nil && mpcData != nil {
			pedCommit := pedData["承诺计算"]
			mpcCommit := mpcData["MPC承诺计算"]
			pedMerkle := pedData["Merkle构建"]
			mpcMerkle := mpcData["MPC Merkle构建"]

			commitRatio := 1.0
			if pedCommit > 0 {
				commitRatio = mpcCommit / pedCommit
			}
			merkleRatio := 1.0
			if pedMerkle > 0 {
				merkleRatio = mpcMerkle / pedMerkle
			}
			fmt.Printf("%-10d %15.1fx %15.1fx\n", n, commitRatio, merkleRatio)
		}
	}

	fmt.Println("\n============================================================")
	fmt.Println("注:")
	fmt.Println("  - 纯Pedersen: 权威机构中心计算, 无通信开销")
	fmt.Println("  - Pedersen+MPC: MPC仅用于重随机化, Merkle仍为中心计算")
	fmt.Println("  - 纯MPC: 承诺和Merkle每一步均通过MPC协议计算")
	fmt.Printf("  - MPC参数: k=%d节点, 通信延迟=%.1fms/轮, 批处理=%d门/轮\n",
		mpcNodes, commDelayMs, mpcBatchSize)
	fmt.Printf("  - SHA-256 MPC: 叶子哈希~%d AND门, 内部哈希~%d AND门\n",
		andGatesLeaf, andGatesNode)
	fmt.Printf("  - Beaver三元组: %d次域乘法/AND门\n", mulsPerANDGate)
	fmt.Println("============================================================")
}

func writeCSV(path string, results []Result) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("创建CSV失败: %v", err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"方案", "属性数量", "阶段", "平均耗时(ms)", "最小耗时(ms)", "最大耗时(ms)", "迭代次数"})
	for _, r := range results {
		w.Write([]string{
			r.Approach,
			fmt.Sprintf("%d", r.NAttrs),
			r.Phase,
			fmt.Sprintf("%.4f", r.AvgMs),
			fmt.Sprintf("%.4f", r.MinMs),
			fmt.Sprintf("%.4f", r.MaxMs),
			fmt.Sprintf("%d", r.Iterations),
		})
	}
	fmt.Printf("\nCSV 已保存: %s\n", path)
}
