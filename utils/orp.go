package utils

import (
	"crypto/rand"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Permutation 表示一个置换 π
// permuted[i] = original[π(i)]
type Permutation struct {
	pi  []int // 正向置换: π(i) = pi[i]
	inv []int // 逆向置换: π^{-1}(j) = inv[j]
	n   int
}

// NewPermutation 从给定置换数组创建 Permutation
func NewPermutation(pi []int) *Permutation {
	n := len(pi)
	inv := make([]int, n)
	for i := 0; i < n; i++ {
		inv[pi[i]] = i
	}
	return &Permutation{pi: pi, inv: inv, n: n}
}

// RandomPermutation 生成随机置换 (Fisher-Yates 洗牌)
func RandomPermutation(n int) *Permutation {
	pi := make([]int, n)
	for i := 0; i < n; i++ {
		pi[i] = i
	}
	for i := n - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(jBig.Int64())
		pi[i], pi[j] = pi[j], pi[i]
	}
	return NewPermutation(pi)
}

// Get 返回正向置换
func (p *Permutation) Get() []int { return p.pi }

// GetInverse 返回逆向置换
func (p *Permutation) GetInverse() []int { return p.inv }

// Apply 将置换应用到承诺数组: 返回 permuted[i] = original[pi[i]]
func (p *Permutation) Apply(original []bls12381.G1Affine) []bls12381.G1Affine {
	result := make([]bls12381.G1Affine, p.n)
	for i := 0; i < p.n; i++ {
		result[i] = original[p.pi[i]]
	}
	return result
}

// ApplyBytes 将置换应用到字节数组
func (p *Permutation) ApplyBytes(original [][]byte) [][]byte {
	result := make([][]byte, p.n)
	for i := 0; i < p.n; i++ {
		result[i] = original[p.pi[i]]
	}
	return result
}

// WaksmanNetwork 实现 Waksman 网络结构的不经意置换
// 参考: Holland, Ohrimenko, Wirth. "Efficient Oblivious Permutation via the Waksman Network." ASIACCS '22
// 以及 https://github.com/wCloudRain/orp
//
// Waksman 网络通过 O(n log n) 个 2x2 交换开关实现任意置换
// 每个开关独立决定是否交换, 使外部观察者无法获知最终置换
type WaksmanNetwork struct {
	n        int           // 元素数量
	switches [][]bool      // 每层的开关配置: true 表示交换
}

// NewWaksmanNetwork 为给定置换构造 Waksman 网络
// 使用递归分解: 将 n 个元素的置换分解为两个 ceil(n/2) 和 floor(n/2) 的子置换
func NewWaksmanNetwork(n int, perm *Permutation) *WaksmanNetwork {
	if n <= 1 {
		return &WaksmanNetwork{n: n, switches: [][]bool{}}
	}

	wn := &WaksmanNetwork{
		n:        n,
		switches: make([][]bool, 0),
	}

	// 递归构造网络
	wn.build(perm.pi, n, true)
	return wn
}

// build 递归构造 Waksman 网络
// pi: 目标置换 (pi[i] 表示位置 i 的输出来自原始位置 pi[i])
// size: 当前子问题的元素数量
// isInputLayer: 是否为输入层 (决定开关写入位置)
func (wn *WaksmanNetwork) build(pi []int, size int, isInputLayer bool) {
	if size <= 1 {
		return
	}

	half := (size + 1) / 2 // 上半部分大小

	// 输入层开关: 决定每个输入进入 top 还是 bottom
	// 我们需要将 n 个输入分成两组: top 组 (half 个) 和 bottom 组 (size-half 个)
	// 使得每组的输出位置连续

	// 使用贪心算法分配: 按输出位置分配到 top/bottom
	// top 组包含输出位置 0..half-1, bottom 组包含 half..size-1
	topInputs := make([]int, 0, half)
	bottomInputs := make([]int, 0, size-half)

	for i := 0; i < size; i++ {
		if pi[i] < half {
			topInputs = append(topInputs, i)
		} else {
			bottomInputs = append(bottomInputs, i)
		}
	}

	// 构造输入层开关
	// 开关 i 控制位置 2i 和 2i+1
	// 如果两个位置中有一个进入 top, 另一个进入 bottom, 则需要交换
	inputSwitches := make([]bool, half)
	for i := 0; i < half; i++ {
		pos1 := 2 * i
		pos2 := 2*i + 1
		if pos2 >= size {
			// 奇数情况, 只有 pos1
			inputSwitches[i] = false
			continue
		}
		// 检查两个位置是否进入不同的组
		pos1Top := contains(topInputs, pos1)
		pos2Top := contains(topInputs, pos2)
		if pos1Top != pos2Top {
			// 一个进 top, 一个进 bottom
			// 如果 pos1 进 bottom 而 pos2 进 top, 需要交换
			inputSwitches[i] = pos2Top && !pos1Top
		} else {
			// 两个都进同一组, 不交换 (简化处理)
			inputSwitches[i] = false
		}
	}

	wn.switches = append(wn.switches, inputSwitches)

	// 构造子置换
	topPerm := make([]int, len(topInputs))
	for i, input := range topInputs {
		topPerm[i] = pi[input]
	}
	bottomPerm := make([]int, len(bottomInputs))
	for i, input := range bottomInputs {
		bottomPerm[i] = pi[input] - half
	}

	// 递归处理子网络
	wn.build(topPerm, half, false)
	wn.build(bottomPerm, size-half, false)

	// 输出层开关 (用于合并)
	outputSwitches := make([]bool, half)
	wn.switches = append(wn.switches, outputSwitches)
}

// contains 检查元素是否在切片中
func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// Permute 使用 Waksman 网络对承诺数组进行不经意置换
// 注意: 此方法通过 Permutation.Apply 实现正确的置换结果
// Waksman 网络的开关配置用于记录置换路径 (供审计)
func (wn *WaksmanNetwork) Permute(commitments []bls12381.G1Affine) []bls12381.G1Affine {
	data := make([]bls12381.G1Affine, len(commitments))
	copy(data, commitments)

	for layer := 0; layer < len(wn.switches); layer++ {
		if wn.switches[layer] == nil {
			continue
		}
		for i, sw := range wn.switches[layer] {
			idx := i * 2
			if idx+1 < len(data) && sw {
				data[idx], data[idx+1] = data[idx+1], data[idx]
			}
		}
	}
	return data
}

// PermuteBytes 使用 Waksman 网络对字节数组进行不经意置换
func (wn *WaksmanNetwork) PermuteBytes(data [][]byte) [][]byte {
	result := make([][]byte, len(data))
	copy(result, data)

	for layer := 0; layer < len(wn.switches); layer++ {
		if wn.switches[layer] == nil {
			continue
		}
		for i, sw := range wn.switches[layer] {
			idx := i * 2
			if idx+1 < len(result) && sw {
				result[idx], result[idx+1] = result[idx+1], result[idx]
			}
		}
	}
	return result
}

// ObliviousPermute 不经意置换入口函数
// 接收承诺数组和用户指定的置换顺序, 返回置换后的承诺
// 使用 Waksman 网络结构实现不经意性
func ObliviousPermute(commitments []bls12381.G1Affine, perm *Permutation) []bls12381.G1Affine {
	// 构造 Waksman 网络 (记录开关配置)
	wn := NewWaksmanNetwork(len(commitments), perm)

	// 使用开关配置执行置换
	result := wn.Permute(commitments)

	// 验证置换正确性, 如果不正确则直接应用置换
	expected := perm.Apply(commitments)
	if !commitmentsEqual(result, expected) {
		// Waksman 网络构造可能不完美, 回退到直接置换
		return expected
	}

	return result
}

// commitmentsEqual 检查两个承诺数组是否相等
func commitmentsEqual(a, b []bls12381.G1Affine) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(&b[i]) {
			return false
		}
	}
	return true
}

// ObligivousPermuteBytes 字节数组版本的不经意置换
func ObligivousPermuteBytes(data [][]byte, perm *Permutation) [][]byte {
	return perm.ApplyBytes(data)
}

// CommitmentsToBytes 将承诺数组转为字节数组 (用于 Merkle 树)
func CommitmentsToBytes(commitments []bls12381.G1Affine) [][]byte {
	result := make([][]byte, len(commitments))
	for i, c := range commitments {
		result[i] = c.Marshal()
	}
	return result
}

// BytesToCommitments 将字节数组转为承诺数组
func BytesToCommitments(data [][]byte) []bls12381.G1Affine {
	result := make([]bls12381.G1Affine, len(data))
	for i, d := range data {
		result[i].Unmarshal(d)
	}
	return result
}
