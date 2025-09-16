package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"log"

	"fmt"
	"github.com/consensys/gnark/std/hash/mimc"
)

// VerifyAggregateSignatureWithPairingCheck 使用 bls12381.PairingCheck 验证聚合签名
func VerifyAggregateSignature(aggPubKey bls12381.G1Affine, aggSignature bls12381.G2Affine, message []byte) bool {
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	hashToG2, err := bls12381.HashToG2(message, dst)
	if err != nil {
		return false
	}

	// 获取生成元
	_, _, g1Gen, _ := bls12381.Generators()

	// 构造 P 和 Q 切片
	var P []bls12381.G1Affine
	var Q []bls12381.G2Affine

	// 项1: e(aggSignature, G1) → (G1, aggSignature)
	P = append(P, g1Gen)
	Q = append(Q, aggSignature)

	// 项2: e(-aggPubKey, H(m)) → (-aggPubKey, H(m))
	var negPubKey bls12381.G1Affine
	negPubKey.Neg(&aggPubKey)

	P = append(P, negPubKey)
	Q = append(Q, hashToG2)

	// 执行配对检查
	ok, err := bls12381.PairingCheck(P, Q)
	if err != nil {
		return false
	}
	return ok
}

// 零知识证明电路
// []byte -> frontend.Variable
func BytesToVariable(data []byte) frontend.Variable {
	bi := new(big.Int).SetBytes(data)
	return bi
}

// [][]byte -> []frontend.Variable
func BytesArrayToVariables(arr [][]byte) []frontend.Variable {
	vars := make([]frontend.Variable, len(arr))
	for i := range arr {
		bi := new(big.Int).SetBytes(arr[i])
		vars[i] = bi
	}
	return vars
}

// uint64 index -> []frontend.Variable (binary bits)
func IndexToHelper(index uint64, depth int) []frontend.Variable {
	helper := make([]frontend.Variable, depth)
	for i := 0; i < depth; i++ {
		// 取 index 的第 i 位
		helper[i] = (index >> i) & 1
	}
	return helper
}

// BLS聚合验证电路
type ValidCircuit struct {
	Valid      frontend.Variable `gnark:",public"`
	MerkleRoot frontend.Variable `gnark:",public"`

	Message frontend.Variable   // 被签名的消息
	Leaf    frontend.Variable   // Merkle 叶子
	Path    []frontend.Variable // Merkle 路径
	Helper  []frontend.Variable // 方向位 (0=左, 1=右)
}

func (c *ValidCircuit) Define(api frontend.API) error {
	// 断言 Valid == 1
	api.AssertIsEqual(c.Valid, 1)
	curr := c.Leaf
	for i := 0; i < len(c.Path); i++ {
		hNode, _ := mimc.NewMiMC(api)

		left := api.Select(c.Helper[i], c.Path[i], curr)
		right := api.Select(c.Helper[i], curr, c.Path[i])

		hNode.Write(left, right)
		curr = hNode.Sum()
	}
	api.AssertIsEqual(curr, c.MerkleRoot)
	return nil
}

// =============================
// 第三部分：证明生成与验证
// =============================

func GenerateZKProof(aggPK bls12381.G1Affine, aggSig bls12381.G2Affine, attr []byte, proofSet [][]byte, proofIndex uint64, proofRoot []byte) {
	ok := VerifyAggregateSignature(aggPK, aggSig, proofRoot)
	if !ok {
		log.Fatal("Chain-side pairing verification failed — abort")
	}
	fmt.Println("Chain-side BLS aggregation verification OK")
	var circuit ValidCircuit

	ccs, err := frontend.Compile(bls12381.ID.ScalarField(), r1cs.NewBuilder, &circuit) // 注意：fr.Modulus() 仅为示例（你可替换为你本地 gnark 要求的 scalar field）
	if err != nil {
		log.Fatalf("frontend.Compile error: %v", err)
	}
	// circuit=&ValidCircuit{
	// 	Valid: ok,
	// 	MerkleRoot: BytesToVariable(proofRoot),

	// 	Message: BytesToVariable(msg),
	// 	Leaf: BytesToVariable(proofSet[proofIndex]),
	// 	Path: BytesArrayToVariables(proofSet[:proofIndex]),
	// 	Helper: IndexToHelper(uint64(proofIndex), len(proofSet)),

	// }
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("groth16.Setup error: %v", err)
	}

	// 生成 witness：Public Valid = 1
	assignment := ValidCircuit{Valid: ok,
		MerkleRoot: BytesToVariable(proofRoot),

		Message: BytesToVariable(attr),
		Leaf:    BytesToVariable(proofSet[proofIndex]),
		Path:    BytesArrayToVariables(proofSet[:proofIndex]),
		Helper:  IndexToHelper(uint64(proofIndex), len(proofSet)),
	}

	witness, err := frontend.NewWitness(&assignment, bls12381.ID.ScalarField())
	if err != nil {
		log.Fatalf("NewWitness error: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("groth16.Prove error: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("witness.Public error: %v", err)
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatalf("groth16.Verify failed: %v", err)
	}

}
