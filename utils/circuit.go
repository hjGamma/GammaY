package utils

import (
	"encoding/json"
	"math/big"
	"os"
	"time"

	"log"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"

	cryptoHash "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
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

func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// BLS聚合验证电路
//
//	type ValidCircuit struct {
//		Valid      frontend.Variable `gnark:",public"`
//		MerkleRoot frontend.Variable `gnark:",public"`
//
//		//Message frontend.Variable   // 被签名的消息
//		Leaf      frontend.Variable   // Merkle 叶子
//		ProofPath []frontend.Variable // Merkle 路径
//		//Helper    []frontend.Variable // 方向位 (0=左, 1=右)
//
// }
type MerkleProofTest struct {
	M     merkle.MerkleProof
	Valid frontend.Variable `gnark:",public"`
	Leaf  frontend.Variable
}

//type MerkleTreeCircuit struct {
//	Valid    frontend.Variable `gnark:",public"`
//	RootHash frontend.Variable `gnark:",public"`
//
//	Leaf frontend.Variable
//
//	ProofPath []frontend.Variable
//}

func (mp *MerkleProofTest) Define(api frontend.API) error {

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mp.M.VerifyProof(api, &h, mp.Leaf)

	return nil
}

// Define 函数定义了电路的约束。
//
//	func (circuit *MerkleTreeCircuit) Define(api frontend.API) error {
//		api.AssertIsEqual(circuit.Valid, 1)
//		hasher, err := mimc.NewMiMC(api)
//		if err != nil {
//			return err
//		}
//
//		proof := merkle.MerkleProof{
//			RootHash: circuit.RootHash,
//			Path:     circuit.ProofPath,
//		}
//
//		proof.VerifyProof(api, &hasher, circuit.Leaf)
//		return nil
//	}
//func leafSumMerkle(api frontend.API, h hash.FieldHasher, data frontend.Variable) frontend.Variable {
//
//	h.Reset()
//	h.Write(data)
//	res := h.Sum()
//
//	return res
//}
//
//func nodeSumMerkle(api frontend.API, h hash.FieldHasher, a, b frontend.Variable) frontend.Variable {
//
//	h.Reset()
//	h.Write(a, b)
//	res := h.Sum()
//
//	return res
//}
//
//func (c *ValidCircuit) Define(api frontend.API) error {
//
//	api.AssertIsEqual(c.Valid, 1)
//
//	hNode, _ := mimc.NewMiMC(api)
//	//curr := leafSum2(api, &hNode, c.Leaf)
//	depth := len(c.ProofPath) - 1
//	sum := leafSumMerkle(api, &hNode, c.ProofPath[0])
//	//computed := c.Leaf
//	binLeaf := api.ToBinary(c.Leaf, depth)
//	for i := 1; i < len(c.ProofPath); i++ {
//
//		//left := api.Select(c.Helper[i], c.ProofPath[i], computed)
//		//right := api.Select(c.Helper[i], computed, c.ProofPath[i])
//		//hNode.Reset()
//		//hNode.Write(left, right)
//		//computed = hNode.Sum()
//		//api.Println("Layer", i, "left=", left, "right=", right, "curr=", computed)
//		d1 := api.Select(binLeaf[i-1], c.ProofPath[i], sum)
//		d2 := api.Select(binLeaf[i-1], sum, c.ProofPath[i])
//		sum = nodeSumMerkle(api, &hNode, d1, d2)
//		api.Println("Layer", i, "left=", d1, "right=", d2, "curr=", sum)
//
//	}
//	api.AssertIsEqual(sum, c.MerkleRoot)
//	return nil
//}

// =============================
// 第三部分：证明生成与验证
// =============================

func GenerateZKProof(aggPK bls12381.G1Affine, aggSig bls12381.G2Affine, attr []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64, proofRoot []byte) {
	timeSetup := time.Now()
	ok := VerifyAggregateSignature(aggPK, aggSig, proofRoot)
	if !ok {
		log.Fatal("Chain-side pairing verification failed — abort")
	}
	log.Println("Chain-side BLS aggregation verification OK")
	var validVariable uint64
	if ok {
		validVariable = 1
	} else {
		validVariable = 0
	}
	h := cryptoHash.NewMiMC()
	ok = merkletree.VerifyProof(h, proofRoot, proofSet, proofIndex, numLeaves)
	if !ok {
		log.Fatal("The verification of merkle tree failed")
	}

	log.Println("The verification of merkle tree pass")
	log.Println("[Time]The cost of setup time is ", time.Since(timeSetup))
	//circuit := MerkleTreeCircuit{
	//	Valid:     frontend.Variable(0),
	//	RootHash:  frontend.Variable(0),
	//	Leaf:      frontend.Variable(0),
	//	ProofPath: make([]frontend.Variable, len(proofSet)),
	//}
	//circuit := ValidCircuit{
	//	Valid:      frontend.Variable(0),
	//	MerkleRoot: frontend.Variable(0),
	//	Leaf:       frontend.Variable(0),
	//	ProofPath:  make([]frontend.Variable, len(proofSet)),
	//	//Helper:     make([]frontend.Variable, len(proofSet)),
	//}
	var circuit MerkleProofTest
	circuit.Leaf = proofIndex
	circuit.Valid = ok
	circuit.M.RootHash = proofRoot
	circuit.M.Path = make([]frontend.Variable, len(proofSet))
	for i, node := range proofSet {
		circuit.M.Path[i] = new(big.Int).SetBytes(node)
	}

	//ccs, err := frontend.Compile(bls12381.ID.ScalarField(), r1cs.NewBuilder, &circuit)
	timeCompile := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("frontend.Compile error: %v", err)
	}
	log.Println("[Time]The cost of compile time is ", time.Since(timeCompile))

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

	//assignment := ValidCircuit{
	//	Valid:      validVariable,
	//	MerkleRoot: BytesToVariable(proofRoot),
	//
	//	Leaf:      proofIndex,
	//	ProofPath: BytesArrayToVariables(proofSet),
	//	//Helper:    IndexToHelper(proofIndex, len(proofSet)),
	//}
	//assignment := MerkleTreeCircuit{
	//	Valid:    validVariable,
	//	RootHash: frontend.Variable(proofRoot),
	//
	//	Leaf:      frontend.Variable(attr),
	//	ProofPath: make([]frontend.Variable, len(proofSet)),
	//}
	assignment := MerkleProofTest{
		Leaf:  proofIndex,
		Valid: validVariable,
		M: merkle.MerkleProof{
			RootHash: BytesToBigInt(proofRoot),
			Path:     make([]frontend.Variable, len(proofSet)),
		},
	}
	for i, p := range proofSet {
		assignment.M.Path[i] = BytesToBigInt(p)
	}
	timeProve := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("NewWitness error: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("groth16.Prove error: %v", err)
	}
	log.Println("[Time]The cost of prove time is ", time.Since(timeProve))
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("witness.Public error: %v", err)
	}
	timeVerify := time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatalf("groth16.Verify failed: %v", err)
	}
	log.Println("[Time]The cost of verify time is ", time.Since(timeVerify))
	proofFile := "proof.json"
	publicFile := "public.json"
	proofData, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		log.Fatalf("marshal proof error: %v", err)
	}
	publicData, err := json.MarshalIndent(publicWitness, "", "  ")
	if err != nil {
		log.Fatalf("marshal public witness error: %v", err)
	}

	// 保存到文件
	if err := os.WriteFile(proofFile, proofData, 0644); err != nil {
		log.Fatalf("write proof.json error: %v", err)
	}
	if err := os.WriteFile(publicFile, publicData, 0644); err != nil {
		log.Fatalf("write public.json error: %v", err)
	}
	log.Printf(" Proof and public inputs exported: %s, %s", proofFile, publicFile)

}
