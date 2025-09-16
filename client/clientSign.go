package main

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"math/big"
)

// 多方BLS签名生成与聚合
type Signer struct {
	PrivateKey fr.Element        // 私钥
	PublicKey  bls12381.G1Affine // 公钥
}

// // 生成N个签名者
// func SignersTEST()(bool, error){
// 	// Step 1: 获取 G1/G2 生成元
// 	_, _, g1Gen, _ := bls12381.Generators()

// 	// Step 2: 生成私钥（随机 fr 元素），并转为 *big.Int
// 	var sk fr.Element
// 	sk.SetRandom()
// 	skBytes := sk.Bytes()                     // [32]byte
// 	skBig := new(big.Int).SetBytes(skBytes[:]) // 使用切片转换

// 	// Step 3: 公钥 = sk * G1
// 	var pk bls12381.G1Affine
// 	pk.ScalarMultiplication(&g1Gen, skBig)
// 	log.Printf("public Key: %s", pk.String())
// 	// Step 4: 签名（消息 hash 到 G2 点，然后乘以 sk）
// 	msg := []byte("hello gnark-bls-signature")
// 	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
// 	hashToG2, err := bls12381.HashToG2(msg, dst)
// 	if err != nil {
// 		panic(err)
// 	}

// 	var sig bls12381.G2Affine
// 	sig.ScalarMultiplication(&hashToG2, skBig)

// 	// Step 5: pairing 验证
// 	// 检查：e(PK, H(msg)) == e(G1, sig)
// 	var negG1 bls12381.G1Affine
//     negG1.Neg(&g1Gen)

// 	P:=[]bls12381.G1Affine{pk,negG1}
// 	Q:=[]bls12381.G2Affine{hashToG2,sig}

// 	ok,err:= bls12381.PairingCheck(P, Q)
// 	if err != nil {
// 		panic(err)

// 	}
// 	return ok,nil

// }

// 生成每个签名者的私钥和公钥
func GenerateSigners(n int) []Signer {
	signers := make([]Signer, n)
	for i := range signers {
		_, _, g1Gen, _ := bls12381.Generators()

		//生成私钥（随机 fr 元素）
		var privateKey fr.Element
		privateKey.SetRandom()
		skBytes := privateKey.Bytes()              // [32]byte
		skBig := new(big.Int).SetBytes(skBytes[:]) // 使用切片转换

		// 计算公钥 (pk = sk * g2)
		var publicKey bls12381.G1Affine
		publicKey.ScalarMultiplication(&g1Gen, skBig)

		signers[i] = Signer{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
	}
	return signers
}

func GenerateKeyPair() (fr.Element, bls12381.G1Affine) {
	_, _, g1Gen, _ := bls12381.Generators()
	//生成私钥（随机 fr 元素）
	var privateKey fr.Element
	privateKey.SetRandom()
	skBytes := privateKey.Bytes()              // [32]byte
	skBig := new(big.Int).SetBytes(skBytes[:]) // 使用切片转换

	// 计算公钥 (pk = sk * g2)
	var publicKey bls12381.G1Affine
	publicKey.ScalarMultiplication(&g1Gen, skBig)
	return privateKey, publicKey
}

// 每个签名者生成对消息的签名
func SignMessage(signer Signer, message []byte) bls12381.G2Affine {
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	hashToG2, err := bls12381.HashToG2(message, dst)
	if err != nil {
		panic(err)
	}
	var signature bls12381.G2Affine
	// 签名: σ_i = sk_i * H(m)
	skBytes := signer.PrivateKey.Bytes()
	signature.ScalarMultiplication(&hashToG2, new(big.Int).SetBytes(skBytes[:]))
	return signature
}
