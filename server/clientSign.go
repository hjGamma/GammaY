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

// 每个签名者生成对消息的签名
func SignMessage(signers []Signer, message []byte) []bls12381.G2Affine {
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	hashToG2, err := bls12381.HashToG2(message, dst)
	if err != nil {
		panic(err)
	}
	signatures := make([]bls12381.G2Affine, len(signers))
	for i, signer := range signers {
		// 签名: σ_i = sk_i * H(m)
		skBytes := signer.PrivateKey.Bytes()
		signatures[i].ScalarMultiplication(&hashToG2, new(big.Int).SetBytes(skBytes[:]))
	}
	return signatures
}

// // 聚合公钥和签名
func Aggregate(pks []bls12381.G1Affine, signatures []bls12381.G2Affine) (bls12381.G1Affine, bls12381.G2Affine) {
	// 聚合公钥 (apk = Σ pk_i)
	var aggPublicKey bls12381.G1Jac
	for _, signer := range pks {
		var pkJac bls12381.G1Jac
		pkJac.FromAffine(&signer)
		aggPublicKey.AddAssign(&pkJac)
	}

	// 聚合签名 (asig = Σ σ_i)
	var aggSignature bls12381.G2Jac
	for _, sig := range signatures {
		var sigJac bls12381.G2Jac
		sigJac.FromAffine(&sig)
		aggSignature.AddAssign(&sigJac)
	}

	// 转回仿射坐标
	var aggPKAff bls12381.G1Affine
	aggPKAff.FromJacobian(&aggPublicKey)

	var aggSigAff bls12381.G2Affine
	aggSigAff.FromJacobian(&aggSignature)

	return aggPKAff, aggSigAff
}

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
