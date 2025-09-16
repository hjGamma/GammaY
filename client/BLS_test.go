package main

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// 简单生成随机消息用于测试
func randomMessage() []byte {
	msg := make([]byte, 32)
	rand.Read(msg)
	return msg
}

// VerifyAggregateSignatureWithPairingCheck 使用 bls12381.PairingCheck 验证聚合签名
func VerifyAggregateSignatureWithPairingCheck(aggPubKey bls12381.G1Affine, aggSignature bls12381.G2Affine, message []byte) bool {
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

func TestBLSAggregateSignature(t *testing.T) {
	const numSigners = 3
	message := randomMessage()

	// Step 1: 生成签名者
	signers := GenerateSigners(numSigners)
	if len(signers) != numSigners {
		t.Fatalf("expected %d signers, got %d", numSigners, len(signers))
	}

	// Step 2: 每个签名者签名
	signatures := SignMessage(signers, message)
	if len(signatures) != numSigners {
		t.Fatalf("expected %d signatures, got %d", numSigners, len(signatures))
	}

	// Step 3: 聚合公钥和签名
	aggPubKey, aggSignature := Aggregate(signers, signatures)

	// Step 4: 使用 PairingCheck 验证聚合签名
	isValid := VerifyAggregateSignatureWithPairingCheck(aggPubKey, aggSignature, message)
	if !isValid {
		t.Error("aggregate signature verification failed using PairingCheck")
	} else {
		t.Log("✅ Aggregate signature verified successfully with PairingCheck!")
	}

	// 可选：测试错误消息是否被拒绝
	wrongMessage := []byte("different message")
	isValidWrong := VerifyAggregateSignatureWithPairingCheck(aggPubKey, aggSignature, wrongMessage)
	if isValidWrong {
		t.Error("aggregate signature should NOT verify with a different message")
	} else {
		t.Log("✅ Correctly rejected signature for modified message.")
	}
}
