package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PedersenCommitment 表示一个 Pedersen 承诺 C = m*G + r*H
// 其中 G, H 是 G1 群的两个独立生成元
// m 是属性 (标量), r 是随机盲化因子
type PedersenCommitment struct {
	G bls12381.G1Affine // 生成元 G
	H bls12381.G1Affine // 生成元 H (与 G 独立)
	C bls12381.G1Affine // 承诺值 C = m*G + r*H
}

// CommitmentParams 保存 Pedersen 承诺的公共参数
type CommitmentParams struct {
	G bls12381.G1Affine // 生成元 G
	H bls12381.G1Affine // 生成元 H
}

// SetupPedersen 初始化 Pedersen 承诺参数
// G 使用 BLS12-381 的标准生成元, H 通过哈希到 G1 生成 (与 G 独立)
func SetupPedersen() *CommitmentParams {
	_, _, g1Gen, _ := bls12381.Generators()
	// 通过 HashToG1 生成独立的 H, 保证 G 和 H 的离散对数关系未知
	hBytes := sha256.Sum256([]byte("DID-Pedersen-H-Generator"))
	hG1, err := bls12381.HashToG1(hBytes[:], []byte("DID-H"))
	if err != nil {
		panic("HashToG1 failed for H generation: " + err.Error())
	}
	return &CommitmentParams{
		G: g1Gen,
		H: hG1,
	}
}

// Commit 计算 Pedersen 承诺: C = m*G + r*H
// m: 属性值 (fr.Element 标量)
// r: 随机盲化因子 (fr.Element 标量)
func (p *CommitmentParams) Commit(m, r fr.Element) PedersenCommitment {
	var mBI, rBI big.Int
	m.BigInt(&mBI)
	r.BigInt(&rBI)

	var mG, rH, c bls12381.G1Affine
	mG.ScalarMultiplication(&p.G, &mBI)
	rH.ScalarMultiplication(&p.H, &rBI)
	c.Add(&mG, &rH)

	return PedersenCommitment{
		G: p.G,
		H: p.H,
		C: c,
	}
}

// CommitBytes 从字节数组属性计算承诺
// attr: 属性的字节表示
func (p *CommitmentParams) CommitBytes(attr []byte) (PedersenCommitment, fr.Element, fr.Element) {
	// 将属性映射到标量
	var m fr.Element
	m.SetBytes(attr)

	// 生成随机盲化因子 r
	var r fr.Element
	r.SetRandom()

	commitment := p.Commit(m, r)
	return commitment, m, r
}

// ReRandomize 对承诺进行重随机化
// 给定 C = m*G + r*H, 添加 r'*H 得到 C' = m*G + (r+r')*H
// C' 仍然是对同一属性 m 的承诺, 但盲化因子不同
func (p *CommitmentParams) ReRandomize(c bls12381.G1Affine, rPrime fr.Element) bls12381.G1Affine {
	var rBI big.Int
	rPrime.BigInt(&rBI)

	var rPrimeH, newC bls12381.G1Affine
	rPrimeH.ScalarMultiplication(&p.H, &rBI)
	newC.Add(&c, &rPrimeH)
	return newC
}

// VerifyCommitment 验证承诺: 检查 C == m*G + r*H
func (p *CommitmentParams) VerifyCommitment(c bls12381.G1Affine, m, r fr.Element) bool {
	expected := p.Commit(m, r)
	return c.Equal(&expected.C)
}

// MarshalCommitment 将承诺序列化为字节 (用于 Merkle 树叶子)
func MarshalCommitment(c bls12381.G1Affine) []byte {
	return c.Marshal()
}

// UnmarshalCommitment 从字节反序列化承诺
func UnmarshalCommitment(data []byte) (bls12381.G1Affine, error) {
	var c bls12381.G1Affine
	err := c.Unmarshal(data)
	if err != nil {
		return c, fmt.Errorf("failed to unmarshal commitment: %v", err)
	}
	return c, nil
}

// RandomScalar 生成随机标量
func RandomScalar() fr.Element {
	var s fr.Element
	s.SetRandom()
	return s
}

// ScalarToBytes 将标量转为字节
func ScalarToBytes(s fr.Element) []byte {
	b := s.Bytes()
	return b[:]
}

// BytesToScalar 将字节转为标量
func BytesToScalar(b []byte) fr.Element {
	var s fr.Element
	s.SetBytes(b)
	return s
}

// GenerateRandomBytes 生成指定长度的随机字节
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
