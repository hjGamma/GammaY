package utils

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func TestMimc(t *testing.T) {
	// 初始化哈希函数（可换成 SHA-512、BLAKE2 等）
	h := mimc.NewMiMC()

	// 创建一棵 Merkle Tree
	tree := New1(h)

	// 插入数据（叶子）
	data := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("18"),
		[]byte("gamma"),
	}
	for _, d := range data {
		tree.Push1(d)
	}

	// 获取 Merkle Root
	root := tree.Root1()
	fmt.Printf("Merkle Root: %x\n", root)
}
