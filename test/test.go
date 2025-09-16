package main

import (
	"DID/utils"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func main() {
	// 初始化哈希函数（可换成 SHA-512、BLAKE2 等）
	h := mimc.NewMiMC()

	// 创建一棵 Merkle Tree
	tree := utils.New(h)

	// 插入数据（叶子）
	data := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("18"),
		[]byte("gamma"),
	}
	for _, d := range data {
		tree.Push(d)
	}

	// 获取 Merkle Root
	root := tree.Root()
	fmt.Printf("Merkle Root: %x\n", root)
}
