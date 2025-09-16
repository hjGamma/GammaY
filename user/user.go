package main

import (
	"DID/utils"
	"encoding/json"
	"fmt"
	"log"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type AggregateMsg struct {
	PubKey    bls12381.G1Affine `json:"pub_key"`
	Signature bls12381.G2Affine `json:"signature"`
}

func main() {
	h := mimc.NewMiMC()
	tree := utils.New1(h)

	_ = tree.SetIndex(2) // 现在设置你想生成 proof 的叶子索引

	data := [][]byte{
		[]byte("18"),
		[]byte("gamma"),
		[]byte("hello"),
		[]byte("world"),
	}

	for _, d := range data {
		tree.Push1(d)
	}

	root, proofSet, proofIndex, _ := tree.Prove1()
	fmt.Printf("Merkle Root: %x\n", root)
	fmt.Printf("Proof Set: \n")
	for i, p := range proofSet {
		fmt.Printf("  [%d]: %x\n", i, p)
	}
	fmt.Printf("Proof Index: %d\n", proofIndex)
	//读取聚合签名与公钥
	filePath := "aggregate_msg.json"
	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("[User] 无法读取聚合消息文件: %v", err)
	}
	var aggMsg AggregateMsg
	err = json.Unmarshal(jsonData, &aggMsg)
	if err != nil {
		log.Fatalf("[User] 无法解析聚合消息文件: %v", err)
	}
	//生成zkproof
	utils.GenerateZKProof(aggMsg.PubKey, aggMsg.Signature, data[2], proofSet, proofIndex, root)

}
