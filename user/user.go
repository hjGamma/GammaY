package main

import (
	"DID/utils"
	"encoding/json"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type AggregateMsg struct {
	PubKey    bls12381.G1Affine `json:"pub_key"`
	Signature bls12381.G2Affine `json:"signature"`
}

func main() {

	h := mimc.NewMiMC()
	//tree := merkletree.New(h)
	tree := merkletree.New(h)
	_ = tree.SetIndex(0)

	//data := [][]byte{
	//	[]byte("18"),
	//	[]byte("gamma"),
	//	[]byte("hello"),
	//	[]byte("world"),
	//}
	data := [][]byte{
		[]byte("18"),
		[]byte("gamma"),
		[]byte("hello"),
		[]byte("world"),
	}

	for _, d := range data {
		tree.Push(d)
	}

	root, proofSet, proofIndex, numLeaves := tree.Prove()
	log.Printf("[重构merkle]merkle root: %x\n", root)

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
	utils.GenerateZKProof(aggMsg.PubKey, aggMsg.Signature, data[0], proofSet, proofIndex, numLeaves, root)

}

//func main() {
//	h := mimc.NewMiMC()
//	tree := utils.New1(h)
//
//	_ = tree.SetIndex(2)
//
//	data := [][]byte{
//		[]byte("18"),
//		[]byte("gamma"),
//		[]byte("hello"),
//		[]byte("world"),
//	}
//
//	for _, d := range data {
//		tree.Push1(d)
//	}
//
//	root, proofSet, proofIndex, _ := tree.Prove1()
//	fmt.Printf("Merkle Root: %x\n", root)
//	fmt.Printf("Proof Set: \n")
//	for i, p := range proofSet {
//		fmt.Printf("  [%d]: %x\n", i, p)
//	}
//	fmt.Printf("Proof Index: %d\n", proofIndex)
//	//读取聚合签名与公钥
//	filePath := "aggregate_msg.json"
//	jsonData, err := os.ReadFile(filePath)
//	if err != nil {
//		log.Fatalf("[User] 无法读取聚合消息文件: %v", err)
//	}
//	var aggMsg AggregateMsg
//	err = json.Unmarshal(jsonData, &aggMsg)
//	if err != nil {
//		log.Fatalf("[User] 无法解析聚合消息文件: %v", err)
//	}
//	//生成zkproof
//	utils.GenerateZKProof(aggMsg.PubKey, aggMsg.Signature, data[2], proofSet, proofIndex, root)
//
//}
