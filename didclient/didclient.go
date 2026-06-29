package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// DIDClient 客户端
// 1. 接收服务器发送的生成元 g
// 2. 基于 g 计算新的参数
// 3. 将新参数分片后发送到 MPC 节点 (通过 DIDServer)
// 4. 提交属性置换顺序 (用于 ORP)
// 5. 获取 Merkle Root
type DIDClient struct {
	params     *utils.CommitmentParams
	generators []bls12381.G1Affine // 收到的各服务器生成元 G
}

// NewDIDClient 创建客户端
func NewDIDClient() *DIDClient {
	return &DIDClient{
		params: utils.SetupPedersen(),
	}
}

// ReceiveGenerator 接收服务器发送的生成元 g
func (c *DIDClient) ReceiveGenerator(gBytes []byte) error {
	var g bls12381.G1Affine
	if err := g.Unmarshal(gBytes); err != nil {
		return fmt.Errorf("解析生成元失败: %v", err)
	}
	c.generators = append(c.generators, g)
	log.Printf("[DIDClient] 接收到生成元 G: %s...", hex.EncodeToString(gBytes[:16]))
	return nil
}

// ComputeNewParams 基于 g 计算新的参数
// 客户端将 g 的哈希映射到标量, 作为新的盲化贡献
// 然后将该参数分成 n 份
func (c *DIDClient) ComputeNewParams(nShards int) ([][]byte, error) {
	if len(c.generators) == 0 {
		return nil, fmt.Errorf("尚未接收到任何生成元")
	}

	// 使用第一个生成元计算新参数 (实际可聚合所有生成元)
	g := c.generators[0]
	gBytes := g.Marshal()

	// 将 g 映射到标量作为客户端贡献参数
	var clientParam fr.Element
	clientParam.SetBytes(gBytes)

	// 添加额外随机性增强安全性
	extraRand := utils.RandomScalar()
	clientParam.Add(&clientParam, &extraRand)

	// 将参数分成 n 份
	shards := utils.ShardSecret(clientParam, nShards)

	// 序列化分片
	shardBytes := make([][]byte, nShards)
	for i, shard := range shards {
		b := shard.Bytes()
		shardBytes[i] = b[:]
	}

	log.Printf("[DIDClient] 新参数计算完成, 已分片为 %d 份", nShards)
	return shardBytes, nil
}

// SubmitClientParams 提交客户端参数分片到 DIDServer
func (c *DIDClient) SubmitClientParams(connAddr string, nShards int) error {
	creds, err := loadTLSCreds()
	if err != nil {
		return err
	}

	conn, err := grpc.Dial(connAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("连接 DIDServer 失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewDIDServiceClient(conn)

	// 计算新参数并分片
	shards, err := c.ComputeNewParams(nShards)
	if err != nil {
		return err
	}

	// 提交
	ctx := context.Background()
	resp, err := client.SubmitClientParams(ctx, &pb.ClientParamsRequest{
		ClientShards: shards,
		ClientId:     1,
	})
	if err != nil {
		return fmt.Errorf("提交参数失败: %v", err)
	}

	log.Printf("[DIDClient] 提交响应: success=%v, msg=%s", resp.Success, resp.Message)
	return nil
}

// SubmitPermutation 提交属性置换顺序 (用于 ORP)
// permutation: 用户指定的属性顺序
func (c *DIDClient) SubmitPermutation(connAddr string, permutation []int) (*pb.PermutationResponse, error) {
	creds, err := loadTLSCreds()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(connAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("连接 DIDServer 失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewDIDServiceClient(conn)

	// 转换为 int32
	perm32 := make([]int32, len(permutation))
	for i, v := range permutation {
		perm32[i] = int32(v)
	}

	ctx := context.Background()
	resp, err := client.SubmitPermutation(ctx, &pb.PermutationRequest{
		Permutation: perm32,
		UserId:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("提交置换失败: %v", err)
	}

	log.Printf("[DIDClient] 置换响应: success=%v, msg=%s", resp.Success, resp.Message)
	log.Printf("[DIDClient] 置换后的承诺数量: %d", len(resp.PermutedCommitments))
	return resp, nil
}

// GetMerkleRoot 获取 Merkle Root
func (c *DIDClient) GetMerkleRoot(connAddr string) (*pb.MerkleRootResponse, error) {
	creds, err := loadTLSCreds()
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(connAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("连接 DIDServer 失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewDIDServiceClient(conn)

	ctx := context.Background()
	resp, err := client.GetMerkleRoot(ctx, &pb.MerkleRootRequest{})
	if err != nil {
		return nil, fmt.Errorf("获取 Merkle Root 失败: %v", err)
	}

	if resp.Success {
		log.Printf("[DIDClient] Merkle Root: %x", resp.MerkleRoot)
		log.Printf("[DIDClient] 叶子数: %d", resp.NumLeaves)
	}

	return resp, nil
}

// loadTLSCreds 加载客户端 TLS 证书
func loadTLSCreds() (credentials.TransportCredentials, error) {
	certFile := "certs/client1/client1.pem"
	keyFile := "certs/client1/client1.key"
	caFile := "certs/ca/ca.pem"

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载证书失败: %v", err)
	}
	caCertData, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("加载 CA 失败: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertData)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}
	return credentials.NewTLS(tlsConfig), nil
}

// RunDIDClient 运行客户端
// 1. 接收生成元 g (这里从本地参数获取, 实际从服务器接收)
// 2. 计算新参数并分片
// 3. 提交到 DIDServer
// 4. 提交置换顺序
// 5. 获取 Merkle Root
func RunDIDClient(didServerAddr string, numAttributes int) {
	client := NewDIDClient()

	// 步骤 1: 接收生成元 g (模拟从服务器接收)
	// 实际场景中, 各服务器将 g 发送给客户端
	params := utils.SetupPedersen()
	gBytes := params.G.Marshal()
	for i := 0; i < numAttributes; i++ {
		client.ReceiveGenerator(gBytes)
	}

	// 步骤 2: 计算新参数并分片, 提交到 DIDServer
	nShards := 4 // 4 个 MPC 节点
	if err := client.SubmitClientParams(didServerAddr, nShards); err != nil {
		log.Fatalf("[DIDClient] 提交参数失败: %v", err)
	}

	// 步骤 3: 提交置换顺序 (用户指定属性顺序)
	// 这里使用随机置换
	perm := utils.RandomPermutation(numAttributes)
	permInts := perm.Get()
	log.Printf("[DIDClient] 提交置换顺序: %v", permInts)

	permResp, err := client.SubmitPermutation(didServerAddr, permInts)
	if err != nil {
		log.Fatalf("[DIDClient] 提交置换失败: %v", err)
	}

	// 步骤 4: 获取 Merkle Root
	rootResp, err := client.GetMerkleRoot(didServerAddr)
	if err != nil {
		log.Fatalf("[DIDClient] 获取 Merkle Root 失败: %v", err)
	}

	if rootResp.Success {
		log.Printf("[DIDClient] 最终 Merkle Root: %x", rootResp.MerkleRoot)
		// 保存叶子数据 + 叶子哈希 + root 供 proof 生成器使用
		saveAggregatorOutput(rootResp, permResp.PermutedCommitments)
	}
}

// saveAggregatorOutput 保存聚合节点输出 (叶子数据 + 哈希 + root) 供 proof 生成器使用
func saveAggregatorOutput(resp *pb.MerkleRootResponse, leafData [][]byte) {
	output := struct {
		MerkleRoot []byte   `json:"merkle_root"`
		NumLeaves  int      `json:"num_leaves"`
		LeafHashes [][]byte `json:"leaf_hashes"`
		LeafData   [][]byte `json:"leaf_data"`
	}{
		MerkleRoot: resp.MerkleRoot,
		NumLeaves:  int(resp.NumLeaves),
		LeafHashes: resp.LeafHashes,
		LeafData:   leafData,
	}

	jsonData, _ := json.MarshalIndent(output, "", "  ")
	if err := os.WriteFile("aggregator_output.json", jsonData, 0644); err != nil {
		log.Printf("[DIDClient] 保存输出失败: %v", err)
	} else {
		log.Printf("[DIDClient] 聚合输出已保存到 aggregator_output.json (含 %d 个叶子数据)", len(leafData))
	}
}

func main() {
	didServerAddr := "localhost:5000"
	numAttributes := 4

	if len(os.Args) > 1 {
		didServerAddr = os.Args[1]
	}
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &numAttributes)
	}

	RunDIDClient(didServerAddr, numAttributes)
}
