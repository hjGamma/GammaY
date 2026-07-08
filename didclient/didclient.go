package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// DIDClient 优化版 DID 客户端
// 优化点:
// 1. 连接复用: 单个 *grpc.ClientConn 贯穿 3 个 RPC 调用
// 2. 超时控制: 每个 RPC 使用 context.WithTimeout
// 3. G 订阅: 通过 SubscribeGenerator 流式接收生成元 G (替代本地伪造)
// 4. WaitForStage: 阻塞等待阶段就绪 (替代 poll-and-fail)
// 5. 检查 Success: 不再忽略服务器返回的失败状态
type DIDClient struct {
	didServerAddr string
	conn          *grpc.ClientConn // 连接复用
	client        pb.DIDServiceClient
	params        *utils.CommitmentParams
	clientID      int
}

// NewDIDClient 创建 DID 客户端
func NewDIDClient(didServerAddr string, clientID int) *DIDClient {
	return &DIDClient{
		didServerAddr: didServerAddr,
		params:        utils.SetupPedersen(),
		clientID:      clientID,
	}
}

// connect 建立并复用 gRPC 连接
func (c *DIDClient) connect() error {
	if c.conn != nil {
		return nil
	}

	creds, err := c.loadTLSCreds()
	if err != nil {
		return err
	}

	conn, err := grpc.Dial(c.didServerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64*1024*1024)),
	)
	if err != nil {
		return fmt.Errorf("连接 DIDServer 失败: %v", err)
	}
	c.conn = conn
	c.client = pb.NewDIDServiceClient(conn)
	log.Printf("[DIDClient] 已建立连接 (复用模式)")
	return nil
}

// loadTLSCreds 加载 TLS 证书 (只读取一次)
func (c *DIDClient) loadTLSCreds() (credentials.TransportCredentials, error) {
	certFile := "certs/client1/client1.pem"
	keyFile := "certs/client1/client1.key"
	caFile := "certs/ca/ca.pem"

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载 client 证书失败: %v", err)
	}
	caCertData, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("加载 CA 失败: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertData) {
		return nil, fmt.Errorf("解析 CA 证书失败")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	return credentials.NewTLS(tlsConfig), nil
}

func (c *DIDClient) close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// ============================================================
// 订阅生成元 G (流式接收, 替代本地伪造)
// ============================================================

// SubscribeGenerators 通过流式 RPC 接收所有服务器的生成元 G
func (c *DIDClient) SubscribeGenerators() ([]bls12381.G1Affine, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := c.client.SubscribeGenerator(ctx, &pb.GeneratorRequest{ClientId: int32(c.clientID)})
	if err != nil {
		return nil, fmt.Errorf("订阅生成元失败: %v", err)
	}

	var generators []bls12381.G1Affine
	for {
		resp, err := stream.Recv()
		if err != nil {
			break // 流结束
		}
		var g bls12381.G1Affine
		if err := g.Unmarshal(resp.GeneratorG); err != nil {
			log.Printf("[DIDClient] 警告: 解析生成元失败: %v", err)
			continue
		}
		generators = append(generators, g)
		log.Printf("[DIDClient] 接收到服务器 %d 的生成元 G: %x...",
			resp.ServerId, resp.GeneratorG[:8])
	}

	if len(generators) == 0 {
		return nil, fmt.Errorf("未接收到任何生成元")
	}

	log.Printf("[DIDClient] 共接收 %d 个生成元", len(generators))
	return generators, nil
}

// ============================================================
// 计算新参数并分片
// ============================================================

// ComputeNewParams 基于生成元 g 计算新参数并分片
func (c *DIDClient) ComputeNewParams(generators []bls12381.G1Affine, nShards int) [][]byte {
	if len(generators) == 0 {
		log.Printf("[DIDClient] 警告: 无生成元, 使用本地参数")
		generators = []bls12381.G1Affine{c.params.G}
	}

	// 使用第一个生成元 (协议简化)
	g := generators[0]

	// 计算新参数: c' = Hash(g) (伪随机)
	var clientParam fr.Element
	gBytes := g.Marshal()
	clientParam.SetBytes(gBytes)

	// 分片
	shards := utils.ShardSecret(clientParam, nShards)
	result := make([][]byte, nShards)
	for i, s := range shards {
		result[i] = utils.ScalarToBytes(s)
	}

	log.Printf("[DIDClient] 计算新参数完成 (%d 个分片)", nShards)
	return result
}

// ============================================================
// 提交客户端参数分片
// ============================================================

// SubmitClientParams 提交客户端参数分片
func (c *DIDClient) SubmitClientParams(clientShards [][]byte) error {
	if err := c.connect(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.client.SubmitClientParams(ctx, &pb.ClientParamsRequest{
		ClientShards: clientShards,
		ClientId:     int32(c.clientID),
	})
	if err != nil {
		return fmt.Errorf("提交客户端参数失败: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("服务器返回失败: %s", resp.Message)
	}

	log.Printf("[DIDClient] 客户端参数提交成功: %s", resp.Message)
	return nil
}

// ============================================================
// 等待阶段就绪
// ============================================================

// WaitForStage 阻塞等待指定阶段就绪
func (c *DIDClient) WaitForStage(stage string, timeoutMs int) error {
	if err := c.connect(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	resp, err := c.client.WaitForStage(ctx, &pb.StageRequest{
		Stage:     stage,
		TimeoutMs: int32(timeoutMs),
	})
	if err != nil {
		return fmt.Errorf("等待阶段失败: %v", err)
	}

	if !resp.Ready {
		return fmt.Errorf("阶段 %s 未就绪: %s", stage, resp.Message)
	}

	log.Printf("[DIDClient] 阶段 %s 就绪: %s", stage, resp.Message)
	return nil
}

// ============================================================
// 提交置换顺序
// ============================================================

// SubmitPermutation 提交置换顺序并获取置换后的承诺
func (c *DIDClient) SubmitPermutation(permutation []int) ([][]byte, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pi := make([]int32, len(permutation))
	for i, v := range permutation {
		pi[i] = int32(v)
	}

	// 先等待重随机化就绪
	if err := c.WaitForStage("rerandomized", 30000); err != nil {
		return nil, fmt.Errorf("等待重随机化失败: %v", err)
	}

	resp, err := c.client.SubmitPermutation(ctx, &pb.PermutationRequest{
		Permutation: pi,
		UserId:      int32(c.clientID),
	})
	if err != nil {
		return nil, fmt.Errorf("提交置换失败: %v", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("置换失败: %s", resp.Message)
	}

	log.Printf("[DIDClient] 置换提交成功, 获得 %d 个置换承诺", len(resp.PermutedCommitments))
	return resp.PermutedCommitments, nil
}

// ============================================================
// 获取 Merkle Root
// ============================================================

// GetMerkleRoot 获取 Merkle Root 和叶子数据
func (c *DIDClient) GetMerkleRoot() ([]byte, [][]byte, [][]byte, error) {
	if err := c.connect(); err != nil {
		return nil, nil, nil, err
	}

	// 等待 Merkle 就绪
	if err := c.WaitForStage("merkle", 30000); err != nil {
		return nil, nil, nil, fmt.Errorf("等待 Merkle 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.client.GetMerkleRoot(ctx, &pb.MerkleRootRequest{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("获取 Merkle Root 失败: %v", err)
	}

	if !resp.Success {
		return nil, nil, nil, fmt.Errorf("服务器返回 Merkle Root 失败")
	}

	log.Printf("[DIDClient] 获取 Merkle Root: %x (叶子数 %d)",
		resp.MerkleRoot, resp.NumLeaves)

	return resp.MerkleRoot, resp.LeafHashes, resp.LeafData, nil
}

// ============================================================
// 运行完整流程
// ============================================================

// AggregatorOutput 聚合输出文件格式
type AggregatorOutput struct {
	MerkleRoot string   `json:"merkle_root"`
	LeafHashes []string `json:"leaf_hashes"`
	LeafData   []string `json:"leaf_data"`
	NumLeaves  int      `json:"num_leaves"`
}

// RunDIDClient 运行完整的 DID 客户端流程
func RunDIDClient(didServerAddr string, numAttributes, nShards int) error {
	client := NewDIDClient(didServerAddr, 1)
	defer client.close()

	log.Printf("[DIDClient] 启动 (didServer=%s, attributes=%d, shards=%d)",
		didServerAddr, numAttributes, nShards)

	// 步骤 1: 等待服务器承诺就绪
	log.Println("[DIDClient] === 步骤 1: 等待服务器承诺就绪 ===")
	if err := client.WaitForStage("commitments", 30000); err != nil {
		return fmt.Errorf("等待承诺失败: %v", err)
	}

	// 步骤 2: 订阅生成元 G (替代本地伪造)
	log.Println("[DIDClient] === 步骤 2: 订阅生成元 G ===")
	generators, err := client.SubscribeGenerators()
	if err != nil {
		return fmt.Errorf("订阅生成元失败: %v", err)
	}

	// 步骤 3: 计算新参数并分片
	log.Println("[DIDClient] === 步骤 3: 计算新参数 ===")
	clientShards := client.ComputeNewParams(generators, nShards)

	// 步骤 4: 提交客户端参数分片 (触发异步重随机化)
	log.Println("[DIDClient] === 步骤 4: 提交客户端参数 ===")
	if err := client.SubmitClientParams(clientShards); err != nil {
		return fmt.Errorf("提交参数失败: %v", err)
	}

	// 步骤 5: 等待重随机化完成并提交置换顺序
	log.Println("[DIDClient] === 步骤 5: 提交置换顺序 ===")
	permutation := make([]int, numAttributes)
	for i := range permutation {
		permutation[i] = (i + 1) % numAttributes // 简单循环置换
	}
	permutedCommitments, err := client.SubmitPermutation(permutation)
	if err != nil {
		return fmt.Errorf("提交置换失败: %v", err)
	}
	log.Printf("[DIDClient] 置换顺序: %v", permutation)

	// 步骤 6: 获取 Merkle Root
	log.Println("[DIDClient] === 步骤 6: 获取 Merkle Root ===")
	merkleRoot, leafHashes, leafData, err := client.GetMerkleRoot()
	if err != nil {
		return fmt.Errorf("获取 Merkle Root 失败: %v", err)
	}

	// 保存聚合输出
	output := AggregatorOutput{
		MerkleRoot: hex.EncodeToString(merkleRoot),
		NumLeaves:  len(leafHashes),
	}
	for _, h := range leafHashes {
		output.LeafHashes = append(output.LeafHashes, hex.EncodeToString(h))
	}
	for _, d := range leafData {
		output.LeafData = append(output.LeafData, hex.EncodeToString(d))
	}

	outputBytes, _ := json.MarshalIndent(output, "", "  ")
	if err := os.WriteFile("aggregator_output.json", outputBytes, 0644); err != nil {
		return fmt.Errorf("写入输出文件失败: %v", err)
	}

	log.Printf("[DIDClient] 完成! Merkle Root: %s", output.MerkleRoot)
	log.Printf("[DIDClient] 输出已保存到 aggregator_output.json")

	_ = permutedCommitments
	return nil
}

func main() {
	didServerAddr := flag.String("addr", "localhost:5000", "DIDServer 地址")
	numAttributes := flag.Int("n", 4, "属性数量")
	nShards := flag.Int("shards", 4, "MPC 分片数")
	flag.Parse()

	if err := RunDIDClient(*didServerAddr, *numAttributes, *nShards); err != nil {
		log.Fatalf("[DIDClient] 失败: %v", err)
	}
}
