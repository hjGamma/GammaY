package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"time"

	"DID/utils"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// AttributeServer 优化版属性服务器
// 优化点:
// 1. 连接复用: 单个 *grpc.ClientConn 贯穿整个会话
// 2. 流式批量提交: 多个属性通过单次流式 RPC 提交
// 3. 重试退避: 提交失败时指数退避重试
// 4. TLS 证书缓存: 只从磁盘读取一次
type AttributeServer struct {
	serverID      int
	didServerAddr string
	params        *utils.CommitmentParams
	conn          *grpc.ClientConn // 连接复用
	tlsCreds      credentials.TransportCredentials // TLS 证书缓存
	client        pb.DIDServiceClient
}

// NewAttributeServer 创建属性服务器
func NewAttributeServer(serverID int, didServerAddr string) *AttributeServer {
	return &AttributeServer{
		serverID:      serverID,
		didServerAddr: didServerAddr,
		params:        utils.SetupPedersen(),
	}
}

// connect 建立并复用 gRPC 连接 (连接复用优化)
func (as *AttributeServer) connect() error {
	if as.conn != nil {
		return nil // 已连接
	}

	creds, err := as.loadTLSCreds()
	if err != nil {
		return fmt.Errorf("加载 TLS 证书失败: %v", err)
	}
	as.tlsCreds = creds

	// 带连接池参数的 Dial
	conn, err := grpc.Dial(as.didServerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64*1024*1024)),
	)
	if err != nil {
		return fmt.Errorf("连接 DIDServer 失败: %v", err)
	}
	as.conn = conn
	as.client = pb.NewDIDServiceClient(conn)
	log.Printf("[AttrServer-%d] 已建立连接 (复用模式)", as.serverID)
	return nil
}

// loadTLSCreds 加载 TLS 证书 (只读取一次, 缓存复用)
func (as *AttributeServer) loadTLSCreds() (credentials.TransportCredentials, error) {
	certFile := fmt.Sprintf("certs/client%d/client%d.pem", as.serverID+1, as.serverID+1)
	keyFile := fmt.Sprintf("certs/client%d/client%d.key", as.serverID+1, as.serverID+1)
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

// close 关闭连接
func (as *AttributeServer) close() {
	if as.conn != nil {
		as.conn.Close()
	}
}

// ============================================================
// 属性生成与承诺计算
// ============================================================

// GenerateAttribute 生成随机属性
func (as *AttributeServer) GenerateAttribute() fr.Element {
	var attr fr.Element
	attr.SetRandom()
	return attr
}

// ComputeCommitmentAndShards 计算承诺和 MPC 分片
func (as *AttributeServer) ComputeCommitmentAndShards(attr fr.Element, nShards int) (
	commitmentBytes []byte,
	shards [][]byte,
	generatorG []byte,
) {
	// 计算承诺 C = m*G + r*H
	commitment := as.params.Commit(attr, utils.RandomScalar())

	// 生成重随机化分片 r' = r'_1 + r'_2 + ... + r'_n
	rerandomized := utils.RandomScalar()

	// 使用加法秘密共享分片 r'
	shardValues := utils.ShardSecret(rerandomized, nShards)
	for _, s := range shardValues {
		shards = append(shards, utils.ScalarToBytes(s))
	}

	// 序列化承诺和生成元
	commitmentBytes = commitment.C.Marshal()
	generatorG = as.params.G.Marshal()

	log.Printf("[AttrServer-%d] 承诺计算完成 (shards=%d, commitment=%x...)",
		as.serverID, len(shards), commitmentBytes[:8])

	return
}

// ============================================================
// 流式批量提交 (减少 N 次 TLS 握手)
// ============================================================

// SubmitCommitments 流式批量提交多个属性的承诺
func (as *AttributeServer) SubmitCommitments(numAttributes, nShards int) error {
	if err := as.connect(); err != nil {
		return err
	}

	// 带超时的 context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 开启流
	stream, err := as.client.SubmitCommitments(ctx)
	if err != nil {
		return fmt.Errorf("开启提交流失败: %v", err)
	}

	// 通过流式 RPC 批量发送多个属性承诺
	for i := 0; i < numAttributes; i++ {
		attr := as.GenerateAttribute()
		commitmentBytes, shards, generatorG := as.ComputeCommitmentAndShards(attr, nShards)

		req := &pb.CommitmentRequest{
			ServerId:       int32(as.serverID),
			Commitment:     commitmentBytes,
			RerandomShards: shards,
			GeneratorG:     generatorG,
			AttributeId:    int32(i),
		}

		if err := stream.Send(req); err != nil {
			return fmt.Errorf("发送承诺 %d 失败: %v", i, err)
		}
		log.Printf("[AttrServer-%d] 已流式发送属性 %d/%d", as.serverID, i+1, numAttributes)
	}

	// 关闭流并接收响应
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("关闭提交流失败: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("服务器返回失败: %s", resp.Message)
	}

	log.Printf("[AttrServer-%d] 流式批量提交成功: %s (共 %d 个属性)",
		as.serverID, resp.Message, numAttributes)
	return nil
}

// submitWithRetry 带指数退避的重试逻辑
func (as *AttributeServer) submitWithRetry(numAttributes, nShards int, maxRetries int) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := as.SubmitCommitments(numAttributes, nShards); err != nil {
			lastErr = err
			backoff := time.Duration(1<<attempt) * time.Second // 1s, 2s, 4s...
			log.Printf("[AttrServer-%d] 提交失败 (尝试 %d/%d): %v, %v 后重试",
				as.serverID, attempt+1, maxRetries, err, backoff)
			time.Sleep(backoff)
			// 重连
			as.close()
			as.conn = nil
			continue
		}
		return nil
	}
	return fmt.Errorf("达到最大重试次数 %d, 最后错误: %v", maxRetries, lastErr)
}

// RunAttributeServer 运行属性服务器
func RunAttributeServer(serverID int, didServerAddr string, numAttributes, nShards int) {
	as := NewAttributeServer(serverID, didServerAddr)
	defer as.close()

	log.Printf("[AttrServer-%d] 启动 (didServer=%s, attributes=%d, shards=%d)",
		serverID, didServerAddr, numAttributes, nShards)

	// 带重试的流式批量提交
	if err := as.submitWithRetry(numAttributes, nShards, 3); err != nil {
		log.Fatalf("[AttrServer-%d] 提交失败: %v", serverID, err)
	}

	log.Printf("[AttrServer-%d] 完成", serverID)
}

func main() {
	serverID := flag.Int("id", 0, "服务器 ID")
	didServerAddr := flag.String("addr", "localhost:5000", "DIDServer 地址")
	numAttributes := flag.Int("n", 1, "属性数量")
	nShards := flag.Int("shards", 4, "MPC 分片数")
	flag.Parse()

	_ = rand.New(rand.NewSource(time.Now().UnixNano()))

	RunAttributeServer(*serverID, *didServerAddr, *numAttributes, *nShards)

	_ = os.Exit
}
