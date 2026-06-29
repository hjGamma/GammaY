package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"DID/utils"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// AttributeServer 属性服务器
// 每个服务器在本地:
// 1. 生成用户属性
// 2. 计算 Pedersen 承诺 C = m*G + r*H
// 3. 将重随机化因子 r' 分成 n 份
// 4. 将分片和承诺发送到 DIDServer (协调节点)
// 5. 将生成元 G 发送给客户端
type AttributeServer struct {
	serverID   int
	params     *utils.CommitmentParams
	attributes map[int][]byte // 属性存储
}

// NewAttributeServer 创建属性服务器
func NewAttributeServer(serverID int) *AttributeServer {
	return &AttributeServer{
		serverID:   serverID,
		params:     utils.SetupPedersen(),
		attributes: make(map[int][]byte),
	}
}

// GenerateAttribute 在本地生成用户属性
// serverID: 服务器 ID, 用于区分不同服务器生成的属性
func (as *AttributeServer) GenerateAttribute(attrID int) []byte {
	// 生成随机属性值 (32 字节)
	attr := make([]byte, 32)
	rand.Read(attr)
	as.attributes[attrID] = attr

	log.Printf("[AttrServer-%d] 生成属性 %d: %s", as.serverID, attrID, hex.EncodeToString(attr[:16]))
	return attr
}

// ComputeCommitmentAndShards 计算 Pedersen 承诺并分片
// 返回: 承诺字节, 重随机化分片, 生成元 G
func (as *AttributeServer) ComputeCommitmentAndShards(attrID, nShards int) ([]byte, [][]byte, []byte, error) {
	attr, ok := as.attributes[attrID]
	if !ok {
		return nil, nil, nil, fmt.Errorf("属性 %d 不存在", attrID)
	}

	// 将属性映射到标量
	var m fr.Element
	m.SetBytes(attr)

	// 生成随机盲化因子 r
	var r fr.Element
	r.SetRandom()

	// 计算 Pedersen 承诺 C = m*G + r*H
	commitment := as.params.Commit(m, r)
	commitmentBytes := commitment.C.Marshal()

	// 生成重随机化因子 r'
	var rPrime fr.Element
	rPrime.SetRandom()

	// 将 r' 分成 n 份 (加法秘密共享)
	shards := utils.ShardSecret(rPrime, nShards)

	// 序列化分片
	shardBytes := make([][]byte, nShards)
	for i, shard := range shards {
		b := shard.Bytes()
		shardBytes[i] = b[:]
	}

	// 生成元 G
	gBytes := as.params.G.Marshal()

	log.Printf("[AttrServer-%d] 承诺计算完成: %s...", as.serverID, hex.EncodeToString(commitmentBytes[:16]))
	log.Printf("[AttrServer-%d] 重随机化因子已分片为 %d 份", as.serverID, nShards)

	return commitmentBytes, shardBytes, gBytes, nil
}

// SubmitToDIDServer 将承诺和分片提交到 DIDServer
func (as *AttributeServer) SubmitToDIDServer(connAddr string, attrID, nShards int) error {
	// 加载 TLS 证书
	certFile := fmt.Sprintf("certs/client%d/client%d.pem", as.serverID+1, as.serverID+1)
	keyFile := fmt.Sprintf("certs/client%d/client%d.key", as.serverID+1, as.serverID+1)
	caFile := "certs/ca/ca.pem"

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("加载证书失败: %v", err)
	}
	caCertData, err := ioutil.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("加载 CA 失败: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertData)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}
	creds := credentials.NewTLS(tlsConfig)

	// 连接 DIDServer
	conn, err := grpc.Dial(connAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("连接 DIDServer 失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewDIDServiceClient(conn)

	// 计算承诺和分片
	commitment, shards, gBytes, err := as.ComputeCommitmentAndShards(attrID, nShards)
	if err != nil {
		return err
	}

	// 提交
	ctx := context.Background()
	resp, err := client.SubmitCommitment(ctx, &pb.CommitmentRequest{
		ServerId:        int32(as.serverID),
		Commitment:      commitment,
		RerandomShards:  shards,
		GeneratorG:      gBytes,
		AttributeId:     int32(attrID),
	})
	if err != nil {
		return fmt.Errorf("提交承诺失败: %v", err)
	}

	log.Printf("[AttrServer-%d] 提交响应: success=%v, msg=%s", as.serverID, resp.Success, resp.Message)
	return nil
}

// GetGenerator 返回生成元 G (发送给客户端)
func (as *AttributeServer) GetGenerator() []byte {
	return as.params.G.Marshal()
}

// RunAttributeServer 运行属性服务器
// 生成属性, 计算承诺, 分片, 提交到 DIDServer
func RunAttributeServer(serverID int, didServerAddr string) {
	as := NewAttributeServer(serverID)

	// 生成属性
	attrID := serverID
	as.GenerateAttribute(attrID)

	// 计算承诺并分片, 提交到 DIDServer
	nShards := 4 // 4 个 MPC 节点
	if err := as.SubmitToDIDServer(didServerAddr, attrID, nShards); err != nil {
		log.Fatalf("[AttrServer-%d] 提交失败: %v", serverID, err)
	}

	// 输出生成元 G (供客户端使用)
	gBytes := as.GetGenerator()
	log.Printf("[AttrServer-%d] 生成元 G: %s", serverID, hex.EncodeToString(gBytes[:16]))
	log.Printf("[AttrServer-%d] 完成", serverID)
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("用法: attrserver <server_id> <did_server_addr>")
	}
	var serverID int
	fmt.Sscanf(os.Args[1], "%d", &serverID)
	didServerAddr := os.Args[2]

	RunAttributeServer(serverID, didServerAddr)
}
