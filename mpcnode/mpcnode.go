package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"sync"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// MPCNodeServer MPC 节点 gRPC 服务
// 每个 MPC 节点作为独立服务运行, 通过消息队列模式接收分片
// 节点收集所有分片后计算重随机化贡献, 实现真正的分布式 MPC
type MPCNodeServer struct {
	pb.UnimplementedMPCNodeServiceServer

	mu     sync.Mutex
	cond   *sync.Cond // 用于通知分片就绪
	nodeID int
	params *utils.CommitmentParams

	// 消息队列: 缓冲接收的分片
	serverShardsQueue []utils.AttributeShard
	clientShard       *utils.ClientShard

	// 计算结果
	contributions map[int]bls12381.G1Affine // attribute_id -> 贡献
	computed      bool

	// 统计
	totalShardsReceived int
}

// NewMPCNodeServer 创建 MPC 节点服务
func NewMPCNodeServer(nodeID int) *MPCNodeServer {
	s := &MPCNodeServer{
		nodeID: nodeID,
		params: utils.SetupPedersen(),
		contributions: make(map[int]bls12381.G1Affine),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// ReceiveShards 流式接收服务器分片 (消息队列消费端)
func (s *MPCNodeServer) ReceiveShards(stream pb.MPCNodeService_ReceiveShardsServer) error {
	count := 0
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			// 流结束, 发送响应
			s.mu.Lock()
			s.totalShardsReceived += count
			s.mu.Unlock()
			log.Printf("[MPCNode-%d] 流式接收完成, 本批 %d 个分片 (总计 %d)",
				s.nodeID, count, s.totalShardsReceived)
			return stream.SendAndClose(&pb.MPCResponse{
				Success: true,
				Message: fmt.Sprintf("接收到 %d 个分片", count),
				NodeId:  int32(s.nodeID),
			})
		}
		if err != nil {
			return fmt.Errorf("接收分片流失败: %v", err)
		}

		// 入队
		var rerandomShare fr.Element
		rerandomShare.SetBytes(msg.RerandomShare)

		var commitment bls12381.G1Affine
		if err := commitment.Unmarshal(msg.Commitment); err != nil {
			return fmt.Errorf("解析承诺失败: %v", err)
		}

		shard := utils.AttributeShard{
			Commitment:    commitment,
			ReRandomShare: rerandomShare,
			AttributeID:   int(msg.AttributeId),
			ServerID:      int(msg.ServerId),
		}

		s.mu.Lock()
		s.serverShardsQueue = append(s.serverShardsQueue, shard)
		s.mu.Unlock()
		count++
	}
}

// ReceiveClientShard 接收客户端分片
func (s *MPCNodeServer) ReceiveClientShard(ctx context.Context, msg *pb.ClientShardMessage) (*pb.MPCResponse, error) {
	var clientShare fr.Element
	clientShare.SetBytes(msg.ClientShare)

	shard := &utils.ClientShard{
		ClientShare: clientShare,
		NodeID:      int(msg.NodeId),
	}

	s.mu.Lock()
	s.clientShard = shard
	s.mu.Unlock()

	log.Printf("[MPCNode-%d] 接收到客户端分片", s.nodeID)
	return &pb.MPCResponse{
		Success: true,
		Message: "客户端分片已接收",
		NodeId:  int32(s.nodeID),
	}, nil
}

// ComputeContribution 计算 MPC 节点的重随机化贡献
func (s *MPCNodeServer) ComputeContribution(ctx context.Context, req *pb.ComputeRequest) (*pb.ContributionResponse, error) {
	s.mu.Lock()

	// 等待分片就绪
	for len(s.serverShardsQueue) == 0 || s.clientShard == nil {
		log.Printf("[MPCNode-%d] 等待分片就绪 (serverShards=%d, clientShard=%v)...",
			s.nodeID, len(s.serverShardsQueue), s.clientShard != nil)
		// 使用 context 超时避免永久阻塞
		waitDone := make(chan struct{})
		go func() {
			s.cond.Wait()
			close(waitDone)
		}()

		select {
		case <-ctx.Done():
			s.mu.Unlock()
			return nil, fmt.Errorf("等待分片超时: %v", ctx.Err())
		case <-waitDone:
		}
	}

	// 使用 MPCNode 计算贡献
	node := utils.NewMPCNode(s.nodeID, s.params)
	for _, shard := range s.serverShardsQueue {
		node.ReceiveServerShard(shard)
	}
	node.ReceiveClientShard(*s.clientShard)

	// 计算贡献 (移到锁外执行以避免阻塞其他请求)
	shardsCopy := make([]utils.AttributeShard, len(s.serverShardsQueue))
	copy(shardsCopy, s.serverShardsQueue)
	clientShardCopy := *s.clientShard
	s.mu.Unlock()

	// 在锁外执行计算 (BLS 标量乘法是 CPU 密集型)
	contributions := computeContributionOffline(s.nodeID, s.params, shardsCopy, clientShardCopy)

	s.mu.Lock()
	s.contributions = contributions
	s.computed = true
	s.mu.Unlock()

	// 序列化贡献
	respContrib := make(map[int32][]byte)
	for attrID, contrib := range contributions {
		respContrib[int32(attrID)] = contrib.Marshal()
	}

	log.Printf("[MPCNode-%d] 计算完成, 生成 %d 个贡献", s.nodeID, len(respContrib))

	return &pb.ContributionResponse{
		NodeId:        int32(s.nodeID),
		Contributions: respContrib,
		Success:       true,
		Message:       "贡献计算完成",
	}, nil
}

// computeContributionOffline 在锁外计算重随机化贡献
func computeContributionOffline(nodeID int, params *utils.CommitmentParams, shards []utils.AttributeShard, clientShard utils.ClientShard) map[int]bls12381.G1Affine {
	result := make(map[int]bls12381.G1Affine)

	for _, shard := range shards {
		var combinedShare fr.Element
		combinedShare.Add(&shard.ReRandomShare, &clientShard.ClientShare)

		var combinedBI big.Int
		combinedShare.BigInt(&combinedBI)

		var hMul bls12381.G1Affine
		hMul.ScalarMultiplication(&params.H, &combinedBI)

		if existing, ok := result[shard.AttributeID]; ok {
			var summed bls12381.G1Affine
			summed.Add(&existing, &hMul)
			result[shard.AttributeID] = summed
		} else {
			result[shard.AttributeID] = hMul
		}
	}

	return result
}

// PermuteShards 置换分片 (ORP 协作)
func (s *MPCNodeServer) PermuteShards(ctx context.Context, req *pb.PermuteRequest) (*pb.MPCResponse, error) {
	pi := make([]int, len(req.Permutation))
	for i, v := range req.Permutation {
		pi[i] = int(v)
	}

	s.mu.Lock()
	// 对本地分片执行置换
	if len(s.serverShardsQueue) > 0 {
		perm := utils.NewPermutation(pi)
		_ = perm
		// 实际置换逻辑在协调节点完成, 这里仅标记
	}
	s.mu.Unlock()

	log.Printf("[MPCNode-%d] 置换分片完成 (长度 %d)", s.nodeID, len(pi))
	return &pb.MPCResponse{
		Success: true,
		Message: "置换完成",
		NodeId:  int32(s.nodeID),
	}, nil
}

// HealthCheck 健康检查
func (s *MPCNodeServer) HealthCheck(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &pb.HealthResponse{
		Healthy:        true,
		NodeId:        int32(s.nodeID),
		PendingShards: int32(len(s.serverShardsQueue)),
		Message:       fmt.Sprintf("节点 %d 健康, 待处理分片 %d", s.nodeID, len(s.serverShardsQueue)),
	}, nil
}

// loadMPCNodeTLSCreds 加载 MPC 节点的 TLS 证书
func loadMPCNodeTLSCreds(nodeID int) (credentials.TransportCredentials, error) {
	certFile := fmt.Sprintf("certs/client%d/client%d.pem", nodeID+1, nodeID+1)
	keyFile := fmt.Sprintf("certs/client%d/client%d.key", nodeID+1, nodeID+1)
	caFile := "certs/ca/ca.pem"

	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载 MPC 节点证书失败: %v", err)
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
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}
	return credentials.NewTLS(tlsConfig), nil
}

func main() {
	nodeID := flag.Int("id", 0, "MPC 节点 ID")
	port := flag.Int("port", 6000, "监听端口")
	flag.Parse()

	// 加载 TLS 证书
	creds, err := loadMPCNodeTLSCreds(*nodeID)
	if err != nil {
		log.Fatalf("[MPCNode-%d] 加载 TLS 证书失败: %v", *nodeID, err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("[MPCNode-%d] 监听端口 %d 失败: %v", *nodeID, *port, err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(creds))
	nodeServer := NewMPCNodeServer(*nodeID)
	pb.RegisterMPCNodeServiceServer(grpcServer, nodeServer)

	log.Printf("[MPCNode-%d] TLS 已启用, 监听端口 :%d", *nodeID, *port)
	log.Printf("[MPCNode-%d] 等待分片流...", *nodeID)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[MPCNode-%d] Serve 失败: %v", *nodeID, err)
	}
}
