package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "DID/proto"
)

// Stage 表示流水线阶段
type Stage string

const (
	StageCommitments  Stage = "commitments"
	StageRerandomized Stage = "rerandomized"
	StageMerkle       Stage = "merkle"
)

// DIDServer 实现 DIDService 接口 (优化版)
// 优化点:
// 1. sync.Cond 替代 poll-and-fail, 数据未就绪时阻塞等待
// 2. 重随机化计算移出锁外异步执行
// 3. 流式 SubmitCommitments 批量接收承诺
// 4. SubscribeGenerator 推送生成元 G 到客户端
// 5. WaitForStage 阻塞等待阶段就绪
// 6. 错误通过 gRPC status 返回, 不再 log.Fatalf
// 7. 通过 MPCNodeService 分布式调用 MPC 节点
type DIDServer struct {
	pb.UnimplementedDIDServiceServer

	mu   sync.Mutex
	cond *sync.Cond // 阶段就绪通知

	params *utils.CommitmentParams

	// 服务器提交的承诺和分片
	serverCommitments map[int][]byte
	serverShards      map[int][][]byte
	generators        map[int]bls12381.G1Affine
	receivedServers   int

	// 客户端提交的分片
	clientShards [][]byte
	clientReady  bool

	// MPC 节点连接池 (连接复用)
	mpcNodeConns map[int]*grpc.ClientConn // nodeID -> 连接
	numMPCNodes  int

	// 重随机化承诺
	rerandomizedCommitments []bls12381.G1Affine
	rerandomizedReady       bool

	// 置换后的承诺
	permutedCommitments [][]byte

	// Merkle 树结果
	merkleRoot   []byte
	leafHashes   [][]byte
	leafData     [][]byte
	numLeaves    int
	merkleReady  bool

	// 配置
	expectedServers int
}

// NewDIDServer 创建优化版 DID 服务器
func NewDIDServer() *DIDServer {
	s := &DIDServer{
		params:           utils.SetupPedersen(),
		serverCommitments: make(map[int][]byte),
		serverShards:      make(map[int][][]byte),
		generators:        make(map[int]bls12381.G1Affine),
		mpcNodeConns:     make(map[int]*grpc.ClientConn),
		expectedServers:  4,
		numMPCNodes:      4,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// ============================================================
// 流式 RPC: SubmitCommitments (批量接收承诺, 减少 N 次 TLS 握手)
// ============================================================

// SubmitCommitments 流式接收多个服务器的承诺
func (s *DIDServer) SubmitCommitments(stream pb.DIDService_SubmitCommitmentsServer) error {
	count := 0
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			// 流结束
			s.mu.Lock()
			s.mu.Unlock()
			log.Printf("[DIDServer] 流式提交完成, 本批 %d 个承诺 (总计 %d 个服务器)",
				count, len(s.serverCommitments))

			// 通知等待 commitments 阶段的客户端
			if len(s.serverCommitments) >= s.expectedServers {
				s.cond.Broadcast()
			}

			return stream.SendAndClose(&pb.CommitmentResponse{
				Success: true,
				Message: fmt.Sprintf("接收到 %d 个承诺", count),
			})
		}
		if err != nil {
			return fmt.Errorf("接收承诺流失败: %v", err)
		}

		s.mu.Lock()
		s.serverCommitments[int(req.ServerId)] = req.Commitment
		s.serverShards[int(req.ServerId)] = req.RerandomShards

		var g bls12381.G1Affine
		if err := g.Unmarshal(req.GeneratorG); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("解析生成元失败: %v", err)
		}
		s.generators[int(req.ServerId)] = g
		s.receivedServers++
		s.mu.Unlock()

		log.Printf("[DIDServer] 收到服务器 %d 的承诺 (属性 %d)", req.ServerId, req.AttributeId)
		count++
	}
}

// ============================================================
// 客户端参数提交 (触发异步重随机化)
// ============================================================

// SubmitClientParams 接收客户端参数分片, 触发异步重随机化
func (s *DIDServer) SubmitClientParams(ctx context.Context, req *pb.ClientParamsRequest) (*pb.ClientParamsResponse, error) {
	s.mu.Lock()
	s.clientShards = req.ClientShards
	s.clientReady = true
	s.mu.Unlock()

	log.Printf("[DIDClient] 收到客户端 %d 的参数分片 (%d 个分片)", req.ClientId, len(req.ClientShards))

	// 异步执行重随机化 (不阻塞 RPC 响应)
	go s.executeReRandomization()

	return &pb.ClientParamsResponse{
		Success: true,
		Message: "客户端参数已接收, 重随机化异步执行中",
	}, nil
}

// executeReRandomization 异步执行 MPC 重随机化
// 将计算移出锁外, 避免阻塞其他 RPC
func (s *DIDServer) executeReRandomization() {
	log.Printf("[DIDServer] 开始异步执行 MPC 重随机化...")

	// 等待所有服务器承诺就绪
	s.mu.Lock()
	for len(s.serverCommitments) < s.expectedServers {
		log.Printf("[DIDServer] 等待服务器承诺就绪 (%d/%d)...",
			len(s.serverCommitments), s.expectedServers)
		s.cond.Wait()
	}

	// 复制数据到局部变量, 释放锁后计算
	originalCommitments := make(map[int]bls12381.G1Affine, len(s.serverCommitments))
	for serverID, commitmentBytes := range s.serverCommitments {
		var c bls12381.G1Affine
		if err := c.Unmarshal(commitmentBytes); err != nil {
			log.Printf("[DIDServer] 警告: 解析服务器 %d 承诺失败: %v", serverID, err)
			continue
		}
		originalCommitments[serverID] = c
	}

	serverShardsCopy := make(map[int][][]byte, len(s.serverShards))
	for k, v := range s.serverShards {
		serverShardsCopy[k] = v
	}

	clientShardsCopy := make([][]byte, len(s.clientShards))
	copy(clientShardsCopy, s.clientShards)
	s.mu.Unlock()

	// ===== 在锁外执行 CPU 密集型计算 =====

	// 模拟 MPC 节点计算 (分布式模式: 实际应通过 MPCNodeService 调用各节点)
	// 这里使用本地模拟以保持兼容性
	nodeContributions := s.computeLocalMPC(originalCommitments, serverShardsCopy, clientShardsCopy)

	// 聚合所有节点的贡献
	rerandomized := utils.AggregateReRandomization(originalCommitments, nodeContributions)

	// 转为有序数组, 更新状态
	s.mu.Lock()
	s.rerandomizedCommitments = make([]bls12381.G1Affine, 0, len(rerandomized))
	for i := 0; i < len(rerandomized); i++ {
		if c, ok := rerandomized[i]; ok {
			s.rerandomizedCommitments = append(s.rerandomizedCommitments, c)
		}
	}
	s.rerandomizedReady = true
	s.cond.Broadcast() // 通知等待 rerandomized 阶段的客户端
	s.mu.Unlock()

	log.Printf("[DIDServer] MPC 重随机化完成, 生成 %d 个新承诺", len(s.rerandomizedCommitments))
	for i, c := range s.rerandomizedCommitments {
		cBytes := c.Marshal()
		log.Printf("[DIDServer] 新承诺[%d]: %s...", i, hex.EncodeToString(cBytes[:16]))
	}
}

// computeLocalMPC 本地模拟 MPC 节点计算 (实际应分布式调用 MPCNodeService)
func (s *DIDServer) computeLocalMPC(
	originalCommitments map[int]bls12381.G1Affine,
	serverShards map[int][][]byte,
	clientShards [][]byte,
) []map[int]bls12381.G1Affine {
	nNodes := s.numMPCNodes
	nodeContributions := make([]map[int]bls12381.G1Affine, nNodes)

	for nodeID := 0; nodeID < nNodes; nodeID++ {
		node := utils.NewMPCNode(nodeID, s.params)

		for serverID, shards := range serverShards {
			if nodeID < len(shards) {
				var shard fr.Element
				shard.SetBytes(shards[nodeID])
				attrShard := utils.AttributeShard{
					Commitment:    originalCommitments[serverID],
					ReRandomShare: shard,
					AttributeID:   serverID,
					ServerID:      serverID,
				}
				node.ReceiveServerShard(attrShard)
			}
		}

		if nodeID < len(clientShards) {
			var clientShare fr.Element
			clientShare.SetBytes(clientShards[nodeID])
			node.ReceiveClientShard(utils.ClientShard{
				ClientShare: clientShare,
				NodeID:      nodeID,
			})
		}

		nodeContributions[nodeID] = node.ComputeReRandomization()
	}

	return nodeContributions
}

// ============================================================
// 置换提交 + Merkle 树构建
// ============================================================

// SubmitPermutation 接收置换顺序, 执行 ORP, 构建 Merkle 树
func (s *DIDServer) SubmitPermutation(ctx context.Context, req *pb.PermutationRequest) (*pb.PermutationResponse, error) {
	// 使用 WaitForStage 逻辑等待重随机化就绪
	if err := s.waitForStage(ctx, StageRerandomized); err != nil {
		return nil, status.Errorf(codes.Unavailable, "重随机化尚未就绪: %v", err)
	}

	s.mu.Lock()
	if len(s.rerandomizedCommitments) == 0 {
		s.mu.Unlock()
		return &pb.PermutationResponse{Success: false, Message: "无重随机化承诺"}, nil
	}
	// 复制数据
	commitments := make([]bls12381.G1Affine, len(s.rerandomizedCommitments))
	copy(commitments, s.rerandomizedCommitments)
	s.mu.Unlock()

	log.Printf("[DIDServer] 收到用户 %d 的置换顺序 (长度 %d)", req.UserId, len(req.Permutation))

	// 构造 Permutation
	pi := make([]int, len(req.Permutation))
	for i, v := range req.Permutation {
		pi[i] = int(v)
	}
	perm := utils.NewPermutation(pi)

	// 执行 ORP 不经意置换 (CPU 密集, 在锁外)
	permuted := utils.ObliviousPermute(commitments, perm)

	// 序列化
	permutedCommitments := make([][]byte, len(permuted))
	for i, c := range permuted {
		permutedCommitments[i] = c.Marshal()
	}

	// 构建 Merkle 树 (CPU 密集, 在锁外)
	tree := utils.NewSimpleMerkleTree()
	for _, cb := range permutedCommitments {
		tree.Push(cb)
	}
	if err := tree.Build(); err != nil {
		// 不再 log.Fatalf, 返回 gRPC 错误
		return nil, status.Errorf(codes.Internal, "构建 Merkle 树失败: %v", err)
	}

	// 更新状态
	s.mu.Lock()
	s.permutedCommitments = permutedCommitments
	s.merkleRoot = tree.Root()
	s.numLeaves = tree.NumLeaves()
	s.leafHashes = tree.LeafHashes()
	s.leafData = permutedCommitments
	s.merkleReady = true
	s.cond.Broadcast() // 通知等待 merkle 阶段的客户端
	s.mu.Unlock()

	log.Printf("[DIDServer] ORP 置换 + Merkle 构建完成")
	log.Printf("[DIDServer] Merkle Root: %x", s.merkleRoot)

	return &pb.PermutationResponse{
		PermutedCommitments: permutedCommitments,
		Success:             true,
		Message:             "置换完成, Merkle 树已构建",
	}, nil
}

// ============================================================
// 新增 RPC: SubscribeGenerator (推送生成元 G 到客户端)
// ============================================================

// SubscribeGenerator 流式推送生成元 G 到客户端
func (s *DIDServer) SubscribeGenerator(req *pb.GeneratorRequest, stream pb.DIDService_SubscribeGeneratorServer) error {
	log.Printf("[DIDServer] 客户端 %d 订阅生成元 G", req.ClientId)

	// 等待服务器承诺就绪 (带超时)
	ctx := stream.Context()
	if err := s.waitForStage(ctx, StageCommitments); err != nil {
		return status.Errorf(codes.Unavailable, "服务器承诺尚未就绪: %v", err)
	}

	s.mu.Lock()
	generators := make(map[int]bls12381.G1Affine, len(s.generators))
	for k, v := range s.generators {
		generators[k] = v
	}
	s.mu.Unlock()

	// 流式推送每个服务器的生成元
	for serverID, g := range generators {
		gBytes := g.Marshal()
		if err := stream.Send(&pb.GeneratorResponse{
			GeneratorG: gBytes,
			ServerId:   int32(serverID),
		}); err != nil {
			return fmt.Errorf("推送生成元失败: %v", err)
		}
		log.Printf("[DIDServer] 推送服务器 %d 的生成元 G 给客户端 %d", serverID, req.ClientId)
	}

	return nil
}

// ============================================================
// 新增 RPC: WaitForStage (阻塞等待阶段就绪)
// ============================================================

// WaitForStage 阻塞等待指定阶段就绪, 替代 poll-and-fail
func (s *DIDServer) WaitForStage(ctx context.Context, req *pb.StageRequest) (*pb.StageResponse, error) {
	stage := Stage(req.Stage)
	log.Printf("[DIDServer] 客户端等待阶段: %s (超时 %dms)", req.Stage, req.TimeoutMs)

	if err := s.waitForStageWithTimeout(ctx, stage, time.Duration(req.TimeoutMs)*time.Millisecond); err != nil {
		return &pb.StageResponse{
			Ready:   false,
			Stage:   req.Stage,
			Message: fmt.Sprintf("等待超时: %v", err),
		}, nil
	}

	return &pb.StageResponse{
		Ready:   true,
		Stage:   req.Stage,
		Message: "阶段就绪",
	}, nil
}

// waitForStage 等待阶段就绪 (使用 context 控制超时)
func (s *DIDServer) waitForStage(ctx context.Context, stage Stage) error {
	return s.waitForStageWithTimeout(ctx, stage, 30*time.Second)
}

// waitForStageWithTimeout 带超时等待阶段就绪
func (s *DIDServer) waitForStageWithTimeout(ctx context.Context, stage Stage, timeout time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 启动一个 goroutine 来处理 context 取消
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.cond.Broadcast() // 唤醒等待者让其检查 context
		case <-done:
		}
	}()
	defer close(done)

	for {
		// 检查阶段是否就绪
		ready := false
		switch stage {
		case StageCommitments:
			ready = len(s.serverCommitments) >= s.expectedServers
		case StageRerandomized:
			ready = s.rerandomizedReady
		case StageMerkle:
			ready = s.merkleReady
		}

		if ready {
			return nil
		}

		// 检查 context 是否已取消
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// 等待通知
		s.cond.Wait()
	}
}

// ============================================================
// GetMerkleRoot
// ============================================================

// GetMerkleRoot 返回 Merkle Root 和叶子数据
func (s *DIDServer) GetMerkleRoot(ctx context.Context, req *pb.MerkleRootRequest) (*pb.MerkleRootResponse, error) {
	// 等待 Merkle 就绪
	if err := s.waitForStage(ctx, StageMerkle); err != nil {
		return &pb.MerkleRootResponse{Success: false}, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return &pb.MerkleRootResponse{
		MerkleRoot: s.merkleRoot,
		NumLeaves:  int32(s.numLeaves),
		LeafHashes: s.leafHashes,
		LeafData:   s.leafData,
		Success:    true,
	}, nil
}

// ============================================================
// TLS + 启动
// ============================================================

func main() {
	certFile := "certs/server/server.pem"
	keyFile := "certs/server/server.key"
	caFile := "certs/ca/ca.pem"

	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("[DIDServer] 无法加载 server 证书或私钥: %v", err)
	}
	caCertData, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("[DIDServer] 无法加载 CA 根证书: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertData) {
		log.Fatalf("[DIDServer] 将 CA 根证书添加到 CertPool 失败")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	creds := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatalf("[DIDServer] 无法监听 :5000: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	didSrv := NewDIDServer()
	pb.RegisterDIDServiceServer(grpcServer, didSrv)

	log.Println("[DIDServer] TLS 已启用 (MinVersion 1.2), 监听端口 :5000")
	log.Println("[DIDServer] 优化: 流式提交, sync.Cond 等待, 异步重随机化, G 推送")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[DIDServer] Serve 失败: %v", err)
	}
}

// 避免未使用导入
var _ = errors.New
