package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"

	"DID/utils"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// DIDServer 实现 DIDService 接口
// 协调多个服务器、客户端、MPC 节点完成:
// 1. Pedersen 承诺收集
// 2. MPC 重随机化
// 3. ORP 不经意置换
// 4. Merkle 树构建
type DIDServer struct {
	pb.UnimplementedDIDServiceServer

	mu sync.Mutex

	params *utils.CommitmentParams // Pedersen 公共参数

	// 服务器提交的承诺和分片
	serverCommitments map[int][]byte          // 服务器提交的原始承诺 (按 serverID)
	serverShards      map[int][][]byte        // 每个服务器的重随机化分片
	generators        map[int]bls12381.G1Affine // 各服务器的生成元 G

	// 客户端提交的分片
	clientShards [][]byte

	// MPC 节点计算的重随机化承诺
	rerandomizedCommitments []bls12381.G1Affine

	// 置换后的承诺
	permutedCommitments [][]byte

	// Merkle 树结果
	merkleRoot []byte
	leafHashes [][]byte
	numLeaves  int

	// 配置
	expectedServers int
	expectedClients int
	numMPCNodes     int
}

// NewDIDServer 创建新的 DID 服务器
func NewDIDServer() *DIDServer {
	return &DIDServer{
		params:           utils.SetupPedersen(),
		serverCommitments: make(map[int][]byte),
		serverShards:      make(map[int][][]byte),
		generators:        make(map[int]bls12381.G1Affine),
		expectedServers:  4,
		expectedClients:  1,
		numMPCNodes:      4,
	}
}

// SubmitCommitment 服务器端: 接收属性承诺与 MPC 分片
func (s *DIDServer) SubmitCommitment(ctx context.Context, req *pb.CommitmentRequest) (*pb.CommitmentResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[DIDServer] 收到服务器 %d 的承诺 (属性 %d)", req.ServerId, req.AttributeId)

	s.serverCommitments[int(req.ServerId)] = req.Commitment
	s.serverShards[int(req.ServerId)] = req.RerandomShards

	var g bls12381.G1Affine
	if err := g.Unmarshal(req.GeneratorG); err != nil {
		return &pb.CommitmentResponse{Success: false, Message: fmt.Sprintf("解析生成元失败: %v", err)}, nil
	}
	s.generators[int(req.ServerId)] = g

	if len(s.serverCommitments) >= s.expectedServers {
		log.Printf("[DIDServer] 所有 %d 个服务器已提交承诺", s.expectedServers)
	}

	return &pb.CommitmentResponse{Success: true, Message: "承诺已接收"}, nil
}

// SubmitClientParams 客户端端: 接收客户端参数分片, 触发重随机化
func (s *DIDServer) SubmitClientParams(ctx context.Context, req *pb.ClientParamsRequest) (*pb.ClientParamsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[DIDServer] 收到客户端 %d 的参数分片 (%d 个分片)", req.ClientId, len(req.ClientShards))
	s.clientShards = req.ClientShards

	s.executeReRandomization()

	return &pb.ClientParamsResponse{Success: true, Message: "客户端参数已接收, 重随机化已执行"}, nil
}

// executeReRandomization 执行 MPC 重随机化
// 将原始承诺加上所有分片的贡献, 得到新的重随机化承诺
func (s *DIDServer) executeReRandomization() {
	log.Printf("[DIDServer] 开始执行 MPC 重随机化...")

	// 解析所有原始承诺
	originalCommitments := make(map[int]bls12381.G1Affine)
	for serverID, commitmentBytes := range s.serverCommitments {
		var c bls12381.G1Affine
		c.Unmarshal(commitmentBytes)
		originalCommitments[serverID] = c
	}

	// 模拟 MPC 节点计算: 每个节点收集对应分片并计算贡献
	nNodes := s.numMPCNodes
	nodeContributions := make([]map[int]bls12381.G1Affine, nNodes)

	for nodeID := 0; nodeID < nNodes; nodeID++ {
		node := utils.NewMPCNode(nodeID, s.params)

		for serverID, shards := range s.serverShards {
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

		if nodeID < len(s.clientShards) {
			var clientShare fr.Element
			clientShare.SetBytes(s.clientShards[nodeID])
			node.ReceiveClientShard(utils.ClientShard{
				ClientShare: clientShare,
				NodeID:      nodeID,
			})
		}

		nodeContributions[nodeID] = node.ComputeReRandomization()
	}

	// 聚合所有节点的贡献
	rerandomized := utils.AggregateReRandomization(originalCommitments, nodeContributions)

	// 转为有序数组
	s.rerandomizedCommitments = make([]bls12381.G1Affine, 0, len(rerandomized))
	for i := 0; i < len(rerandomized); i++ {
		if c, ok := rerandomized[i]; ok {
			s.rerandomizedCommitments = append(s.rerandomizedCommitments, c)
		}
	}

	log.Printf("[DIDServer] MPC 重随机化完成, 生成 %d 个新承诺", len(s.rerandomizedCommitments))
	for i, c := range s.rerandomizedCommitments {
		cBytes := c.Marshal()
		log.Printf("[DIDServer] 新承诺[%d]: %s...", i, hex.EncodeToString(cBytes[:16]))
	}
}

// SubmitPermutation 用户端: 接收置换顺序, 执行 ORP 不经意置换, 构建 Merkle 树
func (s *DIDServer) SubmitPermutation(ctx context.Context, req *pb.PermutationRequest) (*pb.PermutationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.rerandomizedCommitments) == 0 {
		return &pb.PermutationResponse{Success: false, Message: "尚未完成重随机化"}, nil
	}

	log.Printf("[DIDServer] 收到用户 %d 的置换顺序 (长度 %d)", req.UserId, len(req.Permutation))

	// 构造 Permutation
	pi := make([]int, len(req.Permutation))
	for i, v := range req.Permutation {
		pi[i] = int(v)
	}
	perm := utils.NewPermutation(pi)

	// 执行 ORP 不经意置换 (使用 Waksman 网络)
	permuted := utils.ObliviousPermute(s.rerandomizedCommitments, perm)

	// 序列化置换后的承诺
	s.permutedCommitments = make([][]byte, len(permuted))
	for i, c := range permuted {
		s.permutedCommitments[i] = c.Marshal()
	}

	log.Printf("[DIDServer] ORP 不经意置换完成, 生成 %d 个置换承诺", len(s.permutedCommitments))

	// 构建 Merkle 树
	s.buildMerkleTree()

	return &pb.PermutationResponse{
		PermutedCommitments: s.permutedCommitments,
		Success:             true,
		Message:             "置换完成, Merkle 树已构建",
	}, nil
}

// buildMerkleTree 构建单节点 Merkle 树
func (s *DIDServer) buildMerkleTree() {
	log.Printf("[DIDServer] 开始构建 Merkle 树...")

	h := mimc.NewMiMC()
	tree := utils.New(h)

	for _, commitmentBytes := range s.permutedCommitments {
		tree.Push(commitmentBytes)
	}

	s.merkleRoot = tree.Root()
	s.numLeaves = len(s.permutedCommitments)

	// 收集叶子哈希 (用于 proof 生成)
	s.leafHashes = make([][]byte, s.numLeaves)
	for i, commitmentBytes := range s.permutedCommitments {
		h.Reset()
		h.Write(commitmentBytes)
		s.leafHashes[i] = h.Sum(nil)
	}

	log.Printf("[DIDServer] Merkle 树构建完成")
	log.Printf("[DIDServer] Merkle Root: %x", s.merkleRoot)
	log.Printf("[DIDServer] 叶子数: %d", s.numLeaves)
}

// GetMerkleRoot 返回 Merkle Root 和叶子哈希
func (s *DIDServer) GetMerkleRoot(ctx context.Context, req *pb.MerkleRootRequest) (*pb.MerkleRootResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.merkleRoot == nil {
		return &pb.MerkleRootResponse{Success: false}, nil
	}

	return &pb.MerkleRootResponse{
		MerkleRoot: s.merkleRoot,
		NumLeaves:  int32(s.numLeaves),
		LeafHashes: s.leafHashes,
		Success:    true,
	}, nil
}

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
	}

	creds := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatalf("[DIDServer] 无法监听 :5000: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	didSrv := NewDIDServer()
	pb.RegisterDIDServiceServer(grpcServer, didSrv)

	log.Println("[DIDServer] TLS 已启用，监听端口 :5000")
	log.Println("[DIDServer] 等待服务器提交承诺, 客户端提交参数, 用户提交置换顺序...")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[DIDServer] Serve 失败: %v", err)
	}
}
