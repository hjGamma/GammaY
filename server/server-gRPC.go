package main

import (
	"DID/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "DID/proto"
)

// waitingClient 保存等待配对的客户端信息
type waitingClient struct {
	address string
	replyCh chan *pb.MatchResponse
}

type ResultSession struct {
	rmu      sync.Mutex
	expected int // 期望收到的客户端数
	results  map[int][]byte
	readyCh  chan []byte
}

type SignSession struct {
	expected int
	sigs     []bls12381.G2Affine
	pks      []bls12381.G1Affine
	readyCh  chan []byte
	rmu      sync.Mutex
}

// matchServer 实现 MatchServiceServer 接口
type matchServer struct {
	pb.UnimplementedMatchServiceServer

	mu      sync.Mutex
	waiting []*waitingClient
	counter int64

	muResults  sync.Mutex
	MKSession  *ResultSession
	resultSess map[int]*ResultSession

	muSigns  sync.Mutex
	signSess map[int]*SignSession
}

type AggregateMsg struct {
	PubKey    bls12381.G1Affine `json:"pub_key"`
	Signature bls12381.G2Affine `json:"signature"`
}

func newMatchServer() *matchServer {
	return &matchServer{
		resultSess: make(map[int]*ResultSession),
		signSess:   make(map[int]*SignSession),
	}
}

// Register 方法：客户端调用后阻塞，直到另一客户端配对，才返回对端地址
func (s *matchServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.MatchResponse, error) {
	replyCh := make(chan *pb.MatchResponse, 1)
	client := &waitingClient{
		address: req.Address,
		replyCh: replyCh,
	}

	s.mu.Lock()
	s.waiting = append(s.waiting, client)
	if len(s.waiting) >= 2 {
		peer1 := s.waiting[0]
		peer2 := s.waiting[1]
		s.waiting = s.waiting[2:]

		// 每对客户端配对，分配一个连续的序号
		sequence1 := s.counter + 1
		sequence2 := s.counter + 2
		s.counter += 2

		s.mu.Unlock()

		log.Printf("[MatchServer] 客户端 %s 与 %s 配对成功，序号为 %d 和 %d",
			peer1.address, peer2.address, sequence1, sequence2)

		peer1.replyCh <- &pb.MatchResponse{
			PeerAddress:  peer2.address,
			PeerSequence: int32(sequence1),
		}
		peer2.replyCh <- &pb.MatchResponse{
			PeerAddress:  peer1.address,
			PeerSequence: int32(sequence2),
		}
	} else {
		s.mu.Unlock()
	}

	select {
	case resp := <-replyCh:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *matchServer) SubmitResult(ctx context.Context, req *pb.ResultRequest) (*pb.ResultResponse, error) {
	const expectedClients = 4
	if len(req.ResultData) != 64 {
		return nil, fmt.Errorf("invalid data length: expected 64 bytes, got %d", len(req.ResultData))
	}

	seq := int(req.Sequence) // 客户端唯一 ID
	groupKey := 42

	s.muResults.Lock()
	sess, ok := s.resultSess[groupKey]
	if !ok {
		sess = &ResultSession{
			expected: expectedClients,
			results:  make(map[int][]byte),
			readyCh:  make(chan []byte, expectedClients),
		}
		s.resultSess[groupKey] = sess
	}
	s.muResults.Unlock()
	sess.rmu.Lock()
	if _, exists := sess.results[seq]; !exists {
		sess.results[seq] = req.ResultData
		log.Printf("[MatchServer] 收到客户端 %d 的数据: %x\n", seq, req.ResultData)
	}
	if len(sess.results) == sess.expected {
		hashMethod := mimc.NewMiMC()
		mTree := utils.New(hashMethod)
		for _, v := range sess.results {
			mTree.Push(v)
		}
		root := mTree.Root()
		log.Printf("Merkle Root: %x\n", root)
		for i := 0; i < sess.expected; i++ {
			sess.readyCh <- root
		}
	}
	sess.rmu.Unlock()
	select {
	case aggregated := <-sess.readyCh:
		s.muResults.Lock()
		delete(s.resultSess, groupKey)
		s.muResults.Unlock()
		return &pb.ResultResponse{ProcessedData: aggregated}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *matchServer) SignMessage(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	const expectedClients = 4
	groupKey := 42 // 固定值，也可以每轮生成唯一key
	//初始化
	s.muSigns.Lock()
	sess, ok := s.signSess[groupKey]
	if !ok {
		sess = &SignSession{
			expected: expectedClients,
			sigs:     make([]bls12381.G2Affine, expectedClients),
			pks:      make([]bls12381.G1Affine, expectedClients),
			readyCh:  make(chan []byte, expectedClients),
		}
		s.signSess[groupKey] = sess
	}
	s.muSigns.Unlock()
	//存入当前服务器
	sess.rmu.Lock()
	var signature bls12381.G2Affine
	var pk bls12381.G1Affine
	err := signature.Unmarshal(req.SignedMessage)
	if err != nil {
		sess.rmu.Unlock()
		return nil, fmt.Errorf("failed to unmarshal signature: %v", err)
	}
	sess.sigs = append(sess.sigs, signature)
	err = pk.Unmarshal(req.PublicKey)
	if err != nil {
		sess.rmu.Unlock()
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}
	sess.pks = append(sess.pks, pk)

	if len(sess.sigs) == sess.expected && len(sess.pks) == sess.expected {
		aggPK, aggSig := Aggregate(sess.pks, sess.sigs)
		aggSigBytes := aggSig.Marshal()
		if err != nil {
			sess.rmu.Unlock()
			return nil, fmt.Errorf("failed to marshal aggregated signature: %v", err)
		}
		aggPKBytes := aggPK.Marshal()
		if err != nil {
			sess.rmu.Unlock()
			return nil, fmt.Errorf("failed to marshal aggregated public key: %v", err)
		}
		log.Printf("[MatchServer] 聚合签名完成: %x\n", aggSigBytes)
		log.Printf("[MatchServer] 聚合公钥完成: %x\n", aggPKBytes)
		for i := 0; i < sess.expected; i++ {
			sess.readyCh <- aggSigBytes
		}
	}
	sess.rmu.Unlock()
	aggregateMsg := &AggregateMsg{
		PubKey:    pk,
		Signature: signature,
	}
	jsonData, err := json.Marshal(aggregateMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal aggregate message: %v", err)
	}

	fileName := "aggregate_msg.json"
	err = os.WriteFile(fileName, jsonData, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write aggregate message to file: %v", err)
	}
	return nil, nil
}

func main() {
	certFile := "certs/server/server.pem"
	keyFile := "certs/server/server.key"
	caFile := "certs/ca/ca.pem"
	// execPath, err := os.Executable()
	// rootDir := filepath.Dir(filepath.Dir(execPath)) //

	// certFile := filepath.Join(rootDir, "certs/server/server.pem")
	// keyFile := filepath.Join(rootDir, "certs/server/server.key")
	// caFile := filepath.Join(rootDir, "certs/ca/ca.pem")
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("[MatchServer] 无法加载 server 证书或私钥: %v", err)
	}
	caCertData, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("[MatchServer] 无法加载 CA 根证书: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertData) {
		log.Fatalf("[MatchServer] 将 CA 根证书添加到 CertPool 失败")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	creds := credentials.NewTLS(tlsConfig)
	lis, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatalf("[MatchServer] 无法监听 :5000: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	matchSrv := newMatchServer()
	pb.RegisterMatchServiceServer(grpcServer, matchSrv)

	log.Println("[MatchServer] TLS 已启用，监听端口 :5000，等待客户端注册......")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("[MatchServer] Serve 失败: %v", err)
	}
}
