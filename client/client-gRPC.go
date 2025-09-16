// client.go
package main

import (
	pb "DID/proto"
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
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// 匹配服务器地址（与 server.go 保持一致）
	matchServerAddr = "localhost:5000"

	// 聊天会话时长限制：10 分钟（可根据需求自行修改）
	sessionTimeout = 10 * time.Minute
	// 聊天消息条数限制：最多 100 条（发送 + 接收 总和）
	maxMessageCount = 100
)

// 定义消息队列
type ClientMsg struct {
	Stream pb.ChatService_ChatServer // 客户端流
	Msg    *pb.Message               // 客户端消息
}

// ---------------------------
// ChatService 实现
// ---------------------------
type chatServiceServer struct {
	pb.UnimplementedChatServiceServer
	msgChan chan ClientMsg // 消息队列，用于发送和接收消息
}

type User struct {
}

// Chat 方法：双向流，客户端会同时在两端都发起此调用
func (s *chatServiceServer) Chat(stream pb.ChatService_ChatServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		s.msgChan <- ClientMsg{
			Stream: stream,
			Msg:    msg,
		}
	}

}

// func (s *chatServiceServer) Chat(stream pb.ChatService_ChatServer) error {

// 	for {
// 		// 服务器端在此不主动处理，只做中转；如果收到 EOF 或出错，则退出
// 		_, err := stream.Recv()
// 		if err == io.EOF {
// 			return nil
// 		}
// 		if err != nil {
// 			return err
// 		}
// 	}
// }

func main() {

	if len(os.Args) < 3 {
		log.Fatalf("go run client.go <certs path> <Attribute>")
	}

	clientName := os.Args[1]
	secret := os.Args[2]
	certFile := fmt.Sprintf("certs/%s/%s.pem", clientName, clientName)
	keyFile := fmt.Sprintf("certs/%s/%s.key", clientName, clientName)
	caFile := "certs/ca/ca.pem"

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("[Client] 无法加载客户端证书或私钥: %v", err)
	}

	caCertData, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("[Client] 无法加载 CA 根证书: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertData) {
		log.Fatalf("[Client] 将 CA 根证书添加到 CertPool 失败")
	}

	// 1.3 TLS 配置（双向认证）
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
	}
	creds := credentials.NewTLS(tlsConfig)

	chatLis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("[Client] 无法监听随机端口: %v", err)
	}
	chatPort := chatLis.Addr().(*net.TCPAddr).Port
	chatAddr := fmt.Sprintf("localhost:%d", chatPort)
	log.Printf("[Client] 本地 ChatService 正在监听 %s", chatAddr)

	chatServer := grpc.NewServer(grpc.Creds(creds))
	cs := &chatServiceServer{
		msgChan: make(chan ClientMsg, 1), // 缓冲通道
	}
	pb.RegisterChatServiceServer(chatServer, cs)
	go func() {

		if err := chatServer.Serve(chatLis); err != nil {
			log.Fatalf("[Client] ChatService Serve 错误: %v", err)
		}
	}()
	//连接到服务器端，获取对端地址
	ctx := context.Background()
	connMatch, err := grpc.Dial(matchServerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("[Client] 无法连接到匹配服务器 %s: %v", matchServerAddr, err)
	}
	defer connMatch.Close()

	matchClient := pb.NewMatchServiceClient(connMatch)
	log.Printf("[Client] 向匹配服务器发送 Register 请求，携带本地 Chat 地址 %s ...", chatAddr)
	resp, err := matchClient.Register(ctx, &pb.RegisterRequest{Address: chatAddr})
	if err != nil {
		log.Fatalf("[Client] Register 出错: %v", err)
	}
	// 连接到对端客户端
	peerAddr := resp.PeerAddress
	peerSequence := resp.PeerSequence
	log.Printf("[Client] 已配对到对端地址：%s", peerAddr)
	connPeer, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("[Client] 无法连接到对端 %s: %v", peerAddr, err)
	}
	defer connPeer.Close()
	chatClient := pb.NewChatServiceClient(connPeer)
	chatCtx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()
	stream, err := chatClient.Chat(chatCtx)
	if err != nil {
		log.Fatalf("[Client] 打开 Chat 双向流失败: %v", err)
	}
	//计算hash在本地拆分
	Xhash := utils.Mimc(secret)
	fmt.Printf("%s: %s 的 MiMC 哈希 = %s\n", clientName, secret, Xhash)
	x1Bytes, x2Bytes := Disassemble(Xhash)
	//计算BLS公私钥
	sk, pk := GenerateKeyPair()
	signer := Signer{
		PrivateKey: sk,
		PublicKey:  pk}
	jsonData, err := json.MarshalIndent(signer, "", "  ")
	if err != nil {
		fmt.Printf("JSON 序列化失败: %v\n", err)
		return
	}
	filename := fmt.Sprintf("certs/%s/%s_keypair.json", clientName, clientName)
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		fmt.Printf("写入文件失败: %v\n", err)
		return
	}

	var x2y []byte
	var wg sync.WaitGroup
	wg.Add(2)
	///////////
	// 接收对端消息后，计算MPC结果并提交结果至server计算最终的merkle root
	//////////
	go func() {
		defer wg.Done()
		select {
		case <-chatCtx.Done():
			log.Println("[Client] 会话超时，接收消息 Goroutine 退出")
			return
		case msg := <-cs.msgChan:
			peer2Sequence := msg.Msg.Sequence
			y2 := msg.Msg.ClientData
			log.Printf("[Client] 接收到对端消息：%s", new(fr.Element).SetBytes(y2))

			var y2Bytes [32]byte
			copy(y2Bytes[:], y2)
			if peer2Sequence%2 == 0 {
				x2y = utils.MPC(x1Bytes, y2Bytes[:])
			} else {
				x2y = utils.MPC(y2Bytes, x1Bytes[:])
			}
			resCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			MRoot, err := matchClient.SubmitResult(resCtx, &pb.ResultRequest{
				Sequence:   int32(peerSequence),
				ResultData: x2y,
			})
			if err != nil {
				log.Printf("[Client] SubmitResult 出错: %v", err)
				return
			}
			var resElm fr.Element
			resElm.SetBytes(MRoot.ProcessedData)
			log.Printf("Merkle Root: %x\n", MRoot.ProcessedData)
			log.Println("[Client] Merkle Root:", &resElm)
			//对merkle root进行签名
			signedMessage := SignMessage(signer, MRoot.ProcessedData)
			aggrResult, err := matchClient.SignMessage(resCtx, &pb.SignRequest{
				SignedMessage: signedMessage.Marshal(),
				PublicKey:     pk.Marshal(),
			})
			if err != nil {
				log.Printf("[Client] SignMessage 出错: %v", err)
				return
			}
			var aggrElm fr.Element
			aggrElm.SetBytes(aggrResult.AggrResult)
			log.Printf("聚合签名: %x\n", aggrResult.AggrResult)
			log.Println("[Client] 聚合签名:", &aggrElm)
			log.Printf("Merkle Root: %x\n", aggrResult.MerkleRoot)
			var merkleRootElm fr.Element
			merkleRootElm.SetBytes(aggrResult.MerkleRoot)
			log.Println("[Client] Merkle Root:", &merkleRootElm)
			return
		}
	}()
	///////////
	// 发送拆分值
	//////////
	go func() {
		defer wg.Done()

		select {
		case <-chatCtx.Done():
			log.Println("[Client] 会话超时，发送拆分值 Goroutine 退出")
			return
		default:
			err := stream.Send(&pb.Message{
				Sequence:   int32(peerSequence),
				ClientData: x2Bytes[:],
			})
			if err != nil {
				log.Printf("[Client] 发送拆分值时出错: %v，退出发送 Goroutine", err)
			} else {
				log.Println("[Client] 拆分值发送成功，退出发送 Goroutine")
			}
		}

	}()
	wg.Wait()
	log.Println("[Client] 聊天会话结束，退出客户端")
	///////////////////////////////////////////////////////////////////////////
	// // 5.1 接收对端消息
	// go func() {
	// 	defer wg.Done()
	// 	recvCount := 0
	// 	for {
	// 		// 检查是否超时
	// 		select {
	// 		case <-chatCtx.Done():
	// 			log.Println("[Client] 会话超时，接收 Goroutine 退出")
	// 			return
	// 		default:
	// 			// 尝试接收对端消息
	// 			msg, err := stream.Recv()
	// 			if err == io.EOF {
	// 				log.Println("[Client] 对端已关闭连接（EOF），接收 Goroutine 退出")
	// 				return
	// 			} else if err != nil {
	// 				log.Printf("[Client] 接收消息出错: %v，退出接收 Goroutine", err)
	// 				return
	// 			}
	// 			recvCount++
	// 			log.Printf("\n[Peer] %s\n> ", msg.Seed)

	// 			// 检查消息总数限制（发送 + 接收）
	// 			if recvCount >= maxMessageCount {
	// 				log.Println("[Client] 已达到最大接收消息数，主动关闭连接")
	// 				stream.CloseSend()
	// 				return
	// 			}
	// 		}
	// 	}
	// }()

	// // 5.2 读取标准输入并发送消息
	// go func() {
	// 	defer wg.Done()
	// 	sendCount := 0
	// 	scanner := bufio.NewScanner(os.Stdin)
	// 	for {
	// 		// 检查是否超时
	// 		select {
	// 		case <-chatCtx.Done():
	// 			log.Println("[Client] 会话超时，发送 Goroutine 退出")
	// 			return
	// 		default:
	// 			fmt.Print("> ")
	// 			if !scanner.Scan() {
	// 				// stdin 被关闭或出错
	// 				log.Println("[Client] 无法从 stdin 读取，退出发送 Goroutine")
	// 				stream.CloseSend()
	// 				return
	// 			}
	// 			text := scanner.Text()
	// 			if text == "" {
	// 				continue
	// 			}
	// 			// 发送消息
	// 			err := stream.Send(&pb.Message{Seed: text})
	// 			if err != nil {
	// 				log.Printf("[Client] 发送消息时出错: %v，退出发送 Goroutine", err)
	// 				return
	// 			}
	// 			sendCount++
	// 			// 检查消息总数限制
	// 			if sendCount >= maxMessageCount {
	// 				log.Println("[Client] 已达到最大发送消息数，主动关闭连接")
	// 				stream.CloseSend()
	// 				return
	// 			}
	// 		}
	// 	}
	// }()
	///////////////////////////////////////////////////////////////////////////
	// // 等待两条 Goroutine 结束后，关闭流并退出

}

func Disassemble(Xhash *fr.Element) (x1Bytes [32]byte, x2Bytes [32]byte) {
	X1 := new(fr.Element)
	if _, err := X1.SetRandom(); err != nil {
		log.Fatal("SetRandom error:", err)
	}
	x1Bytes = X1.Bytes()
	X2 := new(fr.Element).Sub(Xhash, X1)
	x2Bytes = X2.Bytes()
	return x1Bytes, x2Bytes
}
