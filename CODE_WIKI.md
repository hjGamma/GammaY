# Distributed Identity Authentication System - Code Wiki

## 1. 项目概述

### 项目名称
Distributed Identity Authentication System (DID)

### 项目简介
本项目实现了一个**高安全性和用户友好性的分布式身份认证方案**，基于现代密码学技术构建，包括BLS签名、零知识证明(gnark)和Schnorr承诺。

### 核心特性
- **隐私保护认证**：多个独立权威节点协作颁发通用身份，无需相互通信；用户可在不泄露私有数据的情况下证明身份
- **用户中心化数据所有权**：身份信息存储权归还用户；企业和第三方不再存储敏感个人信息
- **安全可靠的基础设施**：使用OpenSSL生成认证和加密证书；采用gRPC实现分布式节点间安全高效通信

---

## 2. 技术架构

### 2.1 技术栈

| 类别 | 技术 |
|------|------|
| 编程语言 | Go 1.23.4 |
| 密码学库 | gnark, gnark-crypto |
| 签名算法 | BLS12-381 |
| 零知识证明 | Groth16 (gnark) |
| 哈希函数 | MiMC (BN254) |
| 通信框架 | gRPC + TLS |
| 证书管理 | OpenSSL X.509 |

### 2.2 依赖关系

```
DID (主模块)
├── github.com/consensys/gnark v0.13.0          # 零知识证明框架
├── github.com/consensys/gnark-crypto v0.18.0   # 密码学库 (BLS, MiMC)
├── google.golang.org/grpc v1.73.0              # gRPC框架
└── google.golang.org/protobuf v1.36.6          # Protocol Buffers
```

---

## 3. 项目目录结构

```
/workspace/
├── certs/                    # 证书目录
│   ├── ca/                   # CA根证书
│   │   ├── ca.conf
│   │   ├── ca.crt, ca.csr, ca.key, ca.pem, ca.srl
│   ├── server/               # 服务器证书
│   │   ├── server.conf, server.csr, server.key, server.pem
│   └── client1-4/            # 客户端证书 (4个客户端)
│       ├── clientX.conf, clientX.csr, clientX.key, clientX.pem
│       └── clientX_keypair.json  # BLS密钥对存储
├── proto/                    # Protocol Buffers定义
│   ├── chat.proto           # 服务定义文件
│   ├── chat.pb.go           # Protobuf生成代码
│   └── chat_grpc.pb.go      # gRPC生成代码
├── server/                   # 服务器端实现
│   ├── server-gRPC.go       # gRPC服务器主程序
│   └── clientSign.go        # 签名聚合功能
├── client/                   # 客户端实现
│   ├── client-gRPC.go       # gRPC客户端主程序
│   ├── clientSign.go        # BLS签名生成
│   └── BLS_test.go          # BLS签名测试
├── user/                     # 用户验证模块
│   └── user.go              # 聚合签名验证与ZK证明生成
├── utils/                    # 工具函数库
│   ├── hash.go              # MiMC哈希封装
│   ├── merkle.go            # Merkle树实现
│   ├── MIMC1.go             # MiMC辅助函数
│   ├── circuit.go           # ZK证明电路
│   ├── Mimc_test.go         # MiMC测试
│   └── tools/               # 辅助工具
│       ├── IsStr.go         # 字符串判断
│       └── IsNumber.go      # 数字判断
├── test/                     # 测试程序
│   └── test.go              # Merkle树测试
└── go.mod                    # Go模块定义
```

---

## 4. 主要模块详解

### 4.1 Proto 定义 (proto/)

#### chat.proto - 服务定义

**MatchService** - 匹配服务

| RPC方法 | 功能 | 请求 | 响应 |
|---------|------|------|------|
| Register | 客户端注册配对 | RegisterRequest | MatchResponse |
| SubmitResult | 提交计算结果 | ResultRequest | ResultResponse |
| SignMessage | 签名消息 | SignRequest | SignResponse |

**ChatService** - 点对点聊天服务

| RPC方法 | 功能 | 模式 |
|---------|------|------|
| Chat | 双向流通信 | stream Message |

#### 消息类型

```protobuf
RegisterRequest { string address }           // 客户端地址
MatchResponse { string peer_address, int32 peer_sequence }  // 配对结果
ResultRequest { int32 sequence, bytes result_data }           // 计算结果
SignRequest { bytes signed_message, bytes public_key }        // 签名请求
SignResponse { bytes aggr_result, bytes merkle_root }        // 签名响应
Message { int32 sequence, bytes client_data }                // 聊天消息
```

---

### 4.2 服务器端 (server/)

#### server-gRPC.go - gRPC服务器

**核心结构体**

```go
// waitingClient - 等待配对的客户端信息
type waitingClient struct {
    address string           // 客户端地址
    replyCh chan *pb.MatchResponse  // 回复通道
}

// ResultSession - 结果会话管理
type ResultSession struct {
    rmu      sync.Mutex
    expected int             // 期望收到的客户端数量
    results  map[int][]byte  // 客户端结果存储
    readyCh  chan []byte     // 结果就绪通道
}

// SignSession - 签名会话管理
type SignSession struct {
    expected int                     // 期望收到的签名数量
    sigs     []bls12381.G2Affine      // 签名字典
    pks      []bls12381.G1Affine      // 公钥列表
    readyCh  chan []byte
    rmu      sync.Mutex
}

// matchServer - 匹配服务器主结构
type matchServer struct {
    pb.UnimplementedMatchServiceServer
    mu      sync.Mutex
    waiting []*waitingClient   // 等待配对的客户端队列
    counter int64               // 序号计数器
    muResults  sync.Mutex
    MKSession  *ResultSession
    resultSess map[int]*ResultSession    // 结果会话映射
    muSigns    sync.Mutex
    signSess   map[int]*SignSession       // 签名会话映射
}
```

**核心方法**

| 方法 | 功能 |
|------|------|
| `Register(ctx, req)` | 客户端注册并等待配对，返回配对结果 |
| `SubmitResult(ctx, req)` | 接收客户端计算结果，聚合生成Merkle Root |
| `SignMessage(ctx, req)` | 接收客户端签名，聚合BLS签名 |
| `newMatchServer()` | 创建服务器实例 |

**运行配置**
- 监听端口: `:5000`
- 传输层安全: TLS双向认证
- 证书路径: `certs/server/server.pem`, `certs/server/server.key`
- CA证书: `certs/ca/ca.pem`

---

### 4.3 客户端 (client/)

#### client-gRPC.go - gRPC客户端

**核心结构体**

```go
// ClientMsg - 消息队列结构
type ClientMsg struct {
    Stream pb.ChatService_ChatServer  // 客户端流
    Msg    *pb.Message                // 消息内容
}

// chatServiceServer - ChatService服务器实现
type chatServiceServer struct {
    pb.UnimplementedChatServiceServer
    msgChan chan ClientMsg  // 消息通道
}
```

**核心方法**

| 方法 | 功能 |
|------|------|
| `Chat(stream)` | 双向流处理函数 |
| `Disassemble(Xhash)` | 将哈希值拆分为两部分 (秘密分享) |

**运行方式**
```bash
go run client-gRPC.go <client_name> <secret>
# 示例: go run client-gRPC.go client1 mysecret
```

**客户端工作流程**

1. 加载TLS证书
2. 启动本地ChatService监听
3. 连接MatchServer进行注册配对
4. 获取对端地址后建立P2P连接
5. 计算MiMC哈希并进行秘密分享
6. 生成BLS密钥对
7. 通过P2P通道交换数据
8. 计算MPC结果并提交给服务器
9. 对Merkle Root签名并提交

#### clientSign.go - BLS签名

**核心结构体**

```go
type Signer struct {
    PrivateKey fr.Element         // 私钥 (BN254 fr)
    PublicKey  bls12381.G1Affine // 公钥 (BLS12-381 G1)
}
```

**核心函数**

| 函数 | 功能 |
|------|------|
| `GenerateKeyPair()` | 生成BLS密钥对 |
| `SignMessage(signer, message)` | 对消息生成BLS签名 |
| `GenerateSigners(n)` | 生成N个签名者 |

**BLS签名流程**
1. 生成随机私钥 `sk`
2. 计算公钥 `pk = sk * G1`
3. 对消息hash到G2: `H(m)`
4. 计算签名 `σ = sk * H(m)`

#### BLS_test.go - 签名测试

**测试函数**

```go
func TestBLSAggregateSignature(t *testing.T)
```

测试内容：
- 多签名者生成
- 签名生成
- 公钥和签名聚合
- Pairing验证

---

### 4.4 用户验证模块 (user/)

#### user.go - 聚合签名验证与ZK证明生成

** AggregateMsg 结构体**

```go
type AggregateMsg struct {
    PubKey    bls12381.G1Affine   // 聚合公钥
    Signature bls12381.G2Affine   // 聚合签名
}
```

**核心工作流程**

1. 创建MiMC哈希函数
2. 构建Merkle树
3. 生成Merkle证明
4. 读取聚合签名与公钥 (`aggregate_msg.json`)
5. 生成零知识证明

**输出文件**
- `proof.json` - 零知识证明
- `public.json` - 公开输入

---

### 4.5 工具模块 (utils/)

#### hash.go - MiMC哈希

```go
func Mimc(data string) *fr.Element
```
对字符串数据进行MiMC哈希处理，返回有限域元素。

#### merkle.go - Merkle树实现

**核心结构体**

```go
type Tree struct {
    head        *subTree   // 子树栈顶
    hash        hash.Hash // 哈希函数
    currentIndex uint64    // 当前叶子索引
    proofIndex  uint64     // 待证明的叶子索引
    proofSet    [][]byte   // Merkle证明路径
    proofTree   bool      // 是否启用证明功能
    cachedTree  bool       // 是否启用缓存
    leaves      [][]byte  // 叶子节点存储
}

type subTree struct {
    next   *subTree  // 下一子树
    height int       // 树高度 (0=叶子, 1=2叶, 3=8叶...)
    sum    []byte    // Merkle根哈希
}
```

**核心方法**

| 方法 | 功能 |
|------|------|
| `New(h)` | 创建Merkle树 |
| `Push(data)` | 添加叶子节点 |
| `Root()` | 获取Merkle根 |
| `SetIndex(i)` | 设置待证明叶子索引 |
| `Prove()` | 生成Merkle证明 |
| `PushSubTree(height, sum)` | 添加预计算子树 |

**MPC相关函数**

```go
func MPC(X2 [32]byte, Y1 []byte) []byte  // 安全多方计算：拼接两个32字节数组
func frToBytes32(e *fr.Element) []byte   // 将fr.Element转换为32字节
func combineSums(a, b *subTree)          // 合并两个子树的sum
```

#### circuit.go - 零知识证明电路

**核心函数**

| 函数 | 功能 |
|------|------|
| `VerifyAggregateSignature(aggPubKey, aggSignature, message)` | BLS聚合签名验证 |
| `BytesToVariable(data)` | 字节数组转电路变量 |
| `BytesArrayToVariables(arr)` | 字节数组数组转电路变量数组 |
| `GenerateZKProof(aggPK, aggSig, attr, proofSet, proofIndex, numLeaves, proofRoot)` | 生成ZK证明 |

**ZK证明生成流程**

1. **BLS验证**: 使用PairingCheck验证聚合签名
2. **Merkle验证**: 验证Merkle树证明
3. **电路编译**: 使用gnark前端编译电路
4. **Setup**: Groth16可信设置
5. **证明生成**: 生成零知识证明
6. **验证**: 验证证明有效性
7. **导出**: 保存proof.json和public.json

**MerkleProofTest 电路结构**

```go
type MerkleProofTest struct {
    M     merkle.MerkleProof  // Merkle证明
    Valid frontend.Variable   // 验证标志 (公开)
    Leaf  frontend.Variable   // 叶子节点索引
}
```

---

## 5. 密码学原语详解

### 5.1 BLS签名 (BLS12-381)

**曲线参数**
- G1: BLS12-381签名公钥所在群
- G2: BLS12-381签名所在群
- GT: 配对结果群

**签名流程**
```
sk = random()                    // 随机私钥
pk = sk * G1                    // 公钥
H = HashToG2(message)           // 消息hash到G2
σ = sk * H                      // 签名
```

**聚合签名验证**
```
e(Σσ_i, G1) = e(Σpk_i, H(m))   // 配对检查
```

### 5.2 MiMC哈希

MiMC是一种适用于零知识证明的哈希函数，表达式：
```
H(x) = x^3 + c  (在有限域上)
```

**用途**
- Merkle树哈希
- 秘密分享
- MPC计算

### 5.3 零知识证明 (Groth16)

**电路定义** (`circuit.go`)

验证内容：
1. BLS聚合签名有效性
2. Merkle树证明正确性

**证明者**
- 公开输入: Valid, MerkleRoot, Leaf索引
- 秘密输入: proofPath, 聚合公钥, 聚合签名

---

## 6. 通信协议

### 6.1 gRPC服务

**MatchService** (端口5000)

```protobuf
service MatchService {
    rpc Register(RegisterRequest) returns (MatchResponse);
    rpc SubmitResult(ResultRequest) returns (ResultResponse);
    rpc SignMessage(SignRequest) returns (SignResponse);
}
```

**ChatService** (P2P双向流)

```protobuf
service ChatService {
    rpc Chat(stream Message) returns (stream Message);
}
```

### 6.2 TLS配置

**服务器端**
- 单向TLS认证
- 使用服务器证书和私钥
- 验证CA证书

**客户端**
- 双向TLS认证
- 使用客户端证书和私钥
- 使用CA证书验证服务器

---

## 7. 运行方式

### 7.1 准备工作

1. **生成证书** (如尚未生成)
```bash
# CA证书
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes

# 服务器证书
openssl req -newkey rsa:4096 -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.pem -days 365

# 客户端证书 (client1-4同理)
openssl req -newkey rsa:4096 -keyout client1.key -out client1.csr
openssl x509 -req -in client1.csr -CA ca.crt -CAkey ca.key -out client1.pem -days 365
```

2. **安装依赖**
```bash
go mod download
```

### 7.2 启动服务器

```bash
cd /workspace/server
go run server-gRPC.go
```

输出示例:
```
[MatchServer] TLS 已启用，监听端口 :5000，等待客户端注册......
```

### 7.3 启动客户端

```bash
cd /workspace/client
go run client-gRPC.go <client_name> <secret>

# 示例
go run client-gRPC.go client1 mysecret
go run client-gRPC.go client2 mysecret2
```

**客户端参数**
- `client_name`: 客户端标识 (如client1, client2)
- `secret`: 用户秘密值

### 7.4 运行用户验证

```bash
cd /workspace/user
go run user.go
```

### 7.5 运行测试

```bash
# Merkle树测试
cd /workspace
go run test/test.go

# BLS签名测试
cd /workspace/client
go test -v BLS_test.go clientSign.go
```

---

## 8. 数据流图

### 8.1 客户端配对流程

```
Client1                    MatchServer                    Client2
   |                            |                             |
   |--- Register(addr1) ------->|                             |
   |                            |<------ Register(addr2) -----|
   |                            |                             |
   |                       [配对成功]                          |
   |<-- MatchResponse -------->|                             |
   |   {peer_addr=addr2,       |                             |
   |    peer_seq=1}            |                             |
   |                            |      MatchResponse -------->|
   |                            |      {peer_addr=addr1,     |
   |                            |       peer_seq=2}           |
   |                            |                             |
   |<============= P2P Connection Established ===============>|
```

### 8.2 秘密分享与MPC流程

```
用户输入secret
      |
      v
+-----------+
|  MiMC哈希  |
+-----------+
      |
      v
+---------------------+
| Disassemble(Xhash)  |
| X1 = random()       |
| X2 = Xhash - X1     |
+---------------------+
      |                        |
      | X2                     | X2
      v                        v
+-----------+          +-----------+
|  Client1  |---P2P--->|  Client2  |
+-----------+          +-----------+
      |                        |
      |<------- MPC --------->|
      |  X2y = MPC(X2, Y2)     |
      |  or MPC(Y2, X2)       |
      v                        v
+-----------------------------------------+
|          SubmitResult to Server         |
+-----------------------------------------+
                          |
                          v
              +---------------------+
              |   MatchServer       |
              | Build Merkle Tree   |
              | Compute Root       |
              +---------------------+
                          |
                          v
              +---------------------+
              |   Return Root       |
              +---------------------+
                          |
                          v
              +---------------------+
              | SignMessage         |
              | σ = sk * Root       |
              +---------------------+
                          |
                          v
              +---------------------+
              | Aggregate Sigs     |
              +---------------------+
```

---

## 9. 文件清单

### 9.1 源代码文件

| 文件路径 | 行数 | 功能描述 |
|----------|------|----------|
| proto/chat.proto | 61 | gRPC服务定义 |
| proto/chat.pb.go | ~500 | Protobuf生成代码 |
| proto/chat_grpc.pb.go | 313 | gRPC生成代码 |
| server/server-gRPC.go | 276 | 服务器主程序 |
| server/clientSign.go | 同server | 签名聚合 |
| client/client-gRPC.go | 348 | 客户端主程序 |
| client/clientSign.go | 108 | BLS签名 |
| client/BLS_test.go | 86 | BLS测试 |
| user/user.go | 100 | 用户验证 |
| utils/hash.go | 42 | MiMC封装 |
| utils/merkle.go | 417 | Merkle树 |
| utils/MIMC1.go | 363 | MiMC辅助 |
| utils/circuit.go | 327 | ZK电路 |
| utils/tools/IsStr.go | 12 | 字符串判断 |
| utils/tools/IsNumber.go | 8 | 数字判断 |
| test/test.go | 31 | Merkle测试 |

### 9.2 配置文件

| 路径 | 用途 |
|------|------|
| certs/ca/ca.pem | CA根证书 |
| certs/server/server.pem | 服务器证书 |
| certs/clientX/clientX.pem | 客户端证书 |
| user/aggregate_msg.json | 聚合消息存储 |

---

## 10. 安全考虑

1. **TLS传输加密**: 所有gRPC通信均使用TLS加密
2. **双向认证**: 客户端和服务器都验证对方证书
3. **秘密分享**: 用户密钥通过秘密分享分片
4. **零知识证明**: 身份验证过程不泄露实际数据
5. **BLS聚合签名**: 高效的多方签名方案

---

## 11. 注意事项

1. 证书路径使用相对路径，需在正确目录运行
2. 服务器默认监听 `localhost:5000`
3. 客户端需要先启动服务器再连接
4. 至少需要2个客户端才能完成配对
5. ZK证明生成需要较长时间（Setup/Compile/Prove）
