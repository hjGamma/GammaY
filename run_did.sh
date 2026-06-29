#!/bin/bash
# DID 新架构一键运行脚本
# 用法: ./run_did.sh [属性数量]
set -e

# 清理可能残留的 didserver 进程
pkill -f "bin/didserver" 2>/dev/null || true
sleep 0.5

N_ATTRS=${1:-4}
DID_ADDR="localhost:5000"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "============================================"
echo "  DID 新架构一键运行 (属性数: $N_ATTRS)"
echo "============================================"

# 1. 构建所有二进制
echo "[1/7] 构建二进制..."
go build -o bin/didserver ./didserver/
go build -o bin/attrserver ./attrserver/
go build -o bin/didclient ./didclient/
go build -o bin/aggregator ./aggregator/
go build -o bin/proofgen ./proofgen/
echo "    构建完成"

# 2. 清理旧输出
rm -f aggregator_output.json merkle_proof_*.json permuted_commitments.json

# 3. 启动 DIDServer (后台), 输出重定向到日志文件避免阻塞管道
echo "[2/7] 启动 DIDServer..."
./bin/didserver > didserver.log 2>&1 &
DID_PID=$!
sleep 1
echo "    DIDServer PID=$DID_PID, 监听 $DID_ADDR (日志: didserver.log)"

# 4. 启动多个 AttributeServer (并行), 仅 wait 这些子进程
echo "[3/7] 启动 $N_ATTRS 个 AttributeServer 提交承诺..."
ATTR_PIDS=""
for i in $(seq 0 $((N_ATTRS-1))); do
  ./bin/attrserver $i $DID_ADDR &
  ATTR_PIDS="$ATTR_PIDS $!"
done
# 仅等待 attrserver 子进程 (不等待 DIDServer)
for pid in $ATTR_PIDS; do
  wait $pid
done
echo "    所有 AttributeServer 提交完成"

# 5. 运行 DIDClient (提交参数 + 置换 + 获取 Root)
echo "[4/7] 运行 DIDClient..."
./bin/didclient $DID_ADDR $N_ATTRS
echo "    DIDClient 完成"

# 6. 运行 ProofGen (为叶子 0 生成证明)
echo "[5/7] 运行 ProofGen (为叶子 0 生成证明)..."
./bin/proofgen aggregator_output.json 0 merkle_proof_0.json
echo "    Proof 生成完成"

# 7. 停止 DIDServer
echo "[6/7] 停止 DIDServer..."
kill $DID_PID 2>/dev/null || true
echo "    DIDServer 已停止"

# 8. 运行单元测试
echo "[7/7] 运行单元测试..."
go test -run 'TestPedersen|TestReRandom|TestSecret|TestOblivious|TestFullPipe' ./utils/ -timeout 60s 2>&1 | tail -3

echo ""
echo "============================================"
echo "  运行完成! 输出文件:"
echo "  - aggregator_output.json  (Merkle Root + 叶子数据)"
echo "  - merkle_proof_0.json     (叶子 0 的 Merkle proof)"
echo "============================================"
