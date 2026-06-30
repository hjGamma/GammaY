#!/bin/bash
# ============================================================
# DID 系统一键运行脚本 (优化版)
# 优化点: 流式提交, 连接复用, sync.Cond 等待, 异步重随机化, G 订阅
# 用法: ./run_did.sh [属性数量] [服务器数量] [MPC节点数]
# ============================================================

set -e

NUM_ATTRS=${1:-4}
NUM_SERVERS=${2:-4}
NUM_MPC_NODES=${3:-4}
NUM_SHARDS=$NUM_MPC_NODES

echo "============================================================"
echo " DID 系统 (优化版) 运行脚本"
echo "   属性数量:   $NUM_ATTRS"
echo "   服务器数量: $NUM_SERVERS"
echo "   MPC 节点:   $NUM_MPC_NODES"
echo "   分片数:     $NUM_SHARDS"
echo "============================================================"

# 1. 编译二进制
echo ""
echo "[1/7] 编译二进制..."
mkdir -p bin
go build -o bin/didserver   ./didserver/
go build -o bin/attrserver  ./attrserver/
go build -o bin/didclient   ./didclient/
go build -o bin/mpcnode     ./mpcnode/
go build -o bin/proofgen    ./proofgen/
go build -o bin/aggregator  ./aggregator/
go build -o bin/bench       ./bench/
echo "    编译完成"

# 2. 启动 DIDServer
echo ""
echo "[2/7] 启动 DIDServer (TLS, :5000)..."
./bin/didserver > didserver.log 2>&1 &
DID_PID=$!
echo "    DIDServer PID: $DID_PID"
sleep 1

# 3. 启动 MPC 节点 (可选, 当前 DIDServer 本地模拟 MPC)
echo ""
echo "[3/7] 启动 $NUM_MPC_NODES 个 MPC 节点 (端口 6000-600x)..."
MPC_PIDS=()
for i in $(seq 0 $((NUM_MPC_NODES-1))); do
    PORT=$((6000+i))
    ./bin/mpcnode -id $i -port $PORT > mpcnode_$i.log 2>&1 &
    MPC_PIDS+=($!)
    echo "    MPCNode-$i PID: ${MPC_PIDS[$i]} (端口 $PORT)"
done
sleep 1

# 4. 并行启动属性服务器 (流式批量提交)
echo ""
echo "[4/7] 并行启动 $NUM_SERVERS 个属性服务器..."
ATTRS_PER_SERVER=$(( (NUM_ATTRS + NUM_SERVERS - 1) / NUM_SERVERS ))
ATTR_PIDS=()
for i in $(seq 0 $((NUM_SERVERS-1))); do
    ./bin/attrserver -id $i -addr localhost:5000 -n $ATTRS_PER_SERVER -shards $NUM_SHARDS > attrserver_$i.log 2>&1 &
    ATTR_PIDS+=($!)
    echo "    AttrServer-$i PID: ${ATTR_PIDS[$i]} (属性数 $ATTRS_PER_SERVER)"
done

# 等待所有属性服务器完成
for pid in "${ATTR_PIDS[@]}"; do
    wait $pid
    echo "    AttrServer PID $pid 完成"
done

# 5. 运行 DIDClient (连接复用 + G 订阅 + 阶段等待)
echo ""
echo "[5/7] 运行 DIDClient..."
./bin/didclient -addr localhost:5000 -n $NUM_ATTRS -shards $NUM_SHARDS
echo "    DIDClient 完成"

# 6. 生成 Merkle Proof
echo ""
echo "[6/7] 生成 Merkle Proof (leaf 0)..."
./bin/proofgen aggregator_output.json 0 merkle_proof_0.json 2>&1 || echo "    (proofgen 可选)"

# 7. 停止服务器
echo ""
echo "[7/7] 停止服务..."
kill $DID_PID 2>/dev/null || true
for pid in "${MPC_PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done
echo "    已停止"

# 验证输出
echo ""
echo "============================================================"
echo " 运行结果"
echo "============================================================"
if [ -f aggregator_output.json ]; then
    echo "Merkle Root:"
    grep merkle_root aggregator_output.json | head -1
    echo ""
    echo "叶子数量:"
    grep num_leaves aggregator_output.json | head -1
fi

if [ -f merkle_proof_0.json ]; then
    echo ""
    echo "Proof 验证结果:"
    grep verified merkle_proof_0.json | head -1
fi

echo ""
echo "日志文件:"
echo "  - didserver.log"
for i in $(seq 0 $((NUM_SERVERS-1))); do
    echo "  - attrserver_$i.log"
done
for i in $(seq 0 $((NUM_MPC_NODES-1))); do
    echo "  - mpcnode_$i.log"
done
echo ""
echo "完成!"
