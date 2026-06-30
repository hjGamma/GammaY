"""
推理 / Top-K 热点视频汇总脚本
============================
【如何使用】
  1. 训练完成后，指定模型路径运行：
     python inference.py --ckpt outputs/model_best.pt
  2. 也可以不指定 ckpt，直接用随机权重看流程（仅测试）。

【功能】
  - 加载训练好的模型
  - 输入一批视频元数据（模拟或真实）
  - 输出 Top-K 热点视频排名 + 汇总信息
"""
import os
import sys
import json
import argparse
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).parent))

from config import Config, DEFAULT_CONFIG
from data.simulator import SimulatedVideoDataset, CATEGORIES
from model.transformer import HotVideoTransformer
from utils import prepare_batch


def load_model(ckpt_path: str, device: torch.device):
    """从 checkpoint 加载模型"""
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    cfg = ckpt.get("config", DEFAULT_CONFIG)
    model = HotVideoTransformer(cfg).to(device)
    model.load_state_dict(ckpt["model"])
    model.eval()
    print(f"已加载模型: {ckpt_path} (step={ckpt.get('step', '?')})")
    return model, cfg


def infer(model, cfg, batch, device):
    """对一批数据做推理，返回 Top-K 结果"""
    batch_t = prepare_batch(batch, cfg)
    inputs = {k: v.to(device) if isinstance(v, torch.Tensor) else v
              for k, v in batch_t.items()}
    with torch.no_grad():
        outputs = model(
            inputs["title_ids"], inputs["title_mask"],
            inputs["desc_ids"], inputs["desc_mask"],
            inputs["numeric"], inputs["categories"],
        )
    return outputs


def print_top_k(batch, outputs, cfg, sample_idx=0):
    """打印一个样本的 Top-K 结果"""
    k = cfg.data.top_k
    scores = outputs["scores"][sample_idx].cpu()     # [N]
    titles = batch["titles"][sample_idx]
    descs = batch["descs"][sample_idx]
    numeric = batch["numeric"][sample_idx]            # [N, 7]
    categories = batch["categories"][sample_idx]      # [N]
    true_scores = batch["hot_scores"][sample_idx]     # [N]

    # 模型预测 Top-K
    _, pred_topk = torch.topk(scores, k)
    # 真实 Top-K
    _, true_topk = torch.topk(true_scores, k)

    print("\n" + "=" * 70)
    print(f"  样本 {sample_idx}: 模型预测 Top-{k} 热点视频")
    print("=" * 70)
    for rank, idx in enumerate(pred_topk.tolist()):
        cat_name = CATEGORIES[categories[idx].item()]
        views = numeric[idx, 0].item()
        hours = numeric[idx, 5].item()
        print(f"\n  第 {rank+1} 名 (热度分: {scores[idx].item():.2f})")
        print(f"    标题: {titles[idx]}")
        print(f"    类别: {cat_name} | 播放量: {views:,.0f} | 发布: {hours:.1f}h前")
        print(f"    描述: {descs[idx][:60]}...")

    print("\n" + "=" * 70)
    print(f"  真实 Top-{k}（对比）")
    print("=" * 70)
    for rank, idx in enumerate(true_topk.tolist()):
        cat_name = CATEGORIES[categories[idx].item()]
        print(f"  第 {rank+1} 名 (真实热度: {true_scores[idx].item():.2f}) "
              f"- {titles[idx][:30]}... [{cat_name}]")

    # 命中统计
    pred_set = set(pred_topk.tolist())
    true_set = set(true_topk.tolist())
    hit = len(pred_set & true_set)
    print(f"\n  命中率 (Hit@{k}): {hit}/{k} = {hit/k:.0%}")


def main():
    parser = argparse.ArgumentParser(description="热点视频 Top-K 推理")
    parser.add_argument("--ckpt", type=str, default=None,
                        help="训练好的模型路径，不指定则用随机权重（仅测试）")
    parser.add_argument("--num_samples", type=int, default=3,
                        help="推理多少个样本")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # 加载模型或用默认配置创建
    if args.ckpt and os.path.exists(args.ckpt):
        model, cfg = load_model(args.ckpt, device)
    else:
        print("未找到 checkpoint，使用随机权重（仅测试流程）...")
        cfg = DEFAULT_CONFIG
        model = HotVideoTransformer(cfg).to(device)
        model.eval()

    # 生成模拟测试数据
    dataset = SimulatedVideoDataset(
        num_samples=args.num_samples,
        num_videos=cfg.data.num_videos_per_sample,
        num_categories=cfg.data.num_categories,
        seed=args.seed + 9999,
    )

    for i in range(args.num_samples):
        # 取一个样本并拼成 batch
        sample = dataset[i]
        batch = {
            "titles": [sample["titles"]],
            "descs": [sample["descs"]],
            "numeric": sample["numeric"].unsqueeze(0),
            "categories": sample["categories"].unsqueeze(0),
            "hot_scores": sample["hot_scores"].unsqueeze(0),
            "ranks": sample["ranks"].unsqueeze(0),
            "sorted_indices": sample["sorted_indices"].unsqueeze(0),
        }
        outputs = infer(model, cfg, batch, device)
        print_top_k(batch, outputs, cfg, sample_idx=0)


if __name__ == "__main__":
    main()
