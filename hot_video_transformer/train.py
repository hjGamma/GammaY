"""
训练脚本
========
【如何运行训练】
  1. 确认依赖： pip install torch
  2. 直接运行： python train.py
  3. 训练产物保存在 outputs/ 目录下，包括：
     - model_latest.pt   最新 checkpoint
     - model_best.pt     验证集最佳 checkpoint
     - train.log         训练日志

【如何修改训练】
  - 改超参数（学习率、batch size、训练步数）：修改 config.py -> TrainConfig
  - 改模型架构（层数、宽度、注意力头数）：修改 config.py -> ModelConfig
  - 换数据集：替换下方 build_dataloader 中的 SimulatedVideoDataset
  - 改损失函数：修改下方 loss_fn
  - 改优化器：修改 build_optimizer
  - 从断点续训：设置 RESUME_PATH = "outputs/model_latest.pt"

【训练目标说明】
  本模型是一个"排序 + 汇总"双任务模型：
  1. 排名任务（主任务）：预测每个视频的热度分数，用 ListMLE 损失让排序接近真值。
     通俗理解：模型学会把"真正热门的视频"排在前面。
  2. 汇总任务（辅助任务）：用对比学习让 Top-K 汇总向量在同类视频间接近、不同类间远离。
     通俗理解：模型学会从热门视频中提炼出共性主题。
"""
import os
import sys
import time
import math
import random
import logging
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, random_split
from torch.cuda.amp import autocast, GradScaler

# 把项目根目录加入路径
sys.path.insert(0, str(Path(__file__).parent))

from config import Config, DEFAULT_CONFIG
from data.simulator import SimulatedVideoDataset, collate_fn
from model.transformer import HotVideoTransformer
from utils import prepare_batch


# ───────────────── 可修改的训练入口配置 ─────────────────
RESUME_PATH = None   # 断点续训路径，例如 "outputs/model_latest.pt"


# ───────────────── 工具函数 ─────────────────
def setup_logging(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "train.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    return logging.getLogger()


def set_seed(seed: int):
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


# ───────────────── 损失函数 ─────────────────
def listmle_loss(pred_scores: torch.Tensor, true_ranks: torch.Tensor,
                 eps: float = 1e-8) -> torch.Tensor:
    """
    ListMLE 损失：Learning to Rank 的经典 list-wise 损失。
    思想：给定真实排序，最大化该排列的似然。
    pred_scores: [B, N] 模型预测的分数（越高越热）
    true_ranks: [B, N] 真实排名（0 = 最热）
    返回: 标量损失
    """
    B, N = pred_scores.shape
    # 把真实排名换成降序索引（按 rank 从小到大 = 从热到冷）
    sorted_idx = torch.argsort(true_ranks, dim=1, descending=False)  # [B, N]
    # 把 pred_scores 按真实排序重新排列
    ordered = torch.gather(pred_scores, 1, sorted_idx)              # [B, N]
    # ListMLE: -log( prod_i exp(s_i) / sum_{j>=i} exp(s_j) )
    # 数值稳定版本
    cumsum = torch.cumsum(ordered.flip(1), dim=1).flip(1)          # [B, N], 累计后缀和(指数前)
    # logsumexp 技巧：log sum_j exp(s_j)  for j >= i
    # 我们用更稳定的方式：对每行做 logcumsumexp
    log_cumsum_exp = torch.logcumsumexp(ordered.flip(1), dim=1).flip(1)
    loss = (-ordered + log_cumsum_exp).mean()
    return loss


def summary_contrastive_loss(summary: torch.Tensor, top_categories: torch.Tensor,
                             temperature: float = 0.1) -> torch.Tensor:
    """
    汇总向量的对比学习损失。
    思想：同一主类别的视频集合，其汇总向量应该相似；不同类别应该远离。
    summary: [B, D] 汇总向量
    top_categories: [B] 每个样本 Top-1 视频的类别（作为代理标签）
    """
    B, D = summary.shape
    if B < 2:
        return torch.tensor(0.0, device=summary.device)
    # L2 归一化
    summary = F.normalize(summary, dim=-1)
    # 相似度矩阵
    sim = summary @ summary.t() / temperature           # [B, B]
    # 同类为正样本，不同类为负样本
    labels = top_categories.unsqueeze(0) == top_categories.unsqueeze(1)  # [B,B]
    # 对角线不算
    mask = ~torch.eye(B, dtype=torch.bool, device=summary.device)
    # 对每一行做交叉熵：正样本位置的 log-prob
    sim = sim.masked_fill(~mask, -1e9)
    log_probs = F.log_softmax(sim, dim=-1)
    # 正样本的平均 log_prob
    pos_mask = labels & mask
    if pos_mask.sum() == 0:
        return torch.tensor(0.0, device=summary.device)
    pos_log_prob = (log_probs * pos_mask.float()).sum(dim=-1) / pos_mask.float().sum(dim=-1).clamp(min=1)
    loss = -pos_log_prob.mean()
    return loss


# ───────────────── 优化器 & 学习率调度 ─────────────────
def build_optimizer(model: nn.Module, cfg) -> torch.optim.Optimizer:
    """
    AdamW 优化器，对 bias 和 LayerNorm 参数不加 weight_decay。
    """
    t = cfg.train
    decay = set()
    no_decay = set()
    whitelist = (nn.Linear, nn.Conv1d, nn.Conv2d, nn.Embedding)
    blacklist = (nn.LayerNorm, nn.BatchNorm1d, nn.BatchNorm2d)

    for name, p in model.named_parameters():
        if not p.requires_grad:
            continue
        if name.endswith("bias"):
            no_decay.add(name)
        elif name.endswith("weight") and isinstance(
            dict(model.named_modules())[name.rsplit(".", 1)[0]], whitelist
        ):
            decay.add(name)
        elif name.endswith("weight") and isinstance(
            dict(model.named_modules())[name.rsplit(".", 1)[0]], blacklist
        ):
            no_decay.add(name)
        else:
            no_decay.add(name)

    param_groups = [
        {"params": [p for n, p in model.named_parameters() if n in decay],
         "weight_decay": t.weight_decay},
        {"params": [p for n, p in model.named_parameters() if n in no_decay],
         "weight_decay": 0.0},
    ]
    return torch.optim.AdamW(param_groups, lr=t.learning_rate)


def get_lr(step: int, cfg) -> float:
    """
    带 warmup 的余弦学习率调度。
    step: 当前步数（从 0 开始）
    """
    t = cfg.train
    if step < t.warmup_steps:
        return t.learning_rate * (step + 1) / max(t.warmup_steps, 1)
    # 余弦退火
    progress = (step - t.warmup_steps) / max(t.max_steps - t.warmup_steps, 1)
    progress = min(progress, 1.0)
    return t.learning_rate * 0.5 * (1.0 + math.cos(math.pi * progress))


# ───────────────── 数据加载 ─────────────────
def build_dataloader(cfg):
    """
    构建训练/验证 DataLoader。
    【换成真实数据】：把 SimulatedVideoDataset 换成你自己的 Dataset 类即可。
    """
    d = cfg.data
    t = cfg.train

    dataset = SimulatedVideoDataset(
        num_samples=d.dataset_size,
        num_videos=d.num_videos_per_sample,
        num_categories=d.num_categories,
        seed=t.seed,
    )
    # 9:1 切分训练/验证
    val_size = max(1, int(len(dataset) * 0.1))
    train_size = len(dataset) - val_size
    train_set, val_set = random_split(
        dataset, [train_size, val_size],
        generator=torch.Generator().manual_seed(t.seed),
    )

    train_loader = DataLoader(
        train_set, batch_size=t.batch_size, shuffle=True,
        collate_fn=collate_fn, num_workers=0, drop_last=True,
    )
    val_loader = DataLoader(
        val_set, batch_size=t.batch_size, shuffle=False,
        collate_fn=collate_fn, num_workers=0, drop_last=False,
    )
    return train_loader, val_loader


# ───────────────── 评估函数 ─────────────────
@torch.no_grad()
def evaluate(model, val_loader, cfg, device, logger):
    """
    评估指标：
    - Top-K 准确率：模型选出的 Top-K 中，有多少比例在真实 Top-K 里（Hit Ratio）
    - NDCG@K：归一化折损累计增益
    - 排名损失
    """
    model.eval()
    k = cfg.data.top_k
    total_loss = 0.0
    total_hr = 0.0
    total_ndcg = 0.0
    n_batch = 0

    for batch in val_loader:
        batch_t = prepare_batch(batch, cfg)
        # 移到 GPU
        inputs = {k: v.to(device) if isinstance(v, torch.Tensor) else v
                  for k, v in batch_t.items()}
        outputs = model(
            inputs["title_ids"], inputs["title_mask"],
            inputs["desc_ids"], inputs["desc_mask"],
            inputs["numeric"], inputs["categories"],
        )
        loss = listmle_loss(outputs["scores"], inputs["ranks"])
        total_loss += loss.item()

        # Hit Ratio & NDCG
        pred_scores = outputs["scores"]                       # [B, N]
        true_ranks = inputs["ranks"]                           # [B, N]
        _, pred_topk = torch.topk(pred_scores, k, dim=1)       # [B, k]
        # 真实 Top-K 的 rank < k
        true_topk_mask = true_ranks < k                        # [B, N]
        B = pred_scores.shape[0]
        hr_sum = 0.0
        ndcg_sum = 0.0
        for i in range(B):
            pred_set = set(pred_topk[i].tolist())
            true_set = set(torch.where(true_topk_mask[i])[0].tolist())
            hit = len(pred_set & true_set)
            hr_sum += hit / min(k, len(true_set)) if true_set else 0.0
            # NDCG
            dcg = 0.0
            idcg = 0.0
            # 按预测排序的真实相关性（1=在topk，0=不在）
            _, pred_order = torch.sort(pred_scores[i], descending=True)
            for rank, idx in enumerate(pred_order[:k].tolist()):
                rel = 1.0 if idx in true_set else 0.0
                dcg += rel / math.log2(rank + 2)
            # IDCG：全部真实topk排前面
            for rank in range(min(k, len(true_set))):
                idcg += 1.0 / math.log2(rank + 2)
            ndcg_sum += dcg / idcg if idcg > 0 else 0.0
        total_hr += hr_sum / B
        total_ndcg += ndcg_sum / B
        n_batch += 1

    model.train()
    return {
        "val_loss": total_loss / max(n_batch, 1),
        "hr@k": total_hr / max(n_batch, 1),
        "ndcg@k": total_ndcg / max(n_batch, 1),
    }


# ───────────────── 主训练循环 ─────────────────
def train(cfg: Config = DEFAULT_CONFIG):
    t = cfg.train
    logger = setup_logging(t.output_dir)
    set_seed(t.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"使用设备: {device}")

    # 1. 数据
    train_loader, val_loader = build_dataloader(cfg)
    logger.info(f"训练集大小: {len(train_loader.dataset)}, "
                f"验证集大小: {len(val_loader.dataset)}")

    # 2. 模型
    model = HotVideoTransformer(cfg).to(device)
    n_params = sum(p.numel() for p in model.parameters()) / 1e6
    logger.info(f"模型参数量: {n_params:.2f}M")

    # 3. 优化器
    optimizer = build_optimizer(model, cfg)

    # 4. 混合精度
    use_amp = t.mixed_precision in ("fp16", "bf16")
    amp_dtype = torch.bfloat16 if t.mixed_precision == "bf16" else torch.float16
    scaler = GradScaler(enabled=(use_amp and t.mixed_precision == "fp16"))
    logger.info(f"混合精度: {t.mixed_precision}, use_amp={use_amp}")

    # 5. 断点续训
    start_step = 0
    best_hr = 0.0
    if RESUME_PATH and os.path.exists(RESUME_PATH):
        ckpt = torch.load(RESUME_PATH, map_location=device, weights_only=False)
        model.load_state_dict(ckpt["model"])
        optimizer.load_state_dict(ckpt["optimizer"])
        start_step = ckpt.get("step", 0) + 1
        best_hr = ckpt.get("best_hr", 0.0)
        logger.info(f"从 {RESUME_PATH} 恢复训练，从 step {start_step} 开始")

    # 6. 训练循环
    model.train()
    step = start_step
    data_iter = iter(train_loader)
    t0 = time.time()

    while step < t.max_steps:
        # 重新取数据（一个 epoch 完了就重来）
        try:
            batch = next(data_iter)
        except StopIteration:
            data_iter = iter(train_loader)
            batch = next(data_iter)

        # 处理 batch
        batch_t = prepare_batch(batch, cfg)
        inputs = {k: v.to(device) if isinstance(v, torch.Tensor) else v
                  for k, v in batch_t.items()}

        # 设置学习率
        lr = get_lr(step, cfg)
        for pg in optimizer.param_groups:
            pg["lr"] = lr

        # 前向
        optimizer.zero_grad()
        with autocast(enabled=use_amp, dtype=amp_dtype):
            outputs = model(
                inputs["title_ids"], inputs["title_mask"],
                inputs["desc_ids"], inputs["desc_mask"],
                inputs["numeric"], inputs["categories"],
            )
            # 排名损失
            loss_rank = listmle_loss(outputs["scores"], inputs["ranks"])
            # 汇总对比损失（用 Top-1 视频类别作为标签）
            _, top1_idx = torch.max(outputs["scores"], dim=1)
            top1_cat = torch.gather(inputs["categories"], 1, top1_idx.unsqueeze(1)).squeeze(1)
            loss_sum = summary_contrastive_loss(outputs["summary"], top1_cat)
            # 总损失
            loss = t.loss_rank_weight * loss_rank + t.loss_summary_weight * loss_sum

        # 反向
        if t.mixed_precision == "fp16":
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), t.grad_clip)
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), t.grad_clip)
            optimizer.step()

        # 日志
        if step % t.log_interval == 0:
            elapsed = time.time() - t0
            logger.info(
                f"Step {step}/{t.max_steps} | "
                f"LR {lr:.2e} | "
                f"Loss {loss.item():.4f} (rank {loss_rank.item():.4f}, "
                f"sum {loss_sum.item():.4f}) | "
                f"{t.log_interval / elapsed:.1f} step/s"
            )
            t0 = time.time()

        # 评估
        if step > 0 and step % t.eval_interval == 0:
            metrics = evaluate(model, val_loader, cfg, device, logger)
            logger.info(
                f"[Val] Step {step} | loss={metrics['val_loss']:.4f} | "
                f"HR@{cfg.data.top_k}={metrics['hr@k']:.4f} | "
                f"NDCG@{cfg.data.top_k}={metrics['ndcg@k']:.4f}"
            )
            # 保存最佳
            if metrics["hr@k"] > best_hr:
                best_hr = metrics["hr@k"]
                save_path = os.path.join(t.output_dir, "model_best.pt")
                torch.save({
                    "model": model.state_dict(),
                    "optimizer": optimizer.state_dict(),
                    "step": step,
                    "best_hr": best_hr,
                    "config": cfg,
                }, save_path)
                logger.info(f"保存最佳模型到 {save_path} (HR={best_hr:.4f})")
            model.train()

        # 定期保存
        if step > 0 and step % t.save_interval == 0:
            save_path = os.path.join(t.output_dir, "model_latest.pt")
            torch.save({
                "model": model.state_dict(),
                "optimizer": optimizer.state_dict(),
                "step": step,
                "best_hr": best_hr,
                "config": cfg,
            }, save_path)

        step += 1

    # 训练结束
    save_path = os.path.join(t.output_dir, "model_final.pt")
    torch.save({
        "model": model.state_dict(),
        "optimizer": optimizer.state_dict(),
        "step": step - 1,
        "best_hr": best_hr,
        "config": cfg,
    }, save_path)
    logger.info(f"训练完成！最终模型保存到 {save_path}")
    logger.info(f"最佳 HR@{cfg.data.top_k} = {best_hr:.4f}")


if __name__ == "__main__":
    train()
