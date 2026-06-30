"""
Transformer 主体 + 输出头
=========================
- 主体：标准 Transformer Encoder（可选 RoPE），处理视频间交互。
- 排名头：每个视频输出一个热度标量，用于排序选 Top-K。
- 汇总头：基于 Top-K 视频的特征，输出一个全局汇总向量。

【如何修改架构】
- 加深/加宽：改 config.py -> ModelConfig.num_layers / hidden_size
- 换注意力：把 MultiheadAttention 替换为 FlashAttention / Linformer / Performer
- 加时序因果掩码：在 forward 传 attn_mask（例如视频按时间排序时只看过去）
- 改汇总方式：把 "topk pool + MLP" 换成 "交叉注意力解码器" 等
"""
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


# ─────────────── RoPE 旋转位置编码（1D，用于视频序列）───────────────
class RotaryEmbed1D(nn.Module):
    def __init__(self, hidden_size: int, num_heads: int, theta: float = 10000.0):
        super().__init__()
        self.head_dim = hidden_size // num_heads
        self.num_heads = num_heads
        self.theta = theta
        # 预计算频率
        freqs = 1.0 / (theta ** (
            torch.arange(0, self.head_dim, 2).float() / self.head_dim
        ))
        self.register_buffer("freqs", freqs, persistent=False)

    def forward(self, seq_len: int, device):
        t = torch.arange(seq_len, device=device).float()
        angles = torch.outer(t, self.freqs.to(device))       # [N, D/2]
        cos = angles.cos()[:, None, :]                        # [N, 1, D/2]
        sin = angles.sin()[:, None, :]
        return cos, sin


def apply_rope_1d(q, k, cos, sin):
    """
    q, k: [B, H, N, D]
    cos, sin: [N, 1, D/2]  -> 需要转成 [1, 1, N, D/2]
    """
    d = q.shape[-1]
    half = d // 2
    q1, q2 = q[..., :half], q[..., half:]
    k1, k2 = k[..., :half], k[..., half:]
    # cos/sin 形状 [N, 1, D/2] -> [1, 1, N, D/2]
    cos = cos.permute(1, 0, 2).unsqueeze(0)  # [1, 1, N, D/2]
    sin = sin.permute(1, 0, 2).unsqueeze(0)
    q_rot = torch.cat([q1 * cos - q2 * sin, q1 * sin + q2 * cos], dim=-1)
    k_rot = torch.cat([k1 * cos - k2 * sin, k1 * sin + k2 * cos], dim=-1)
    return q_rot, k_rot


# ─────────────── 自注意力层（含 RoPE）───────────────
class SelfAttention(nn.Module):
    def __init__(self, hidden_size: int, num_heads: int, dropout: float = 0.0):
        super().__init__()
        self.num_heads = num_heads
        self.head_dim = hidden_size // num_heads
        self.scale = self.head_dim ** -0.5
        self.qkv = nn.Linear(hidden_size, hidden_size * 3, bias=True)
        self.proj = nn.Linear(hidden_size, hidden_size)
        self.drop = nn.Dropout(dropout)

    def forward(self, x, cos=None, sin=None, mask=None):
        B, N, C = x.shape
        qkv = self.qkv(x).reshape(B, N, 3, self.num_heads, self.head_dim)
        qkv = qkv.permute(2, 0, 3, 1, 4)        # [3, B, H, N, D]
        q, k, v = qkv[0], qkv[1], qkv[2]
        if cos is not None and sin is not None:
            q, k = apply_rope_1d(q, k, cos, sin)
        attn = (q @ k.transpose(-2, -1)) * self.scale
        if mask is not None:
            attn = attn.masked_fill(mask == 0, float("-inf"))
        attn = attn.softmax(dim=-1)
        attn = self.drop(attn)
        out = (attn @ v).transpose(1, 2).reshape(B, N, C)
        return self.proj(out)


# ─────────────── Transformer Block ───────────────
class TransformerBlock(nn.Module):
    def __init__(self, hidden_size: int, num_heads: int,
                 mlp_ratio: float, dropout: float = 0.0,
                 use_rope: bool = True):
        super().__init__()
        self.norm1 = nn.LayerNorm(hidden_size)
        self.attn = SelfAttention(hidden_size, num_heads, dropout)
        self.norm2 = nn.LayerNorm(hidden_size)
        mlp_hid = int(hidden_size * mlp_ratio)
        self.mlp = nn.Sequential(
            nn.Linear(hidden_size, mlp_hid),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(mlp_hid, hidden_size),
            nn.Dropout(dropout),
        )
        self.use_rope = use_rope

    def forward(self, x, cos=None, sin=None, mask=None):
        x = x + self.attn(self.norm1(x), cos, sin, mask)
        x = x + self.mlp(self.norm2(x))
        return x


# ─────────────── 排名头 ───────────────
class RankingHead(nn.Module):
    """
    对每个视频输出一个标量热度分数。
    分数越高 = 越热。用 ListMLE 或 MSE 训练。
    """

    def __init__(self, hidden_size: int, hidden_layers: list):
        super().__init__()
        layers = []
        in_dim = hidden_size
        for hid in hidden_layers:
            layers.append(nn.Linear(in_dim, hid))
            layers.append(nn.GELU())
            in_dim = hid
        layers.append(nn.Linear(in_dim, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        # x: [B, N, D] -> [B, N]
        return self.net(x).squeeze(-1)


# ─────────────── 汇总头 ───────────────
class SummaryHead(nn.Module):
    """
    从 Top-K 视频特征中生成一个全局汇总向量。
    方法：取出 Top-K 特征 -> 加权平均（用排名分数做 softmax 权重）
          -> MLP 映射到 summary_dim。
    """

    def __init__(self, hidden_size: int, top_k: int,
                 hidden_layers: list, summary_dim: int):
        super().__init__()
        self.top_k = top_k
        layers = []
        in_dim = hidden_size
        for hid in hidden_layers:
            layers.append(nn.Linear(in_dim, hid))
            layers.append(nn.GELU())
            in_dim = hid
        layers.append(nn.Linear(in_dim, summary_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x, scores):
        """
        x: [B, N, D] 视频特征
        scores: [B, N] 热度分数（越高越热）
        return: [B, summary_dim] 汇总向量
        """
        B, N, D = x.shape
        k = min(self.top_k, N)
        # 取 Top-K 索引
        _, top_idx = torch.topk(scores, k, dim=1)          # [B, k]
        top_idx_exp = top_idx.unsqueeze(-1).expand(-1, -1, D)
        top_feats = torch.gather(x, 1, top_idx_exp)         # [B, k, D]
        # 用分数做 softmax 加权平均
        top_scores = torch.gather(scores, 1, top_idx)       # [B, k]
        weights = F.softmax(top_scores, dim=1).unsqueeze(-1)  # [B, k, 1]
        pooled = (top_feats * weights).sum(dim=1)            # [B, D]
        return self.net(pooled)


# ─────────────── 完整模型 ───────────────
class HotVideoTransformer(nn.Module):
    """
    热点视频 Transformer 大模型。
    输入：一批视频的多模态特征
    输出：
        - scores: [B, N] 每个视频的热度分数
        - summary: [B, summary_dim] 全局热点汇总向量
    """

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        m = cfg.model

        # 1. 视频级编码器
        from .encoder import VideoEncoder
        self.video_encoder = VideoEncoder(cfg)

        # 2. 位置编码
        self.use_rope = m.use_rope
        if m.use_rope:
            self.rope = RotaryEmbed1D(m.hidden_size, m.num_heads)
        else:
            # 可学习绝对位置编码（最大支持 1000 个视频）
            self.pos_embed = nn.Parameter(
                torch.zeros(1, 1000, m.hidden_size)
            )
            nn.init.trunc_normal_(self.pos_embed, std=0.02)

        # 3. Transformer 主体
        self.layers = nn.ModuleList([
            TransformerBlock(m.hidden_size, m.num_heads, m.mlp_ratio,
                             m.dropout, m.use_rope)
            for _ in range(m.num_layers)
        ])
        self.final_norm = nn.LayerNorm(m.hidden_size)

        # 4. 输出头
        self.ranking_head = RankingHead(m.hidden_size, m.ranking_hidden)
        self.summary_head = SummaryHead(
            m.hidden_size, cfg.data.top_k,
            m.summary_hidden, m.summary_dim,
        )

    def forward(self, title_ids, title_mask, desc_ids, desc_mask,
                numeric, categories):
        """
        返回:
            scores: [B, N] 热度分数
            summary: [B, summary_dim] 汇总向量
            feats: [B, N, D] Transformer 输出的视频特征（用于调试/分析）
        """
        B, N, _ = title_ids.shape

        # 1. 编码每个视频
        feats = self.video_encoder(
            title_ids, title_mask, desc_ids, desc_mask,
            numeric, categories,
        )  # [B, N, D]

        # 2. 位置编码
        if self.use_rope:
            cos, sin = self.rope(N, feats.device)
        else:
            feats = feats + self.pos_embed[:, :N, :]
            cos = sin = None

        # 3. Transformer 堆叠
        for layer in self.layers:
            feats = layer(feats, cos, sin)
        feats = self.final_norm(feats)

        # 4. 输出头
        scores = self.ranking_head(feats)
        summary = self.summary_head(feats, scores)

        return {
            "scores": scores,     # [B, N]
            "summary": summary,   # [B, summary_dim]
            "feats": feats,       # [B, N, D]
        }
