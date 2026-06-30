"""
DiT 视频生成主体
================
Diffusion Transformer：在 latent/像素空间做去噪。
- 输入：噪声视频 [B,C,T,H,W] + 时间步 t + 类别 c
- 输出：预测的噪声/速度 [B,C,T,H,W]

【如何修改架构】
1. 改 block 数量/宽度：config.py -> ModelConfig.depth / hidden_size
2. 加新条件（如文本）：在 __init__ 加 text embed，拼到 cond_emb
3. 换注意力为窗口/线性注意力：替换 blocks.Attention
4. 加时序因果掩码：在 DiTBlock 传 attn_mask
"""
import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.checkpoint import checkpoint

from .blocks import (
    VideoPatchEmbed3D, RotaryEmbed3D, Attention, Mlp,
    Modulation, modulate,
)


class DiTBlock(nn.Module):
    """一个 DiT Transformer Block（adaLN-Zero 版）"""

    def __init__(self, hidden_size, num_heads, mlp_ratio, dropout=0.0,
                 use_checkpoint=False):
        super().__init__()
        self.norm1 = nn.LayerNorm(hidden_size, elementwise_affine=False, eps=1e-6)
        self.attn = Attention(hidden_size, num_heads, dropout)
        self.norm2 = nn.LayerNorm(hidden_size, elementwise_affine=False, eps=1e-6)
        self.mlp = Mlp(hidden_size, int(hidden_size * mlp_ratio), dropout)
        self.adaLN = Modulation(hidden_size, hidden_size, num=6)
        self.use_checkpoint = use_checkpoint

    def _forward(self, x, c, cos, sin):
        shift_msa, scale_msa, gate_msa, shift_mlp, scale_mlp, gate_mlp = \
            self.adaLN(c).chunk(6, dim=1)              # 各为 [B,1,D]
        # 自注意力分支
        h = modulate(self.norm1(x), shift_msa, scale_msa)
        h = self.attn(h, cos, sin)
        x = x + gate_msa * h
        # FFN 分支
        h = modulate(self.norm2(x), shift_mlp, scale_mlp)
        h = self.mlp(h)
        x = x + gate_mlp * h
        return x

    def forward(self, x, c, cos, sin):
        if self.use_checkpoint and self.training:
            return checkpoint(self._forward, x, c, cos, sin, use_reentrant=False)
        return self._forward(x, c, cos, sin)


class TimestepEmbedder(nn.Module):
    """把整数时间步 embedding 成向量（正弦 + MLP）"""

    def __init__(self, hidden_size):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.SiLU(),
            nn.Linear(hidden_size, hidden_size),
        )
        self.dim = hidden_size

    def forward(self, t):
        half = self.dim // 2
        freqs = torch.exp(-math.log(10000) * torch.arange(half, device=t.device) / half)
        args = t[:, None].float() * freqs[None]
        emb = torch.cat([torch.cos(args), torch.sin(args)], dim=-1)
        if self.dim % 2 == 1:
            emb = F.pad(emb, (0, 1))
        return self.mlp(emb)


class LabelEmbedder(nn.Module):
    """类别 embedding + Classifier-Free Guidance 的 dropout"""

    def __init__(self, num_classes, hidden_size, dropout_prob=0.1):
        super().__init__()
        # +1 个"无条件"类别，用于 CFG
        self.num_classes = num_classes + 1
        self.uncond_id = num_classes
        self.table = nn.Embedding(self.num_classes, hidden_size)
        self.dropout_prob = dropout_prob

    def forward(self, labels, train=True):
        if train and self.dropout_prob > 0:
            drop = torch.rand_like(labels.float()) < self.dropout_prob
            labels = torch.where(drop, torch.full_like(labels, self.uncond_id), labels)
        return self.table(labels)


class VideoDiT(nn.Module):
    """视频 Diffusion Transformer"""

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        m = cfg.model
        v = cfg.video

        self.patch_embed = VideoPatchEmbed3D(m.patch_size, m.in_channels, m.hidden_size)
        pt, ph, pw = m.patch_size
        self.T_patch = v.num_frames // pt
        self.H_patch = v.image_size // ph
        self.W_patch = v.image_size // pw

        # 位置编码
        if m.use_rope:
            self.rope = RotaryEmbed3D(m.hidden_size, m.num_heads)
        else:
            # 退化为可学习绝对位置编码
            self.pos_embed = nn.Parameter(
                torch.zeros(1, self.T_patch * self.H_patch * self.W_patch, m.hidden_size)
            )
            nn.init.trunc_normal_(self.pos_embed, std=0.02)
        self.use_rope = m.use_rope

        # 条件 embedding
        self.t_embed = TimestepEmbedder(m.hidden_size)
        self.y_embed = LabelEmbedder(m.num_classes, m.hidden_size, m.class_dropout_prob)

        # Transformer 主体
        self.blocks = nn.ModuleList([
            DiTBlock(m.hidden_size, m.num_heads, m.mlp_ratio, m.dropout,
                     use_checkpoint=m.use_checkpoint)
            for _ in range(m.depth)
        ])

        # 输出头：最终 adaLN + Linear 还原回 patch
        self.final_norm = nn.LayerNorm(m.hidden_size, elementwise_affine=False, eps=1e-6)
        self.final_ada = Modulation(m.hidden_size, m.hidden_size, num=2)
        self.out_proj = nn.Linear(m.hidden_size, m.in_channels * pt * ph * pw)
        nn.init.zeros_(self.out_proj.weight)
        nn.init.zeros_(self.out_proj.bias)

        self.patch_size = m.patch_size

    def forward(self, x, t, y):
        """
        x: [B, C, T, H, W] 噪声视频
        t: [B] 时间步
        y: [B] 类别
        return: [B, C, T, H, W] 预测噪声
        """
        B = x.shape[0]
        # 1. patch 化
        tokens, (T, H, W) = self.patch_embed(x)        # [B, N, D]
        N = tokens.shape[1]

        # 2. 位置编码
        if self.use_rope:
            cos, sin = self.rope(T, H, W, x.device)
        else:
            tokens = tokens + self.pos_embed
            cos = sin = None

        # 3. 条件
        c = self.t_embed(t) + self.y_embed(y, self.training)

        # 4. Transformer 堆叠
        for blk in self.blocks:
            tokens = blk(tokens, c, cos, sin)

        # 5. 输出头
        shift, scale = self.final_ada(c).chunk(2, dim=1)
        tokens = modulate(self.final_norm(tokens), shift, scale)
        tokens = self.out_proj(tokens)                 # [B, N, C*pt*ph*pw]

        # 6. 还原回 [B, C, T, H, W]
        pt, ph, pw = self.patch_size
        C = self.cfg.model.in_channels
        return self._fold(tokens, B, C, T, H, W, pt, ph, pw)

    def _fold(self, tokens, B, C, T, H, W, pt, ph, pw):
        """把 patch tokens 还原成视频 [B,C,T,H,W]"""
        # tokens: [B, N, C*pt*ph*pw], N = T*H*W
        x = tokens.reshape(B, T, H, W, C, pt, ph, pw)
        # 目标 [B, C, T, H, W] 其中 T=T*pt...
        # 实际是 [B, C, T*pt, H*ph, W*pw]
        x = x.permute(0, 4, 1, 5, 2, 6, 3, 7).contiguous()
        x = x.reshape(B, C, T * pt, H * ph, W * pw)
        return x
