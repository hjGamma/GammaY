"""
模型基础组件
============
包含：Patch 嵌入、RoPE 旋转位置编码、多模态条件注入(adaLN)、注意力、FFN。
所有组件都可单独替换 —— 想改架构时主要改这里。
"""
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


# ───────────────────────── 时空 Patch 嵌入 ─────────────────────────
class VideoPatchEmbed3D(nn.Module):
    """把 [B,C,T,H,W] 视频切成时空 patch，每个 patch 编码成一个 token。"""

    def __init__(self, patch_size=(2, 8, 8), in_channels=3, hidden_size=384):
        super().__init__()
        self.patch_size = patch_size
        # 用 3D 卷积一次性完成 "切块 + 线性投影"
        self.proj = nn.Conv3d(
            in_channels, hidden_size,
            kernel_size=patch_size, stride=patch_size,
        )
        pt, ph, pw = patch_size
        self.num_patches_per_frame = ph * pw
        self.grid_size = None  # 在 forward 里动态算

    def forward(self, x):
        # x: [B, C, T, H, W]
        x = self.proj(x)                       # [B, hidden, T', H', W']
        B, D, T, H, W = x.shape
        self.grid_size = (T, H, W)
        x = x.flatten(2).transpose(1, 2)       # [B, T*H*W, D]
        return x, (T, H, W)


# ───────────────────────── 旋转位置编码 RoPE ─────────────────────────
class RotaryEmbed3D(nn.Module):
    """
    3D 旋转位置编码：分别对 (T, H, W) 三个轴做 RoPE，再复合。
    比可学习的绝对位置编码更具外推性（推理时可换分辨率/帧数）。
    """

    def __init__(self, hidden_size, num_heads, theta=10000.0):
        super().__init__()
        assert hidden_size % num_heads == 0
        self.head_dim = hidden_size // num_heads
        self.num_heads = num_heads
        self.theta = theta
        # 每个轴分到 head_dim/3 的维度（处理整除）
        per_axis = self.head_dim // 3
        self.per_axis = per_axis

    def _build_freqs(self, seq_len, device):
        # 返回 [seq_len, per_axis] 的频率
        freqs = 1.0 / (self.theta ** (
            torch.arange(0, self.per_axis, device=device).float() / self.per_axis
        ))
        t = torch.arange(seq_len, device=device).float()
        angles = torch.outer(t, freqs)               # [seq, per_axis]
        return angles

    def forward(self, t_len, h_len, w_len, device):
        ft = self._build_freqs(t_len, device)
        fh = self._build_freqs(h_len, device)
        fw = self._build_freqs(w_len, device)
        # 每个空间位置展开成时序长度
        T, H, W = t_len, h_len, w_len
        # 构造每个 token 的三维坐标
        ct = torch.arange(T, device=device).view(T, 1, 1).expand(T, H, W)
        ch = torch.arange(H, device=device).view(1, H, 1).expand(T, H, W)
        cw = torch.arange(W, device=device).view(1, 1, W).expand(T, H, W)
        ct, ch, cw = ct.reshape(-1), ch.reshape(-1), cw.reshape(-1)
        # [N, per_axis] * 3
        at = ft[ct]
        ah = fh[ch]
        aw = fw[cw]
        ang = torch.cat([at, ah, aw], dim=-1)         # [N, 3*per_axis]
        # 补齐到 head_dim
        if ang.shape[-1] < self.head_dim:
            pad = torch.zeros(ang.shape[0], self.head_dim - ang.shape[-1], device=device)
            ang = torch.cat([ang, pad], dim=-1)
        else:
            ang = ang[..., :self.head_dim]
        cos = ang.cos()[None, :, None, :]             # [1, N, 1, head_dim]
        sin = ang.sin()[None, :, None, :]
        return cos, sin


def apply_rope(q, k, cos, sin):
    """对 q,k 应用 RoPE。q,k: [B, N, H, D]"""
    # 调整维度顺序到 [B, H, N, D]
    q = q.transpose(1, 2)
    k = k.transpose(1, 2)
    d = q.shape[-1]
    half = d // 2
    q1, q2 = q[..., :half], q[..., half:]
    k1, k2 = k[..., :half], k[..., half:]
    cos = cos[..., :half].transpose(1, 2)  # [1, N, 1, half] -> [1, 1, N, half]
    sin = sin[..., :half].transpose(1, 2)
    q_rot = torch.cat([q1 * cos - q2 * sin, q1 * sin + q2 * cos], dim=-1)
    k_rot = torch.cat([k1 * cos - k2 * sin, k1 * sin + k2 * cos], dim=-1)
    return q_rot.transpose(1, 2), k_rot.transpose(1, 2)


# ───────────────────────── 注意力 & FFN ─────────────────────────
class Attention(nn.Module):
    def __init__(self, dim, num_heads, dropout=0.0):
        super().__init__()
        self.num_heads = num_heads
        self.head_dim = dim // num_heads
        self.scale = self.head_dim ** -0.5
        self.qkv = nn.Linear(dim, dim * 3, bias=True)
        self.proj = nn.Linear(dim, dim)
        self.drop = nn.Dropout(dropout)

    def forward(self, x, cos=None, sin=None):
        B, N, C = x.shape
        qkv = self.qkv(x).reshape(B, N, 3, self.num_heads, self.head_dim)
        qkv = qkv.permute(2, 0, 1, 3, 4)
        q, k, v = qkv[0], qkv[1], qkv[2]          # [B, N, H, D]
        if cos is not None and sin is not None:
            q, k = apply_rope(q, k, cos, sin)
        q = q.transpose(1, 2)                      # [B, H, N, D]
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)
        attn = (q @ k.transpose(-2, -1)) * self.scale
        attn = attn.softmax(dim=-1)
        attn = self.drop(attn)
        out = (attn @ v).transpose(1, 2).reshape(B, N, C)
        return self.proj(out)


class Mlp(nn.Module):
    def __init__(self, dim, hidden, dropout=0.0):
        super().__init__()
        self.fc1 = nn.Linear(dim, hidden)
        self.act = nn.GELU()
        self.fc2 = nn.Linear(hidden, dim)
        self.drop = nn.Dropout(dropout)

    def forward(self, x):
        return self.drop(self.fc2(self.drop(self.act(self.fc1(x)))))


# ───────────────────────── adaLN-Zero 条件注入 ─────────────────────────
class Modulation(nn.Module):
    """
    adaLN-Zero：用条件(时间步/类别)生成 6 组调制参数
    (shift_msa, scale_msa, gate_msa, shift_mlp, scale_mlp, gate_mlp)。
    这是 DiT 的核心：让条件"控制"每一层归一化。
    """

    def __init__(self, hidden_size, cond_dim, num=6):
        super().__init__()
        self.num = num
        self.proj = nn.Sequential(
            nn.SiLU(),
            nn.Linear(cond_dim, num * hidden_size, bias=True),
        )
        nn.init.zeros_(self.proj[-1].weight)
        nn.init.zeros_(self.proj[-1].bias)

    def forward(self, c):
        # c: [B, cond_dim] -> [B, num, hidden]
        return self.proj(c).reshape(c.shape[0], self.num, -1)


def modulate(x, shift, scale):
    # x: [B,N,D], shift/scale: [B,1,D] 或 [B,D]
    if shift.dim() == 2:
        shift = shift.unsqueeze(1)
        scale = scale.unsqueeze(1)
    return x * (1 + scale) + shift
