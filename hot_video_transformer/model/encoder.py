"""
视频特征编码器
==============
把每个视频的多模态元数据（文本标题/描述、数值特征、类别）编码成一个统一的 embedding。

【如何修改编码器】
- 想加新模态（如封面图）：新增 ImageEncoder，然后在 VideoEncoder.forward 里拼起来。
- 想换文本编码为 BERT：把 CharTextEncoder 换成 HuggingFace 的 AutoModel。
- 想改数值处理：在 NumericEncoder 里改归一化/网络结构。
"""
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


# ─────────────── 文本编码器（字符级简化版，避免依赖外部词表）───────────────
class CharTextEncoder(nn.Module):
    """
    字符级文本编码器，用 1D 卷积 + Transformer 做文本特征提取。
    优点：不需要预训练词表，开箱即用，适合演示和小规模数据。
    生产环境可换成 BERT / RoBERTa 等预训练模型。
    """

    def __init__(self, vocab_size: int, embed_dim: int, num_heads: int,
                 num_layers: int, max_len: int, dropout: float = 0.1):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_embed = nn.Parameter(torch.zeros(1, max_len, embed_dim))
        nn.init.trunc_normal_(self.pos_embed, std=0.02)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=dropout, batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.dropout = nn.Dropout(dropout)

    def forward(self, input_ids: torch.Tensor, mask: torch.Tensor = None):
        """
        input_ids: [B, L] 字符索引
        mask: [B, L] True 表示有效 token
        return: [B, D] 文本全局向量（CLS 式 mean pooling）
        """
        x = self.embed(input_ids) + self.pos_embed[:, :input_ids.shape[1], :]
        x = self.dropout(x)
        # Transformer 用 src_key_padding_mask（True=忽略）
        if mask is not None:
            key_pad = ~mask  # 翻转：True = padding
        else:
            key_pad = None
        x = self.transformer(x, src_key_padding_mask=key_pad)
        # mean pooling
        if mask is not None:
            mask_f = mask.float().unsqueeze(-1)  # [B, L, 1]
            pooled = (x * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1)
        else:
            pooled = x.mean(dim=1)
        return pooled


# ─────────────── 数值特征编码器 ───────────────
class NumericEncoder(nn.Module):
    """
    数值特征编码器。
    先做层归一化稳定分布，再通过 MLP 映射到 hidden_size。
    对播放量这类长尾分布，先用 log1p 做变换。
    """

    def __init__(self, num_features: int, hidden_size: int,
                 norm: str = "layer", dropout: float = 0.1):
        super().__init__()
        self.norm_type = norm
        if norm == "layer":
            self.norm = nn.LayerNorm(num_features)
        elif norm == "batch":
            self.norm = nn.BatchNorm1d(num_features)
        else:
            self.norm = None

        self.mlp = nn.Sequential(
            nn.Linear(num_features, hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, hidden_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [B, N, num_features] 或 [B, num_features]
        # 对长尾分布做 log1p（除了"发布时长"这类可能为 0 的也 OK）
        x = torch.log1p(x.clamp(min=0))
        if self.norm_type == "batch" and x.dim() == 3:
            # BatchNorm1D 要求 [B, C, L]
            B, N, D = x.shape
            x = self.norm(x.transpose(1, 2)).transpose(1, 2)
        elif self.norm is not None:
            x = self.norm(x)
        return self.mlp(x)


# ─────────────── 类别特征编码器 ───────────────
class CategoryEncoder(nn.Module):
    def __init__(self, num_categories: int, hidden_size: int):
        super().__init__()
        self.embed = nn.Embedding(num_categories, hidden_size)
        nn.init.trunc_normal_(self.embed.weight, std=0.02)

    def forward(self, cat_ids: torch.Tensor) -> torch.Tensor:
        return self.embed(cat_ids)


# ─────────────── 视频级融合编码器 ───────────────
class VideoEncoder(nn.Module):
    """
    把单个视频的所有模态融合成一个 embedding。
    融合方式：文本、数值、类别各自编码 -> 拼接 -> 投影层。
    """

    def __init__(self, cfg):
        super().__init__()
        d = cfg.data
        m = cfg.model

        # 标题编码器
        self.title_encoder = CharTextEncoder(
            vocab_size=d.vocab_size,
            embed_dim=m.text_embed_dim,
            num_heads=m.text_num_heads,
            num_layers=m.text_num_layers,
            max_len=d.title_max_len,
            dropout=m.dropout,
        )
        # 描述编码器（共享标题的 embedding 权重可以省参，这里独立演示）
        self.desc_encoder = CharTextEncoder(
            vocab_size=d.vocab_size,
            embed_dim=m.text_embed_dim,
            num_heads=m.text_num_heads,
            num_layers=m.text_num_layers,
            max_len=d.desc_max_len,
            dropout=m.dropout,
        )
        # 数值编码器
        self.numeric_encoder = NumericEncoder(
            num_features=d.num_numeric_features,
            hidden_size=m.hidden_size,
            norm=m.numeric_norm,
            dropout=m.dropout,
        )
        # 类别编码器
        self.category_encoder = CategoryEncoder(d.num_categories, m.hidden_size)

        # 融合投影：title + desc + numeric + category -> hidden_size
        fuse_dim = m.text_embed_dim * 2 + m.hidden_size * 2
        self.fuse = nn.Sequential(
            nn.Linear(fuse_dim, m.hidden_size),
            nn.LayerNorm(m.hidden_size),
            nn.GELU(),
            nn.Dropout(m.dropout),
        )

    def forward(self, title_ids, title_mask, desc_ids, desc_mask,
                numeric, categories):
        """
        输入形状（带 B 批，N 视频维）：
            title_ids: [B, N, L_title]
            title_mask: [B, N, L_title]
            desc_ids: [B, N, L_desc]
            desc_mask: [B, N, L_desc]
            numeric: [B, N, D_num]
            categories: [B, N]
        return: [B, N, hidden_size]
        """
        B, N, _ = title_ids.shape

        # 把 N 维并入 batch 维，一次性编码所有视频
        t_ids = title_ids.reshape(B * N, -1)
        t_mask = title_mask.reshape(B * N, -1)
        d_ids = desc_ids.reshape(B * N, -1)
        d_mask = desc_mask.reshape(B * N, -1)
        num_flat = numeric.reshape(B * N, -1)
        cat_flat = categories.reshape(B * N)

        t_emb = self.title_encoder(t_ids, t_mask)        # [B*N, D_text]
        d_emb = self.desc_encoder(d_ids, d_mask)         # [B*N, D_text]
        n_emb = self.numeric_encoder(num_flat)           # [B*N, D_hid]
        c_emb = self.category_encoder(cat_flat)          # [B*N, D_hid]

        fused = torch.cat([t_emb, d_emb, n_emb, c_emb], dim=-1)
        out = self.fuse(fused)                           # [B*N, D_hid]
        return out.view(B, N, -1)
