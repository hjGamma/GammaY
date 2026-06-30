"""
全局配置文件
============
这里集中管理所有超参数与架构开关。
【如何修改模型架构】：直接改本文件中的字段即可，无需改动其他代码。
【如何训练】：见 train.py 顶部的详细说明。
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class DataConfig:
    """视频数据规格与模拟数据集配置"""
    # 每个样本包含的视频数量（一个样本 = 一批候选视频集合）
    num_videos_per_sample: int = 20
    # 标题/描述的最大 token 数（字符级简化词汇表）
    title_max_len: int = 32
    desc_max_len: int = 64
    # 类别数量
    num_categories: int = 10
    # 数值特征数量：播放量、点赞数、评论数、转发数、收藏数、发布时长(小时)、视频时长(秒)
    num_numeric_features: int = 7
    # 字符级词汇表大小（用 ASCII 可打印字符模拟文本）
    vocab_size: int = 256
    # 模拟数据集规模
    dataset_size: int = 5000
    # Top-K 热点视频数
    top_k: int = 5


@dataclass
class ModelConfig:
    """Transformer 架构配置 —— 修改这里即可改变模型结构"""
    # —— 视频级 embedding 维度 ——
    hidden_size: int = 256
    # —— 文本编码 ——
    text_embed_dim: int = 64
    text_num_heads: int = 2
    text_num_layers: int = 2
    # —— Transformer 主体（视频间交互）——
    num_heads: int = 8
    num_layers: int = 6
    mlp_ratio: float = 4.0
    dropout: float = 0.1
    # —— 输出头 ——
    # 排名头：每个视频输出一个热度分数
    ranking_hidden: List[int] = field(default_factory=lambda: [128, 64])
    # 汇总头：输出 Top-K 视频的结构化摘要（维度 = hidden_size * top_k -> summary_dim）
    summary_hidden: List[int] = field(default_factory=lambda: [512, 256])
    summary_dim: int = 128
    # —— 位置编码 ——
    use_rope: bool = True       # 是否用 RoPE 旋转位置编码
    # —— 数值特征归一化方式
    numeric_norm: str = "layer"    # "layer" | "batch" | "none"


@dataclass
class TrainConfig:
    """训练超参数"""
    batch_size: int = 16
    learning_rate: float = 3e-4
    weight_decay: float = 0.01
    warmup_steps: int = 200
    max_steps: int = 3000
    grad_clip: float = 1.0
    log_interval: int = 20
    save_interval: int = 500
    eval_interval: int = 200
    output_dir: str = "outputs"
    seed: int = 42
    # 混合精度
    mixed_precision: str = "bf16"   # "none" | "fp16" | "bf16"
    # 损失权重
    loss_rank_weight: float = 1.0     # 排名损失权重（ListMLE）
    loss_summary_weight: float = 0.5  # 汇总表征损失权重（对比学习）


@dataclass
class Config:
    data: DataConfig = field(default_factory=DataConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    train: TrainConfig = field(default_factory=TrainConfig)


# 默认全局配置实例
DEFAULT_CONFIG = Config()
