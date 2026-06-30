"""
全局配置文件
================
这里集中管理所有超参数与架构开关。
【如何修改模型】：直接改本文件中的字段即可，无需改动其他代码。
【如何训练】：见 train.py 顶部说明。
"""
from dataclasses import dataclass, field
from typing import Tuple


@dataclass
class VideoConfig:
    """视频数据规格"""
    num_frames: int = 16          # 一段视频的帧数（时序长度 T）
    image_size: int = 64          # 单帧分辨率 H=W
    channels: int = 3             # RGB 通道


@dataclass
class ModelConfig:
    """Transformer / DiT 架构配置 —— 修改这里即可改变模型结构"""
    # —— Patch 化参数（把视频切成时空 token）——
    patch_size: Tuple[int, int, int] = (2, 8, 8)   # (t_patch, h_patch, w_patch)
    in_channels: int = 3

    # —— Transformer 主体 ——
    hidden_size: int = 384        # embedding 维度（模型宽度）
    depth: int = 8                # Transformer Block 层数
    num_heads: int = 6            # 多头注意力头数
    mlp_ratio: float = 4.0        # FFN 隐层 = hidden_size * mlp_ratio
    dropout: float = 0.0          # 训练时 dropout

    # —— 条件注入 ——
    num_classes: int = 10         # 类别条件数（无条件生成设为 0）
    class_dropout_prob: float = 0.1  # 训练时随机丢弃类别（Classifier-Free Guidance）

    # —— 自定义架构开关 ——
    use_temporal_attention: bool = True   # 是否单独做时序注意力（时空分离）
    use_rope: bool = True                 # 是否使用旋转位置编码 RoPE
    use_checkpoint: bool = False          # 是否开启梯度检查点节省显存


@dataclass
class DiffusionConfig:
    """扩散过程配置"""
    num_train_timesteps: int = 1000   # 训练时间步数
    num_inference_timesteps: int = 50 # 推理采样步数
    beta_start: float = 1e-4          # 噪声调度起始 beta
    beta_end: float = 2e-2            # 噪声调度终止 beta
    schedule: str = "cosine"          # "linear" | "cosine"
    prediction_type: str = "epsilon"  # "epsilon" | "v_prediction" | "sample"


@dataclass
class TrainConfig:
    """训练超参数"""
    batch_size: int = 8
    learning_rate: float = 1e-4
    weight_decay: float = 0.0
    warmup_steps: int = 500
    max_steps: int = 5000            # 训练总步数
    grad_clip: float = 1.0           # 梯度裁剪阈值
    ema_decay: float = 0.9999        # EMA 权重衰减（用于推理）
    use_ema: bool = True
    log_interval: int = 20           # 每多少步打印一次
    save_interval: int = 1000        # 每多少步存一次 checkpoint
    sample_interval: int = 1000      # 每多少步生成一次样本
    output_dir: str = "outputs"
    seed: int = 42
    # 混合精度：可选 "none" | "fp16" | "bf16"
    mixed_precision: str = "bf16"
    # 数据集规模（模拟数据）
    dataset_size: int = 2048


@dataclass
class Config:
    video: VideoConfig = field(default_factory=VideoConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    diffusion: DiffusionConfig = field(default_factory=DiffusionConfig)
    train: TrainConfig = field(default_factory=TrainConfig)

    def __post_init__(self):
        # 一致性校验
        assert self.model.in_channels == self.video.channels
        pt, ph, pw = self.model.patch_size
        assert self.video.num_frames % pt == 0, "num_frames 必须能被 patch_size[0] 整除"
        assert self.video.image_size % ph == 0, "image_size 必须能被 patch_size[1] 整除"
        assert self.video.image_size % pw == 0, "image_size 必须能被 patch_size[2] 整除"


# 默认全局配置实例
DEFAULT_CONFIG = Config()
