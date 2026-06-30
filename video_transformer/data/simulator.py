"""
视频数据集模拟器
================
在真实数据集到来之前，用程序化方式生成带语义类别的"假视频"，
让训练管线可以端到端跑通。

【如何换成真实数据】
1. 实现 torch.utils.data.Dataset 的 __getitem__ 返回
   (video: Tensor[T,C,H,W], label: int) 即可，
   video 需归一化到 [0,1] 或 [-1,1]，label 为整数类别索引。
2. 在 train.py 里把 SimulatedVideoDataset 换成你的 Dataset。

这里的模拟数据：每个类别对应一种"运动模式"，
例如类别 0 = 向右移动的方块，类别 1 = 旋转的渐变……
模型可以从这些模式中学到时空相关性，验证架构有效性。
"""
import math
import torch
from torch.utils.data import Dataset


def _make_video(label: int, num_frames: int, image_size: int) -> torch.Tensor:
    """根据类别 label 生成一段 [C,T,H,W] 视频张量，值域 [0,1]"""
    t = torch.linspace(0, 1, num_frames)
    img = torch.zeros(3, num_frames, image_size, image_size)

    if label == 0:
        # 类别 0：水平移动的彩色方块
        size = image_size // 6
        for i, ti in enumerate(t):
            cx = int((image_size - size) * ti)
            cy = image_size // 2
            img[0, i, cy:cy + size, cx:cx + size] = 0.9
            img[1, i, cy:cy + size, cx:cx + size] = 0.2
            img[2, i, cy:cy + size, cx:cx + size] = 0.3

    elif label == 1:
        # 类别 1：垂直移动的方块
        size = image_size // 6
        for i, ti in enumerate(t):
            cx = image_size // 2
            cy = int((image_size - size) * ti)
            img[1, i, cy:cy + size, cx:cx + size] = 0.9
            img[0, i, cy:cy + size, cx:cx + size] = 0.2

    elif label == 2:
        # 类别 2：旋转的渐变色环
        yy, xx = torch.meshgrid(
            torch.linspace(-1, 1, image_size),
            torch.linspace(-1, 1, image_size),
            indexing="ij",
        )
        for i, ti in enumerate(t):
            ang = ti * 2 * math.pi
            r = torch.sqrt(xx ** 2 + yy ** 2)
            a = torch.atan2(yy, xx) + ang
            img[0, i] = (torch.sin(a * 3) * 0.5 + 0.5) * (r < 0.9)
            img[1, i] = (torch.cos(a * 3) * 0.5 + 0.5) * (r < 0.9)
            img[2, i] = (torch.sin(a * 2 + 1) * 0.5 + 0.5) * (r < 0.9)

    elif label == 3:
        # 类别 3：向中心收缩的脉冲
        yy, xx = torch.meshgrid(
            torch.linspace(-1, 1, image_size),
            torch.linspace(-1, 1, image_size),
            indexing="ij",
        )
        r = torch.sqrt(xx ** 2 + yy ** 2)
        for i, ti in enumerate(t):
            phase = (1 - r) * 8 - ti * 6
            val = (torch.sin(phase) * 0.5 + 0.5).clamp(0, 1)
            img[0, i] = val
            img[2, i] = (1 - val)

    elif label == 4:
        # 类别 4：对角移动的圆
        size = image_size // 5
        for i, ti in enumerate(t):
            cx = int((image_size - size) * ti)
            cy = int((image_size - size) * (1 - ti))
            for c in range(3):
                img[c, i, cy:cy + size, cx:cx + size] = 0.3 + 0.2 * c

    else:
        # 其余类别：随机噪声 + 类别相关偏色（保证有可学模式）
        g = torch.Generator().manual_seed(int(label * 1000))
        base = torch.rand(3, 1, image_size, image_size, generator=g) * 0.3
        bias = torch.tensor([label / 10.0, (label % 3) / 5.0, (label % 7) / 8.0])
        bias = bias.view(3, 1, 1, 1)
        for i in range(num_frames):
            noise = torch.rand(3, image_size, image_size) * 0.15
            img[:, i] = (base[:, 0] + bias + noise).clamp(0, 1)

    # 归一化到 [-1, 1]，与 diffusion 习惯一致
    return img * 2 - 1


class SimulatedVideoDataset(Dataset):
    """模拟视频数据集"""

    def __init__(self, num_samples: int, num_frames: int,
                 image_size: int, num_classes: int, seed: int = 0):
        self.num_samples = num_samples
        self.num_frames = num_frames
        self.image_size = image_size
        self.num_classes = num_classes
        # 预生成 label 序列，保证可复现
        g = torch.Generator().manual_seed(seed)
        self.labels = torch.randint(0, num_classes, (num_samples,), generator=g)

    def __len__(self):
        return self.num_samples

    def __getitem__(self, idx):
        label = int(self.labels[idx])
        video = _make_video(label, self.num_frames, self.image_size)
        return video, label


def collate_fn(batch):
    """把 list[(video, label)] 打包成 batch"""
    videos = torch.stack([b[0] for b in batch], dim=0)   # [B,C,T,H,W]
    labels = torch.tensor([b[1] for b in batch], dtype=torch.long)
    return videos, labels
