"""
模拟视频数据集
==============
为热点视频汇总任务生成模拟数据。

每个样本包含：
- N 个视频的元数据（标题、描述、播放量、点赞、评论、转发、收藏、发布时长、视频时长、类别）
- 每个视频的"真实热度标签"（由模拟算法生成，作为训练监督）
- Top-K 索引（按热度排序的前 K 个视频下标）

【如何换成真实数据】
1. 实现 torch.utils.data.Dataset，__getitem__ 返回字典，字段与下方 VideoBatch 对齐。
2. 标签：真实热度可以用人为标注、或用播放量+点赞+评论加权计算。
3. 在 train.py 里把 SimulatedVideoDataset 换成你的 Dataset。
"""
import random
import math
import torch
from torch.utils.data import Dataset


# 10 个视频类别（模拟）
CATEGORIES = [
    "科技", "娱乐", "体育", "游戏", "音乐",
    "教育", "生活", "美食", "旅行", "动漫"
]

# 每类的热门关键词（用于生成有意义的标题）
KEYWORDS = {
    "科技": ["AI", "芯片", "手机", "发布", "评测", "新品", "黑科技", "突破", "量子", "机器人"],
    "娱乐": ["明星", "综艺", "电影", "电视剧", "八卦", "红毯", "颁奖", "新歌", "演唱会", "热搜"],
    "体育": ["比赛", "冠军", "进球", "NBA", "世界杯", "奥运会", "转会", "绝杀", "纪录", "教练"],
    "游戏": ["新游", "攻略", "直播", "电竞", "皮肤", "上线", "玩家", "通关", "BOSS", "彩蛋"],
    "音乐": ["新歌", "MV", "演唱会", "翻唱", "原创", "排行榜", "专辑", "歌手", "弹唱", "现场"],
    "教育": ["考研", "学习", "方法", "课程", "大学", "英语", "数学", "考试", "技巧", "笔记"],
    "生活": ["日常", "vlog", "技巧", "好物", "分享", "体验", "开箱", "测评", "教程", "挑战"],
    "美食": ["美食", "探店", "做法", "教程", "家常菜", "小吃", "甜品", "火锅", "烧烤", "甜点"],
    "旅行": ["旅行", "攻略", "景点", "打卡", "自驾", "穷游", "海岛", "雪山", "古镇", "民宿"],
    "动漫": ["新番", "国漫", "日漫", "解说", "COS", "手办", "OP", "ED", "名场面", "混剪"],
}


def _random_title(category: str, rng: random.Random) -> str:
    """生成一个模拟标题"""
    kws = KEYWORDS.get(category, KEYWORDS["生活"])
    templates = [
        "震惊！{k1}居然发生了这件事",
        "{k1}深度解析：你不知道的{k2}",
        "三分钟带你了解{k1}的真相",
        "{k1}最新消息：{k2}引热议",
        "必看！{k1}的{n}个技巧",
        "{k1} vs {k2}，谁更强？",
        "全网最火的{k1}，你看过吗？",
        "独家揭秘{k1}背后的{k2}",
        "{k1}大事件：{k2}引发轰动",
        "普通人如何靠{k1}实现逆袭",
    ]
    t = rng.choice(templates)
    k1, k2 = rng.sample(kws, 2)
    n = rng.randint(3, 10)
    return t.format(k1=k1, k2=k2, n=n)


def _random_desc(category: str, rng: random.Random) -> str:
    """生成一个模拟描述"""
    kws = KEYWORDS.get(category, KEYWORDS["生活"])
    t = rng.choice([
        "本期视频带你深入了解{k1}的方方面面，从入门到精通，让你一次性搞懂{k2}。记得点赞收藏关注！",
        "关于{k1}，你需要知道的都在这里了。我们整理了{n}个关键点，帮助你全面认识{k2}。",
        "{k1}最近火了，背后的原因是什么？本期视频为你深度解读{k2}的来龙去脉。",
        "今天分享一个关于{k1}的实用技巧，学会了{k2}再也不用愁！三连支持一下~",
        "盘点近期{k1}领域的{n}大热点，{k2}排名第一，你猜对了吗？",
    ])
    k1, k2 = rng.sample(kws, 2)
    n = rng.randint(5, 15)
    return t.format(k1=k1, k2=k2, n=n)


def _compute_hot_score(views: float, likes: float, comments: float,
                       shares: float, favorites: float,
                       hours_ago: float, category_boost: float) -> float:
    """
    模拟"真实热度"计算函数（训练时的监督信号）。
    公式是经典的热度算法：互动量 + 时效性衰减 + 类别权重。
    模型需要学习从原始特征预测这个分数。
    """
    # 互动综合得分（对数缩放避免大值主导）
    engagement = (
        math.log1p(views) * 1.0 +
        math.log1p(likes) * 2.0 +
        math.log1p(comments) * 3.0 +
        math.log1p(shares) * 4.0 +
        math.log1p(favorites) * 2.5
    )
    # 时间衰减：越新热度越高（半衰期 24 小时）
    time_decay = math.exp(-hours_ago / 24.0 * math.log(2))
    # 热度 = 互动量 × 时间衰减 × 类别系数
    score = engagement * time_decay * category_boost
    return score


class SimulatedVideoDataset(Dataset):
    """模拟热点视频数据集"""

    def __init__(self, num_samples: int, num_videos: int,
                 num_categories: int, seed: int = 0):
        self.num_samples = num_samples
        self.num_videos = num_videos
        self.num_categories = num_categories
        self.rng = random.Random(seed)

    def __len__(self):
        return self.num_samples

    def _gen_video(self, idx: int) -> dict:
        """生成单个视频的元数据 + 真实热度"""
        cat_id = self.rng.randint(0, self.num_categories - 1)
        cat_name = CATEGORIES[cat_id]

        # 热度基础：部分视频是"爆款"，大部分普通
        is_viral = self.rng.random() < 0.2   # 20% 概率爆款
        if is_viral:
            views = self.rng.uniform(1e5, 1e7)
            likes = views * self.rng.uniform(0.02, 0.08)
            comments = views * self.rng.uniform(0.002, 0.01)
            shares = views * self.rng.uniform(0.001, 0.005)
            favorites = views * self.rng.uniform(0.01, 0.05)
            hours_ago = self.rng.uniform(0.5, 12)  # 爆款通常较新
            category_boost = self.rng.uniform(1.0, 1.5)
        else:
            views = self.rng.uniform(1e2, 1e5)
            likes = views * self.rng.uniform(0.005, 0.03)
            comments = views * self.rng.uniform(0.0005, 0.003)
            shares = views * self.rng.uniform(0.0002, 0.002)
            favorites = views * self.rng.uniform(0.002, 0.02)
            hours_ago = self.rng.uniform(1, 72)  # 普通视频时间分布更广
            category_boost = self.rng.uniform(0.7, 1.2)

        title = _random_title(cat_name, self.rng)
        desc = _random_desc(cat_name, self.rng)
        duration = self.rng.uniform(15, 600)  # 视频时长 15 秒 ~ 10 分钟

        hot_score = _compute_hot_score(
            views, likes, comments, shares, favorites, hours_ago, category_boost
        )

        return {
            "title": title,
            "desc": desc,
            "views": views,
            "likes": likes,
            "comments": comments,
            "shares": shares,
            "favorites": favorites,
            "hours_ago": hours_ago,
            "duration": duration,
            "category_id": cat_id,
            "hot_score": hot_score,
        }

    def __getitem__(self, idx: int) -> dict:
        """
        返回一个样本：N 个视频 + 热度排序。
        返回的字段都是 Tensor，方便 DataLoader 直接 batch。
        """
        videos = [self._gen_video(i) for i in range(self.num_videos)]

        # 热度排序的索引（从高到低）
        scores = [v["hot_score"] for v in videos]
        sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        rank = [0] * len(scores)
        for r, i in enumerate(sorted_indices):
            rank[i] = r  # rank[i] = 视频 i 的排名（0=最高）

        # 打包成 dict
        return {
            "titles": [v["title"] for v in videos],
            "descs": [v["desc"] for v in videos],
            "numeric": torch.tensor([
                [v["views"], v["likes"], v["comments"], v["shares"],
                 v["favorites"], v["hours_ago"], v["duration"]]
                for v in videos
            ], dtype=torch.float32),                            # [N, 7]
            "categories": torch.tensor(
                [v["category_id"] for v in videos], dtype=torch.long
            ),                                                    # [N]
            "hot_scores": torch.tensor(scores, dtype=torch.float32),  # [N]
            "ranks": torch.tensor(rank, dtype=torch.long),       # [N], 0=最热
            "sorted_indices": torch.tensor(sorted_indices, dtype=torch.long),  # [N]
        }


def collate_fn(batch: list) -> dict:
    """把 list[dict] 打包成 batch。所有字段都增加 batch 维。"""
    b = batch[0]
    out = {}
    for key in b:
        if isinstance(b[key], torch.Tensor):
            out[key] = torch.stack([item[key] for item in batch], dim=0)
        else:
            out[key] = [item[key] for item in batch]  # 文本保留 list[list[str]]
    return out
