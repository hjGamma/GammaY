"""
文本 tokenize 工具
===================
把字符串转成字符级 token id，用于 CharTextEncoder。
真实场景可换成 BPE / WordPiece 等。
"""
import torch


def char_tokenize(text: str, max_len: int, vocab_size: int = 256):
    """
    把字符串转成字符级 token id + mask。
    - id=0 保留为 padding
    - 其余用 ord(c) % vocab_size
    返回: ids (Tensor[L]), mask (Tensor[L])
    """
    chars = list(text[:max_len])
    ids = [0] * max_len
    mask = [0] * max_len
    for i, c in enumerate(chars):
        ids[i] = (ord(c) % (vocab_size - 1)) + 1  # 1..vocab_size-1
        mask[i] = 1
    return torch.tensor(ids, dtype=torch.long), torch.tensor(mask, dtype=torch.bool)


def batch_tokenize(texts: list, max_len: int, vocab_size: int = 256):
    """
    texts: list[str] 长度为 B*N（扁平列表）
    返回: ids [B*N, L], mask [B*N, L]
    """
    ids_list, mask_list = [], []
    for t in texts:
        ids, mask = char_tokenize(t, max_len, vocab_size)
        ids_list.append(ids)
        mask_list.append(mask)
    return torch.stack(ids_list), torch.stack(mask_list)


def prepare_batch(batch: dict, cfg) -> dict:
    """
    把 DataLoader 来的 batch 处理成模型需要的输入格式。
    batch 中 titles/descs 是 list[list[str]]（外层 batch，内层 N 个视频）。
    返回模型前向所需的全部 Tensor。
    """
    d = cfg.data
    B = len(batch["titles"])
    N = len(batch["titles"][0])

    # 展平标题和描述
    flat_titles = [t for sample in batch["titles"] for t in sample]
    flat_descs = [d for sample in batch["descs"] for d in sample]

    title_ids, title_mask = batch_tokenize(flat_titles, d.title_max_len, d.vocab_size)
    desc_ids, desc_mask = batch_tokenize(flat_descs, d.desc_max_len, d.vocab_size)

    # 恢复 [B, N, ...] 形状
    title_ids = title_ids.view(B, N, -1)
    title_mask = title_mask.view(B, N, -1)
    desc_ids = desc_ids.view(B, N, -1)
    desc_mask = desc_mask.view(B, N, -1)

    return {
        "title_ids": title_ids,
        "title_mask": title_mask,
        "desc_ids": desc_ids,
        "desc_mask": desc_mask,
        "numeric": batch["numeric"],
        "categories": batch["categories"],
        "hot_scores": batch["hot_scores"],
        "ranks": batch["ranks"],
        "sorted_indices": batch["sorted_indices"],
    }
