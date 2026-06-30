"""
扩散噪声调度器
==============
负责：
- 训练时给干净视频加噪（前向 q 过程）
- 推理时从噪声逐步去噪（反向 p 过程）
支持 linear / cosine 调度，以及 epsilon / v_prediction / sample 三种预测目标。
"""
import math
import torch


class NoiseScheduler:
    def __init__(self, cfg):
        d = cfg.diffusion
        self.num_train = d.num_train_timesteps
        self.num_infer = d.num_inference_timesteps
        self.pred_type = d.pred_type
        self.betas = self._make_betas(d, self.num_train)
        self.alphas = 1.0 - self.betas
        self.alphas_cumprod = torch.cumprod(self.alphas, dim=0)
        self.alphas_cumprod_prev = torch.cat(
            [torch.tensor([1.0]), self.alphas_cumprod[:-1]]
        )

    @staticmethod
    def _make_betas(d, num):
        if d.schedule == "linear":
            return torch.linspace(d.beta_start, d.beta_end, num)
        elif d.schedule == "cosine":
            # Improved DDPM cosine 调度
            steps = num + 1
            x = torch.linspace(0, num, steps)
            f = torch.cos(((x / num) + 0.008) / 1.008 * math.pi * 0.5) ** 2
            alpha_bar = f / f[0]
            betas = 1 - (alpha_bar[1:] / alpha_bar[:-1])
            betas = betas.clamp(0, 0.999)
            # 缩放到 [beta_start, beta_end] 范围内以保证起点合理
            betas = betas * (d.beta_end - d.beta_start) + d.beta_start
            return betas.clamp(max=0.999)
        else:
            raise ValueError(f"未知 schedule: {d.schedule}")

    def to(self, device):
        self.betas = self.betas.to(device)
        self.alphas = self.alphas.to(device)
        self.alphas_cumprod = self.alphas_cumprod.to(device)
        self.alphas_cumprod_prev = self.alphas_cumprod_prev.to(device)
        return self

    # ─────── 前向加噪 ───────
    def q_sample(self, x0, t, noise=None):
        """给干净样本 x0 在时间步 t 加噪，返回 (x_t, noise)"""
        if noise is None:
            noise = torch.randn_like(x0)
        acp = self.alphas_cumprod.to(x0.device)[t].view(-1, 1, 1, 1, 1)
        xt = torch.sqrt(acp) * x0 + torch.sqrt(1 - acp) * noise
        return xt, noise

    # ─────── 训练目标 ───────
    def training_target(self, x0, noise, t):
        """根据 prediction_type 返回模型应预测的目标"""
        acp = self.alphas_cumprod.to(x0.device)[t].view(-1, 1, 1, 1, 1)
        if self.pred_type == "epsilon":
            return noise
        elif self.pred_type == "v_prediction":
            return torch.sqrt(acp) * noise - torch.sqrt(1 - acp) * x0
        elif self.pred_type == "sample":
            return x0
        else:
            raise ValueError(self.pred_type)

    # ─────── 从预测还原 x0 ───────
    def pred_x0(self, model_out, xt, t):
        acp = self.alphas_cumprod.to(xt.device)[t].view(-1, 1, 1, 1, 1)
        if self.pred_type == "epsilon":
            return (xt - torch.sqrt(1 - acp) * model_out) / torch.sqrt(acp)
        elif self.pred_type == "v_prediction":
            return torch.sqrt(acp) * xt - torch.sqrt(1 - acp) * model_out
        else:  # sample
            return model_out

    # ─────── 单步去噪 ───────
    def step(self, model_out, xt, t, prev_t):
        """从 xt 去噪到 x_prev。t/prev_t 为标量 int（推理时按时间步遍历整批）。
        prev_t < 0 表示最后一步，取 alpha_bar_prev = 1.0。
        """
        device = xt.device
        acp_all = self.alphas_cumprod.to(device)
        acp_prev_all = self.alphas_cumprod_prev.to(device)

        # 标量索引，负数钳到 0
        t_idx = max(int(t), 0)
        prev_idx = max(int(prev_t), 0)

        acp = acp_all[t_idx].view(1, 1, 1, 1, 1)
        acp_prev = acp_prev_all[prev_idx].view(1, 1, 1, 1, 1)

        x0 = self.pred_x0(model_out, xt, t)

        # DDPM 后向均值：μ = c1·x0 + c2·xt
        denom = (1 - acp).clamp(min=1e-8)
        c1 = torch.sqrt(acp_prev) * (1 - acp) / (1 - acp_prev).clamp(min=1e-8)
        c2 = torch.sqrt(acp) * (1 - acp_prev) / denom
        mean = c1 * x0 + c2 * xt
        mean = mean.clamp(-1e4, 1e4)

        # 只在非最后一步加随机噪声
        if int(t) > 0:
            var = (1 - acp_prev) / denom * (1 - acp)
            var = var.clamp(min=1e-8)
            xt_prev = mean + torch.sqrt(var) * torch.randn_like(xt)
        else:
            xt_prev = mean
        return xt_prev, x0

    # ─────── 推理时间步序列 ───────
    def inference_timesteps(self):
        """返回推理用的 (t, prev_t) 序列"""
        step_ratio = self.num_train // self.num_infer
        ts = list(range(0, self.num_train, step_ratio))[::-1]
        pairs = []
        for i, t in enumerate(ts):
            prev_t = ts[i + 1] if i + 1 < len(ts) else -1
            pairs.append((t, prev_t))
        return pairs


# ───────────────────────── EMA ─────────────────────────
class EMA:
    """指数滑动平均权重，推理时通常用 EMA 模型质量更好"""

    def __init__(self, model, decay=0.9999):
        self.decay = decay
        self.shadow = {k: v.detach().clone() for k, v in model.state_dict().items()}

    @torch.no_grad()
    def update(self, model):
        for k, v in model.state_dict().items():
            if v.dtype.is_floating_point:
                self.shadow[k].mul_(self.decay).add_(v.detach(), alpha=1 - self.decay)
            else:
                self.shadow[k] = v.detach().clone()

    def apply_to(self, model):
        model.load_state_dict(self.shadow, strict=True)
