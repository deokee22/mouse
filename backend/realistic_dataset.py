# -*- coding: utf-8 -*-
"""
贴近真实分布的数据集构造器
==========================
参考 NSL-KDD / CICIDS2017 的分布特性，自建一份"更真实"的流量数据集，
用于与"每类等量的平衡合成数据"做对比实验。

与 traffic_generator.generate_dataset 的区别（也是真实感来源）：
1. 类别不平衡：真实网络中正常流量远多于攻击，攻击内部各类比例也不均。
2. 困难样本：在类边界做更激进的插值（模拟低慢扫描、低频爆破等灰色流量）。
3. 标签噪声：模拟真实标注错误（少量样本标签被翻转）。
4. 协议/业务多样性：复用各生成器的分布，正常流量覆盖多业务形态。

构造参数全部显式化，便于答辩解释"数据是怎么来的"。
"""

import numpy as np

try:
    from traffic_generator import GENERATORS, FEATURES, LABELS
except ImportError:
    from backend.traffic_generator import GENERATORS, FEATURES, LABELS

# 真实网络中各类占比（正常占绝大多数，攻击内部也不均）
DEFAULT_RATIO = {
    "normal": 0.70,
    "dos": 0.12,
    "port_scan": 0.08,
    "brute_force": 0.06,
    "exfiltration": 0.04,
}


def generate_realistic(n_total=5000, ratio=None, hard_ratio=0.12, label_noise=0.02, seed=7):
    """
    生成贴近真实分布的数据集。

    参数：
        n_total     : 总样本数
        ratio       : 各类占比（默认见 DEFAULT_RATIO）
        hard_ratio  : 困难样本比例（在类边界做线性插值，alpha 越小越靠近边界）
        label_noise : 标签噪声比例（模拟标注错误）
        seed        : 随机种子

    返回：
        X (n,9) ndarray, y list, meta dict（记录构造参数与各类实际数量）
    """
    rng = np.random.default_rng(seed)
    ratio = dict(ratio or DEFAULT_RATIO)
    total_ratio = sum(ratio.values())
    ratio = {k: v / total_ratio for k, v in ratio.items()}

    counts = {k: int(round(n_total * v)) for k, v in ratio.items()}
    # 修正舍入误差，保证总数精确
    diff = n_total - sum(counts.values())
    if diff != 0:
        counts["normal"] += diff

    X, y = [], []
    for label, cnt in counts.items():
        gen = GENERATORS[label]
        for _ in range(cnt):
            vec = np.array(gen(rng), dtype=float)
            if rng.random() < hard_ratio:
                other = str(rng.choice([l for l in LABELS if l != label]))
                other_vec = np.array(GENERATORS[other](rng), dtype=float)
                alpha = rng.uniform(0.15, 0.45)  # 更激进的边界插值
                vec = (1 - alpha) * vec + alpha * other_vec
            X.append(vec)
            y.append(label)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=object)

    # 标签噪声：随机翻转少量标签（模拟真实标注错误）
    n_flip = int(len(y) * label_noise)
    if n_flip > 0:
        flip_idx = rng.choice(len(y), n_flip, replace=False)
        for i in flip_idx:
            y[i] = str(rng.choice([l for l in LABELS if l != y[i]]))

    order = rng.permutation(len(y))
    X = X[order]
    y = [str(v) for v in y[order]]

    meta = {
        "n_total": n_total,
        "ratio": {k: round(v, 3) for k, v in ratio.items()},
        "counts": counts,
        "hard_ratio": hard_ratio,
        "label_noise": label_noise,
        "seed": seed,
        "features": FEATURES,
        "labels": LABELS,
    }
    return X, y, meta
