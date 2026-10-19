# -*- coding: utf-8 -*-
"""
合成网络流量生成器
==================
生成带标签的连接级流量记录，用于训练与演示。
设计参考 NSL-KDD 的连接记录范式：每条记录代表一条“连接”，
而非单个数据包，特征聚合自该连接内的所有数据包。

类别：
    normal        正常业务流量（HTTP/DNS/SSH/FTP 等）
    dos           拒绝服务攻击（海量小包、高频 SYN）
    port_scan     端口扫描（单源对多目的端口的短连接）
    brute_force   暴力破解（高失败登录次数）
    exfiltration  数据外泄（上行字节远大于下行）
"""

import numpy as np

# 特征顺序（训练与推理必须一致）
FEATURES = [
    "duration",          # 连接持续时间（秒）
    "protocol_type",     # 协议：0=tcp, 1=udp, 2=icmp
    "src_bytes",         # 源 -> 目的字节数
    "dst_bytes",         # 目的 -> 源字节数
    "packet_count",      # 包总数
    "failed_logins",     # 失败登录次数
    "num_unique_ports",  # 源主机在时间窗内访问的不同目的端口数
    "syn_rate",          # SYN 包占比（tcp）
    "bytes_per_packet",  # 平均每包字节数
]

LABELS = ["normal", "dos", "port_scan", "brute_force", "exfiltration"]


def _clip(x, lo, hi):
    return float(np.clip(x, lo, hi))


def gen_normal(rng):
    protocol = rng.choice([0, 0, 0, 1, 2])  # tcp 为主
    pkts = int(rng.integers(4, 200))
    src_b = _clip(rng.lognormal(7.0, 1.0), 50, 2_000_000)
    dst_b = _clip(rng.lognormal(8.0, 1.2), 100, 5_000_000)
    return [
        _clip(rng.lognormal(1.5, 1.0), 0.1, 3600),
        int(protocol),
        src_b,
        dst_b,
        pkts,
        int(rng.integers(0, 2)),
        int(rng.integers(1, 5)),
        _clip(rng.normal(0.3, 0.15), 0.0, 1.0) if protocol == 0 else 0.0,
        (src_b + dst_b) / max(pkts, 1),
    ]


def gen_dos(rng):
    pkts = int(rng.integers(500, 5000))
    src_b = _clip(rng.lognormal(9.0, 0.8), 10_000, 10_000_000)
    dst_b = _clip(rng.lognormal(4.0, 0.8), 0, 5_000)  # 几乎无响应
    return [
        _clip(rng.normal(0.5, 0.3), 0.01, 5),           # 极短
        0,
        src_b,
        dst_b,
        pkts,
        0,
        int(rng.integers(1, 3)),
        _clip(rng.normal(0.95, 0.05), 0.5, 1.0),        # SYN 洪泛
        (src_b + dst_b) / max(pkts, 1),
    ]


def gen_port_scan(rng):
    return [
        _clip(rng.normal(0.1, 0.05), 0.01, 1),          # 每个端口试探极短
        0,
        _clip(rng.normal(80, 30), 20, 500),
        _clip(rng.normal(30, 20), 0, 200),
        int(rng.integers(2, 6)),
        0,
        int(rng.integers(20, 500)),                     # 关键特征：端口离散度极高
        _clip(rng.normal(0.9, 0.1), 0.4, 1.0),
        _clip(rng.normal(60, 20), 20, 300),
    ]


def gen_brute_force(rng):
    return [
        _clip(rng.lognormal(2.5, 0.8), 1, 7200),        # 长时间反复尝试
        0,
        _clip(rng.lognormal(6.0, 0.6), 500, 100_000),
        _clip(rng.lognormal(5.5, 0.6), 300, 50_000),
        int(rng.integers(50, 800)),
        int(rng.integers(10, 500)),                     # 关键特征：大量失败登录
        int(rng.integers(1, 3)),
        _clip(rng.normal(0.4, 0.15), 0.0, 1.0),
        _clip(rng.normal(200, 80), 50, 1000),
    ]


def gen_exfiltration(rng):
    src_b = _clip(rng.lognormal(13.0, 0.8), 1_000_000, 100_000_000)  # 上行巨大
    dst_b = _clip(rng.lognormal(5.0, 0.8), 100, 20_000)
    pkts = int(rng.integers(1000, 20000))
    return [
        _clip(rng.lognormal(3.5, 0.6), 10, 14400),
        0,
        src_b,
        dst_b,
        pkts,
        0,
        int(rng.integers(1, 4)),
        _clip(rng.normal(0.2, 0.1), 0.0, 0.6),
        (src_b + dst_b) / max(pkts, 1),
    ]


GENERATORS = {
    "normal": gen_normal,
    "dos": gen_dos,
    "port_scan": gen_port_scan,
    "brute_force": gen_brute_force,
    "exfiltration": gen_exfiltration,
}


def generate_dataset(n_per_class=800, seed=42, boundary_mix=0.06):
    """
    生成平衡训练集：X (n, 9) numpy 数组，y 标签列表。

    boundary_mix：边界样本比例。真实网络中攻击与正常流量存在
    过渡形态（如低频扫描、慢速暴力破解），这里按该比例对样本
    特征与随机另一类别做线性插值，模拟类别边界重叠，
    避免数据集"过干净"导致指标失真。
    """
    rng = np.random.default_rng(seed)
    X, y = [], []
    for label in LABELS:
        gen = GENERATORS[label]
        for _ in range(n_per_class):
            vec = np.array(gen(rng), dtype=float)
            if rng.random() < boundary_mix:
                other = str(rng.choice([l for l in LABELS if l != label]))
                other_vec = np.array(GENERATORS[other](rng), dtype=float)
                alpha = rng.uniform(0.25, 0.5)  # 保留自身主导特征
                vec = (1 - alpha) * vec + alpha * other_vec
            X.append(vec)
            y.append(label)
    X = np.array(X, dtype=float)
    order = rng.permutation(len(y))
    return X[order], [y[i] for i in order]


def simulate_live_event(rng=None):
    """
    模拟一条实时流量事件（用于仪表盘演示）。
    约 85% 为正常流量，15% 随机混入一种攻击。
    返回 (features dict, 真实标签)
    """
    if rng is None:
        rng = np.random.default_rng()
    if rng.random() < 0.85:
        label = "normal"
    else:
        label = str(rng.choice(["dos", "port_scan", "brute_force", "exfiltration"]))
    vec = GENERATORS[label](rng)
    return dict(zip(FEATURES, vec)), label
