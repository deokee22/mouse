# -*- coding: utf-8 -*-
"""
构造 CICIDS2017 格式的样本数据（仅用于验证接入流程）
=====================================================
真实实验请下载 CICIDS2017 MachineLearningCSV 放到 data/cicids/ 下替换。

用法：python scripts/make_cicids_sample.py
产出：data/cicids/sample.csv（CICIDS 列名 + Label）

注意：这是**构造样本**，分布参考 CICIDS 的类别比例与量级，不是真实流量，
只能验证 adapter/训练流程是否跑通，不能作为真实实验结论。
"""

import os
import numpy as np
import pandas as pd

COLUMNS = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s",
    "SYN Flag Count", "ACK Flag Count", "RST Flag Count",
    "Average Packet Size",
]


def gen_rows(label, n, rng):
    rows = []
    for _ in range(n):
        if label == "BENIGN":
            dport = int(rng.choice([80, 443, 53, 22, 3306, 8080]))
            dur = rng.lognormal(8, 1.2)          # 微秒
            fwd_pkts = int(rng.integers(3, 60))
            bwd_pkts = int(rng.integers(2, 60))
            fwd_bytes = rng.lognormal(6.5, 1.0)
            bwd_bytes = rng.lognormal(7.0, 1.0)
            syn = int(rng.integers(0, 2))
            rst = 0
        elif label == "DoS Hulk":
            dport = 80
            dur = rng.lognormal(5, 0.5)
            fwd_pkts = int(rng.integers(200, 800))
            bwd_pkts = int(rng.integers(0, 10))
            fwd_bytes = rng.lognormal(9, 0.6)
            bwd_bytes = rng.lognormal(3, 0.6)
            syn = int(rng.integers(1, 3))
            rst = 0
        elif label == "PortScan":
            dport = int(rng.integers(1, 65535))
            dur = rng.lognormal(3, 0.4)
            fwd_pkts = 1
            bwd_pkts = int(rng.integers(0, 2))
            fwd_bytes = rng.lognormal(2, 0.5)
            bwd_bytes = rng.lognormal(2, 0.5)
            syn = 1
            rst = int(rng.integers(0, 2))
        elif label == "SSH-Patator":
            dport = 22
            dur = rng.lognormal(10, 0.8)
            fwd_pkts = int(rng.integers(20, 120))
            bwd_pkts = int(rng.integers(15, 100))
            fwd_bytes = rng.lognormal(7, 0.6)
            bwd_bytes = rng.lognormal(7, 0.6)
            syn = int(rng.integers(1, 3))
            rst = 0
        else:  # Web Attack Sql Injection
            dport = 80
            dur = rng.lognormal(7, 0.8)
            fwd_pkts = int(rng.integers(5, 40))
            bwd_pkts = int(rng.integers(3, 30))
            fwd_bytes = rng.lognormal(7.5, 0.7)
            bwd_bytes = rng.lognormal(6.5, 0.7)
            syn = int(rng.integers(0, 2))
            rst = 0

        pkts = max(fwd_pkts + bwd_pkts, 1)
        total_bytes = fwd_bytes + bwd_bytes
        rows.append({
            "Destination Port": dport,
            "Flow Duration": round(float(dur), 1),
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": round(float(fwd_bytes), 1),
            "Total Length of Bwd Packets": round(float(bwd_bytes), 1),
            "Fwd Packet Length Mean": round(float(fwd_bytes) / max(fwd_pkts, 1), 2),
            "Bwd Packet Length Mean": round(float(bwd_bytes) / max(bwd_pkts, 1), 2),
            "Flow Bytes/s": round(total_bytes / max(dur / 1e6, 1e-6), 2),
            "Flow Packets/s": round(pkts / max(dur / 1e6, 1e-6), 2),
            "SYN Flag Count": syn,
            "ACK Flag Count": int(rng.integers(1, max(fwd_pkts + bwd_pkts, 2))),
            "RST Flag Count": rst,
            "Average Packet Size": round(total_bytes / pkts, 2),
            "Label": label,
        })
    return rows


def build(n_total=4000, seed=7):
    rng = np.random.default_rng(seed)
    dist = [
        ("BENIGN", 0.70),
        ("DoS Hulk", 0.12),
        ("PortScan", 0.08),
        ("SSH-Patator", 0.06),
        ("Web Attack  Sql Injection", 0.04),
    ]
    rows = []
    for label, ratio in dist:
        rows.extend(gen_rows(label, int(n_total * ratio), rng))

    df = pd.DataFrame(rows, columns=COLUMNS + ["Label"])
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base, "data", "cicids")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "sample.csv")
    df.to_csv(out, index=False, encoding="utf-8-sig")
    print("wrote", out, "rows:", len(df))
    print(df["Label"].value_counts().to_string())


if __name__ == "__main__":
    build()
