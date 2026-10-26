# -*- coding: utf-8 -*-
"""
CICIDS2017 适配器
=================
读取 CICIDS2017 MachineLearningCSV（CICFlowMeter 输出），做标签映射与特征选择。

重要说明：
- CICIDS2017 的 79 维特征由 CICFlowMeter 生成，与项目自定义的 9 维连接特征
  语义不完全一致。本适配器**保留 CICIDS 原始数值特征做基线**，不强行映射到 9 维。
- 若要把项目模型接到 CICIDS，需要单独做特征映射实验（见 docs/CICIDS接入说明.md）。

标签：
- 二分类：BENIGN=0，其余攻击=1
- 多分类：映射到项目 5 类（normal/dos/port_scan/brute_force/exfiltration）
"""

import os
import numpy as np
import pandas as pd

LABEL_MAP = {
    "BENIGN": "normal",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "DDoS": "dos",
    "Heartbleed": "dos",
    "PortScan": "port_scan",
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
    "Web Attack  Brute Force": "brute_force",
    "Web Attack  XSS": "exfiltration",
    "Web Attack  Sql Injection": "exfiltration",
    "Bot": "exfiltration",
    "Infiltration": "exfiltration",
}


def _clean_label(s):
    return str(s).strip().replace("\u2013", "").replace("\u2014", "")


def load_cicids(paths, binary=True, max_rows=None, seed=42):
    """读取一个或多个 CICIDS CSV，返回 (X, y, feature_names)。"""
    frames = []
    for p in paths:
        df = pd.read_csv(p, low_memory=False)
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df.columns = [str(c).strip() for c in df.columns]

    label_col = "Label" if "Label" in df.columns else df.columns[-1]
    df[label_col] = df[label_col].map(_clean_label)

    # 去掉无穷/缺失
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    if max_rows and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=seed)

    if binary:
        y = (df[label_col] != "BENIGN").astype(int).values
    else:
        y = df[label_col].map(LABEL_MAP).fillna("other").values

    feat_df = df.drop(columns=[label_col]).select_dtypes(include=[np.number])
    X = feat_df.values.astype(float)
    return X, y, list(feat_df.columns)


def load_cicids_dir(data_dir, binary=True, max_rows=None):
    if not os.path.isdir(data_dir):
        raise FileNotFoundError("CICIDS 数据目录不存在: %s" % data_dir)
    paths = [os.path.join(data_dir, f) for f in sorted(os.listdir(data_dir))
             if f.lower().endswith(".csv")]
    if not paths:
        raise FileNotFoundError("目录下没有 CSV: %s" % data_dir)
    return load_cicids(paths, binary=binary, max_rows=max_rows)
