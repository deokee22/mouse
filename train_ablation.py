# -*- coding: utf-8 -*-
"""
特征消融实验（Feature Ablation Study）
======================================
用法：python train_ablation.py

目的
----
回答一个复试必问的问题：**"你选的这 9 个特征，到底有没有用？"**

做法
----
把 9 维特征按"信息成本"从低到高拆成三组，在**同一份数据、同一个划分、同一组超参**下
分别训练，只看特征组这一个变量的影响：

    A 基础流量特征（basic，5 维）
        duration, protocol_type, src_bytes, dst_bytes, packet_count
        —— 直接从包头/流统计就能拿到，不需要跟踪应用层语义

    B 基础 + 行为特征（behavior，8 维）
        A + failed_logins, num_unique_ports, syn_rate
        —— 需要跨包/跨会话聚合（登录失败次数、端口扫描广度、SYN 占比），
           采集成本更高，但刻画的是"攻击行为"而不是"流量体量"

    C 全特征（full，9 维）
        B + bytes_per_packet（派生特征 = (src_bytes+dst_bytes)/packet_count）

评价维度
--------
1. 准确率 / macro-F1 / weighted-F1
2. 各类召回率（重点看少数类：exfiltration、brute_force）
3. 单样本推理延迟（毫秒/千条）——特征越多，采集与推理成本越高
4. 相对 A 组的增量（delta）

输出
----
    models/metrics_ablation.json

设计说明
--------
- 数据用 realistic 数据集（不平衡 + 困难样本 + 标签噪声），
  因为均衡合成数据上三组都会接近 1.0，区分度不够，结论没有说服力；
- 先对全量数据做一次 train_test_split，再按组切列，
  保证三组看到的是**完全相同的训练/测试样本**；
- 同时跑 RandomForest 与 DecisionTree，若两者趋势一致，结论更稳。
"""

import os
import json
import time
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix,
)

from backend.traffic_generator import FEATURES, LABELS
from backend.realistic_dataset import generate_realistic

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE, "models")

# ---------------------------------------------------------------- 特征分组定义
GROUPS = [
    {
        "key": "A",
        "name": "基础流量特征",
        "name_en": "basic",
        "features": ["duration", "protocol_type", "src_bytes", "dst_bytes", "packet_count"],
        "note": "仅需单流统计（时长/协议/双向字节数/包数），采集成本最低",
    },
    {
        "key": "B",
        "name": "基础 + 行为特征",
        "name_en": "behavior",
        "features": ["duration", "protocol_type", "src_bytes", "dst_bytes", "packet_count",
                     "failed_logins", "num_unique_ports", "syn_rate"],
        "note": "增加跨包/跨会话聚合特征（登录失败、端口广度、SYN 占比），刻画攻击行为",
    },
    {
        "key": "C",
        "name": "全特征",
        "name_en": "full",
        "features": list(FEATURES),
        "note": "再加入派生特征 bytes_per_packet（平均包长）",
    },
]

# 与 train_realistic.py 保持一致的超参，确保横向可比
RF_PARAMS = dict(n_estimators=120, max_depth=12, random_state=42, n_jobs=-1)
DT_PARAMS = dict(max_depth=12, random_state=42)


def evaluate(model, X_test, y_test):
    pred = model.predict(X_test)

    # 推理延迟：重复 5 轮取均值，排除首次调用的冷启动
    lat = []
    for _ in range(5):
        t0 = time.perf_counter()
        model.predict(X_test)
        lat.append(time.perf_counter() - t0)
    ms_per_1k = float(np.mean(lat)) / len(y_test) * 1000 * 1000  # 秒 -> 毫秒/千条

    per_class_recall = {}
    for lbl in LABELS:
        per_class_recall[lbl] = round(float(
            recall_score(y_test, pred, labels=[lbl], average="macro", zero_division=0)), 4)

    return {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision_macro": round(float(precision_score(y_test, pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_test, pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_test, pred, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_test, pred, average="weighted", zero_division=0)), 4),
        "per_class_recall": per_class_recall,
        "latency_ms_per_1k": round(ms_per_1k, 2),
        "confusion_matrix": confusion_matrix(y_test, pred, labels=LABELS).tolist(),
    }


def fmt_row(label, r, base=None):
    """打印一行；base 不为 None 时附带相对 A 组的增量。"""
    delta = ""
    if base is not None:
        d_acc = (r["accuracy"] - base["accuracy"]) * 100
        d_f1 = (r["f1_macro"] - base["f1_macro"]) * 100
        delta = "  Δacc=%+5.2fpp  ΔF1=%+5.2fpp" % (d_acc, d_f1)
    return "  %-16s acc=%.4f  macroF1=%.4f  wF1=%.4f  %.1fms/1k%s" % (
        label, r["accuracy"], r["f1_macro"], r["f1_weighted"], r["latency_ms_per_1k"], delta)


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("=" * 78)
    print("特征消融实验 · Feature Ablation Study")
    print("=" * 78)

    print("\n[1/4] 生成 realistic 数据集（不平衡 + 困难样本 + 标签噪声）...")
    X, y, meta = generate_realistic(n_total=5000, seed=7)
    print("      样本 %d | 分布 %s" % (len(y), meta["counts"]))
    print("      困难样本 %.0f%% | 标签噪声 %.0f%%" % (meta["hard_ratio"] * 100, meta["label_noise"] * 100))

    # 只切一次，保证三组用的是同一批训练/测试样本
    X_train_full, X_test_full, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)
    print("      训练/测试 %d / %d（三组共用同一划分）" % (len(y_train), len(y_test)))

    print("\n[2/4] 特征组构成：")
    for g in GROUPS:
        print("      %s %-16s %d 维  %s" % (g["key"], g["name"], len(g["features"]), g["features"]))

    print("\n[3/4] 逐组训练（RandomForest / DecisionTree）...")
    results = {}
    for g in GROUPS:
        idx = [FEATURES.index(f) for f in g["features"]]
        Xtr, Xte = X_train_full[:, idx], X_test_full[:, idx]

        rf = RandomForestClassifier(**RF_PARAMS).fit(Xtr, y_train)
        dt = DecisionTreeClassifier(**DT_PARAMS).fit(Xtr, y_train)

        results[g["key"]] = {
            "key": g["key"],
            "name": g["name"],
            "name_en": g["name_en"],
            "features": g["features"],
            "n_features": len(g["features"]),
            "note": g["note"],
            "RandomForest": evaluate(rf, Xte, y_test),
            "DecisionTree": evaluate(dt, Xte, y_test),
            "feature_importance": {
                f: round(float(v), 4)
                for f, v in zip(g["features"], rf.feature_importances_)
            },
        }
        print("      %s 组完成（%d 维）" % (g["key"], len(g["features"])))

    # ------------------------------------------------------------ 汇总与增量
    base_rf = results["A"]["RandomForest"]
    base_dt = results["A"]["DecisionTree"]
    for key in ("B", "C"):
        for algo, base in (("RandomForest", base_rf), ("DecisionTree", base_dt)):
            r = results[key][algo]
            r["delta_vs_A"] = {
                "accuracy_pp": round((r["accuracy"] - base["accuracy"]) * 100, 2),
                "f1_macro_pp": round((r["f1_macro"] - base["f1_macro"]) * 100, 2),
            }

    print("\n" + "=" * 78)
    print("[4/4] 结果汇总（行=特征组，列=指标）")
    print("=" * 78)

    print("\n-- RandomForest --")
    for g in GROUPS:
        r = results[g["key"]]["RandomForest"]
        print(fmt_row("%s %s" % (g["key"], g["name"]), r, None if g["key"] == "A" else base_rf))

    print("\n-- DecisionTree（稳健性对照）--")
    for g in GROUPS:
        r = results[g["key"]]["DecisionTree"]
        print(fmt_row("%s %s" % (g["key"], g["name"]), r, None if g["key"] == "A" else base_dt))

    print("\n-- 各类召回率（RandomForest）--")
    header = "  %-16s" % "特征组" + "".join("%14s" % l for l in LABELS)
    print(header)
    for g in GROUPS:
        r = results[g["key"]]["RandomForest"]["per_class_recall"]
        print("  %-16s" % ("%s %s" % (g["key"], g["name"])) +
              "".join("%14.4f" % r[l] for l in LABELS))

    # 派生特征是否值得：C 相对 B 的增量
    d_f1 = results["C"]["RandomForest"]["f1_macro"] - results["B"]["RandomForest"]["f1_macro"]
    print("\n-- 关键读数 --")
    print("  B 相对 A 的 macro-F1 增量: %+.4f（行为特征的整体贡献）"
          % (results["B"]["RandomForest"]["f1_macro"] - base_rf["f1_macro"]))
    print("  C 相对 B 的 macro-F1 增量: %+.4f（派生特征 bytes_per_packet 的边际贡献）" % d_f1)

    payload = {
        "experiment": "feature_ablation",
        "dataset": "realistic",
        "n_total": int(len(y)),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "meta": meta,
        "split": {"test_size": 0.25, "random_state": 42, "stratify": True},
        "rf_params": RF_PARAMS,
        "dt_params": DT_PARAMS,
        "groups": [results[g["key"]] for g in GROUPS],
    }
    out = os.path.join(MODEL_DIR, "metrics_ablation.json")
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
    print("\n已保存 %s" % out)


if __name__ == "__main__":
    main()
