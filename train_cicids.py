# -*- coding: utf-8 -*-
"""
CICIDS2017 二分类基线训练
=========================
用法：
    1) 真实实验：把 CICIDS2017 MachineLearningCSV 的 CSV 放到 data/cicids/ 下
    2) 验证流程：先运行 python scripts/make_cicids_sample.py 生成构造样本
    3) 训练：python train_cicids.py

产出：models/metrics_cicids.json（Accuracy / Precision / Recall / F1 / 混淆矩阵）

说明：先做二分类（BENIGN vs Attack），这是公开数据集的标准基线；
多分类等二分类打通后再做。
"""

import os
import json
import sys

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "backend"))

from cicids_adapter import load_cicids_dir  # noqa: E402

DATA_DIR = os.path.join(BASE, "data", "cicids")
MODEL_DIR = os.path.join(BASE, "models")


def evaluate(model, X_test, y_test):
    pred = model.predict(X_test)
    return {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, pred, zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("[1/3] 读取 CICIDS 数据（%s）..." % DATA_DIR)
    X, y, feats = load_cicids_dir(DATA_DIR, binary=True, max_rows=100000)
    print("      样本数: %d | 特征数: %d | 攻击占比: %.2f%%" % (
        len(y), len(feats), float(np.mean(y)) * 100))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    print("[2/3] 训练二分类基线 ...")
    models = {
        "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
        "RandomForest": RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42, n_jobs=-1),
    }
    results = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        results[name] = evaluate(model, X_test, y_test)
        r = results[name]
        print("      %-20s acc=%.4f precision=%.4f recall=%.4f f1=%.4f" % (
            name, r["accuracy"], r["precision"], r["recall"], r["f1"]))

    print("[3/3] 保存指标 ...")
    metrics = {
        "dataset": "CICIDS2017 (binary)",
        "n_total": int(len(y)),
        "n_features": len(feats),
        "attack_ratio": round(float(np.mean(y)), 4),
        "models": results,
        "feature_names": feats,
    }
    out = os.path.join(MODEL_DIR, "metrics_cicids.json")
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(metrics, fp, ensure_ascii=False, indent=2)
    print("      已保存", out)

    print("\n===== RandomForest 分类报告 =====")
    rf = models["RandomForest"]
    print(classification_report(y_test, rf.predict(X_test), zero_division=0))


if __name__ == "__main__":
    main()
