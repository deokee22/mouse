# -*- coding: utf-8 -*-
"""
真实分布数据集对比实验
======================
用法：python train_realistic.py

在"贴近真实分布"的数据集（不平衡 + 困难样本 + 标签噪声）上训练并评估，
与 train_model.py 的"平衡合成数据"结果形成对比，输出：
    models/metrics_realistic.json   真实分布数据集上的评估指标

说明：
- 不覆盖 models/random_forest.joblib（演示主模型仍用平衡数据模型）；
- 目的是展示"数据分布更真实时指标会下降"，体现方法论严谨性。
"""

import os
import json
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

from backend.traffic_generator import FEATURES, LABELS
from backend.realistic_dataset import generate_realistic

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE, "models")


def evaluate(model, X_test, y_test):
    pred = model.predict(X_test)
    per_class_recall = {
        str(lbl): round(float(recall_score(y_test, pred, labels=[lbl], average="macro", zero_division=0)), 4)
        for lbl in LABELS
    }
    return {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision_macro": round(float(precision_score(y_test, pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_test, pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_test, pred, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_test, pred, average="weighted", zero_division=0)), 4),
        "per_class_recall": per_class_recall,
    }


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("[1/3] 生成贴近真实分布的数据集（不平衡 + 困难样本 + 标签噪声）...")
    X, y, meta = generate_realistic(n_total=5000, seed=7)
    print("      样本数: %d | 各类数量: %s" % (len(y), meta["counts"]))
    print("      困难样本比例: %.0f%% | 标签噪声: %.0f%%" % (meta["hard_ratio"] * 100, meta["label_noise"] * 100))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)
    print("      训练/测试: %d / %d" % (len(y_train), len(y_test)))

    print("[2/3] 训练并对比 RandomForest / SVM / DecisionTree ...")
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42, n_jobs=-1),
        "SVM": make_pipeline(StandardScaler(), SVC(kernel="rbf", C=1.0, gamma="scale")),
        "DecisionTree": DecisionTreeClassifier(max_depth=12, random_state=42),
    }
    comparison = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        comparison[name] = evaluate(model, X_test, y_test)
        print("      %-14s acc=%.4f  macro_f1=%.4f  weighted_f1=%.4f" % (
            name, comparison[name]["accuracy"], comparison[name]["f1_macro"], comparison[name]["f1_weighted"]))

    rf = models["RandomForest"]
    pred = rf.predict(X_test)
    cm = confusion_matrix(y_test, pred, labels=LABELS).tolist()

    metrics = {
        "dataset": "realistic",
        "n_total": len(y),
        "n_train": len(y_train),
        "n_test": len(y_test),
        "meta": meta,
        "model_comparison": comparison,
        "confusion_matrix": {"labels": LABELS, "matrix": cm},
        "feature_importance": {
            FEATURES[i]: round(float(v), 4) for i, v in enumerate(rf.feature_importances_)
        },
    }
    with open(os.path.join(MODEL_DIR, "metrics_realistic.json"), "w", encoding="utf-8") as fp:
        json.dump(metrics, fp, ensure_ascii=False, indent=2)

    print("[3/3] 已保存 models/metrics_realistic.json")
    print("\n===== 真实分布数据集 · 混淆矩阵 (行=真实, 列=预测) =====")
    print("        " + "".join("%14s" % l for l in LABELS))
    for i, row in enumerate(cm):
        print("%8s" % LABELS[i] + "".join("%14d" % v for v in row))
    print("\n分类报告:")
    print(classification_report(y_test, pred, zero_division=0))


if __name__ == "__main__":
    main()
