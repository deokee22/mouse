# -*- coding: utf-8 -*-
"""
模型训练脚本（多模型对比版）
============================
用法：python train_model.py

产出：
    models/random_forest.joblib     有监督多分类器（推理主模型）
    models/isolation_forest.joblib  无监督异常检测器（仅正常流量训练）
    models/normal_stats.json        正常样本各特征均值/标准差（供可解释模块）
    data/train_sample.csv           训练数据快照
    models/metrics.json             评估指标 + 多模型对比 + 特征重要性 + 混淆矩阵
"""

import os
import json
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

from backend.traffic_generator import generate_dataset, FEATURES, LABELS

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE, "models")
DATA_DIR = os.path.join(BASE, "data")


def evaluate(model, X_test, y_test):
    pred = model.predict(X_test)
    return {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision_macro": round(float(precision_score(y_test, pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_test, pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_test, pred, average="macro", zero_division=0)), 4),
    }


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    print("[1/5] 生成合成流量数据集 ...")
    X, y = generate_dataset(n_per_class=800, seed=42)
    print(f"      样本数: {len(y)}，特征数: {X.shape[1]}，类别: {LABELS}")

    df = pd.DataFrame(X, columns=FEATURES)
    df["label"] = y
    df.head(200).to_csv(os.path.join(DATA_DIR, "train_sample.csv"),
                        index=False, encoding="utf-8-sig")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    print("[2/5] 训练 RandomForest 多分类器 ...")
    rf = RandomForestClassifier(n_estimators=120, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    print("[3/5] 训练 IsolationForest 异常检测器（仅正常样本） ...")
    X_normal = X_train[[i for i, t in enumerate(y_train) if t == "normal"]]
    iso = IsolationForest(n_estimators=150, contamination=0.03, random_state=42, n_jobs=-1)
    iso.fit(X_normal)

    # 正常样本统计（供可解释模块：z-score 偏离度）
    normal_stats = {
        FEATURES[j]: {
            "mean": round(float(X_normal[:, j].mean()), 4),
            "std": round(float(X_normal[:, j].std()), 4),
        }
        for j in range(len(FEATURES))
    }
    with open(os.path.join(MODEL_DIR, "normal_stats.json"), "w", encoding="utf-8") as fp:
        json.dump(normal_stats, fp, ensure_ascii=False, indent=2)

    print("[4/5] 训练对比模型：SVM / DecisionTree ...")
    svm = make_pipeline(StandardScaler(), SVC(kernel="rbf", C=1.0, gamma="scale"))
    dt = DecisionTreeClassifier(max_depth=12, random_state=42)
    svm.fit(X_train, y_train)
    dt.fit(X_train, y_train)

    print("[5/5] 评估并保存 ...")
    rf_metrics = evaluate(rf, X_test, y_test)
    model_comparison = {
        "RandomForest": rf_metrics,
        "SVM": evaluate(svm, X_test, y_test),
        "DecisionTree": evaluate(dt, X_test, y_test),
    }

    y_pred = rf.predict(X_test)
    cm = confusion_matrix(y_test, y_pred, labels=LABELS).tolist()

    metrics = {
        "accuracy": rf_metrics["accuracy"],
        "precision_macro": rf_metrics["precision_macro"],
        "recall_macro": rf_metrics["recall_macro"],
        "f1_macro": rf_metrics["f1_macro"],
        "confusion_matrix": {"labels": LABELS, "matrix": cm},
        "model_comparison": model_comparison,
        "n_train": len(y_train),
        "n_test": len(y_test),
        "feature_importance": {
            FEATURES[i]: round(float(v), 4) for i, v in enumerate(rf.feature_importances_)
        },
    }

    joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.joblib"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.joblib"))
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w", encoding="utf-8") as fp:
        json.dump(metrics, fp, ensure_ascii=False, indent=2)

    print("\n===== 测试集评估（RandomForest 主模型）=====")
    print(f"Accuracy : {rf_metrics['accuracy']:.4f}")
    print(f"Precision: {rf_metrics['precision_macro']:.4f} (macro)")
    print(f"Recall   : {rf_metrics['recall_macro']:.4f} (macro)")
    print(f"F1-score : {rf_metrics['f1_macro']:.4f} (macro)")
    print("\n===== 多模型对比 =====")
    for name, m in model_comparison.items():
        print(f"{name:>14}: acc={m['accuracy']:.4f}  f1={m['f1_macro']:.4f}")
    print("\n混淆矩阵 (行=真实, 列=预测):")
    print("        " + "".join(f"{l:>14}" for l in LABELS))
    for i, row in enumerate(cm):
        print(f"{LABELS[i]:>8}" + "".join(f"{v:>14}" for v in row))
    print("\n分类报告:")
    print(classification_report(y_test, y_pred, zero_division=0))
    print("模型已保存到 models/，指标已保存到 models/metrics.json")


if __name__ == "__main__":
    main()
