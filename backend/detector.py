# -*- coding: utf-8 -*-
"""
双引擎检测器
============
规则引擎（RuleEngine）：
    基于领域知识的白盒规则，输出命中的规则名与置信度。
    优点：可解释、零延迟；缺点：无法覆盖未知攻击。

机器学习引擎（MLEngine）：
    - IsolationForest：仅以正常流量训练的无监督异常检测器，
      负责发现"未知攻击"（训练集中没有的形态）。
    - RandomForest：有监督多分类器，给出具体攻击类别。

融合策略（FusionPolicy）：
    规则命中 -> 直接采信规则结论（高置信）
    否则 -> 采信 ML 分类结果，并叠加异常分数修正
"""

import os
import numpy as np
import joblib

from traffic_generator import FEATURES, LABELS

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

LABEL_ZH = {
    "normal": "正常",
    "dos": "拒绝服务攻击 (DoS)",
    "port_scan": "端口扫描",
    "brute_force": "暴力破解",
    "exfiltration": "数据外泄",
}

SEVERITY = {
    "normal": "info",
    "dos": "critical",
    "port_scan": "medium",
    "brute_force": "high",
    "exfiltration": "critical",
}


class RuleEngine:
    """基于阈值与统计特征的白盒规则集。"""

    RULES = [
        # (规则名, 判定函数, 类别, 置信度)
        ("SYN洪泛特征", lambda f: f["syn_rate"] > 0.8 and f["packet_count"] > 400, "dos", 0.95),
        ("小包洪泛", lambda f: f["packet_count"] > 800 and f["bytes_per_packet"] < 100, "dos", 0.85),
        ("端口离散度异常", lambda f: f["num_unique_ports"] > 15, "port_scan", 0.92),
        ("高频失败登录", lambda f: f["failed_logins"] >= 8, "brute_force", 0.9),
        ("上行流量失衡", lambda f: f["src_bytes"] > 500_000 and f["src_bytes"] > 20 * max(f["dst_bytes"], 1), "exfiltration", 0.88),
    ]

    def evaluate(self, features: dict):
        hits = []
        for name, fn, label, conf in self.RULES:
            try:
                if fn(features):
                    hits.append({"rule": name, "label": label, "confidence": conf})
            except Exception:
                continue
        return hits


class MLEngine:
    """封装训练好的 sklearn 模型。"""

    def __init__(self):
        rf_path = os.path.join(MODEL_DIR, "random_forest.joblib")
        if_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
        if not (os.path.exists(rf_path) and os.path.exists(if_path)):
            raise FileNotFoundError("模型文件不存在，请先运行 train_model.py")
        self.rf = joblib.load(rf_path)
        self.iso = joblib.load(if_path)

    def _to_vector(self, features: dict):
        return np.array([[features[k] for k in FEATURES]], dtype=float)

    def predict(self, features: dict):
        X = self._to_vector(features)
        label = self.rf.predict(X)[0]
        proba = self.rf.predict_proba(X)[0]
        classes = list(self.rf.classes_)
        confidence = float(max(proba))
        # IsolationForest: decision_function < 0 视为异常
        anomaly_score = float(-self.iso.decision_function(X)[0])
        dist = {classes[i]: round(float(proba[i]), 4) for i in range(len(classes))}
        return {
            "label": str(label),
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
            "probabilities": dist,
        }


class FusionPolicy:
    """规则优先，ML 兜底；异常分过高时提升告警级别。"""

    def __init__(self):
        self.rules = RuleEngine()
        self.ml = MLEngine()

    def detect(self, features: dict, true_label: str = None):
        hits = self.rules.evaluate(features)
        ml = self.ml.predict(features)

        if hits:
            best = max(hits, key=lambda h: h["confidence"])
            label, conf, engine = best["label"], best["confidence"], "rule"
        else:
            label, conf, engine = ml["label"], ml["confidence"], "ml"

        # 异常分修正：ML 判正常但异常分显著偏高 -> 标记可疑
        suspicious = False
        if label == "normal" and ml["anomaly_score"] > 0.08:
            suspicious = True

        result = {
            "label": label,
            "label_zh": LABEL_ZH.get(label, label),
            "severity": "medium" if suspicious else SEVERITY.get(label, "info"),
            "suspicious": suspicious,
            "confidence": conf,
            "engine": engine,
            "rule_hits": hits,
            "ml_detail": ml,
            "is_attack": label != "normal" or suspicious,
        }
        if true_label is not None:
            result["true_label"] = true_label
            result["correct"] = (label == true_label)
        return result
