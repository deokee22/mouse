# -*- coding: utf-8 -*-
"""
双引擎检测器
============
规则引擎（RuleEngine）：
    基于领域知识的白盒规则，输出命中的规则名与置信度。
    支持 sensitivity（0~1）灵敏度调节：值越大阈值越宽松、越容易触发告警。
    优点：可解释、零延迟；缺点：无法覆盖未知攻击。

机器学习引擎（MLEngine）：
    - IsolationForest：仅以正常流量训练的无监督异常检测器，
      负责发现"未知攻击"（训练集中没有的形态）。
    - RandomForest：有监督多分类器，给出具体攻击类别。

融合策略（FusionPolicy）：
    规则命中 -> 直接采信规则结论（高置信）
    否则 -> 采信 ML 分类结果，并叠加异常分数修正
    另提供 explain()：基于"特征重要性 × 相对正常样本偏离度"给出可解释依据。
"""

import os
import json
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
    """基于阈值与统计特征的白盒规则集，阈值随灵敏度缩放。"""

    def evaluate(self, features: dict, sensitivity: float = 0.5):
        # sensitivity 0 -> k=1.25（阈值抬高，更保守）；1 -> k=0.75（阈值降低，更敏感）
        s = max(0.0, min(1.0, float(sensitivity)))
        k = 1.25 - 0.5 * s
        hits = []

        def add(name, label, conf):
            hits.append({"rule": name, "label": label, "confidence": conf})

        try:
            if features["syn_rate"] > 0.8 * k and features["packet_count"] > 400 * k:
                add("SYN洪泛特征", "dos", 0.95)
            if features["packet_count"] > 800 * k and features["bytes_per_packet"] < 100.0 / k:
                add("小包洪泛", "dos", 0.85)
            if features["num_unique_ports"] > 15 * k:
                add("端口离散度异常", "port_scan", 0.92)
            if features["failed_logins"] >= 8 * k:
                add("高频失败登录", "brute_force", 0.90)
            if (features["src_bytes"] > 500_000 * k
                    and features["src_bytes"] > 20 * k * max(features["dst_bytes"], 1)):
                add("上行流量失衡", "exfiltration", 0.88)
        except Exception:
            pass
        return hits


class MLEngine:
    """封装训练好的 sklearn 模型，并暴露特征重要性 / 正常样本统计。"""

    def __init__(self):
        rf_path = os.path.join(MODEL_DIR, "random_forest.joblib")
        if_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
        if not (os.path.exists(rf_path) and os.path.exists(if_path)):
            raise FileNotFoundError("模型文件不存在，请先运行 train_model.py")
        self.rf = joblib.load(rf_path)
        self.iso = joblib.load(if_path)
        self.feature_importance = {
            FEATURES[i]: round(float(v), 4) for i, v in enumerate(self.rf.feature_importances_)
        }
        self.normal_stats = {}
        ns_path = os.path.join(MODEL_DIR, "normal_stats.json")
        if os.path.exists(ns_path):
            with open(ns_path, "r", encoding="utf-8") as fp:
                self.normal_stats = json.load(fp)

    def _to_vector(self, features: dict):
        return np.array([[features[k] for k in FEATURES]], dtype=float)

    def predict(self, features: dict):
        X = self._to_vector(features)
        label = self.rf.predict(X)[0]
        proba = self.rf.predict_proba(X)[0]
        classes = list(self.rf.classes_)
        confidence = float(max(proba))
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
        self.sensitivity = 0.5

    def detect(self, features: dict, true_label: str = None, sensitivity: float = None):
        s = self.sensitivity if sensitivity is None else sensitivity
        hits = self.rules.evaluate(features, s)
        ml = self.ml.predict(features)

        if hits:
            best = max(hits, key=lambda h: h["confidence"])
            label, conf, engine = best["label"], best["confidence"], "rule"
        else:
            label, conf, engine = ml["label"], ml["confidence"], "ml"

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

    def explain(self, features: dict, sensitivity: float = None):
        """给出单条检测的可解释依据：规则命中 + 特征贡献（重要性×偏离度）。"""
        s = self.sensitivity if sensitivity is None else sensitivity
        hits = self.rules.evaluate(features, s)
        ml = self.ml.predict(features)

        contribs = []
        for feat in FEATURES:
            v = float(features.get(feat, 0.0))
            st = self.ml.normal_stats.get(feat, {})
            mean = float(st.get("mean", 0.0))
            std = float(st.get("std", 0.0)) or 1.0
            z = (v - mean) / std
            imp = float(self.ml.feature_importance.get(feat, 0.0))
            contribs.append({
                "feature": feat,
                "value": round(v, 3),
                "zscore": round(z, 3),
                "importance": round(imp, 4),
                "contribution": round(z * imp, 4),
            })
        contribs.sort(key=lambda x: abs(x["contribution"]), reverse=True)

        return {
            "label": ml["label"],
            "label_zh": LABEL_ZH.get(ml["label"], ml["label"]),
            "confidence": ml["confidence"],
            "anomaly_score": ml["anomaly_score"],
            "rule_hits": hits,
            "top_features": contribs[:6],
            "all_features": contribs,
            "note": "贡献度 = 特征重要性 × 相对正常样本的偏离度(z-score)；正负表示偏离方向",
        }
