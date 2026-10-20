# -*- coding: utf-8 -*-
"""
Flask 后端 API（安全运营控制台版）
==================================
启动：python backend/api.py   （默认 127.0.0.1:5000）

接口：
    GET  /                      控制台页面
    GET  /api/simulate?n=20     混合流量模拟并逐条检测
    GET  /api/scenario?type=&count=&intensity=   指定攻击场景模拟
    POST /api/detect            单条特征检测
    POST /api/explain           单条检测的可解释依据（特征贡献）
    GET  /api/sensitivity?value= 读取/设置灵敏度（0~1）
    GET  /api/metrics           模型评估指标
    GET  /api/model_compare     多模型对比 + 特征重要性 + 混淆矩阵
    GET  /api/feature_importance 特征重要性
    GET  /api/scenarios         可用攻击场景清单
    GET  /api/rules             规则清单
    GET  /api/features          特征定义
    POST /api/reset             重置（占位，统计在前端维护）
"""

import os
import json
import time
import random

import numpy as np
from flask import Flask, jsonify, request, send_from_directory

from traffic_generator import FEATURES, LABELS, GENERATORS, simulate_live_event
from detector import FusionPolicy, LABEL_ZH

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE, "frontend")
MODEL_DIR = os.path.join(BASE, "models")

app = Flask(__name__, static_folder=None)
fusion = FusionPolicy()
_rng = np.random.default_rng()

SRC_POOL = ["10.0.0.11", "10.0.0.23", "172.16.8.4", "192.168.1.105",
            "203.0.113.9", "198.51.100.77", "10.0.1.52", "45.33.32.156"]
DST_POOL = ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8", "10.0.0.13"]
DST_PORTS = [21, 22, 53, 80, 443, 3306, 3389, 8080]

SCENARIOS = {
    "ssh": {"label": "SSH 暴力破解", "attack": "brute_force"},
    "scan": {"label": "端口扫描", "attack": "port_scan"},
    "ddos": {"label": "DDoS 洪泛", "attack": "dos"},
    "exfil": {"label": "数据外泄", "attack": "exfiltration"},
    "mix": {"label": "混合流量", "attack": None},
}
INTENSITY = {"low": 0.3, "medium": 0.6, "high": 0.9}


def make_event(idx, feats, true_label, now):
    result = fusion.detect(feats, true_label=true_label)
    return {
        "id": int(now * 1000) + idx,
        "ts": time.strftime("%H:%M:%S", time.localtime(now + idx * 0.3)),
        "src": random.choice(SRC_POOL),
        "dst": random.choice(DST_POOL),
        "dst_port": random.choice(DST_PORTS),
        "result": result,
        "features": {k: round(float(v), 3) for k, v in feats.items()},
    }


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/simulate")
def api_simulate():
    n = min(int(request.args.get("n", 20)), 200)
    events = []
    now = time.time()
    for i in range(n):
        feats, true_label = simulate_live_event(_rng)
        events.append(make_event(i, feats, true_label, now))
    return jsonify({"events": events, "sensitivity": fusion.sensitivity})


@app.route("/api/scenario")
def api_scenario():
    stype = request.args.get("type", "mix")
    n = min(int(request.args.get("count", 30)), 200)
    intensity = request.args.get("intensity", "medium")
    ratio = INTENSITY.get(intensity, 0.6)
    sc = SCENARIOS.get(stype, SCENARIOS["mix"])
    attack = sc["attack"]

    events = []
    now = time.time()
    for i in range(n):
        if attack is None:
            feats, true_label = simulate_live_event(_rng)
        else:
            label = attack if _rng.random() < ratio else "normal"
            vec = GENERATORS[label](_rng)
            feats = dict(zip(FEATURES, vec))
            true_label = label
        events.append(make_event(i, feats, true_label, now))
    return jsonify({"events": events, "scenario": stype, "intensity": intensity})


@app.route("/api/detect", methods=["POST"])
def api_detect():
    body = request.get_json(force=True)
    feats = body.get("features", {})
    missing = [k for k in FEATURES if k not in feats]
    if missing:
        return jsonify({"error": f"缺少特征: {missing}", "required": FEATURES}), 400
    feats = {k: float(feats[k]) for k in FEATURES}
    return jsonify(fusion.detect(feats))


@app.route("/api/explain", methods=["POST"])
def api_explain():
    body = request.get_json(force=True)
    feats = body.get("features", {})
    missing = [k for k in FEATURES if k not in feats]
    if missing:
        return jsonify({"error": f"缺少特征: {missing}", "required": FEATURES}), 400
    feats = {k: float(feats[k]) for k in FEATURES}
    return jsonify(fusion.explain(feats))


@app.route("/api/sensitivity")
def api_sensitivity():
    value = request.args.get("value")
    if value is not None:
        try:
            fusion.sensitivity = max(0.0, min(1.0, float(value)))
        except ValueError:
            pass
    return jsonify({"sensitivity": fusion.sensitivity})


@app.route("/api/metrics")
def api_metrics():
    path = os.path.join(MODEL_DIR, "metrics.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics 不存在，请先运行 train_model.py"}), 404
    with open(path, "r", encoding="utf-8") as fp:
        return jsonify(json.load(fp))


@app.route("/api/model_compare")
def api_model_compare():
    path = os.path.join(MODEL_DIR, "metrics.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics 不存在，请先运行 train_model.py"}), 404
    with open(path, "r", encoding="utf-8") as fp:
        m = json.load(fp)
    return jsonify({
        "model_comparison": m.get("model_comparison", {}),
        "feature_importance": m.get("feature_importance", {}),
        "confusion_matrix": m.get("confusion_matrix", {}),
        "labels": LABELS,
    })


@app.route("/api/feature_importance")
def api_feature_importance():
    return jsonify({"feature_importance": fusion.ml.feature_importance})


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify({"scenarios": [{"key": k, "label": v["label"]} for k, v in SCENARIOS.items()]})


@app.route("/api/rules")
def api_rules():
    desc = [
        {"name": "SYN洪泛特征", "condition": "syn_rate > 0.8×k 且 packet_count > 400×k", "category": "DoS"},
        {"name": "小包洪泛", "condition": "packet_count > 800×k 且 bytes_per_packet < 100/k", "category": "DoS"},
        {"name": "端口离散度异常", "condition": "num_unique_ports > 15×k", "category": "端口扫描"},
        {"name": "高频失败登录", "condition": "failed_logins >= 8×k", "category": "暴力破解"},
        {"name": "上行流量失衡", "condition": "src_bytes > 500KB×k 且 src_bytes > 20k×dst_bytes", "category": "数据外泄"},
    ]
    return jsonify({"rules": desc, "note": "k 随灵敏度变化：灵敏度越高 k 越小，阈值越宽松"})


@app.route("/api/features")
def api_features():
    return jsonify({"features": FEATURES, "labels_zh": LABEL_ZH})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("NIDS 服务已启动: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
