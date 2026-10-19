# -*- coding: utf-8 -*-
"""
Flask 后端 API
==============
启动：python backend/api.py   （默认 127.0.0.1:5000）

接口：
    GET  /                     仪表盘页面
    GET  /api/metrics          模型评估指标（训练时保存）
    GET  /api/simulate?n=20    模拟 n 条实时流量并逐条检测（返回事件+判定）
    POST /api/detect           对单条特征记录做检测  body: {features: {...}}
    GET  /api/rules            返回规则引擎的规则清单（答辩展示可解释性）
    GET  /api/features         返回特征定义与重要性
"""

import os
import json
import time
import random

import numpy as np
from flask import Flask, jsonify, request, send_from_directory

from traffic_generator import FEATURES, simulate_live_event
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


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/metrics")
def api_metrics():
    path = os.path.join(MODEL_DIR, "metrics.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics 不存在，请先运行 train_model.py"}), 404
    with open(path, "r", encoding="utf-8") as fp:
        return jsonify(json.load(fp))


@app.route("/api/simulate")
def api_simulate():
    n = min(int(request.args.get("n", 20)), 200)
    events = []
    now = time.time()
    for i in range(n):
        feats, true_label = simulate_live_event(_rng)
        result = fusion.detect(feats, true_label=true_label)
        events.append({
            "id": int(now * 1000) + i,
            "ts": time.strftime("%H:%M:%S", time.localtime(now + i * 0.4)),
            "src": random.choice(SRC_POOL),
            "dst": random.choice(DST_POOL),
            "dst_port": random.choice([22, 53, 80, 443, 3306, 8080]),
            "result": result,
            "features": {k: round(float(v), 3) for k, v in feats.items()},
        })
    return jsonify({"events": events})


@app.route("/api/detect", methods=["POST"])
def api_detect():
    body = request.get_json(force=True)
    feats = body.get("features", {})
    missing = [k for k in FEATURES if k not in feats]
    if missing:
        return jsonify({"error": f"缺少特征: {missing}", "required": FEATURES}), 400
    feats = {k: float(feats[k]) for k in FEATURES}
    return jsonify(fusion.detect(feats))


@app.route("/api/rules")
def api_rules():
    desc = [
        {"name": "SYN洪泛特征", "condition": "syn_rate > 0.8 且 packet_count > 400", "category": "DoS"},
        {"name": "小包洪泛", "condition": "packet_count > 800 且 bytes_per_packet < 100", "category": "DoS"},
        {"name": "端口离散度异常", "condition": "num_unique_ports > 15", "category": "端口扫描"},
        {"name": "高频失败登录", "condition": "failed_logins >= 8", "category": "暴力破解"},
        {"name": "上行流量失衡", "condition": "src_bytes > 500KB 且 src_bytes > 20 × dst_bytes", "category": "数据外泄"},
    ]
    return jsonify({"rules": desc})


@app.route("/api/features")
def api_features():
    return jsonify({"features": FEATURES, "labels_zh": LABEL_ZH})


if __name__ == "__main__":
    print("NIDS 服务已启动: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
