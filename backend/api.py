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
    GET  /api/dataset_compare   均衡 vs 真实分布 两套数据集的指标对比
    GET  /api/ablation          特征消融实验（A/B/C 三组特征）
    GET  /api/cicids            CICIDS2017 二分类基线结果
    GET  /api/feature_importance 特征重要性
    GET  /api/scenarios         可用攻击场景清单
    GET  /api/rules             规则清单
    GET  /api/features          特征定义
    POST /api/pcap              上传 pcap 解析检测
    POST /api/report            生成 HTML 检测报告
    GET  /api/alerts            告警历史查询（分页/筛选）
    GET  /api/alerts/stats      告警统计
    POST /api/alerts/clear      清空告警历史
    POST /api/reset             重置（占位）
"""

import os
import json
import time
import queue
import random

import logging
import numpy as np
from flask import Flask, jsonify, request, send_from_directory, Response

from traffic_generator import FEATURES, LABELS, GENERATORS, simulate_live_event
from detector import FusionPolicy, LABEL_ZH
from pcap_parser import parse_pcap
from event_factory import make_event
from stream_engine import StreamEngine
import correlation
import storage
import config

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE, "frontend")
MODEL_DIR = os.path.join(BASE, "models")

os.makedirs(config.LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(config.LOG_FILE, encoding="utf-8")],
)
logger = logging.getLogger("nids")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH


@app.errorhandler(404)
def _not_found(e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(500)
def _server_error(e):
    logger.exception("internal error")
    return jsonify({"error": "internal server error"}), 500


fusion = FusionPolicy()
storage.init()
correlation.WINDOW_SECONDS = config.CORRELATION_WINDOW
_rng = np.random.default_rng()
stream = StreamEngine(fusion, rate=config.STREAM_RATE)

SCENARIOS = {
    "ssh": {"label": "SSH 暴力破解", "attack": "brute_force"},
    "scan": {"label": "端口扫描", "attack": "port_scan"},
    "ddos": {"label": "DDoS 洪泛", "attack": "dos"},
    "exfil": {"label": "数据外泄", "attack": "exfiltration"},
    "mix": {"label": "混合流量", "attack": None},
}
INTENSITY = {"low": 0.3, "medium": 0.6, "high": 0.9}


def _ingest(events):
    """写入告警并做关联聚合，返回 (写入条数, 受影响事件数)。"""
    rows = storage.insert_events_with_ids(events)
    if not rows:
        return 0, 0
    touched = correlation.process(rows)
    return len(rows), len({t["id"] for t in touched})


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
        events.append(make_event(fusion, feats, true_label, now, idx=i))
    written, incidents = _ingest(events)
    return jsonify({"events": events, "sensitivity": fusion.sensitivity,
                    "written": written, "incidents": incidents})


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
        events.append(make_event(fusion, feats, true_label, now, idx=i))
    written, incidents = _ingest(events)
    return jsonify({"events": events, "scenario": stype, "intensity": intensity,
                    "written": written, "incidents": incidents})


@app.route("/api/detect", methods=["POST"])
def api_detect():
    body = request.get_json(force=True)
    feats = body.get("features", {})
    missing = [k for k in FEATURES if k not in feats]
    if missing:
        return jsonify({"error": f"缺少特征: {missing}", "required": FEATURES}), 400
    feats = {k: float(feats[k]) for k in FEATURES}
    result = fusion.detect(feats)
    _ingest([{
        "ts": time.strftime("%H:%M:%S"),
        "epoch": time.time(),
        "src": body.get("src", "api"), "dst": body.get("dst", "api"),
        "dst_port": int(body.get("dst_port", 0) or 0),
        "result": result,
    }])
    return jsonify(result)


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


@app.route("/api/dataset_compare")
def api_dataset_compare():
    balanced_path = os.path.join(MODEL_DIR, "metrics.json")
    realistic_path = os.path.join(MODEL_DIR, "metrics_realistic.json")
    result = {"balanced": None, "realistic": None}
    if os.path.exists(balanced_path):
        with open(balanced_path, "r", encoding="utf-8") as fp:
            m = json.load(fp)
        result["balanced"] = {
            "model_comparison": m.get("model_comparison", {}),
            "n_total": int(m.get("n_train", 0)) + int(m.get("n_test", 0)),
        }
    if os.path.exists(realistic_path):
        with open(realistic_path, "r", encoding="utf-8") as fp:
            m = json.load(fp)
        result["realistic"] = {
            "model_comparison": m.get("model_comparison", {}),
            "n_total": m.get("n_total", 0),
            "meta": m.get("meta", {}),
            "confusion_matrix": m.get("confusion_matrix", {}),
        }
    return jsonify(result)


@app.route("/api/ablation")
def api_ablation():
    """特征消融实验结果（train_ablation.py 产出）。

    返回三组特征（A 基础流量 / B +行为 / C 全特征）在同一划分下的指标，
    供控制台"模型分析"页做 A/B/C 对比。
    """
    path = os.path.join(MODEL_DIR, "metrics_ablation.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics_ablation.json 不存在，请先运行 train_ablation.py"}), 404
    with open(path, "r", encoding="utf-8") as fp:
        m = json.load(fp)
    return jsonify({
        "dataset": m.get("dataset"),
        "n_total": m.get("n_total"),
        "n_train": m.get("n_train"),
        "n_test": m.get("n_test"),
        "split": m.get("split", {}),
        "groups": m.get("groups", []),
        "labels": LABELS,
    })


@app.route("/api/cicids")
def api_cicids():
    """CICIDS2017 二分类基线结果（train_cicids.py 产出）。"""
    path = os.path.join(MODEL_DIR, "metrics_cicids.json")
    if not os.path.exists(path):
        return jsonify({"error": "metrics_cicids.json 不存在，请先运行 train_cicids.py"}), 404
    with open(path, "r", encoding="utf-8") as fp:
        return jsonify(json.load(fp))


@app.route("/api/feature_importance")
def api_feature_importance():
    return jsonify({"feature_importance": fusion.ml.feature_importance})


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify({"scenarios": [{"key": k, "label": v["label"]} for k, v in SCENARIOS.items()]})


@app.route("/api/rules")
def api_rules():
    """规则库：来自 rules/*.yaml（DSL），不再是硬编码。"""
    rs = fusion.rules.rule_set
    return jsonify({
        "rules": [r.to_dict() for r in rs.rules],
        "stats": rs.stats(),
        "note": "k 随灵敏度变化：k = 1.25 - 0.5×灵敏度；"
                "增大类阈值×k、减小类阈值÷k，所以灵敏度越高越容易命中",
    })


@app.route("/api/rules/reload", methods=["POST"])
def api_rules_reload():
    """热重载规则文件，无需重启服务。"""
    rs = fusion.rules.rule_set
    rs.reload()
    return jsonify({"reloaded": True, "stats": rs.stats()})


@app.route("/api/features")
def api_features():
    return jsonify({"features": FEATURES, "labels_zh": LABEL_ZH})


@app.route("/api/alerts")
def api_alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    severity = request.args.get("severity") or None
    label = request.args.get("label") or None
    return jsonify(storage.query(limit, offset, severity, label))


@app.route("/api/alerts/stats")
def api_alerts_stats():
    st = storage.stats()
    st["correlation"] = correlation.summary()
    return jsonify(st)


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    storage.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------- 攻击事件（关联）
@app.route("/api/incidents")
def api_incidents():
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))
    status = request.args.get("status") or None
    data = storage.query_incidents(limit, offset, status)
    data["summary"] = correlation.summary()
    return jsonify(data)


@app.route("/api/incidents/<int:inc_id>")
def api_incident_detail(inc_id):
    inc = storage.incident_detail(inc_id)
    if not inc:
        return jsonify({"error": "事件不存在"}), 404
    return jsonify(inc)


@app.route("/api/incidents/<int:inc_id>/status", methods=["POST"])
def api_incident_status(inc_id):
    body = request.get_json(force=True, silent=True) or {}
    status = body.get("status", "")
    try:
        storage.update_incident_status(inc_id, status)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True, "id": inc_id, "status": status})


# ---------------------------------------------------------------- 实时流（SSE）
@app.route("/api/stream/status")
def api_stream_status():
    return jsonify(stream.status())


@app.route("/api/stream/start", methods=["POST"])
def api_stream_start():
    body = request.get_json(force=True, silent=True) or {}
    rate = body.get("rate")
    started = stream.start(rate)
    return jsonify({"ok": True, "started": started, "status": stream.status()})


@app.route("/api/stream/stop", methods=["POST"])
def api_stream_stop():
    stream.stop()
    return jsonify({"ok": True, "status": stream.status()})


@app.route("/api/stream")
def api_stream():
    """SSE：服务端持续推送检测事件，前端用 EventSource 接收。"""
    q = stream.subscribe()

    def generate():
        try:
            yield "retry: 3000\n\n"
            yield "data: %s\n\n" % json.dumps({"type": "hello", "stats": stream.status()},
                                              ensure_ascii=False)
            while True:
                try:
                    item = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"     # 心跳，防止代理断连
                    continue
                yield "data: %s\n\n" % json.dumps(item, ensure_ascii=False)
        finally:
            stream.unsubscribe(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "Connection": "keep-alive",
                             "X-Accel-Buffering": "no"})


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "sensitivity": fusion.sensitivity,
        "model_loaded": fusion.ml.rf is not None,
        "db": config.DB_PATH,
        "rules": len(fusion.rules.rules),
        "rule_errors": len(fusion.rules.rule_set.errors),
        "stream": stream.status(include_subs=False),
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    return jsonify({"ok": True})


def build_report_html(stats, events):
    import html as _html
    total = stats.get("total", 0)
    attack = stats.get("attack", 0)
    by_label = stats.get("by_label", {})
    label_zh = {"normal": "正常", "dos": "拒绝服务", "port_scan": "端口扫描",
                "brute_force": "暴力破解", "exfiltration": "数据外泄"}
    label_rows = "".join(
        "<li>%s：%d</li>" % (_html.escape(label_zh.get(k, k)), v)
        for k, v in by_label.items())
    rows = []
    for e in events[:500]:
        r = e.get("result", {})
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td><td>%s</td><td>%s%%</td></tr>" % (
                _html.escape(str(e.get("ts", ""))),
                _html.escape(str(e.get("src", ""))),
                _html.escape(str(e.get("dst", ""))),
                e.get("dst_port", ""),
                _html.escape(str(r.get("label_zh", ""))),
                r.get("severity", ""),
                round(float(r.get("confidence", 0)) * 100, 1),
            ))
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>NIDS 检测报告</title>
<style>
body{font-family:'Microsoft YaHei',sans-serif;max-width:920px;margin:40px auto;color:#222;padding:0 20px}
h1{border-bottom:2px solid #1E4FA8;padding-bottom:10px}
.kpi{display:flex;gap:30px;margin:20px 0}
.kpi div{background:#f4f7fb;padding:16px 24px;border-radius:8px}
.kpi b{font-size:24px;color:#1E4FA8}
table{width:100%%;border-collapse:collapse;margin-top:20px}
th,td{border:1px solid #ddd;padding:6px 10px;font-size:13px;text-align:left}
th{background:#1E4FA8;color:#fff}
</style></head><body>
<h1>NIDS 入侵检测报告</h1>
<p>生成时间：%s</p>
<div class="kpi"><div>已检测连接<br><b>%d</b></div><div>攻击警告<br><b style="color:#c0392b">%d</b></div></div>
<h3>攻击类型分布</h3><ul>%s</ul>
<h3>检测明细（前 500 条）</h3>
<table><thead><tr><th>时间</th><th>源 IP</th><th>目的</th><th>判定</th><th>级别</th><th>置信度</th></tr></thead>
<tbody>%s</tbody></table>
<p style="color:#888;margin-top:30px">由 NIDS 双引擎检测系统生成</p>
</body></html>""" % (time.strftime("%Y-%m-%d %H:%M:%S"), total, attack, label_rows, "".join(rows))


@app.route("/api/pcap", methods=["POST"])
def api_pcap():
    if "file" not in request.files:
        return jsonify({"error": "未上传文件"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "文件名为空"}), 400
    tmp_path = os.path.join(BASE, "data", "_upload.pcap")
    os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
    f.save(tmp_path)
    try:
        conns = parse_pcap(tmp_path)
    except Exception as e:
        return jsonify({"error": "解析失败: %s" % e}), 400
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    events = []
    now = time.time()
    for i, c in enumerate(conns):
        result = fusion.detect(c["features"])
        events.append({
            "id": int(now * 1000) + i,
            "ts": "PCAP",
            "epoch": now + i * 0.01,
            "src": c["src"],
            "dst": c["dst"],
            "dst_port": c["dport"],
            "result": result,
            "features": c["features"],
        })
    written, incidents = _ingest(events)
    attack = sum(1 for e in events if e["result"]["is_attack"])
    by_label = {}
    for e in events:
        k = e["result"]["label"]
        by_label[k] = by_label.get(k, 0) + 1
    return jsonify({
        "summary": {"total": len(events), "attack": attack, "by_label": by_label,
                    "incidents": incidents},
        "events": events,
    })


@app.route("/api/report", methods=["POST"])
def api_report():
    body = request.get_json(force=True)
    stats = body.get("stats", {})
    events = body.get("events", [])
    html = build_report_html(stats, events)
    return app.response_class(html, mimetype="text/html")


if __name__ == "__main__":
    import socket
    import sys

    # 单实例检查：端口被占时直接退出。
    # 否则会出现"第二个实例照常跑实时流、但绑不上端口"的情况，
    # 两条流同时往一个库里写，告警数量会翻倍且难以排查。
    _probe = socket.socket()
    try:
        _probe.bind((config.HOST, config.PORT))
    except OSError:
        logger.error("端口 %d 已被占用：可能已有一个 NIDS 实例在运行。"
                     "请先关闭旧窗口/进程再启动。", config.PORT)
        sys.exit(1)
    finally:
        _probe.close()

    logger.info("NIDS 服务已启动: http://%s:%d", config.HOST, config.PORT)
    stream.start()
    logger.info("实时流已启动：%.1f 事件/秒，告警关联窗口 %d 秒",
                stream.rate, config.CORRELATION_WINDOW)
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
