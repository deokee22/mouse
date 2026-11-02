# -*- coding: utf-8 -*-
"""
告警关联引擎（Alert Correlation）
=================================
解决的问题：**告警疲劳**。

一个端口扫描会命中几百条规则，产生几百条告警；运维看到的是满屏红点，
真正重要的那一条被淹掉了。真实 SOC 里这不是"体验问题"，是"漏报问题"。

本模块把"单条告警"聚合成"攻击事件（incident）"：

    同一攻击源 + 时间窗内（默认 10 分钟）的告警 → 归并为同一个 incident

并在 incident 上做三件单条告警做不到的事：

1. **攻击链推断**：按 侦察 → 初始访问 → 影响 → 外泄 的阶段模型，
   判断这个源已经走到哪一步。走到后段的事件优先级更高。
2. **风险打分**：严重度基数 + 阶段跨度奖励 + 告警量奖励，归一化到 0~100。
3. **降噪比**：alerts / incidents，直接量化"压掉了多少噪声"。

阶段模型参考 MITRE ATT&CK 的战术顺序（Reconnaissance → Initial Access →
Impact → Exfiltration），但只保留本项目能观测到的 4 个阶段，
不假装能覆盖完整杀伤链。
"""

import time
import math

import storage

WINDOW_SECONDS = 600          # 同一源多久之内的告警归为一个事件
SEV_ORDER = ["info", "low", "medium", "high", "critical"]
SEV_WEIGHT = {"info": 5, "low": 10, "medium": 20, "high": 30, "critical": 40}

# 攻击类型 → 攻击链阶段（order 用于排序与"跨度"计算）
STAGE_OF_LABEL = {
    "port_scan":    {"key": "recon",       "zh": "侦察",     "order": 1},
    "brute_force":  {"key": "access",      "zh": "初始访问", "order": 2},
    "dos":          {"key": "impact",      "zh": "影响",     "order": 3},
    "exfiltration": {"key": "exfiltration", "zh": "外泄",    "order": 4},
}

LABEL_ATTCK = {
    "port_scan": "T1046",
    "brute_force": "T1110",
    "dos": "T1498",
    "exfiltration": "T1041",
}


def _sev_max(a, b):
    ia = SEV_ORDER.index(a) if a in SEV_ORDER else 0
    ib = SEV_ORDER.index(b) if b in SEV_ORDER else 0
    return a if ia >= ib else b


def _title(src, stages, labels):
    if len(stages) >= 2:
        chain = " → ".join(s["zh"] for s in stages)
        return "%s 多阶段攻击（%s）" % (src, chain)
    if len(stages) == 1:
        return "%s 的%s活动" % (src, stages[0]["zh"])
    top = max(labels, key=labels.get) if labels else "异常"
    return "%s 的可疑活动（%s）" % (src, top)


def score_incident(severity, stages, alert_count):
    """风险分 = 严重度基数 + 阶段跨度奖励 + 告警量奖励（封顶 100）。

    设计意图：让"多阶段"和"高严重度"跑在前面，而不是单纯按告警条数排序——
    否则一个刷了 500 条的低危扫描会盖住一个只有 12 条但已走到外泄的攻击。
    """
    base = SEV_WEIGHT.get(severity, 10)
    stage_bonus = 15 * max(0, len(stages) - 1)
    volume_bonus = min(25, round(5 * math.log2(alert_count + 1)))
    return int(min(100, base + stage_bonus + volume_bonus))


def _merge(existing, alert, hits):
    """把一条新告警并入事件状态。"""
    labels = dict(existing.get("labels") or {})
    label = alert.get("label") or "unknown"
    labels[label] = labels.get(label, 0) + 1

    stages = list(existing.get("stages") or [])
    known = {s["key"] for s in stages}
    st = STAGE_OF_LABEL.get(label)
    if st and st["key"] not in known:
        stages.append(st)
        stages.sort(key=lambda s: s["order"])

    dsts = list(existing.get("dsts") or [])
    dst = alert.get("dst") or ""
    if dst and dst not in dsts:
        dsts = (dsts + [dst])[-12:]

    attck = list(existing.get("attck") or [])
    for h in hits or []:
        a = h.get("attck")
        if a and a not in attck:
            attck.append(a)
    if not attck:
        a = LABEL_ATTCK.get(label)
        if a and a not in attck:
            attck.append(a)

    severity = _sev_max(existing.get("severity") or "info", alert.get("severity") or "info")
    count = int(existing.get("alert_count") or 0) + 1

    return {
        "src": existing.get("src") or alert.get("src") or "?",
        "title": _title(existing.get("src") or alert.get("src") or "?", stages, labels),
        "severity": severity,
        "score": score_incident(severity, stages, count),
        "first_seen": existing.get("first_seen") or alert.get("ts") or "",
        "last_seen": alert.get("ts") or "",
        "first_ts": float(existing.get("first_ts") or alert.get("epoch") or time.time()),
        "last_ts": float(alert.get("epoch") or time.time()),
        "alert_count": count,
        "labels": labels,
        "stages": stages,
        "dsts": dsts,
        "attck": attck,
        "status": existing.get("status") or "open",
    }


def process(alert_rows, window=WINDOW_SECONDS):
    """把一批新告警并入事件，返回本次受影响的事件列表。

    alert_rows 来自 storage.insert_events_with_ids()，每行带 "_hits"。
    """
    touched = []
    for alert in alert_rows:
        now = float(alert.get("epoch") or time.time())
        inc = storage.find_open_incident(alert.get("src", ""), now - window)

        if inc is None:
            merged = _merge({"src": alert.get("src", ""),
                             "first_seen": alert.get("ts", ""),
                             "first_ts": now}, alert, alert.get("_hits"))
            inc_id = storage.create_incident(merged)
        else:
            merged = _merge(inc, alert, alert.get("_hits"))
            inc_id = int(inc["id"])
            storage.update_incident(inc_id, merged)

        storage.set_alert_incident([alert["id"]], inc_id)
        merged["id"] = inc_id
        touched.append(merged)
    return touched


def summary():
    """给控制台用的一句话摘要：告警压掉了多少。"""
    st = storage.stats()
    total, incs = st.get("total", 0), st.get("incidents", 0)
    if not incs:
        return {"alerts": total, "incidents": 0, "compression": 0.0, "text": "暂无事件"}
    ratio = total / incs
    return {
        "alerts": total,
        "incidents": incs,
        "compression": round(ratio, 1),
        "text": "%d 条告警已归并为 %d 个攻击事件，平均每个事件 %.1f 条（降噪 %.0f%%）"
                % (total, incs, ratio, (1 - incs / total) * 100 if total else 0),
    }
