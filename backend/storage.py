# -*- coding: utf-8 -*-
"""
告警持久化存储（SQLite）
========================
把检测出的攻击告警落库，支持历史查询、统计与清空。
DB 文件：data/alerts.db
"""

import os
import sqlite3
import threading

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE, "data", "alerts.db")
_lock = threading.Lock()


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    conn = _conn()
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, src TEXT, dst TEXT, dst_port INTEGER,
            label TEXT, label_zh TEXT, severity TEXT, confidence REAL,
            engine TEXT, basis TEXT, is_attack INTEGER
        )""")
        conn.commit()
    finally:
        conn.close()


def insert_events(events):
    """把 events 中的攻击告警写入库，返回写入条数。"""
    rows = []
    for e in events:
        r = e.get("result", {})
        if not r.get("is_attack"):
            continue
        hits = r.get("rule_hits") or []
        basis = "、".join(h.get("rule", "") for h in hits) or (
            "异常分%s" % r.get("ml_detail", {}).get("anomaly_score", ""))
        rows.append((
            e.get("ts", ""), e.get("src", ""), e.get("dst", ""), int(e.get("dst_port", 0) or 0),
            r.get("label", ""), r.get("label_zh", ""), r.get("severity", ""),
            float(r.get("confidence", 0)), r.get("engine", ""), basis, 1,
        ))
    if not rows:
        return 0
    with _lock:
        conn = _conn()
        try:
            conn.executemany(
                "INSERT INTO alerts (ts,src,dst,dst_port,label,label_zh,severity,confidence,engine,basis,is_attack) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            conn.commit()
        finally:
            conn.close()
    return len(rows)


def query(limit=100, offset=0, severity=None, label=None):
    sql = "SELECT * FROM alerts WHERE 1=1"
    args = []
    if severity:
        sql += " AND severity=?"
        args.append(severity)
    if label:
        sql += " AND label=?"
        args.append(label)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args += [int(limit), int(offset)]
    with _lock:
        conn = _conn()
        try:
            items = [dict(r) for r in conn.execute(sql, args).fetchall()]
            total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        finally:
            conn.close()
    return {"total": total, "items": items}


def stats():
    with _lock:
        conn = _conn()
        try:
            total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            by_sev = {r["severity"]: r["c"] for r in
                      conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")}
            by_label = {r["label"]: r["c"] for r in
                        conn.execute("SELECT label, COUNT(*) c FROM alerts GROUP BY label")}
            top_src = [dict(r) for r in conn.execute(
                "SELECT src, COUNT(*) c FROM alerts GROUP BY src ORDER BY c DESC LIMIT 8")]
        finally:
            conn.close()
    return {"total": total, "by_severity": by_sev, "by_label": by_label, "top_src": top_src}


def clear():
    with _lock:
        conn = _conn()
        try:
            conn.execute("DELETE FROM alerts")
            conn.commit()
        finally:
            conn.close()
    return True
