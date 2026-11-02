# -*- coding: utf-8 -*-
"""
告警与攻击事件持久化（SQLite）
==============================
两张表：
    alerts     单条告警（一条连接一次判定）
    incidents  攻击事件（同一攻击源在时间窗内的多条告警聚合而成）

为什么要两张表
--------------
单条告警是"检测"的产物，攻击事件是"研判"的产物。
一个端口扫描会产出几百条告警，但运维需要的是**一个**待处理事件。
alerts.incident_id 把两者关联起来，既能下钻看原始证据，也能在事件层降噪。
"""

import os
import json
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
            ts TEXT, epoch REAL, src TEXT, dst TEXT, dst_port INTEGER,
            label TEXT, label_zh TEXT, severity TEXT, confidence REAL,
            engine TEXT, basis TEXT, attck TEXT, is_attack INTEGER
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src TEXT, title TEXT, status TEXT DEFAULT 'open',
            severity TEXT, score INTEGER DEFAULT 0,
            first_seen TEXT, last_seen TEXT,
            first_ts REAL, last_ts REAL,
            alert_count INTEGER DEFAULT 0,
            labels TEXT, stages TEXT, dsts TEXT, attck TEXT,
            src_bytes REAL DEFAULT 0, dst_bytes REAL DEFAULT 0
        )""")
        # 老库升级：补列
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
        for col, ddl in (("incident_id", "INTEGER"), ("epoch", "REAL"), ("attck", "TEXT")):
            if col not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN %s %s" % (col, ddl))
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_src ON incidents(src, last_ts)")
        conn.commit()
    finally:
        conn.close()


def _basis_of(result):
    hits = result.get("rule_hits") or []
    return "、".join(h.get("rule", "") for h in hits) or (
        "异常分%s" % result.get("ml_detail", {}).get("anomaly_score", ""))


def insert_events_with_ids(events):
    """写入攻击告警，返回写入的行（含自增 id 与命中规则），供关联引擎使用。

    返回的每行额外带 "_hits"（规则命中列表），不落库，只用于聚合时取 ATT&CK 编号。
    """
    rows, hits_list = [], []
    for e in events:
        r = e.get("result", {})
        if not r.get("is_attack"):
            continue
        hits = r.get("rule_hits") or []
        attck = sorted({h.get("attck") for h in hits if h.get("attck")})
        rows.append((
            e.get("ts", ""), float(e.get("epoch") or 0), e.get("src", ""), e.get("dst", ""),
            int(e.get("dst_port", 0) or 0),
            r.get("label", ""), r.get("label_zh", ""), r.get("severity", ""),
            float(r.get("confidence", 0)), r.get("engine", ""), _basis_of(r),
            ",".join(attck), 1,
        ))
        hits_list.append(hits)
    if not rows:
        return []
    with _lock:
        conn = _conn()
        conn.isolation_level = None          # 手动事务，防止并发写入时取错 id 区间
        try:
            conn.execute("BEGIN IMMEDIATE")
            before = conn.execute("SELECT COALESCE(MAX(id),0) m FROM alerts").fetchone()["m"]
            conn.executemany(
                "INSERT INTO alerts (ts,epoch,src,dst,dst_port,label,label_zh,severity,confidence,"
                "engine,basis,attck,is_attack) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            out = [dict(r) for r in conn.execute(
                "SELECT * FROM alerts WHERE id > ? ORDER BY id", (before,)).fetchall()]
            conn.execute("COMMIT")
        finally:
            conn.close()
    for row, hits in zip(out, hits_list):
        row["_hits"] = hits
    return out


def insert_events(events):
    """兼容旧接口：返回写入条数。"""
    return len(insert_events_with_ids(events))


# ------------------------------------------------------------------ 事件（incident）
def find_open_incident(src, since_ts):
    with _lock:
        conn = _conn()
        try:
            row = conn.execute(
                "SELECT * FROM incidents WHERE src=? AND status!='closed' AND last_ts>=? "
                "ORDER BY last_ts DESC LIMIT 1", (src, float(since_ts))).fetchone()
            return _inc_row(row) if row else None
        finally:
            conn.close()


def create_incident(inc):
    with _lock:
        conn = _conn()
        try:
            cur = conn.execute(
                "INSERT INTO incidents (src,title,status,severity,score,first_seen,last_seen,"
                "first_ts,last_ts,alert_count,labels,stages,dsts,attck,src_bytes,dst_bytes) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc["src"], inc["title"], inc.get("status", "open"), inc["severity"],
                 int(inc.get("score", 0)), inc["first_seen"], inc["last_seen"],
                 float(inc["first_ts"]), float(inc["last_ts"]), int(inc["alert_count"]),
                 json.dumps(inc.get("labels", {}), ensure_ascii=False),
                 json.dumps(inc.get("stages", []), ensure_ascii=False),
                 json.dumps(inc.get("dsts", []), ensure_ascii=False),
                 json.dumps(inc.get("attck", []), ensure_ascii=False),
                 float(inc.get("src_bytes", 0)), float(inc.get("dst_bytes", 0))))
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()


def update_incident(inc_id, inc):
    with _lock:
        conn = _conn()
        try:
            conn.execute(
                "UPDATE incidents SET title=?,severity=?,score=?,last_seen=?,last_ts=?,"
                "alert_count=?,labels=?,stages=?,dsts=?,attck=?,src_bytes=?,dst_bytes=? WHERE id=?",
                (inc["title"], inc["severity"], int(inc.get("score", 0)), inc["last_seen"],
                 float(inc["last_ts"]), int(inc["alert_count"]),
                 json.dumps(inc.get("labels", {}), ensure_ascii=False),
                 json.dumps(inc.get("stages", []), ensure_ascii=False),
                 json.dumps(inc.get("dsts", []), ensure_ascii=False),
                 json.dumps(inc.get("attck", []), ensure_ascii=False),
                 float(inc.get("src_bytes", 0)), float(inc.get("dst_bytes", 0)), int(inc_id)))
            conn.commit()
        finally:
            conn.close()


def set_alert_incident(alert_ids, inc_id):
    if not alert_ids:
        return
    with _lock:
        conn = _conn()
        try:
            conn.executemany("UPDATE alerts SET incident_id=? WHERE id=?",
                             [(int(inc_id), int(a)) for a in alert_ids])
            conn.commit()
        finally:
            conn.close()


def update_incident_status(inc_id, status):
    if status not in ("open", "investigating", "closed"):
        raise ValueError("非法状态: %s" % status)
    with _lock:
        conn = _conn()
        try:
            conn.execute("UPDATE incidents SET status=? WHERE id=?", (status, int(inc_id)))
            conn.commit()
            return conn.total_changes > 0
        finally:
            conn.close()


def _inc_row(row):
    d = dict(row)
    for k in ("labels", "stages", "dsts", "attck"):
        try:
            d[k] = json.loads(d.get(k) or "null") or ({} if k == "labels" else [])
        except Exception:
            d[k] = {} if k == "labels" else []
    d["alert_count"] = int(d.get("alert_count") or 0)
    d["score"] = int(d.get("score") or 0)
    return d


def query_incidents(limit=50, offset=0, status=None):
    sql = "SELECT * FROM incidents WHERE 1=1"
    args = []
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY score DESC, last_ts DESC LIMIT ? OFFSET ?"
    args += [int(limit), int(offset)]
    with _lock:
        conn = _conn()
        try:
            items = [_inc_row(r) for r in conn.execute(sql, args).fetchall()]
            total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
        finally:
            conn.close()
    return {"total": total, "items": items}


def incident_detail(inc_id, alert_limit=200):
    with _lock:
        conn = _conn()
        try:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (int(inc_id),)).fetchone()
            if not row:
                return None
            inc = _inc_row(row)
            alerts = [dict(r) for r in conn.execute(
                "SELECT * FROM alerts WHERE incident_id=? ORDER BY id DESC LIMIT ?",
                (int(inc_id), int(alert_limit))).fetchall()]
        finally:
            conn.close()
    inc["alerts"] = alerts
    return inc


# ------------------------------------------------------------------ 查询 / 统计
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
            inc_total = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
            inc_open = conn.execute(
                "SELECT COUNT(*) c FROM incidents WHERE status!='closed'").fetchone()["c"]
        finally:
            conn.close()
    ratio = round(total / inc_total, 1) if inc_total else 0.0
    return {"total": total, "by_severity": by_sev, "by_label": by_label,
            "top_src": top_src, "incidents": inc_total, "incidents_open": inc_open,
            "compression_ratio": ratio}


def clear():
    with _lock:
        conn = _conn()
        try:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM incidents")
            conn.commit()
        finally:
            conn.close()
    return True
