# -*- coding: utf-8 -*-
"""告警关联引擎测试：聚合、时间窗、攻击链、打分、状态流转。"""

import os
import sys
import time
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "backend"))

import storage      # noqa: E402
import correlation  # noqa: E402


def make_alert_event(src, label, epoch, severity="high", dst="10.0.0.5", hits=None):
    """构造一条检测事件（is_attack=True）。"""
    return {
        "ts": time.strftime("%H:%M:%S", time.localtime(epoch)),
        "epoch": epoch,
        "src": src, "dst": dst, "dst_port": 22,
        "result": {
            "label": label, "label_zh": label, "severity": severity,
            "confidence": 0.9, "engine": "rule", "is_attack": True,
            "rule_hits": hits or [{"rule": "test", "attck": "T1046"}],
            "ml_detail": {"anomaly_score": 0.1},
        },
    }


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        storage.DB_PATH = self.tmp
        storage.init()
        self.t0 = time.time()

    def tearDown(self):
        try:
            os.remove(self.tmp)
        except OSError:
            pass

    def _ingest(self, events):
        rows = storage.insert_events_with_ids(events)
        return correlation.process(rows)

    def test_same_src_merged(self):
        touched = self._ingest([
            make_alert_event("1.1.1.1", "port_scan", self.t0),
            make_alert_event("1.1.1.1", "port_scan", self.t0 + 5),
            make_alert_event("1.1.1.1", "port_scan", self.t0 + 10),
        ])
        self.assertEqual(len({t["id"] for t in touched}), 1, "同源告警应归并为一个事件")
        inc = storage.query_incidents()["items"][0]
        self.assertEqual(inc["alert_count"], 3)

    def test_different_src_split(self):
        self._ingest([
            make_alert_event("1.1.1.1", "port_scan", self.t0),
            make_alert_event("2.2.2.2", "port_scan", self.t0 + 1),
        ])
        self.assertEqual(storage.query_incidents()["total"], 2)

    def test_outside_window_creates_new(self):
        self._ingest([make_alert_event("1.1.1.1", "port_scan", self.t0)])
        # 超出关联窗口
        self._ingest([make_alert_event("1.1.1.1", "port_scan",
                                       self.t0 + correlation.WINDOW_SECONDS + 10)])
        self.assertEqual(storage.query_incidents()["total"], 2)

    def test_kill_chain_stages(self):
        self._ingest([
            make_alert_event("1.1.1.1", "port_scan", self.t0),
            make_alert_event("1.1.1.1", "brute_force", self.t0 + 5),
            make_alert_event("1.1.1.1", "exfiltration", self.t0 + 10),
        ])
        inc = storage.query_incidents()["items"][0]
        keys = [s["key"] for s in inc["stages"]]
        self.assertEqual(keys, ["recon", "access", "exfiltration"], "阶段应按杀伤链顺序排列")
        self.assertIn("多阶段", inc["title"])

    def test_score_rewards_stage_span(self):
        one = correlation.score_incident("high", [{"key": "recon"}], 10)
        many = correlation.score_incident("high", [{"key": "recon"}, {"key": "access"},
                                                   {"key": "impact"}], 10)
        self.assertGreater(many, one, "阶段跨度越大，风险分应越高")
        self.assertLessEqual(correlation.score_incident("critical",
                                                        [{"key": "a"}, {"key": "b"},
                                                         {"key": "c"}, {"key": "d"}], 500), 100)

    def test_severity_escalates(self):
        self._ingest([make_alert_event("1.1.1.1", "port_scan", self.t0, severity="medium")])
        self._ingest([make_alert_event("1.1.1.1", "dos", self.t0 + 3, severity="critical")])
        inc = storage.query_incidents()["items"][0]
        self.assertEqual(inc["severity"], "critical")

    def test_alert_linked_to_incident(self):
        self._ingest([make_alert_event("1.1.1.1", "port_scan", self.t0)])
        inc = storage.query_incidents()["items"][0]
        detail = storage.incident_detail(inc["id"])
        self.assertEqual(len(detail["alerts"]), 1)
        self.assertEqual(detail["alerts"][0]["src"], "1.1.1.1")

    def test_status_transition(self):
        self._ingest([make_alert_event("1.1.1.1", "port_scan", self.t0)])
        inc = storage.query_incidents()["items"][0]
        storage.update_incident_status(inc["id"], "closed")
        self.assertEqual(storage.query_incidents()["items"][0]["status"], "closed")
        # 已关闭的事件不再接收新告警，应新建
        self._ingest([make_alert_event("1.1.1.1", "port_scan", self.t0 + 2)])
        self.assertEqual(storage.query_incidents()["total"], 2)

    def test_invalid_status_rejected(self):
        self._ingest([make_alert_event("1.1.1.1", "port_scan", self.t0)])
        inc = storage.query_incidents()["items"][0]
        with self.assertRaises(ValueError):
            storage.update_incident_status(inc["id"], "deleted")

    def test_compression_summary(self):
        events = [make_alert_event("1.1.1.1", "port_scan", self.t0 + i) for i in range(20)]
        self._ingest(events)
        s = correlation.summary()
        self.assertEqual(s["alerts"], 20)
        self.assertEqual(s["incidents"], 1)
        self.assertAlmostEqual(s["compression"], 20.0, places=1)

    def test_non_attack_ignored(self):
        ev = make_alert_event("1.1.1.1", "normal", self.t0)
        ev["result"]["is_attack"] = False
        rows = storage.insert_events_with_ids([ev])
        self.assertEqual(rows, [])
        self.assertEqual(storage.query_incidents()["total"], 0)


if __name__ == "__main__":
    unittest.main()
