# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "backend"))

import storage  # noqa: E402


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")
        storage.DB_PATH = self.tmp
        storage.init()

    def tearDown(self):
        try:
            os.remove(self.tmp)
        except OSError:
            pass

    def _event(self, label="dos", is_attack=True):
        return {
            "ts": "12:00:00", "src": "1.1.1.1", "dst": "2.2.2.2", "dst_port": 80,
            "result": {"label": label, "label_zh": "拒绝服务", "severity": "critical",
                       "confidence": 0.9, "engine": "rule", "is_attack": is_attack,
                       "rule_hits": [{"rule": "SYN洪泛特征"}], "ml_detail": {"anomaly_score": 0.1}},
        }

    def test_insert_and_query(self):
        n = storage.insert_events([self._event(), self._event("normal", False)])
        self.assertEqual(n, 1)  # 只写入攻击
        q = storage.query()
        self.assertEqual(q["total"], 1)
        self.assertEqual(q["items"][0]["src"], "1.1.1.1")

    def test_stats(self):
        storage.insert_events([self._event(), self._event()])
        st = storage.stats()
        self.assertEqual(st["total"], 2)
        self.assertEqual(st["by_severity"].get("critical"), 2)

    def test_clear(self):
        storage.insert_events([self._event()])
        storage.clear()
        self.assertEqual(storage.stats()["total"], 0)


if __name__ == "__main__":
    unittest.main()
