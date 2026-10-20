# -*- coding: utf-8 -*-
import os
import sys
import unittest

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, BACKEND)

from detector import RuleEngine, FusionPolicy  # noqa: E402


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.re = RuleEngine()

    def test_syn_flood_hit(self):
        f = {"duration": 0.1, "protocol_type": 0, "src_bytes": 10000, "dst_bytes": 0,
             "packet_count": 500, "failed_logins": 0, "num_unique_ports": 1,
             "syn_rate": 0.95, "bytes_per_packet": 20}
        hits = self.re.evaluate(f)
        self.assertTrue(any(h["rule"] == "SYN洪泛特征" for h in hits))

    def test_port_scan_hit(self):
        f = {"duration": 0.1, "protocol_type": 0, "src_bytes": 80, "dst_bytes": 30,
             "packet_count": 3, "failed_logins": 0, "num_unique_ports": 50,
             "syn_rate": 0.9, "bytes_per_packet": 60}
        hits = self.re.evaluate(f)
        self.assertTrue(any(h["rule"] == "端口离散度异常" for h in hits))

    def test_brute_force_hit(self):
        f = {"duration": 100, "protocol_type": 0, "src_bytes": 5000, "dst_bytes": 3000,
             "packet_count": 200, "failed_logins": 20, "num_unique_ports": 1,
             "syn_rate": 0.4, "bytes_per_packet": 200}
        hits = self.re.evaluate(f)
        self.assertTrue(any(h["rule"] == "高频失败登录" for h in hits))

    def test_normal_no_hit(self):
        f = {"duration": 2, "protocol_type": 0, "src_bytes": 500, "dst_bytes": 1000,
             "packet_count": 10, "failed_logins": 0, "num_unique_ports": 2,
             "syn_rate": 0.1, "bytes_per_packet": 150}
        self.assertEqual(self.re.evaluate(f), [])

    def test_sensitivity_affects_threshold(self):
        # 边界样本：灵敏度高时更易命中
        f = {"duration": 0.1, "protocol_type": 0, "src_bytes": 80, "dst_bytes": 30,
             "packet_count": 3, "failed_logins": 0, "num_unique_ports": 13,
             "syn_rate": 0.9, "bytes_per_packet": 60}
        low = self.re.evaluate(f, sensitivity=0.0)
        high = self.re.evaluate(f, sensitivity=1.0)
        self.assertEqual(len(low), 0)
        self.assertTrue(len(high) >= 1)


if __name__ == "__main__":
    unittest.main()
