# -*- coding: utf-8 -*-
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "backend"))

from pcap_parser import parse_pcap  # noqa: E402
from traffic_generator import FEATURES  # noqa: E402


class TestPcapParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap = os.path.join(BASE, "data", "sample.pcap")

    def test_parse_returns_connections(self):
        self.assertTrue(os.path.exists(self.pcap), "sample.pcap 不存在")
        conns = parse_pcap(self.pcap)
        self.assertGreater(len(conns), 0)

    def test_feature_keys_complete(self):
        conns = parse_pcap(self.pcap)
        for c in conns[:10]:
            for k in FEATURES:
                self.assertIn(k, c["features"])

    def test_attack_types_detected(self):
        conns = parse_pcap(self.pcap)
        # 端口扫描应产生高 num_unique_ports
        self.assertTrue(any(c["features"]["num_unique_ports"] > 15 for c in conns))


if __name__ == "__main__":
    unittest.main()
