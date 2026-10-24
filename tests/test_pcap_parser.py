# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "backend"))

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # noqa: E402
from pcap_parser import parse_pcap  # noqa: E402
from traffic_generator import FEATURES  # noqa: E402


class TestPcapParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample_pcap = os.path.join(BASE, "data", "sample.pcap")

    def parse_packets(self, packets):
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            wrpcap(path, packets)
            return parse_pcap(path)
        finally:
            os.remove(path)

    @staticmethod
    def tcp(src, dst, sport, dport, flags="PA", payload=b"x", ts=1.0):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = ts
        return pkt

    def test_parse_returns_connections(self):
        self.assertTrue(os.path.exists(self.sample_pcap), "sample.pcap 不存在")
        conns = parse_pcap(self.sample_pcap)
        self.assertGreater(len(conns), 0)

    def test_feature_keys_complete(self):
        conns = parse_pcap(self.sample_pcap)
        for c in conns[:10]:
            self.assertEqual(set(c["features"]), set(FEATURES))

    def test_attack_types_detected(self):
        conns = parse_pcap(self.sample_pcap)
        # 端口扫描应产生高 num_unique_ports
        self.assertTrue(any(c["features"]["num_unique_ports"] > 15 for c in conns))

    def test_single_tcp_packet(self):
        conns = self.parse_packets([
            self.tcp("10.0.0.1", "10.0.0.2", 12345, 80, flags="S", payload=b"", ts=1.0),
        ])
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0]["features"]["packet_count"], 1.0)
        self.assertEqual(conns[0]["features"]["duration"], 0.001)
        self.assertEqual(conns[0]["features"]["syn_rate"], 1.0)

    def test_bidirectional_packets_share_connection(self):
        conns = self.parse_packets([
            self.tcp("10.0.0.1", "10.0.0.2", 12345, 80, flags="S", payload=b"", ts=1.0),
            self.tcp("10.0.0.2", "10.0.0.1", 80, 12345, flags="SA", payload=b"", ts=1.1),
        ])
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0]["features"]["packet_count"], 2.0)
        self.assertGreater(conns[0]["features"]["src_bytes"], 0)
        self.assertGreater(conns[0]["features"]["dst_bytes"], 0)

    def test_same_source_ip_multiple_destination_ports(self):
        conns = self.parse_packets([
            self.tcp("10.0.0.1", "10.0.0.2", 40001, 80, flags="S", payload=b"", ts=1.0),
            self.tcp("10.0.0.1", "10.0.0.2", 40002, 443, flags="S", payload=b"", ts=1.1),
        ])
        self.assertEqual(len(conns), 2)
        self.assertTrue(all(c["features"]["num_unique_ports"] == 2.0 for c in conns))

    def test_closed_tcp_tuple_can_start_new_session(self):
        conns = self.parse_packets([
            self.tcp("10.0.0.1", "10.0.0.2", 12345, 80, flags="S", payload=b"", ts=1.0),
            self.tcp("10.0.0.1", "10.0.0.2", 12345, 80, flags="R", payload=b"", ts=1.1),
            self.tcp("10.0.0.1", "10.0.0.2", 12345, 80, flags="S", payload=b"", ts=2.0),
        ])
        self.assertEqual(len(conns), 2)
        self.assertEqual([c["features"]["packet_count"] for c in conns], [2.0, 1.0])


if __name__ == "__main__":
    unittest.main()
