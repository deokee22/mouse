# -*- coding: utf-8 -*-
"""
生成演示用示例 PCAP（含正常流量 + 四类攻击）
============================================
用法：python scripts/generate_sample_pcap.py
产出：data/sample.pcap

构造说明（为便于演示，部分攻击做了简化）：
- 正常 HTTP：多源访问 93.184.216.34:80，双向带 payload
- SYN 洪泛：单源对 10.0.0.1:80 发送 500 个 SYN（同五元组，突出 packet_count/syn_rate）
- 端口扫描：单源对 10.0.0.2 的 1~59 端口各发 SYN（num_unique_ports 高）
- SSH 爆破：单源对 10.0.0.5:22 发起 30 次短连接（failed_logins 高）
- 数据外泄：单源向外部 443 端口持续发送大 payload（src_bytes 极高）
"""

import os
from scapy.all import Ether, IP, TCP, Raw, wrpcap


def build():
    pkts = []
    t = 1700000000.0

    # 正常 HTTP
    for i in range(30):
        src = "10.0.0.%d" % (10 + i % 5)
        sp = 40000 + i
        p = Ether() / IP(src=src, dst="93.184.216.34") / TCP(sport=sp, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        p.time = t; pkts.append(p); t += 0.02
        r = Ether() / IP(src="93.184.216.34", dst=src) / TCP(sport=80, dport=sp, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\n" + b"x" * 500)
        r.time = t; pkts.append(r); t += 0.02

    # SYN 洪泛
    for i in range(500):
        p = Ether() / IP(src="203.0.113.66", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
        p.time = t; pkts.append(p); t += 0.001

    # 端口扫描
    for port in range(1, 60):
        p = Ether() / IP(src="198.51.100.77", dst="10.0.0.2") / TCP(sport=5555, dport=port, flags="S")
        p.time = t; pkts.append(p); t += 0.001

    # SSH 爆破
    for i in range(30):
        sp = 6000 + i
        p = Ether() / IP(src="45.33.32.156", dst="10.0.0.5") / TCP(sport=sp, dport=22, flags="S")
        p.time = t; pkts.append(p); t += 0.01
        p2 = Ether() / IP(src="10.0.0.5", dst="45.33.32.156") / TCP(sport=22, dport=sp, flags="SA")
        p2.time = t; pkts.append(p2); t += 0.01
        p3 = Ether() / IP(src="45.33.32.156", dst="10.0.0.5") / TCP(sport=sp, dport=22, flags="PA") / Raw(b"SSH-2.0-OpenSSH_8.9\r\n")
        p3.time = t; pkts.append(p3); t += 0.01

    # 数据外泄
    for i in range(400):
        p = Ether() / IP(src="10.0.1.52", dst="45.33.32.156") / TCP(sport=7000, dport=443, flags="PA") / Raw(b"A" * 1450)
        p.time = t; pkts.append(p); t += 0.005

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base, "data")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "sample.pcap")
    wrpcap(out, pkts)
    print("wrote", out, "packets:", len(pkts))


if __name__ == "__main__":
    build()
