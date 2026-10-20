# -*- coding: utf-8 -*-
"""
PCAP 解析器
============
把包级流量（.pcap）按双向五元组聚合为 9 维连接特征，
特征定义与 traffic_generator.FEATURES 完全一致，可直接送入检测器推理。

说明：
- src_bytes / dst_bytes 以连接发起方（首个包方向）为源，区分上下行。
- failed_logins 无法从网络层直接获得，这里用"该源 IP 对认证端口(21/22/3389)
  发起的连接次数"作为近似（真实部署可结合应用层日志）。
- num_unique_ports 为该源 IP 在 pcap 内访问过的不同目的端口数。
"""

from collections import defaultdict

from scapy.all import rdpcap, IP, TCP, UDP

from traffic_generator import FEATURES

PROTO_MAP = {6: 0, 17: 1, 1: 2}  # TCP=0, UDP=1, ICMP=2
AUTH_PORTS = {21, 22, 3389}


def _payload_len(pkt, ip):
    try:
        return len(bytes(ip.payload))
    except Exception:
        return 0


def parse_pcap(path):
    """返回连接列表：[{src,dst,sport,dport,proto,features:{...}}]"""
    packets = rdpcap(path)
    conns = {}
    src_auth = defaultdict(int)
    src_ports = defaultdict(set)

    for pkt in packets:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        proto = int(ip.proto)
        if TCP in pkt:
            l4 = pkt[TCP]
            sport, dport, flags = int(l4.sport), int(l4.dport), int(l4.flags)
        elif UDP in pkt:
            l4 = pkt[UDP]
            sport, dport, flags = int(l4.sport), int(l4.dport), 0
        else:
            continue

        proto_id = PROTO_MAP.get(proto, 0)
        ts = float(pkt.time)
        plen = _payload_len(pkt, ip)

        a = (ip.src, sport)
        b = (ip.dst, dport)
        key = (tuple(sorted([a, b])), proto_id)
        c = conns.get(key)
        if c is None:
            c = {
                "init": a, "start": ts, "end": ts,
                "src_bytes": 0, "dst_bytes": 0, "packet_count": 0,
                "syn": 0, "tcp": 0, "proto": proto_id,
                "src": ip.src, "dst": ip.dst, "sport": sport, "dport": dport,
            }
            conns[key] = c

        if a == c["init"]:
            c["src_bytes"] += plen
        else:
            c["dst_bytes"] += plen
        c["packet_count"] += 1
        c["start"] = min(c["start"], ts)
        c["end"] = max(c["end"], ts)
        if proto == 6:
            c["tcp"] += 1
            if flags & 0x02:
                c["syn"] += 1

        src_ports[ip.src].add(dport)
        if dport in AUTH_PORTS:
            src_auth[ip.src] += 1

    out = []
    for c in conns.values():
        pkts = max(c["packet_count"], 1)
        duration = max(c["end"] - c["start"], 0.001)
        feats = {
            "duration": round(duration, 3),
            "protocol_type": c["proto"],
            "src_bytes": float(c["src_bytes"]),
            "dst_bytes": float(c["dst_bytes"]),
            "packet_count": float(pkts),
            "failed_logins": float(src_auth.get(c["src"], 0)),
            "num_unique_ports": float(len(src_ports.get(c["src"], set()))),
            "syn_rate": round(c["syn"] / max(c["tcp"], 1), 3),
            "bytes_per_packet": round((c["src_bytes"] + c["dst_bytes"]) / pkts, 3),
        }
        out.append({
            "src": c["src"], "dst": c["dst"],
            "sport": c["sport"], "dport": c["dport"], "proto": c["proto"],
            "features": feats,
        })
    return out
