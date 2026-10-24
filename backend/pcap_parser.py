# -*- coding: utf-8 -*-
"""PCAP 解析器：将 TCP/UDP 数据包聚合为连接级 9 维特征。

注意：这里是轻量级流聚合，不是完整 TCP 重组器。TCP 会话以双向端点
(IP, port) + 协议作为基础键；看到 RST 或双向 FIN 后，再看到新的 SYN
（且没有 ACK）时会开启新会话。缺少关闭标志、抓包中途开始/结束等情况仍可能
造成会话边界不准确。
"""

from collections import defaultdict

from scapy.all import rdpcap, IP, TCP, UDP

from traffic_generator import FEATURES  # 保留特征契约，供调用方/IDE 检查

PROTO_MAP = {6: 0, 17: 1, 1: 2}  # 模型编码：TCP=0, UDP=1, ICMP=2
AUTH_PORTS = {21, 22, 3389}


def _payload_len(pkt, ip):
    """返回 IP 层 payload 长度；包含 TCP/UDP 头，不等于纯应用层数据长度。"""
    try:
        return len(bytes(ip.payload))
    except Exception:
        return 0


def _new_connection(a, b, proto_id, ts):
    return {
        "init": a,
        "start": ts,
        "end": ts,
        "src_bytes": 0,
        "dst_bytes": 0,
        "packet_count": 0,
        "syn": 0,
        "tcp": 0,
        "proto": proto_id,
        "src": a[0],
        "dst": b[0],
        "sport": a[1],
        "dport": b[1],
        "fin_directions": set(),
        "closed": False,
    }


def parse_pcap(path):
    """返回连接列表：[{src,dst,sport,dport,proto,features:{...}}, ...]。

    src/dst 是该会话首次观察到的数据包方向，不保证等同客户端/服务端。
    """
    packets = rdpcap(path)
    active = {}
    all_conns = []
    src_auth_hits = defaultdict(int)
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
            # 当前实现只聚合 TCP/UDP；虽然模型编码预留 ICMP=2，但 ICMP 尚未解析。
            continue

        proto_id = PROTO_MAP[proto]
        ts = float(pkt.time)
        plen = _payload_len(pkt, ip)
        a = (ip.src, sport)
        b = (ip.dst, dport)
        base_key = (tuple(sorted((a, b))), proto_id)
        c = active.get(base_key)

        # SYN 且无 ACK 通常表示 TCP 新会话。只有前一会话已关闭时才切分，
        # 避免把普通 SYN 重传误当成多个会话。
        is_new_tcp_syn = proto == 6 and (flags & 0x02) and not (flags & 0x10)
        if c is None or (is_new_tcp_syn and c["closed"]):
            c = _new_connection(a, b, proto_id, ts)
            active[base_key] = c
            all_conns.append(c)

        direction = 0 if a == c["init"] else 1
        if direction == 0:
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
            if flags & 0x04:  # RST
                c["closed"] = True
            if flags & 0x01:  # FIN
                c["fin_directions"].add(direction)
                if len(c["fin_directions"]) == 2:
                    c["closed"] = True

        # 这两个指标是源 IP 在整个 PCAP 范围内的统计，不是单连接局部统计。
        src_ports[ip.src].add(dport)
        if dport in AUTH_PORTS:
            src_auth_hits[ip.src] += 1

    out = []
    for c in all_conns:
        pkts = max(c["packet_count"], 1)
        duration = max(c["end"] - c["start"], 0.001)
        feats = {
            "duration": round(duration, 3),
            "protocol_type": c["proto"],
            "src_bytes": float(c["src_bytes"]),
            "dst_bytes": float(c["dst_bytes"]),
            "packet_count": float(pkts),
            # 兼容既有模型字段名；实际是认证端口命中包数，不是真实失败登录次数。
            "failed_logins": float(src_auth_hits.get(c["src"], 0)),
            "num_unique_ports": float(len(src_ports.get(c["src"], set()))),
            "syn_rate": round(c["syn"] / max(c["tcp"], 1), 3),
            "bytes_per_packet": round((c["src_bytes"] + c["dst_bytes"]) / pkts, 3),
        }
        # 防止特征定义变更时解析器静默漏字段。
        feats = {name: feats[name] for name in FEATURES}
        out.append({
            "src": c["src"], "dst": c["dst"],
            "sport": c["sport"], "dport": c["dport"], "proto": c["proto"],
            "features": feats,
        })
    return out
