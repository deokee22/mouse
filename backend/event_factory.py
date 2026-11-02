# -*- coding: utf-8 -*-
"""
流量事件工厂
============
把"一条连接的特征"包装成前端/存储/关联都认识的事件结构。

之所以单独抽出来，是因为实时流（stream_engine）和按需模拟（api.simulate）
必须产出**完全同构**的事件，否则前端要写两套渲染逻辑。
"""

import time
import random

# 演示用的地址池：混合内网与公网，便于在控制台上看出"内对内外"的区别
SRC_POOL = ["10.0.0.11", "10.0.0.23", "172.16.8.4", "192.168.1.105",
            "203.0.113.9", "198.51.100.77", "10.0.1.52", "45.33.32.156"]
DST_POOL = ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.8", "10.0.0.13"]
DST_PORTS = [21, 22, 53, 80, 443, 3306, 3389, 8080]

_seq = [0]


def next_id(now=None):
    """单调递增的事件 id（毫秒时间戳 + 序号），避免同一毫秒内碰撞。"""
    _seq[0] = (_seq[0] + 1) % 1000
    return int((now or time.time()) * 1000) + _seq[0]


def make_event(fusion, feats, true_label, now, idx=0, src=None, dst=None, dst_port=None):
    """检测一条特征并组装成事件。"""
    result = fusion.detect(feats, true_label=true_label)
    return {
        "id": next_id(now),
        "ts": time.strftime("%H:%M:%S", time.localtime(now + idx * 0.3)),
        "epoch": round(float(now + idx * 0.3), 3),
        "src": src or random.choice(SRC_POOL),
        "dst": dst or random.choice(DST_POOL),
        "dst_port": dst_port or random.choice(DST_PORTS),
        "result": result,
        "features": {k: round(float(v), 3) for k, v in feats.items()},
    }
