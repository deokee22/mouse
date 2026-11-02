# -*- coding: utf-8 -*-
"""
实时流引擎
==========
让控制台"自己动起来"：后台线程按固定速率持续产生流量 → 检测 → 落库 →
关联 → 通过 SSE 推给前端。

为什么不用前端定时轮询
----------------------
轮询的问题：
    1. 每次请求都要重新拉一批数据，前端要自己去重、自己算增量；
    2. 空闲时也在发请求，攻击突发时又拉不到（轮询间隔是死的）；
    3. 服务端的检测节奏被前端带着走，不是"持续监测"。

改成服务端主动推（Server-Sent Events）之后：
    检测节奏由服务端控制，前端只是显示器；断线自动重连（浏览器原生支持）。

线程安全
--------
- 订阅者列表用锁保护；
- 每个订阅者一个有界队列（默认 200），满了丢最旧的，
  保证一个卡住的客户端不会把服务端内存拖爆。
"""

import time
import queue
import random
import threading

import numpy as np

import storage
import correlation
from event_factory import make_event, SRC_POOL, DST_POOL, DST_PORTS
from traffic_generator import FEATURES, GENERATORS, simulate_live_event

# 攻击战役的典型路径：侦察 → 初始访问 → 影响 → 外泄
CAMPAIGN_PATH = ["port_scan", "brute_force", "dos", "exfiltration"]
# 各阶段偏好的目标端口（让事件详情看起来像真的）
STAGE_PORT = {"port_scan": None, "brute_force": 22, "dos": 80, "exfiltration": 443}


class StreamEngine:
    """持续产生流量并推送检测结果的引擎。"""

    def __init__(self, fusion, rate=2.0, queue_size=200, background_ratio=0.45):
        self.fusion = fusion
        self.rate = float(rate)
        self.queue_size = int(queue_size)
        self.background_ratio = float(background_ratio)

        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._subs = []
        self._campaign = None
        self._cooldown = 0

        self.started_at = 0.0
        self.emitted = 0
        self.attacks = 0
        self.campaigns = 0
        self.last_error = ""

    # ------------------------------------------------------------ 生命周期
    def start(self, rate=None):
        if rate is not None:
            self.rate = max(0.2, min(50.0, float(rate)))
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self._stop.clear()
            self.started_at = time.time()
            self._thread = threading.Thread(target=self._run, name="nids-stream", daemon=True)
            self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=3.0)
        self._thread = None
        return True

    def set_rate(self, rate):
        self.rate = max(0.2, min(50.0, float(rate)))
        return self.rate

    # ------------------------------------------------------------ 订阅
    def subscribe(self):
        q = queue.Queue(maxsize=self.queue_size)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def _broadcast(self, payload):
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(payload)
            except queue.Full:
                try:
                    q.get_nowait()      # 丢最旧的
                    q.put_nowait(payload)
                except queue.Empty:
                    pass

    # ------------------------------------------------------------ 主循环
    def _run(self):
        rng = np.random.default_rng()
        while not self._stop.is_set():
            t0 = time.time()
            try:
                self._tick(rng)
            except Exception as e:                      # 单条失败不应终止流
                self.last_error = "%s: %s" % (type(e).__name__, e)
            interval = 1.0 / self.rate if self.rate > 0 else 0.5
            self._stop.wait(max(0.05, interval - (time.time() - t0)))

    def _new_campaign(self, rng):
        """开一轮攻击战役：同一个源、同一个目标，按杀伤链逐阶段推进。

        真实攻击不会一个源只发一条包就消失。用"战役"模型生成流量，
        才能让关联引擎真正把多条告警聚成一个多阶段事件——
        否则每个事件都只有 1 条告警，降噪比永远是 1.0，等于没做。
        """
        start = int(rng.choice([0, 0, 0, 1]))
        length = int(rng.integers(2, 5))
        stages = CAMPAIGN_PATH[start:start + length]
        self.campaigns += 1
        return {
            "src": str(rng.choice(SRC_POOL[:5] + SRC_POOL[6:])),   # 偏向公网源
            "dst": str(rng.choice(DST_POOL)),
            "stages": stages,
            "step": 0,
            "per_stage": int(rng.integers(6, 14)),                  # 每阶段多少条连接
            "remaining": 0,
        }

    def _campaign_event(self, rng):
        c = self._campaign
        stage = c["stages"][min(c["step"] // c["per_stage"], len(c["stages"]) - 1)]
        vec = GENERATORS[stage](rng)
        feats = dict(zip(FEATURES, vec))
        port = STAGE_PORT.get(stage) or int(rng.choice(DST_PORTS))
        c["step"] += 1
        if c["step"] >= c["per_stage"] * len(c["stages"]):
            self._campaign = None
            # 战役之间留一段平静期，否则控制台上永远在"被打"，不像真实网络
            self._cooldown = int(rng.integers(6, 18))
        return feats, stage, c["src"], c["dst"], port

    def _tick(self, rng):
        if self._campaign is None:
            if self._cooldown > 0:
                self._cooldown -= 1
            elif rng.random() < 0.75:
                self._campaign = self._new_campaign(rng)

        if self._campaign is not None and rng.random() >= self.background_ratio:
            feats, true_label, src, dst, port = self._campaign_event(rng)
        else:
            feats, true_label = simulate_live_event(rng)     # 背景流量（可能是别的攻击）
            src = dst = port = None

        ev = make_event(self.fusion, feats, true_label, time.time(),
                        src=src, dst=dst, dst_port=port)

        rows = storage.insert_events_with_ids([ev])
        if rows:
            touched = correlation.process(rows)
            inc = touched[-1] if touched else None
            ev["incident_id"] = inc["id"] if inc else None
            ev["incident_title"] = inc["title"] if inc else None
            ev["incident_score"] = inc["score"] if inc else None

        self.emitted += 1
        if ev["result"].get("is_attack"):
            self.attacks += 1

        self._broadcast({
            "type": "event",
            "event": ev,
            "stats": self.status(include_subs=False),
        })

    # ------------------------------------------------------------ 状态
    def status(self, include_subs=True):
        running = bool(self._thread and self._thread.is_alive())
        out = {
            "running": running,
            "rate": self.rate,
            "emitted": self.emitted,
            "attacks": self.attacks,
            "campaigns": self.campaigns,
            "uptime": round(time.time() - self.started_at, 1) if running else 0.0,
            "last_error": self.last_error,
        }
        if include_subs:
            with self._lock:
                out["subscribers"] = len(self._subs)
        return out
