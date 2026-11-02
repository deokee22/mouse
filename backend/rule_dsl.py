# -*- coding: utf-8 -*-
"""
规则 DSL（Domain Specific Language）
===================================
把检测规则从"硬编码的 if"变成"可热加载的 YAML 数据"。

为什么这么做
------------
硬编码规则的问题不是性能，是**运维**：
    加一条规则要改代码 → 走测试 → 重新发版，
    安全运营里规则一天可能要改十几次，这个流程跑不动。

改成 YAML 之后：
    改文件 → 调 /api/rules/reload → 立即生效，不重启服务。

规则文件格式
------------
    version: 1
    rules:
      - id: DOS-001                  # 全局唯一编号，便于在告警里追溯
        name: SYN洪泛特征            # 展示名
        enabled: true
        attack: dos                  # 命中后判定的攻击类型
        severity: critical           # info/low/medium/high/critical
        confidence: 0.95             # 规则置信度（融合时与 ML 竞争用）
        attck: T1498.001             # MITRE ATT&CK 技术编号
        attck_name: Direct Network Flood
        description: 短时 SYN 占比极高且包量巨大
        tags: [flood, tcp]
        condition:                   # 条件树，支持 all / any / none 嵌套
          all:
            - field: syn_rate
              op: gte
              value: 0.8
            - field: packet_count
              op: gte
              value: 400

条件树语义
----------
    all:  子条件全部为真 → 命中
    any:  任一为真 → 命中
    none: 全部为假 → 命中（用于"排除型"规则）
    可嵌套，例如 all 里放一个 any。

支持的运算符（op）
------------------
    gt / gte / lt / lte / eq / ne      与常量比较
    ratio_gte / ratio_lte              两字段比值比较，value 形如
                                       {other: dst_bytes, factor: 20, floor: 1}

灵敏度缩放
----------
每条叶子条件默认 scalable=true，阈值按 k = 1.25 - 0.5*s 缩放：
    增大类（gt/gte/ratio_gte）阈值 × k  → k 越小越敏感
    减小类（lt/lte/ratio_lte）阈值 ÷ k
某个条件不想被缩放时写 scalable: false。
"""

import os
import time

import yaml

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE, "rules")

SEVERITIES = ("info", "low", "medium", "high", "critical")
_GT_OPS = {"gt", "gte", "ratio_gte"}
_LT_OPS = {"lt", "lte", "ratio_lte"}
_VALID_OPS = _GT_OPS | _LT_OPS | {"eq", "ne"}


class RuleError(Exception):
    """规则文件格式错误。"""


def _num(v, where):
    try:
        return float(v)
    except (TypeError, ValueError):
        raise RuleError("%s: 期望数值，得到 %r" % (where, v))


class Condition:
    """一条叶子条件。"""

    __slots__ = ("field", "op", "value", "scalable", "other", "factor", "floor")

    def __init__(self, spec, where):
        if not isinstance(spec, dict):
            raise RuleError("%s: 叶子条件必须是 mapping" % where)
        self.field = spec.get("field")
        self.op = spec.get("op")
        if not self.field:
            raise RuleError("%s: 缺少 field" % where)
        if self.op not in _VALID_OPS:
            raise RuleError("%s: 非法 op=%r，可选 %s" % (where, self.op, sorted(_VALID_OPS)))
        self.scalable = bool(spec.get("scalable", True))

        raw = spec.get("value")
        if self.op in ("ratio_gte", "ratio_lte"):
            if not isinstance(raw, dict) or "other" not in raw or "factor" not in raw:
                raise RuleError("%s: ratio 类 op 的 value 需要 {other, factor}" % where)
            self.other = raw["other"]
            self.factor = _num(raw["factor"], where + ".factor")
            self.floor = _num(raw.get("floor", 1.0), where + ".floor")
            self.value = None
        else:
            self.value = _num(raw, where + ".value")
            self.other = self.factor = self.floor = None

    def test(self, feats, k):
        v = float(feats.get(self.field, 0.0))
        if self.op in ("gt", "gte"):
            thr = self.value * k if self.scalable else self.value
            return v > thr if self.op == "gt" else v >= thr
        if self.op in ("lt", "lte"):
            thr = self.value / k if self.scalable else self.value
            return v < thr if self.op == "lt" else v <= thr
        if self.op == "eq":
            return v == self.value
        if self.op == "ne":
            return v != self.value
        other = max(float(feats.get(self.other, 0.0)), self.floor)
        factor = self.factor * k if self.scalable else self.factor
        if self.op == "ratio_gte":
            return v >= factor * other
        return v <= factor * other

    def describe(self):
        if self.op in ("ratio_gte", "ratio_lte"):
            sym = "≥" if self.op == "ratio_gte" else "≤"
            return "%s %s %g×max(%s, %g)" % (self.field, sym, self.factor, self.other, self.floor)
        sym = {"gt": ">", "gte": "≥", "lt": "<", "lte": "≤", "eq": "=", "ne": "≠"}[self.op]
        return "%s %s %g" % (self.field, sym, self.value)


class ConditionNode:
    """条件树节点：组合子（all/any/none）或叶子条件。"""

    __slots__ = ("kind", "children", "leaf")

    def __init__(self, spec, where="condition"):
        self.kind = None
        self.children = []
        self.leaf = None
        if not isinstance(spec, dict):
            raise RuleError("%s: 条件树必须是 mapping" % where)

        keys = set(spec) & {"all", "any", "none"}
        if keys:
            if len(keys) > 1:
                raise RuleError("%s: all/any/none 只能出现一个，得到 %s" % (where, sorted(keys)))
            self.kind = keys.pop()
            items = spec[self.kind]
            if not isinstance(items, list) or not items:
                raise RuleError("%s.%s: 需要非空列表" % (where, self.kind))
            for i, item in enumerate(items):
                self.children.append(ConditionNode(item, "%s.%s[%d]" % (where, self.kind, i)))
        else:
            self.kind = "leaf"
            self.leaf = Condition(spec, where)

    def test(self, feats, k):
        if self.kind == "leaf":
            return self.leaf.test(feats, k)
        if self.kind == "all":
            return all(c.test(feats, k) for c in self.children)
        if self.kind == "any":
            return any(c.test(feats, k) for c in self.children)
        return not any(c.test(feats, k) for c in self.children)  # none

    def describe(self):
        if self.kind == "leaf":
            return self.leaf.describe()
        joiner = {"all": " 且 ", "any": " 或 ", "none": " 且非 "}[self.kind]
        inner = joiner.join(c.describe() for c in self.children)
        return "(%s)" % inner if len(self.children) > 1 else inner

    def leaves(self):
        if self.kind == "leaf":
            return [self.leaf]
        out = []
        for c in self.children:
            out.extend(c.leaves())
        return out


class Rule:
    """一条完整规则。"""

    __slots__ = ("id", "name", "enabled", "attack", "severity", "confidence",
                 "attck", "attck_name", "description", "tags", "window",
                 "condition", "source", "hit_count")

    def __init__(self, spec, source="?"):
        where = "%s[%s]" % (source, spec.get("id", "?"))
        if not isinstance(spec, dict):
            raise RuleError("%s: 规则必须是 mapping" % where)

        self.id = str(spec.get("id") or "").strip()
        if not self.id:
            raise RuleError("%s: 缺少 id" % where)
        self.name = str(spec.get("name") or self.id)
        self.enabled = bool(spec.get("enabled", True))
        self.attack = str(spec.get("attack") or "unknown")
        self.severity = str(spec.get("severity") or "medium")
        if self.severity not in SEVERITIES:
            raise RuleError("%s: 非法 severity=%r" % (where, self.severity))
        self.confidence = _num(spec.get("confidence", 0.8), where + ".confidence")
        if not 0.0 <= self.confidence <= 1.0:
            raise RuleError("%s: confidence 必须在 0~1" % where)
        self.attck = str(spec.get("attck") or "")
        self.attck_name = str(spec.get("attck_name") or "")
        self.description = str(spec.get("description") or "")
        self.tags = list(spec.get("tags") or [])
        self.window = str(spec.get("window") or "")
        self.condition = ConditionNode(spec.get("condition"), where + ".condition")
        self.source = source
        self.hit_count = 0

    def match(self, feats, k):
        return self.condition.test(feats, k)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "attack": self.attack,
            "severity": self.severity,
            "confidence": self.confidence,
            "attck": self.attck,
            "attck_name": self.attck_name,
            "description": self.description,
            "tags": self.tags,
            "window": self.window,
            "expression": self.condition.describe(),
            "source": self.source,
            "hit_count": self.hit_count,
        }


class RuleSet:
    """规则集合：加载、热重载、求值。"""

    def __init__(self, rules_dir=None, auto_reload=True, reload_interval=2.0):
        self.rules_dir = rules_dir or RULES_DIR
        self.auto_reload = auto_reload
        self.reload_interval = reload_interval
        self.rules = []
        self.errors = []
        self.loaded_at = 0.0
        self._mtimes = {}
        self._last_check = 0.0
        self.load()

    # ------------------------------------------------------------ 加载
    def _scan(self):
        """返回 {文件路径: mtime}。"""
        found = {}
        if not os.path.isdir(self.rules_dir):
            return found
        for fn in sorted(os.listdir(self.rules_dir)):
            if fn.endswith((".yaml", ".yml")):
                p = os.path.join(self.rules_dir, fn)
                found[p] = os.path.getmtime(p)
        return found

    def load(self):
        """全量加载；单文件出错不影响其他文件（错误收集到 self.errors）。"""
        rules, errors, mtimes = [], [], {}
        for path, mtime in self._scan().items():
            fname = os.path.basename(path)
            mtimes[path] = mtime
            try:
                with open(path, "r", encoding="utf-8") as fp:
                    doc = yaml.safe_load(fp) or {}
            except Exception as e:  # YAML 语法错
                errors.append({"file": fname, "error": "YAML 解析失败: %s" % e})
                continue
            items = doc.get("rules") if isinstance(doc, dict) else None
            if not isinstance(items, list):
                errors.append({"file": fname, "error": "缺少 rules 列表"})
                continue
            for spec in items:
                try:
                    rules.append(Rule(spec, fname))
                except RuleError as e:
                    errors.append({"file": fname, "error": str(e)})

        # 重复 id 检测：后加载的覆盖前者，但要报错提醒
        seen = {}
        deduped = []
        for r in rules:
            if r.id in seen:
                errors.append({"file": r.source, "error": "规则 id 重复: %s（已忽略后者）" % r.id})
                continue
            seen[r.id] = r
            deduped.append(r)

        self.rules = deduped
        self.errors = errors
        self._mtimes = mtimes
        self.loaded_at = time.time()
        return self

    def reload_if_changed(self):
        """按文件 mtime 判断是否需要重载，最多每 reload_interval 秒检查一次。"""
        if not self.auto_reload:
            return False
        now = time.time()
        if now - self._last_check < self.reload_interval:
            return False
        self._last_check = now
        if self._scan() != self._mtimes:
            self.load()
            return True
        return False

    def reload(self):
        """强制重载（供 /api/rules/reload 调用）。"""
        return self.load()

    # ------------------------------------------------------------ 求值
    def evaluate(self, features, sensitivity=0.5):
        """返回命中列表；字段名保持向后兼容（rule/label/confidence）。"""
        self.reload_if_changed()
        s = max(0.0, min(1.0, float(sensitivity)))
        k = 1.25 - 0.5 * s
        hits = []
        for r in self.rules:
            if not r.enabled:
                continue
            try:
                if r.match(features, k):
                    r.hit_count += 1
                    hits.append({
                        "rule": r.name,          # 兼容旧字段
                        "label": r.attack,       # 兼容旧字段
                        "confidence": r.confidence,
                        "id": r.id,
                        "severity": r.severity,
                        "attck": r.attck,
                        "attck_name": r.attck_name,
                        "description": r.description,
                        "expression": r.condition.describe(),
                    })
            except Exception:
                # 单条规则异常不应影响整体检测
                continue
        return hits

    def stats(self):
        return {
            "total": len(self.rules),
            "enabled": sum(1 for r in self.rules if r.enabled),
            "by_attack": _count_by(self.rules, "attack"),
            "by_severity": _count_by(self.rules, "severity"),
            "loaded_at": self.loaded_at,
            "errors": self.errors,
            "rules_dir": self.rules_dir,
        }


def _count_by(rules, attr):
    out = {}
    for r in rules:
        key = getattr(r, attr)
        out[key] = out.get(key, 0) + 1
    return out
