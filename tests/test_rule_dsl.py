# -*- coding: utf-8 -*-
"""规则 DSL 测试：加载、求值、灵敏度缩放、热重载、错误隔离。"""

import os
import sys
import tempfile
import shutil
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "backend"))

from rule_dsl import RuleSet, Rule, RuleError, ConditionNode, RULES_DIR  # noqa: E402

NORMAL = {"duration": 2, "protocol_type": 0, "src_bytes": 500, "dst_bytes": 1000,
          "packet_count": 10, "failed_logins": 0, "num_unique_ports": 2,
          "syn_rate": 0.1, "bytes_per_packet": 150}

SYN_FLOOD = {"duration": 0.5, "protocol_type": 0, "src_bytes": 500000, "dst_bytes": 100,
             "packet_count": 1200, "failed_logins": 0, "num_unique_ports": 1,
             "syn_rate": 0.95, "bytes_per_packet": 400}


class TestRuleLoading(unittest.TestCase):
    def setUp(self):
        self.rs = RuleSet(RULES_DIR, auto_reload=False)

    def test_rules_loaded_without_error(self):
        self.assertGreaterEqual(len(self.rs.rules), 10, "规则库至少应有 10 条规则")
        self.assertEqual(self.rs.errors, [], "规则文件不应有解析错误")

    def test_rule_ids_unique(self):
        ids = [r.id for r in self.rs.rules]
        self.assertEqual(len(ids), len(set(ids)), "规则 id 必须唯一")

    def test_every_rule_has_attck(self):
        missing = [r.id for r in self.rs.rules if not r.attck]
        self.assertEqual(missing, [], "每条规则都应标注 ATT&CK 编号: %s" % missing)

    def test_stats_shape(self):
        st = self.rs.stats()
        self.assertEqual(st["total"], len(self.rs.rules))
        self.assertIn("by_attack", st)
        self.assertIn("by_severity", st)


class TestRuleEvaluation(unittest.TestCase):
    def setUp(self):
        self.rs = RuleSet(RULES_DIR, auto_reload=False)

    def test_normal_traffic_no_hit(self):
        self.assertEqual(self.rs.evaluate(NORMAL, 0.5), [], "正常流量不应命中任何规则")

    def test_syn_flood_hit(self):
        hits = self.rs.evaluate(SYN_FLOOD, 0.5)
        ids = [h["id"] for h in hits]
        self.assertIn("DOS-001", ids)
        hit = [h for h in hits if h["id"] == "DOS-001"][0]
        # 向后兼容字段
        self.assertEqual(hit["rule"], "SYN洪泛特征")
        self.assertEqual(hit["label"], "dos")
        self.assertEqual(hit["attck"], "T1498.001")

    def test_sensitivity_scaling(self):
        """灵敏度越高，阈值越宽松，边界样本才可能命中。"""
        border = dict(NORMAL, num_unique_ports=13, packet_count=3, bytes_per_packet=60)
        self.assertEqual(self.rs.evaluate(border, 0.0), [])
        self.assertGreaterEqual(len(self.rs.evaluate(border, 1.0)), 1)

    def test_ratio_operator(self):
        """EX-001 用到了 ratio_gte：上行字节需达到下行的 20 倍。"""
        ok = {"duration": 60, "protocol_type": 0, "src_bytes": 3_000_000, "dst_bytes": 1000,
              "packet_count": 3000, "failed_logins": 0, "num_unique_ports": 1,
              "syn_rate": 0.1, "bytes_per_packet": 1000}
        ids = [h["id"] for h in self.rs.evaluate(ok, 0.5)]
        self.assertIn("EX-001", ids)

        # 同样上行量，但下行也很大 → 不满足 20 倍关系，不应命中
        balanced = dict(ok, dst_bytes=2_000_000)
        ids2 = [h["id"] for h in self.rs.evaluate(balanced, 0.5)]
        self.assertNotIn("EX-001", ids2)

    def test_hit_count_accumulates(self):
        before = next(r.hit_count for r in self.rs.rules if r.id == "DOS-001")
        self.rs.evaluate(SYN_FLOOD, 0.5)
        after = next(r.hit_count for r in self.rs.rules if r.id == "DOS-001")
        self.assertEqual(after, before + 1)


class TestRuleErrors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, text):
        with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as fp:
            fp.write(text)

    def test_bad_yaml_isolated(self):
        self._write("good.yaml", """
version: 1
rules:
  - id: OK-001
    name: 正常规则
    attack: dos
    severity: medium
    condition:
      all:
        - field: packet_count
          op: gte
          value: 10
""")
        self._write("bad.yaml", "version: 1\nrules: [ this is not: valid\n")
        rs = RuleSet(self.tmp, auto_reload=False)
        self.assertEqual(len(rs.rules), 1, "坏文件不应影响好文件")
        self.assertEqual(len(rs.errors), 1)

    def test_invalid_op_reported(self):
        self._write("bad.yaml", """
version: 1
rules:
  - id: BAD-001
    name: 非法运算符
    attack: dos
    severity: low
    condition:
      all:
        - field: packet_count
          op: roughly_equal
          value: 10
""")
        rs = RuleSet(self.tmp, auto_reload=False)
        self.assertEqual(rs.rules, [])
        self.assertEqual(len(rs.errors), 1)
        self.assertIn("op", rs.errors[0]["error"])

    def test_duplicate_id_rejected(self):
        body = """
version: 1
rules:
  - id: DUP-001
    name: 规则%s
    attack: dos
    severity: low
    condition:
      all:
        - field: packet_count
          op: gte
          value: 10
"""
        self._write("a.yaml", body % "A")
        self._write("b.yaml", body % "B")
        rs = RuleSet(self.tmp, auto_reload=False)
        self.assertEqual(len(rs.rules), 1)
        self.assertTrue(any("重复" in e["error"] for e in rs.errors))

    def test_hot_reload(self):
        path = os.path.join(self.tmp, "r.yaml")
        self._write("r.yaml", """
version: 1
rules:
  - id: HOT-001
    name: 热加载测试
    attack: dos
    severity: low
    condition:
      all:
        - field: packet_count
          op: gte
          value: 10
""")
        rs = RuleSet(self.tmp, auto_reload=True, reload_interval=0)
        self.assertEqual(len(rs.rules), 1)
        # 改文件（mtime 变化）后应自动重载
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("""
version: 1
rules:
  - id: HOT-001
    name: 热加载测试
    attack: dos
    severity: low
    condition:
      all:
        - field: packet_count
          op: gte
          value: 10
  - id: HOT-002
    name: 新增规则
    attack: dos
    severity: low
    condition:
      all:
        - field: packet_count
          op: gte
          value: 20
""")
        os.utime(path, (os.path.getmtime(path) + 5, os.path.getmtime(path) + 5))
        self.assertTrue(rs.reload_if_changed())
        self.assertEqual(len(rs.rules), 2)


class TestConditionTree(unittest.TestCase):
    def test_nested_any_all(self):
        spec = {"all": [
            {"field": "a", "op": "gte", "value": 1},
            {"any": [
                {"field": "b", "op": "gte", "value": 5},
                {"field": "c", "op": "gte", "value": 5},
            ]},
        ]}
        node = ConditionNode(spec)
        self.assertTrue(node.test({"a": 2, "b": 6, "c": 0}, 1.0))
        self.assertFalse(node.test({"a": 2, "b": 1, "c": 1}, 1.0))
        self.assertFalse(node.test({"a": 0, "b": 9, "c": 9}, 1.0))

    def test_none_combinator(self):
        node = ConditionNode({"none": [{"field": "x", "op": "gte", "value": 10}]})
        self.assertTrue(node.test({"x": 5}, 1.0))
        self.assertFalse(node.test({"x": 10}, 1.0))

    def test_describe_readable(self):
        node = ConditionNode({"all": [
            {"field": "syn_rate", "op": "gte", "value": 0.8},
            {"field": "packet_count", "op": "gte", "value": 400},
        ]})
        text = node.describe()
        self.assertIn("syn_rate", text)
        self.assertIn("≥", text)


if __name__ == "__main__":
    unittest.main()
