# -*- coding: utf-8 -*-
"""特征消融实验的结构性测试。

重点不是复现完整指标（那要跑 train_ablation.py，20 秒），
而是保证分组定义本身不出错——分组错了，整份实验结论都是错的。
"""

import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from backend.traffic_generator import FEATURES  # noqa: E402
from train_ablation import GROUPS  # noqa: E402


class TestAblationGroups(unittest.TestCase):
    def setUp(self):
        self.by_key = {g["key"]: g for g in GROUPS}

    def test_three_groups_defined(self):
        self.assertEqual([g["key"] for g in GROUPS], ["A", "B", "C"])

    def test_all_features_known(self):
        """每组引用的特征名必须真实存在，否则切列会 IndexError。"""
        for g in GROUPS:
            for f in g["features"]:
                self.assertIn(f, FEATURES, "组 %s 引用了未知特征 %s" % (g["key"], f))

    def test_no_duplicate_feature_in_group(self):
        for g in GROUPS:
            self.assertEqual(len(g["features"]), len(set(g["features"])),
                             "组 %s 有重复特征" % g["key"])

    def test_nested_a_subset_b_subset_c(self):
        """A ⊂ B ⊂ C 是"逐组加特征"的前提，破坏了就不是消融而是换特征集。"""
        a = set(self.by_key["A"]["features"])
        b = set(self.by_key["B"]["features"])
        c = set(self.by_key["C"]["features"])
        self.assertTrue(a < b, "A 不是 B 的真子集")
        self.assertTrue(b < c, "B 不是 C 的真子集")
        self.assertEqual(c, set(FEATURES), "C 组应覆盖全部 9 维特征")

    def test_dimension_growth(self):
        self.assertEqual(len(self.by_key["A"]["features"]), 5)
        self.assertEqual(len(self.by_key["B"]["features"]), 8)
        self.assertEqual(len(self.by_key["C"]["features"]), 9)


if __name__ == "__main__":
    unittest.main()
