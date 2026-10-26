# CICIDS2017 接入说明（P1）

## 1. 为什么用 CICIDS2017
- 公开、带标签、包含正常 + 多种攻击，是 NIDS 研究最常用的基准之一。
- 提供 **MachineLearningCSV**（CICFlowMeter 已提取特征），不用自己从 pcap 提特征，适合先打通流程。

## 2. 下载
- 官方：https://www.unb.ca/cic/datasets/ids-2017.html
- 下载 **MachineLearningCSV.zip**（约 300MB，8 个 CSV：Monday–Friday）
- 解压后把 CSV 放到 `data/cicids/`（项目会读取该目录下所有 `.csv`）

## 3. 运行
```bash
# 真实数据：把 CSV 放到 data/cicids/ 后
python train_cicids.py
```

输出 `models/metrics_cicids.json`（Accuracy / Precision / Recall / F1 / 混淆矩阵）。

## 4. 标签映射
- 二分类：`BENIGN` = 0，其余攻击 = 1
- 多分类（adapter 已支持）：映射到项目 5 类
  - DoS / DDoS / Heartbleed → `dos`
  - PortScan → `port_scan`
  - FTP-Patator / SSH-Patator / Web Brute Force → `brute_force`
  - Web XSS / SQLi / Bot / Infiltration → `exfiltration`

## 5. 当前验证用的"构造样本"
- `data/cicids/sample.csv` 是 `scripts/make_cicids_sample.py` 构造的，**不是真实 CICIDS**。
- 它的作用只是验证 adapter / 训练流程能跑通（构造样本上 RF acc 0.973）。
- **真实实验请用官方 CSV 替换它**，否则不能写进答辩材料。

## 6. 与项目 9 维特征的关系（关键）
- CICIDS 的 79 维特征是 CICFlowMeter 生成的，和项目自定义的 9 维连接特征**语义不完全对应**。
- 因此 adapter 保留 CICIDS 原始数值特征做基线，**不强行映射**到 9 维。
- 若要把项目模型接到 CICIDS，需要单独做特征映射实验（例如把 Flow Duration / Total Fwd Packets 映射到 `duration` / `packet_count`），并逐列核对单位与方向。

## 7. 真实数据实验的注意事项
- **避免数据泄漏**：CICIDS 同一攻击场景会产生大量相似流。划分时按日期/场景分组，别让同场景样本同时进训练和测试。
- 类别极不平衡（BENIGN 占绝大多数），指标要看 **Recall / macro-F1 / 每类召回**，不能只看 Accuracy。
- 报告要写清楚：用了哪些 CSV、标签怎么映射、怎么划分。

## 8. 下一步（P2）
- 特征消融：A 基础特征 / B 加行为特征 / C 完整特征，固定划分对比 macro-F1 与各类 Recall。
