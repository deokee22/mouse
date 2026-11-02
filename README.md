# NIDS · 基于双引擎融合的网络入侵检测系统

> **作者：许智雄**　|　个人项目 / 考研复试作品　|　技术栈：Python · scikit-learn · Flask · Chart.js

这是一个**网络入侵检测系统（NIDS）**演示项目。传统方案要么只有规则（认不出未知攻击），要么只有机器学习（黑盒、解释不了）。本项目采用**规则引擎 + 机器学习双引擎融合架构**，对连接级网络流量进行实时入侵检测，并提供可解释的可视化监控仪表盘。测试集准确率 **99.1%**，且每条警告都能说明"为什么这么判"。

---

## ✨ 核心特性

- **双引擎融合检测**：规则引擎（白盒可解释）+ 机器学习引擎（RandomForest 分类 + IsolationForest 异常检测），规则优先、ML 兜底。
- **规则是可热加载的数据**：14 条规则写在 `rules/*.yaml`，改完调 `/api/rules/reload` 立即生效，不用重启；每条规则带 MITRE ATT&CK 编号。
- **告警关联降噪**：同一攻击源 10 分钟内的告警自动聚合成"攻击事件"，推断攻击链阶段（侦察→初始访问→影响→外泄），实测 300 条告警压缩到 8 个事件（降噪 97%）。
- **服务端实时推送**：后台流引擎持续产生流量并检测，通过 SSE 推给控制台，不再依赖前端轮询。
- **可解释性**：每条警告输出命中规则名与置信度，不是黑盒。
- **未知攻击发现**：IsolationForest 仅用正常流量训练，专门捕捉训练时未见的异常形态。
- **实验完整**：均衡基线 / 真实分布 / CICIDS2017 二分类 / 特征消融四组实验，47 项单元测试。

---

## 🚀 快速开始

```bash
# 1. 安装依赖（建议虚拟环境）
pip install -r requirements.txt

# 2. 训练模型（首次运行必须执行，约 30 秒）
python train_model.py

# 3. 启动服务
python backend/api.py
# 浏览器打开 http://127.0.0.1:5000
```

仪表盘默认开启"持续监控"，每 2.5 秒模拟注入一批（20 条）流量并实时展示检测结果。也可双击 `启动仪表盘.bat` 一键启动。

---

## 🏗️ 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                  浏览器控制台 (Chart.js + EventSource)          │
│  监控台 │ 攻击事件 │ 规则库 │ 模型分析 │ 告警历史                 │
└────────▲──────────────────────────────┬──────────────────────┘
         │ SSE 实时推送（服务端 → 前端）    │ REST（启停/查询/配置）
┌────────┴──────────────────────────────▼──────────────────────┐
│                      Flask 后端 (api.py, threaded)             │
└────────▲──────────────────────┬───────────────────────────────┘
         │                      │
┌────────┴─────────┐   ┌────────▼─────────┐   ┌────────────────┐
│ 实时流 StreamEngine│   │ 检测 FusionPolicy │   │ 关联 Correlation │
│ 战役模型持续产生流量│──▶│ 规则优先 + ML 兜底 │──▶│ 同源聚合/攻击链  │
└──────────────────┘   └────────┬─────────┘   └───────┬────────┘
                                │                     │
                    ┌───────────┴──────────┐   ┌──────▼───────┐
                    │ 规则引擎（YAML DSL）  │   │ SQLite        │
                    │ 14 条规则 · 可热加载  │   │ alerts        │
                    ├──────────────────────┤   │ incidents     │
                    │ ML 引擎               │   └──────────────┘
                    │ RF 分类 + IF 异常检测 │
                    └──────────────────────┘
```

## 📁 目录结构

```
nids-project/
├── train_model.py            # 主模型训练（均衡数据）
├── train_realistic.py        # 真实分布数据集对比实验
├── train_cicids.py           # CICIDS2017 二分类基线
├── train_ablation.py         # 特征消融实验（A/B/C 三组）
├── requirements.txt
├── rules/                    # ★ 规则库（YAML DSL，可热加载）
│   ├── dos.yaml              #   DoS 类 4 条
│   ├── port_scan.yaml        #   端口扫描 4 条
│   ├── brute_force.yaml      #   暴力破解 3 条
│   └── exfiltration.yaml     #   数据外泄 3 条
├── backend/
│   ├── traffic_generator.py  # 合成流量生成器（5 类标签、含边界样本）
│   ├── rule_dsl.py           # 规则 DSL：加载/条件树/热重载/错误隔离
│   ├── detector.py           # 规则引擎 + ML 引擎 + 融合策略
│   ├── correlation.py        # 告警关联：聚合/攻击链/风险打分
│   ├── stream_engine.py      # 实时流：战役模型 + SSE 广播
│   ├── event_factory.py      # 事件结构（模拟与实时共用）
│   ├── storage.py            # SQLite：alerts + incidents
│   ├── pcap_parser.py        # PCAP 解析（TCP 会话切分）
│   ├── cicids_adapter.py     # CICIDS2017 适配器
│   ├── realistic_dataset.py  # 真实分布数据集生成
│   ├── config.py             # 环境变量配置中心
│   └── api.py                # Flask REST + SSE 服务
├── frontend/
│   ├── index.html            # 控制台页面（5 个标签页）
│   └── dashboard.js          # 前端逻辑（SSE 接收 + Chart.js 渲染）
├── models/                   # 训练产出
│   ├── random_forest.joblib
│   ├── isolation_forest.joblib
│   ├── metrics.json          # 均衡数据指标
│   ├── metrics_realistic.json# 真实分布指标
│   ├── metrics_cicids.json   # CICIDS 指标
│   └── metrics_ablation.json # 消融实验结果
├── tests/                    # 47 项单元测试
├── docs/                     # 设计文档与专题说明
├── data/                     # 样本数据、PCAP、SQLite 库
├── NIDS项目答辩/             # 答辩 PPT 与大纲
└── 答辩宝典.md               # 口语化走读 + 导师追问话术
```

---

## 🔬 关键技术

### 特征工程
借鉴连接记录式 IDS 的思路，从 PCAP 聚合出 **9 维自定义特征**：`duration`、`protocol_type`、`src_bytes`、`dst_bytes`、`packet_count`、`failed_logins`、`num_unique_ports`、`syn_rate`、`bytes_per_packet`。其中 `failed_logins` 当前只是源 IP 发往 21/22/3389 端口的包命中数，并非真实失败登录次数；`num_unique_ports` 是源 IP 在整个 PCAP 范围内访问的不同目的端口数。详细语义与边界见 [`docs/特征语义说明.md`](docs/特征语义说明.md)。

### 双引擎设计动机
- **规则引擎**：对已知攻击模式给出零延迟、可解释的判定，但无法发现规则之外的攻击。
- **IsolationForest**：仅用正常流量训练（无监督），不依赖攻击标签，可发现**未知攻击**；输出异常分用于提升可疑级别。
- **RandomForest**：有监督多分类，给出具体攻击类别与概率分布，支持特征重要性分析。
- **融合策略**：规则优先（避免 ML 在明显模式上的不确定性），ML 兜底（覆盖规则盲区），异常分修正（ML 判正常但形态异常时标记"可疑"）。这对应工业界 IDS 的实际架构（Snort/Suricata 规则 + 统计/ML 辅助）。

### 评估结果（合成测试集）
- Accuracy / Precision / Recall / F1 均为 **0.991**（macro）
- 混淆矩阵显示误判集中在 `normal ↔ port_scan` 边界（低速扫描与高频正常访问形态重叠），这是刻意保留的边界样本，用于讨论误报与漏报的权衡。

### 数据集说明
演示版使用**合成流量生成器**（`traffic_generator.py`），按各类攻击统计特征建模，并通过 `boundary_mix` 参数注入约 6% 类边界重叠样本，避免指标虚高。目前训练与指标主要来自合成数据及自建的贴近真实分布数据，尚不能据此声称已在 CICIDS2017 等公开真实数据集上验证。接入公开数据集时需要单独编写适配器，并逐项核对字段语义、单位、聚合窗口和标签；不能假定 `FEATURES` 与公开数据集原始特征一一对应。详见 [`docs/特征语义说明.md`](docs/特征语义说明.md)。

---

## 🔌 API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/stream` | **SSE 实时推送**检测事件 |
| GET | `/api/stream/status` | 实时流状态（速率/已推送/攻击数） |
| POST | `/api/stream/start` | 启动实时流，body: `{"rate": 2}` |
| POST | `/api/stream/stop` | 暂停实时流 |
| GET | `/api/incidents` | 攻击事件列表（含降噪比统计） |
| GET | `/api/incidents/<id>` | 事件详情 + 原始告警下钻 |
| POST | `/api/incidents/<id>/status` | 处置状态流转（open/investigating/closed） |
| GET | `/api/rules` | 规则库（YAML DSL，含 ATT&CK 与命中次数） |
| POST | `/api/rules/reload` | 热重载规则文件，无需重启 |
| GET | `/api/simulate?n=20` | 模拟 n 条流量并逐条检测 |
| GET | `/api/scenario?type=ssh` | 指定攻击场景批量注入 |
| POST | `/api/detect` | 对单条特征记录检测，body: `{"features": {...}}` |
| GET | `/api/metrics` | 模型评估指标 |
| GET | `/api/dataset_compare` | 平衡合成 vs 真实分布 两套数据集指标对比 |
| GET | `/api/ablation` | 特征消融实验（A/B/C 三组特征） |
| GET | `/api/cicids` | CICIDS2017 二分类基线结果 |
| GET | `/api/features` | 特征定义 |

---

## 📌 可扩展方向
- 规则从"单连接判据"升级为"跨事件状态机"（CEP：5 分钟内失败 20 次再成功 1 次）
- 用官方 CICIDS2017 全量 CSV 复跑 P1 / P2（当前为构造样本）
- 增加 LSTM/AutoEncoder 时序模型做对比
- 真实网卡抓包（需 Npcap，Windows 下要管理员权限）
- PCAP 文件上传解析（Scapy / Zeek）

---

## 🆕 v2 增强：安全运营控制台

在原有检测核心之上，v2 将演示层升级为可交互的安全运营控制台：

- **攻击场景模拟器**：一键注入 SSH 爆破 / 端口扫描 / DDoS / 数据外泄 / 混合流量，支持低/中/高三级强度。
- **灵敏度调节**：滑块实时调整规则阈值（0~100%），现场可演示"提高灵敏度 → 误报/召回变化"的权衡。
- **多图表监控**：检测趋势、攻击类型分布、协议分布、Top 攻击源 IP。
- **告警管理**：按级别/攻击筛选，点击任意告警查看**可解释依据**，支持导出 CSV。
- **可解释性**：每条告警给出"特征重要性 × 相对正常样本偏离度"的贡献分解（如暴力破解样本 top 贡献为 `failed_logins`）。
- **多模型对比**：模型分析页对比 RandomForest / SVM / DecisionTree 的准确率、精确率、召回率、F1，并展示特征重要性与混淆矩阵。

对应接口：`/api/scenario`、`/api/sensitivity`、`/api/explain`、`/api/model_compare`、`/api/feature_importance`、`/api/scenarios`。

## 🆕 v3 增强：真实 PCAP 与检测报告

- **真实 PCAP 上传**：上传 `.pcap` 文件，Scapy 解析包级流量并按双向五元组聚合为 9 维连接特征，复用双引擎检测——不再只是"合成数据"。
- **示例 PCAP**：`data/sample.pcap`（1109 包），含正常 HTTP + SYN 洪泛 + 端口扫描 + SSH 爆破 + 数据外泄；实测四类攻击全部识别（121 连接 / 91 攻击）。
- **检测报告导出**：一键生成 HTML 检测报告（KPI、攻击分布、明细表），可下载留痕。

对应接口：`/api/pcap`（multipart 上传）、`/api/report`（生成 HTML 报告）。

## 🆕 v4 增强：告警持久化与历史查询

- **SQLite 告警库**：所有检测出的攻击告警自动落库（`data/alerts.db`），含时间、源/目的、判定、级别、置信度、引擎、依据。
- **历史查询页**：新增"告警历史"标签页，支持按严重级别筛选、分页浏览、一键清空、导出 CSV。
- **统计**：历史告警总数、按级别分布、按攻击类型分布、Top 源 IP。

对应接口：`/api/alerts`（分页/筛选查询）、`/api/alerts/stats`、`/api/alerts/clear`。

## 🆕 v5 增强：真实分布数据集对比实验

- 新增 `backend/realistic_dataset.py`：按 NSL-KDD / CICIDS2017 范式自建"贴近真实分布"数据集（正常 70%、攻击 30% 且内部不均、12% 困难样本、2% 标签噪声）。
- 新增 `train_realistic.py`：在真实分布数据上训练对比，产出 `models/metrics_realistic.json`。
- 对比结果：平衡数据 RF **0.991** → 真实分布 RF **0.9688**（macro-F1 0.9406），少数类外泄召回 0.85——更接近真实场景。
- 前端「模型分析」页新增数据集对比图。
- 详见 `数据集说明.md`（构造方法、参数、答辩话术）。

对应接口：`/api/dataset_compare`。

## 🆕 v6 工程化完善：配置 / 日志 / 测试 / Docker

- **集中配置** `backend/config.py`：端口、路径、灵敏度、日志级别、上传上限，均支持环境变量覆盖（`NIDS_HOST` / `NIDS_PORT` / `NIDS_LOG_LEVEL` / `NIDS_SENSITIVITY`）。
- **日志系统**：请求与异常写入 `logs/nids.log`，同时输出控制台。
- **健康检查**：`GET /api/health` 返回服务状态、模型加载、灵敏度、DB 路径。
- **统一错误处理**：404 / 500 返回 JSON。
- **单元测试** `tests/`：检测器规则、PCAP 解析、告警存储共 **15 个用例**，运行 `python -m unittest discover -s tests`。
- **Docker 部署**：`Dockerfile` + `docker-compose.yml`，`docker compose up -d` 一键启动。

## 🆕 P1：CICIDS2017 真实数据集接入

- **适配器** `backend/cicids_adapter.py`：读取 CICIDS2017 MachineLearningCSV，支持二分类（BENIGN vs Attack）与多分类（映射到项目 5 类）。
- **训练脚本** `train_cicids.py`：二分类基线（LogisticRegression + RandomForest），输出 `models/metrics_cicids.json`。
- **构造样本** `scripts/make_cicids_sample.py`：生成 CICIDS 格式样本，用于验证流程（**非真实数据**）。
- **接入说明** `docs/CICIDS接入说明.md`：下载、标签映射、数据泄漏注意事项。

> 注意：当前 `data/cicids/sample.csv` 是构造样本，仅验证流程；真实实验请用官方 CSV 替换。

## 🆕 P2：特征消融实验

回答"这 9 维特征到底有没有用"：把特征按采集成本拆成三组，在**同一数据划分、同一组超参**下分别训练，只让特征组这一个变量变化。

| 组 | 特征 | 维度 | 准确率 | Macro-F1 | brute_force 召回 | 推理延迟 |
|---|---|---|---|---|---|---|
| A 基础流量 | duration, protocol_type, src_bytes, dst_bytes, packet_count | 5 | 0.9608 | 0.9272 | 0.8148 | 34.5 ms/千条 |
| **B 基础+行为** | A + failed_logins, num_unique_ports, syn_rate | 8 | **0.9704** | **0.9431** | **0.9012** | 38.1 ms/千条 |
| C 全特征 | B + bytes_per_packet | 9 | 0.9688 | 0.9406 | 0.9136 | 38.3 ms/千条 |

结论（RandomForest，DecisionTree 趋势一致）：

1. **行为特征贡献显著**：A→B 带来 +1.59pp Macro-F1，其中暴力破解召回从 81.5% 提升到 90.1%（+8.6pp）——`failed_logins` 直接刻画"试错次数"，是基础流量特征给不出的信息。
2. **派生特征边际贡献为负**：B→C 的 `bytes_per_packet` 反而让 Macro-F1 下降 0.25pp。因为它 = (src_bytes+dst_bytes)/packet_count，信息已被三个原始特征完全覆盖，多一个维度只增加分裂噪声。
3. **最优组合是 B 组，不是全特征**：这说明"特征越多越好"是错的，消融实验的价值正在于证伪它。

- 脚本：`train_ablation.py` → `models/metrics_ablation.json`
- 接口：`GET /api/ablation`，控制台"模型分析"页可视化

## 🆕 P3：实时流 · 告警关联 · 规则 DSL

从"能检测"到"能运营"，补三块：

**1. 实时流（`stream_engine.py`）**

后台线程按固定速率产生流量 → 检测 → 落库 → 关联 → 通过 SSE 广播。控制台打开就在动，不再需要点按钮。内含"攻击战役"模型：一个源按杀伤链推进（扫描→爆破→洪泛→外传），战役之间留平静期，背景流量占 45%。

**2. 告警关联（`correlation.py`）**

| 能力 | 实现 |
|---|---|
| 聚合 | 同源 + 10 分钟滑动窗口 → 一个 incident |
| 攻击链 | 4 阶段模型，按 MITRE 战术顺序排列 |
| 风险分 | `严重度基数 + 15×阶段跨度 + 5·log2(告警数)`，封顶 100 |
| 降噪比 | `alerts / incidents`，控制台直接展示 |
| 处置 | open → investigating → closed，已关闭不再接收新告警 |

**3. 规则 DSL（`rule_dsl.py` + `rules/*.yaml`）**

规则从硬编码 `if` 变成 YAML 数据：条件树（all/any/none 可嵌套）、比值运算符（`src_bytes >= 20×dst_bytes`）、灵敏度自动缩放、文件 mtime 热重载、单规则错误隔离。14 条规则覆盖 4 类攻击，全部标注 ATT&CK。

详见 [`docs/P3_实时流与告警关联.md`](docs/P3_实时流与告警关联.md)。

## 📄 License
MIT © 许智雄
