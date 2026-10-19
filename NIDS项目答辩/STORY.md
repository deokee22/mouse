# STORY.md — NIDS 项目考研复试答辩

## ① 用户意图对齐

- **目标受众**：考研复试现场的导师组（网络空间安全方向），评审场景
- **核心目标**：让导师相信候选人具备"安全领域知识 + 机器学习工程能力 + 系统落地思维"的复合素质；记住"双引擎融合"这一设计决策及其理由
- **PPT 长度**：13 页（Hero 页 3 页：封面、评估结果、致谢，占 23%）
- **视觉调性**：学术严谨 / 蓝白克制 / 证据驱动
- **内容边界**：必讲——双引擎动机、特征工程、评估指标、误差分析；不讲——代码逐行讲解、与商业产品对比；禁碰——虚构数据（所有指标来自真实训练输出）

## ② 页面布局骨架

共 13 页，4 个章节。目录声明 4 章 → 4 个 section 扉页（页 3/5/8/11），编号 01–04 连续，标题与目录逐字一致。

| 页 | 类型 | 角色 | 节奏 | 版式 |
|---|---|---|---|---|
| 1 | cover | hero | peak | 全屏视觉+大标题（对称，封面豁免） |
| 2 | catalog | supporting | valley | 左深蓝栏导航（非对称） |
| 3 | section 01 | transition | transition | 大数字+标题 |
| 4 | content | supporting | valley | 非对称双栏 60:40（论述+攻击类型表） |
| 5 | section 02 | transition | transition | 大数字+标题 |
| 6 | content | supporting | peak | 左标题窄栏+右 SVG 架构大图（L1 主视觉） |
| 7 | content | supporting | valley | 上大图（特征重要性条形图）+ 下方特征表 |
| 8 | section 03 | transition | transition | 大数字+标题 |
| 9 | content | hero | peak | 巨型数字+洞察（99.10% 准确率 + KPI 三联数） |
| 10 | content | supporting | valley | 表格页（混淆矩阵 + 误差洞察） |
| 11 | section 04 | transition | transition | 大数字+标题 |
| 12 | content | supporting | valley | 左标题+右内容（结论与展望） |
| 13 | ending | hero | peak | 全屏视觉+致谢 |

Hero 占比 3/13 = 23% ✓；Hero 不相邻 ✓；非对称版式 6 页（2/4/6/7/9/12 中非对称为主）≥40% ✓；N 卡片横排 0 次 ✓；相邻页版式无重复 ✓；valley 无连续 3 页 ✓。

## ③ 页面大纲

### 页 1 · 封面（cover / hero / peak）
- layout: 全屏视觉+大标题
- visual: L1 顶部深蓝横条 + 底部信息条（atmosphere）
- density: 字数约 60 / 留白约 30%
- anti_pattern: 禁止党政红金；禁止装饰小图塞标题右侧
- description: 主标"基于双引擎融合的网络入侵检测系统"，英文副标，汇报人占位，时间 2026 年

### 页 2 · 目录（catalog / supporting / valley）
- layout: 左深蓝栏导航（非对称）
- visual: L3 章节编号方块
- density: 4 条目 + 摘要，字数约 90
- anti_pattern: 禁止圆球编号；禁止英文比中文抢眼
- description: 四章：研究背景与动机 / 系统设计 / 实验与评估 / 总结与展望

### 页 3 · 章节扉页 01（section / transition）
- 标题：研究背景与动机；要点：威胁态势、检测范式、问题定义

### 页 4 · 背景与问题定义（content / supporting / valley）
- layout: 非对称双栏 60:40
- visual: L1 四类攻击特征表（evidence）
- description: 入侵检测是网络边界防护的核心环节；四类攻击特征差异显著 → 单一检测手段无法兼顾"已知模式可解释"与"未知攻击可发现"，这是双引擎动机的问题来源

### 页 5 · 章节扉页 02（section / transition）
- 标题：系统设计；要点：双引擎架构、融合策略、特征工程

### 页 6 · 双引擎融合架构（content / supporting / peak）
- layout: 左标题窄栏 + 右 SVG 架构图（L1 占右 65%）
- visual: L1 架构 SVG（anchor）
- description: 规则引擎负责已知模式的零延迟可解释判定，IsolationForest 以纯正常流量训练发现未知攻击，RandomForest 给出攻击类别；规则优先、ML 兜底、异常分修正 → 对应工业界 Snort/Suricata 混合架构

### 页 7 · 特征工程（content / supporting / valley）
- layout: 上大图（特征重要性横向条形图）+ 下方特征表
- visual: Chart(bar) + Table（evidence）
- description: 9 维连接级特征参考 NSL-KDD 范式；特征重要性前三 src_bytes 0.28 / failed_logins 0.16 / packet_count 0.14 → 与攻击机理一致，证明特征设计有效

### 页 8 · 章节扉页 03（section / transition）
- 标题：实验与评估；要点：数据集、评估指标、误差分析

### 页 9 · 评估结果（content / hero / peak）
- layout: 巨型数字+洞察
- visual: 大数字 99.10%（≥100px）+ KPI 三联数（anchor）
- description: 测试集 1000 条，Accuracy/Precision/Recall/F1 均 0.991；刻意注入 6% 边界重叠样本避免指标虚高 → 指标真实可信而非"数据过干净"

### 页 10 · 混淆矩阵与误差分析（content / supporting / valley）
- layout: 表格页（混淆矩阵 ≥50% + 右侧洞察）
- visual: Table（evidence）
- description: 误判集中在 normal↔port_scan 边界：低速扫描形态接近高频正常访问 → 单连接特征存在理论极限，需时间序列聚合缓解

### 页 11 · 章节扉页 04（section / transition）
- 标题：总结与展望；要点：主要结论、不足、改进方向

### 页 12 · 结论与展望（content / supporting / valley）
- layout: 左标题+右内容
- description: 结论：双引擎融合兼顾可解释性与覆盖率；不足：合成数据与真实分布有差距、未覆盖加密流量；展望：接入 NSL-KDD/CICIDS-2017、时序模型对比、PCAP 实时解析

### 页 13 · 致谢（ending / hero / peak）
- layout: 全屏视觉+大标题
- description: 恳请各位老师批评指正
