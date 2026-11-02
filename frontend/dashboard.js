// NIDS 安全运营控制台 · 前端逻辑
const LABEL_ZH = { normal: "正常", dos: "拒绝服务", port_scan: "端口扫描", brute_force: "暴力破解", exfiltration: "数据外泄" };
const COLORS = { normal: "#3fb950", dos: "#f85149", port_scan: "#d29922", brute_force: "#f0883e", exfiltration: "#a371f7" };
const PROTO_ZH = { 0: "TCP", 1: "UDP", 2: "ICMP" };
const SCEN = [
  { k: "ssh", l: "SSH 爆破" }, { k: "scan", l: "端口扫描" }, { k: "ddos", l: "DDoS" },
  { k: "exfil", l: "数据外泄" }, { k: "mix", l: "混合流量" },
];

const state = {
  total: 0, attack: 0, live: true, timer: null, es: null,
  sensitivity: 0.5, scenario: "mix", intensity: "medium",
  labelCount: {}, protoCount: {}, srcAttack: {},
  trendLabels: [], trendAttack: [], trendNormal: [],
  trendAcc: { attack: 0, normal: 0 },
  rows: [], filter: "all",
  incidents: [], incFilter: "", incTimer: null, streamRate: 2,
  seenIncidents: new Set(),
};

const charts = {};

function chartDefaults() {
  Chart.defaults.color = "#8b98a5";
  Chart.defaults.font.size = 10;
}

function initCharts() {
  chartDefaults();
  const grid = { color: "rgba(255,255,255,.05)" };
  const ticks = { color: "#8b98a5", font: { size: 10 } };

  charts.trend = new Chart(document.getElementById("trendChart"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "攻击", data: [], borderColor: "#f85149", backgroundColor: "rgba(248,81,73,.12)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
      { label: "正常", data: [], borderColor: "#3fb950", backgroundColor: "rgba(63,185,80,.10)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
    ] },
    options: { responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: { x: { ticks: { ...ticks, maxTicksLimit: 8 }, grid }, y: { beginAtZero: true, ticks, grid } } },
  });

  charts.pie = new Chart(document.getElementById("pieChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: "#141a21", borderWidth: 2 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false, cutout: "62%",
      plugins: { legend: { position: "right", labels: { boxWidth: 10 } } } },
  });

  charts.proto = new Chart(document.getElementById("protoChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "连接数", data: [], backgroundColor: "#4c8dff", borderRadius: 4 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false } },
      scales: { x: { ticks, grid: { display: false } }, y: { beginAtZero: true, ticks, grid } } },
  });

  charts.src = new Chart(document.getElementById("srcChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "攻击次数", data: [], backgroundColor: "#f0883e", borderRadius: 4 }] },
    options: { indexAxis: "y", responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks, grid }, y: { ticks, grid: { display: false } } } },
  });

  charts.compare = new Chart(document.getElementById("compareChart"), {
    type: "bar",
    data: { labels: [], datasets: [] },
    options: { responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: { x: { ticks, grid: { display: false } }, y: { beginAtZero: true, max: 1, ticks, grid } } },
  });

  charts.importance = new Chart(document.getElementById("importanceChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "重要性", data: [], backgroundColor: "#4c8dff", borderRadius: 3 }] },
    options: { indexAxis: "y", responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks, grid }, y: { ticks, grid: { display: false } } } },
  });

  charts.dataset = new Chart(document.getElementById("datasetChart"), {
    type: "bar",
    data: { labels: [], datasets: [] },
    options: { responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: { x: { ticks, grid: { display: false } }, y: { beginAtZero: true, max: 1, ticks, grid } } },
  });

  charts.ablation = new Chart(document.getElementById("ablationChart"), {
    type: "bar",
    data: { labels: [], datasets: [] },
    options: { responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { labels: { boxWidth: 10 } } },
      scales: { x: { ticks, grid: { display: false } }, y: { beginAtZero: true, max: 1, ticks, grid } } },
  });
}

function renderScenarioBtns() {
  const box = document.getElementById("scenarioBtns");
  box.innerHTML = SCEN.map(s => `<button data-k="${s.k}" class="${s.k === state.scenario ? "active" : ""}">${s.l}</button>`).join("");
  box.querySelectorAll("button").forEach(btn => {
    btn.addEventListener("click", () => {
      state.scenario = btn.dataset.k;
      box.querySelectorAll("button").forEach(b => b.classList.toggle("active", b.dataset.k === state.scenario));
      fetchBatch();
    });
  });
}

function batchSize() {
  return state.intensity === "low" ? 10 : state.intensity === "high" ? 40 : 20;
}

async function fetchBatch() {
  const n = batchSize();
  const url = (state.scenario && state.scenario !== "mix")
    ? `/api/scenario?type=${state.scenario}&count=${n}&intensity=${state.intensity}`
    : `/api/simulate?n=${n}`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    processEvents(data.events || []);
  } catch (err) {
    document.getElementById("lastInfo").textContent = "请求失败：" + err.message;
  }
}

function processEvents(events) {
  let attack = 0, normal = 0;
  events.forEach(e => {
    state.total += 1;
    const r = e.result;
    const key = (r.label === "normal" && !r.suspicious) ? "normal" : r.label;
    state.labelCount[key] = (state.labelCount[key] || 0) + 1;
    const proto = PROTO_ZH[e.features.protocol_type] || "TCP";
    state.protoCount[proto] = (state.protoCount[proto] || 0) + 1;
    if (r.is_attack) {
      attack += 1; state.attack += 1;
      state.srcAttack[e.src] = (state.srcAttack[e.src] || 0) + 1;
    } else { normal += 1; }
    state.rows.unshift(e);
  });
  if (state.rows.length > 400) state.rows.length = 400;

  state.trendAcc.attack += attack;
  state.trendAcc.normal += normal;
  updatePie();
  updateProto();
  updateSrc();
  updateStats();
  renderTable();

  document.getElementById("lastInfo").textContent =
    `最近更新 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })} · 本批攻击 ${attack} 条`;
}

function updateStats() {
  document.getElementById("statTotal").textContent = state.total;
  document.getElementById("statAttack").textContent = state.attack;
  document.getElementById("statSens").textContent = Math.round(state.sensitivity * 100) + "%";
}

function pushTrend(attack, normal) {
  state.trendLabels.push(new Date().toLocaleTimeString("zh-CN", { hour12: false }));
  state.trendAttack.push(attack);
  state.trendNormal.push(normal);
  if (state.trendLabels.length > 20) {
    state.trendLabels.shift(); state.trendAttack.shift(); state.trendNormal.shift();
  }
  charts.trend.data.labels = state.trendLabels;
  charts.trend.data.datasets[0].data = state.trendAttack;
  charts.trend.data.datasets[1].data = state.trendNormal;
  charts.trend.update("none");
}

// 实时流是逐条到达的，如果每条都往趋势图上打一个点，2 秒就会刷满。
// 所以先累加，每 2 秒汇总成一个点。
function flushTrend() {
  if (!state.trendAcc.attack && !state.trendAcc.normal) return;
  pushTrend(state.trendAcc.attack, state.trendAcc.normal);
  state.trendAcc = { attack: 0, normal: 0 };
}

function updatePie() {
  const labels = Object.keys(state.labelCount).filter(k => state.labelCount[k] > 0);
  charts.pie.data.labels = labels.map(k => LABEL_ZH[k] || k);
  charts.pie.data.datasets[0].data = labels.map(k => state.labelCount[k]);
  charts.pie.data.datasets[0].backgroundColor = labels.map(k => COLORS[k] || "#8b98a5");
  charts.pie.update("none");
}

function updateProto() {
  const labels = Object.keys(state.protoCount);
  charts.proto.data.labels = labels;
  charts.proto.data.datasets[0].data = labels.map(k => state.protoCount[k]);
  charts.proto.update("none");
}

function updateSrc() {
  const entries = Object.entries(state.srcAttack).sort((a, b) => b[1] - a[1]).slice(0, 6);
  charts.src.data.labels = entries.map(e => e[0]);
  charts.src.data.datasets[0].data = entries.map(e => e[1]);
  charts.src.update("none");
}

function sevBadge(r) {
  const sev = (r.suspicious && r.label === "normal") ? "medium" : r.severity;
  const text = (r.suspicious && r.label === "normal") ? "可疑" : r.label_zh;
  return { sev, text };
}

function rowHtml(e) {
  const r = e.result;
  const { sev, text } = sevBadge(r);
  const basis = r.rule_hits.length
    ? r.rule_hits.map(h => h.rule).join("、")
    : `异常分 ${r.ml_detail.anomaly_score}`;
  const confPct = Math.round(r.confidence * 100);
  return `<tr data-id="${e.id}">
    <td>${e.ts}</td>
    <td>${e.src}</td>
    <td>${e.dst}:${e.dst_port}</td>
    <td>${text}</td>
    <td><span class="badge ${sev}">${sev.toUpperCase()}</span></td>
    <td><div class="conf-bar"><div class="conf-fill" style="width:${confPct}%"></div></div><span class="muted">${confPct}%</span></td>
    <td class="engine">${r.engine === "rule" ? "规则引擎" : "机器学习"}</td>
    <td class="engine">${basis}</td>
  </tr>`;
}

function passFilter(e) {
  const f = state.filter;
  if (f === "all") return true;
  if (f === "attack") return e.result.is_attack;
  return sevBadge(e.result).sev === f;
}

function renderTable() {
  const body = document.getElementById("logBody");
  const rows = state.rows.filter(passFilter).slice(0, 120);
  body.innerHTML = rows.map(rowHtml).join("");
  body.querySelectorAll("tr").forEach(tr => {
    tr.addEventListener("click", () => openExplain(Number(tr.dataset.id)));
  });
}

async function openExplain(id) {
  const evt = state.rows.find(r => r.id === id);
  if (!evt) return;
  const panel = document.getElementById("explainPanel");
  const body = document.getElementById("explainBody");
  body.innerHTML = '<div class="muted">计算中…</div>';
  panel.classList.add("open");
  try {
    const res = await fetch("/api/explain", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features: evt.features }),
    });
    const ex = await res.json();
    renderExplain(ex);
  } catch (err) {
    body.innerHTML = '<div class="muted">解释请求失败：' + err.message + "</div>";
  }
}

function renderExplain(ex) {
  let html = `<div class="kv"><span>判定</span><b>${ex.label_zh}</b></div>
    <div class="kv"><span>置信度</span><span>${(ex.confidence * 100).toFixed(1)}%</span></div>
    <div class="kv"><span>异常分</span><span>${ex.anomaly_score}</span></div>`;
  if (ex.rule_hits && ex.rule_hits.length) {
    html += `<div style="margin:12px 0"><div class="muted" style="margin-bottom:6px">命中规则</div>${ex.rule_hits.map(h => `<span class="rule-tag">${h.rule} · ${Math.round(h.confidence * 100)}%</span>`).join("")}</div>`;
  } else {
    html += `<div style="margin:12px 0" class="muted">未命中规则，判定来自机器学习模型</div>`;
  }
  html += `<div class="contrib"><div class="muted" style="margin-bottom:8px">特征贡献（重要性 × 偏离度）</div>`;
  const max = Math.max(...ex.top_features.map(f => Math.abs(f.contribution)), 0.0001);
  ex.top_features.forEach(f => {
    const pct = Math.abs(f.contribution) / max * 50;
    const bar = f.contribution >= 0
      ? `<div class="contrib-pos" style="width:${pct}%"></div>`
      : `<div class="contrib-neg" style="width:${pct}%"></div>`;
    html += `<div class="contrib-row"><span>${f.feature}</span><div class="contrib-track">${bar}</div><span>${f.contribution > 0 ? "+" : ""}${f.contribution.toFixed(3)}</span></div>`;
  });
  html += `</div><div class="muted" style="margin-top:12px;line-height:1.6">${ex.note}</div>`;
  document.getElementById("explainBody").innerHTML = html;
}

/* ================= 实时流（SSE） ================= */
function setLiveUI(on, text) {
  state.live = on;
  const btn = document.getElementById("btnLive");
  const badge = document.getElementById("liveBadge");
  const badgeText = document.getElementById("liveBadgeText");
  const runDot = document.getElementById("runDot");
  const runText = document.getElementById("runText");
  btn.innerHTML = on
    ? '<span id="liveDot" class="dot"></span>暂停监控'
    : '<span id="liveDot" class="dot off"></span>继续监控';
  if (badge) badge.classList.toggle("paused", !on);
  if (badgeText) badgeText.textContent = text || (on ? "接收中" : "已暂停");
  if (runDot) runDot.classList.toggle("off", !on);
  if (runText) runText.textContent = on ? "运行中" : "已暂停";
}

function updateStreamInfo(s) {
  if (!s) return;
  const el = document.getElementById("streamInfo");
  if (!el) return;
  el.textContent = `已推送 ${s.emitted} 条 · 攻击 ${s.attacks} 条 · ${s.rate} 条/秒 · 已运行 ${Math.round(s.uptime)}s`;
}

function connectStream() {
  if (state.es) { state.es.close(); state.es = null; }
  const es = new EventSource("/api/stream");
  state.es = es;
  es.onopen = () => setLiveUI(true, "接收中");
  es.onmessage = (msg) => {
    let d;
    try { d = JSON.parse(msg.data); } catch (_) { return; }
    if (d.type === "event") {
      handleStreamEvent(d.event, d.stats);
    } else if (d.type === "hello") {
      updateStreamInfo(d.stats);
    }
  };
  es.onerror = () => {
    // EventSource 会自己重连，这里只把 UI 状态标出来，避免"看着在跑其实断了"
    setLiveUI(true, "重连中…");
  };
}

function handleStreamEvent(e, stats) {
  if (!e) return;
  processEvents([e]);
  updateStreamInfo(stats);
  const info = document.getElementById("lastInfo");
  if (info) {
    info.textContent = `${e.ts} · ${e.src} → ${e.dst}:${e.dst_port} · ${e.result.label_zh}` +
      (e.incident_title ? ` · 事件：${e.incident_title}` : "");
  }
}

async function startStream() {
  try {
    const res = await fetch("/api/stream/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rate: state.streamRate }),
    });
    const d = await res.json();
    setLiveUI(true, "接收中");
    updateStreamInfo(d.status);
    connectStream();
  } catch (err) {
    setLiveUI(false, "启动失败");
  }
}

async function stopStream() {
  try { await fetch("/api/stream/stop", { method: "POST" }); } catch (_) { /* 忽略 */ }
  if (state.es) { state.es.close(); state.es = null; }
  setLiveUI(false, "已暂停");
}

function toggleLive() {
  if (state.live) stopStream(); else startStream();
}

function resetAll() {
  state.total = 0; state.attack = 0;
  state.labelCount = {}; state.protoCount = {}; state.srcAttack = {};
  state.trendLabels = []; state.trendAttack = []; state.trendNormal = [];
  state.rows = [];
  updateStats(); updatePie(); updateProto(); updateSrc(); renderTable();
  charts.trend.data.labels = []; charts.trend.data.datasets[0].data = []; charts.trend.data.datasets[1].data = [];
  charts.trend.update("none");
  document.getElementById("lastInfo").textContent = "已重置";
}

function exportCsv() {
  const head = ["时间", "源IP", "目的IP", "端口", "判定", "级别", "置信度", "引擎", "依据"];
  const lines = state.rows.map(e => {
    const r = e.result; const { sev, text } = sevBadge(r);
    const basis = r.rule_hits.length ? r.rule_hits.map(h => h.rule).join("|") : "异常分" + r.ml_detail.anomaly_score;
    return [e.ts, e.src, e.dst, e.dst_port, text, sev, (r.confidence * 100).toFixed(1) + "%",
      r.engine === "rule" ? "规则引擎" : "机器学习", basis].join(",");
  });
  const csv = "\uFEFF" + [head.join(","), ...lines].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "nids_alerts_" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".csv";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function uploadPcap(file) {
  const fd = new FormData();
  fd.append("file", file);
  document.getElementById("lastInfo").textContent = "解析 PCAP 中…";
  try {
    const res = await fetch("/api/pcap", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) {
      document.getElementById("lastInfo").textContent = "解析失败：" + data.error;
      return;
    }
    processEvents(data.events || []);
    const s = data.summary || {};
    document.getElementById("lastInfo").textContent =
      `PCAP 解析完成：${s.total} 条连接，${s.attack} 条攻击`;
  } catch (err) {
    document.getElementById("lastInfo").textContent = "上传失败：" + err.message;
  }
}

async function exportReport() {
  const by_label = {};
  state.rows.forEach(e => {
    const k = e.result.label;
    by_label[k] = (by_label[k] || 0) + 1;
  });
  const stats = { total: state.total, attack: state.attack, by_label };
  const events = state.rows.map(e => ({
    ts: e.ts, src: e.src, dst: e.dst, dst_port: e.dst_port, result: e.result,
  }));
  try {
    const res = await fetch("/api/report", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stats, events }),
    });
    const html = await res.text();
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "nids_report_" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".html";
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (err) {
    document.getElementById("lastInfo").textContent = "报告生成失败：" + err.message;
  }
}

async function loadMetrics() {
  try {
    const res = await fetch("/api/metrics");
    const m = await res.json();
    if (m.accuracy !== undefined) {
      document.getElementById("statAcc").textContent = (m.accuracy * 100).toFixed(2) + "%";
    }
  } catch (_) { document.getElementById("statAcc").textContent = "—"; }

  try {
    const st = await (await fetch("/api/alerts/stats")).json();
    const el = document.getElementById("statIncidents");
    if (el) el.textContent = st.incidents || 0;
  } catch (_) { /* 忽略 */ }
}

function renderCM(cm) {
  const labels = cm.labels || []; const m = cm.matrix || [];
  const wrap = document.getElementById("cmWrap");
  if (!labels.length) { wrap.innerHTML = '<div class="muted">无数据</div>'; return; }
  const max = Math.max(...m.flat(), 1);
  let html = `<div class="cm" style="grid-template-columns:90px repeat(${labels.length},66px)"><div class="cm-head"></div>`;
  labels.forEach(l => html += `<div class="cm-head">${LABEL_ZH[l] || l}</div>`);
  m.forEach((row, i) => {
    html += `<div class="cm-rowlabel">${LABEL_ZH[labels[i]] || labels[i]}</div>`;
    row.forEach((v, j) => {
      const alpha = v / max * 0.7 + 0.05;
      const color = i === j ? `rgba(63,185,80,${alpha})` : `rgba(248,81,73,${alpha})`;
      html += `<div class="cm-cell" style="background:${color}">${v}</div>`;
    });
  });
  html += `</div>`;
  wrap.innerHTML = html;
}

function renderDatasetCompare(dc) {
  const b = dc.balanced || {};
  const r = dc.realistic || {};
  const bm = (b.model_comparison || {}).RandomForest || {};
  const rm = (r.model_comparison || {}).RandomForest || {};
  charts.dataset.data.labels = ["平衡合成数据", "真实分布数据"];
  charts.dataset.data.datasets = [
    { label: "准确率", data: [bm.accuracy || 0, rm.accuracy || 0], backgroundColor: "#4c8dff", borderRadius: 4 },
    { label: "Macro-F1", data: [bm.f1_macro || 0, rm.f1_macro || 0], backgroundColor: "#f0883e", borderRadius: 4 },
  ];
  charts.dataset.update("none");
  const meta = r.meta || {};
  const ratio = meta.ratio || {};
  document.getElementById("datasetNote").textContent =
    `真实分布数据：正常 ${Math.round((ratio.normal || 0) * 100)}% · 困难样本 ${Math.round((meta.hard_ratio || 0) * 100)}% · 标签噪声 ${Math.round((meta.label_noise || 0) * 100)}% · 共 ${r.n_total || 0} 条。指标下降是"更真实"的代价。`;
}

function renderAblation(ab) {
  const groups = ab.groups || [];
  const body = document.getElementById("ablationBody");
  if (!groups.length) {
    body.innerHTML = '<tr><td colspan="7" class="muted">无数据，请先运行 python train_ablation.py</td></tr>';
    document.getElementById("ablationNote").textContent = "";
    return;
  }

  charts.ablation.data.labels = groups.map(g => `${g.key} ${g.name}（${g.n_features}维）`);
  charts.ablation.data.datasets = [
    { label: "准确率", data: groups.map(g => g.RandomForest.accuracy), backgroundColor: "#4c8dff", borderRadius: 4 },
    { label: "Macro-F1", data: groups.map(g => g.RandomForest.f1_macro), backgroundColor: "#f0883e", borderRadius: 4 },
  ];
  charts.ablation.update("none");

  const base = groups[0].RandomForest;
  body.innerHTML = groups.map(g => {
    const r = g.RandomForest;
    const dF1 = (r.f1_macro - base.f1_macro) * 100;
    const delta = g.key === "A" ? '<span class="muted">基线</span>'
      : `<span style="color:${dF1 >= 0 ? "#3fb950" : "#f85149"}">${dF1 >= 0 ? "+" : ""}${dF1.toFixed(2)}pp</span>`;
    return `<tr>
      <td><b>${g.key}</b> ${g.name}</td>
      <td>${g.n_features}</td>
      <td>${(r.accuracy * 100).toFixed(2)}%</td>
      <td>${(r.f1_macro * 100).toFixed(2)}% ${delta}</td>
      <td>${((r.per_class_recall.brute_force || 0) * 100).toFixed(1)}%</td>
      <td>${((r.per_class_recall.exfiltration || 0) * 100).toFixed(1)}%</td>
      <td>${r.latency_ms_per_1k} ms/千条</td>
    </tr>`;
  }).join("");

  const b = groups.find(g => g.key === "B"), c = groups.find(g => g.key === "C");
  let note = `同一数据划分（${ab.n_total} 条，训练/测试 ${ab.n_train}/${ab.n_test}）下只改特征组。`;
  if (b && c) {
    const gain = (b.RandomForest.f1_macro - base.f1_macro) * 100;
    const extra = (c.RandomForest.f1_macro - b.RandomForest.f1_macro) * 100;
    note += ` 行为特征（failed_logins / num_unique_ports / syn_rate）带来 ${gain >= 0 ? "+" : ""}${gain.toFixed(2)}pp Macro-F1`;
    note += `，而派生特征 bytes_per_packet 的边际贡献为 ${extra >= 0 ? "+" : ""}${extra.toFixed(2)}pp`;
    note += extra <= 0
      ? "——原始特征已包含该信息，多一个维度反而引入噪声，故最优组合是 B 组而非全特征。"
      : "——派生特征仍有正向作用。";
  }
  document.getElementById("ablationNote").textContent = note;
}

async function loadAnalysis() {
  try {
    const res = await fetch("/api/model_compare");
    const d = await res.json();
    const comp = d.model_comparison || {};
    const models = Object.keys(comp);
    const metrics = ["accuracy", "precision_macro", "recall_macro", "f1_macro"];
    const metricZh = { accuracy: "准确率", precision_macro: "精确率", recall_macro: "召回率", f1_macro: "F1" };
    const mColors = ["#4c8dff", "#f0883e", "#3fb950", "#a371f7"];
    charts.compare.data.labels = models;
    charts.compare.data.datasets = metrics.map((m, i) => ({
      label: metricZh[m],
      data: models.map(mm => comp[mm][m]),
      backgroundColor: mColors[i], borderRadius: 4,
    }));
    charts.compare.update("none");

    const fi = d.feature_importance || {};
    const feats = Object.keys(fi).sort((a, b) => fi[a] - fi[b]);
    charts.importance.data.labels = feats;
    charts.importance.data.datasets[0].data = feats.map(f => fi[f]);
    charts.importance.update("none");

    renderCM(d.confusion_matrix || {});

    const dc = await (await fetch("/api/dataset_compare")).json();
    renderDatasetCompare(dc);

    const abRes = await fetch("/api/ablation");
    if (abRes.ok) renderAblation(await abRes.json());
  } catch (err) {
    document.getElementById("cmWrap").innerHTML = '<div class="muted">模型对比数据加载失败：' + err.message + "</div>";
  }
}

const histState = { offset: 0, limit: 20, severity: "" };

async function loadHistory() {
  const sev = histState.severity;
  const url = `/api/alerts?limit=${histState.limit}&offset=${histState.offset}` + (sev ? `&severity=${sev}` : "");
  try {
    const [res, sres] = await Promise.all([fetch(url), fetch("/api/alerts/stats")]);
    const data = await res.json();
    const st = await sres.json();
    document.getElementById("histTotal").textContent = st.total || 0;
    document.getElementById("histCritical").textContent = (st.by_severity || {}).critical || 0;
    document.getElementById("histHigh").textContent = (st.by_severity || {}).high || 0;
    document.getElementById("histMedium").textContent = (st.by_severity || {}).medium || 0;
    renderHistory(data.items || []);
    const page = Math.floor(histState.offset / histState.limit) + 1;
    const pages = Math.max(1, Math.ceil(data.total / histState.limit));
    document.getElementById("histPageInfo").textContent = `第 ${page} / ${pages} 页 · 共 ${data.total} 条`;
  } catch (err) {
    document.getElementById("histBody").innerHTML = `<tr><td colspan="9" class="muted">加载失败：${err.message}</td></tr>`;
  }
}

function renderHistory(items) {
  const body = document.getElementById("histBody");
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="9" class="muted">暂无告警（先注入流量或上传 PCAP 产生告警）</td></tr>';
    return;
  }
  body.innerHTML = items.map((a, i) => `<tr>
    <td class="muted">${histState.offset + i + 1}</td>
    <td>${a.ts || ""}</td>
    <td>${a.src || ""}</td>
    <td>${a.dst || ""}:${a.dst_port || ""}</td>
    <td>${a.label_zh || a.label || ""}</td>
    <td><span class="badge ${a.severity || "info"}">${(a.severity || "").toUpperCase()}</span></td>
    <td>${Math.round((a.confidence || 0) * 100)}%</td>
    <td class="engine">${a.engine === "rule" ? "规则引擎" : "机器学习"}</td>
    <td class="engine">${a.basis || ""}</td>
  </tr>`).join("");
}

async function clearHistory() {
  if (!confirm("确定清空全部告警历史？")) return;
  await fetch("/api/alerts/clear", { method: "POST" });
  histState.offset = 0;
  loadHistory();
}

async function exportHistory() {
  const res = await fetch("/api/alerts?limit=500&offset=0");
  const data = await res.json();
  const head = ["ID", "时间", "源IP", "目的IP", "端口", "判定", "级别", "置信度", "引擎", "依据"];
  const lines = (data.items || []).map(a => [
    a.id, a.ts, a.src, a.dst, a.dst_port, a.label_zh || a.label,
    a.severity, Math.round((a.confidence || 0) * 100) + "%",
    a.engine === "rule" ? "规则引擎" : "机器学习", a.basis,
  ].join(","));
  const csv = "\uFEFF" + [head.join(","), ...lines].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "nids_alert_history.csv";
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ================= 攻击事件（关联） ================= */
const STAGE_ALL = ["recon", "access", "impact", "exfiltration"];
const STAGE_ZH = { recon: "侦察", access: "初始访问", impact: "影响", exfiltration: "外泄" };
const STATUS_ZH = { open: "待处理", investigating: "处理中", closed: "已关闭" };

function chainHtml(stages) {
  const on = new Set((stages || []).map(s => s.key));
  return `<div class="chain">` + STAGE_ALL.map((k, i) =>
    `${i ? '<span class="chain-arrow">›</span>' : ""}<span class="chain-step ${on.has(k) ? "on" : ""}">${STAGE_ZH[k]}</span>`
  ).join("") + `</div>`;
}

function scoreColor(score) {
  if (score >= 85) return "#f85149";
  if (score >= 65) return "#f0883e";
  if (score >= 45) return "#d29922";
  return "#3fb950";
}

async function loadIncidents() {
  const url = "/api/incidents?limit=60" + (state.incFilter ? `&status=${state.incFilter}` : "");
  try {
    const [res, sres] = await Promise.all([fetch(url), fetch("/api/alerts/stats")]);
    const d = await res.json();
    const st = await sres.json();
    state.incidents = d.items || [];
    renderIncidents(d);
    document.getElementById("incAlerts").textContent = st.total || 0;
    document.getElementById("incCount").textContent = (st.incidents || 0);
    document.getElementById("incRatio").textContent =
      st.compression_ratio ? st.compression_ratio.toFixed(1) + " : 1" : "—";
    document.getElementById("incMulti").textContent =
      state.incidents.filter(i => (i.stages || []).length >= 2).length;
    document.getElementById("incNote").textContent =
      (st.correlation && st.correlation.text ? st.correlation.text + "。" : "") +
      "关联规则：同一攻击源 10 分钟内的告警归并为一个事件；风险分 = 严重度基数 + 阶段跨度奖励 + 告警量奖励。";
  } catch (err) {
    document.getElementById("incBody").innerHTML =
      `<tr><td colspan="10" class="muted">加载失败：${err.message}</td></tr>`;
  }
}

function renderIncidents(d) {
  const body = document.getElementById("incBody");
  if (!state.incidents.length) {
    body.innerHTML = '<tr><td colspan="10" class="muted">暂无事件（等待实时流产生告警…）</td></tr>';
    return;
  }
  body.innerHTML = state.incidents.map(it => {
    const c = scoreColor(it.score);
    const attck = (it.attck || []).map(a => `<span class="attck-tag">${a}</span>`).join(" ");
    return `<tr data-id="${it.id}">
      <td>${it.id}</td>
      <td>${it.title || it.src}</td>
      <td>${it.src}</td>
      <td>${chainHtml(it.stages)}</td>
      <td><span class="badge ${it.severity}">${(it.severity || "").toUpperCase()}</span></td>
      <td><div class="score-wrap"><div class="score-track"><div class="score-fill" style="width:${it.score}%;background:${c}"></div></div><span>${it.score}</span></div></td>
      <td>${it.alert_count}</td>
      <td>${attck || '<span class="muted">—</span>'}</td>
      <td><span class="status-pill ${it.status}">${STATUS_ZH[it.status] || it.status}</span></td>
      <td>${it.last_seen || ""}</td>
    </tr>`;
  }).join("");
  body.querySelectorAll("tr").forEach(tr => {
    tr.addEventListener("click", () => openIncident(Number(tr.dataset.id)));
  });
}

async function openIncident(id) {
  const panel = document.getElementById("incidentPanel");
  const body = document.getElementById("incidentBody");
  body.innerHTML = '<div class="muted">加载中…</div>';
  panel.classList.add("open");
  try {
    const d = await (await fetch(`/api/incidents/${id}`)).json();
    if (d.error) { body.innerHTML = `<div class="muted">${d.error}</div>`; return; }
    const c = scoreColor(d.score);
    let html = `
      <div class="kv"><span>事件</span><b>${d.title}</b></div>
      <div class="kv"><span>攻击源</span><b>${d.src}</b></div>
      <div class="kv"><span>风险分</span><span style="color:${c};font-weight:600">${d.score} / 100</span></div>
      <div class="kv"><span>级别</span><span class="badge ${d.severity}">${(d.severity || "").toUpperCase()}</span></div>
      <div class="kv"><span>告警数</span><span>${d.alert_count}</span></div>
      <div class="kv"><span>首次 / 最近</span><span>${d.first_seen} → ${d.last_seen}</span></div>
      <div class="kv"><span>ATT&amp;CK</span><span>${(d.attck || []).map(a => `<span class="attck-tag">${a}</span>`).join(" ") || "—"}</span></div>
      <div style="margin:14px 0">
        <div class="muted" style="margin-bottom:6px">攻击链进度</div>
        ${chainHtml(d.stages)}
      </div>
      <div style="margin:14px 0">
        <div class="muted" style="margin-bottom:6px">目标主机</div>
        ${(d.dsts || []).map(x => `<span class="rule-tag">${x}</span>`).join("") || "—"}
      </div>
      <div class="muted" style="margin:14px 0 6px">处置状态</div>
      <div style="display:flex;gap:6px">
        ${Object.keys(STATUS_ZH).map(s =>
          `<button class="btn-mini ${d.status === s ? "active" : ""}" data-status="${s}">${STATUS_ZH[s]}</button>`).join("")}
      </div>
      <div class="muted" style="margin:18px 0 8px">原始告警（最近 ${Math.min(d.alerts.length, 30)} 条，共 ${d.alerts.length} 条）</div>
      <div style="font-size:11px;line-height:1.9">`;
    d.alerts.slice(0, 30).forEach(a => {
      html += `<div style="border-bottom:1px dashed var(--border);padding:3px 0">
        <span class="muted">${a.ts}</span> · ${a.dst}:${a.dst_port} ·
        <b>${a.label_zh || a.label}</b> · <span class="muted">${a.basis}</span></div>`;
    });
    html += `</div>`;
    body.innerHTML = html;
    body.querySelectorAll("button[data-status]").forEach(btn => {
      btn.addEventListener("click", () => setIncidentStatus(d.id, btn.dataset.status));
    });
  } catch (err) {
    body.innerHTML = `<div class="muted">加载失败：${err.message}</div>`;
  }
}

async function setIncidentStatus(id, status) {
  try {
    await fetch(`/api/incidents/${id}/status`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    openIncident(id);
    loadIncidents();
  } catch (_) { /* 忽略 */ }
}

/* ================= 规则库 ================= */
async function loadRules() {
  try {
    const d = await (await fetch("/api/rules")).json();
    const rules = d.rules || [];
    const st = d.stats || {};
    document.getElementById("ruleCount").textContent =
      `共 ${st.total || 0} 条 · 启用 ${st.enabled || 0} 条`;
    document.getElementById("ruleNote").textContent = d.note || "";
    const errs = st.errors || [];
    document.getElementById("ruleErrors").innerHTML = errs.length
      ? `<div class="rule-err">${errs.length} 处规则文件问题：` +
        errs.map(e => `${e.file} — ${e.error}`).join("；") + `</div>`
      : "";
    document.getElementById("ruleBody").innerHTML = rules.map(r => `
      <tr>
        <td style="font-family:Consolas,monospace">${r.id}</td>
        <td>${r.name}</td>
        <td>${LABEL_ZH[r.attack] || r.attack}</td>
        <td><span class="badge ${r.severity}">${r.severity.toUpperCase()}</span></td>
        <td>${r.attck ? `<span class="attck-tag">${r.attck}</span><div class="muted">${r.attck_name || ""}</div>` : "—"}</td>
        <td class="rule-expr">${r.expression}</td>
        <td>${r.hit_count || 0}</td>
        <td class="muted">${r.source}</td>
      </tr>`).join("");
  } catch (err) {
    document.getElementById("ruleBody").innerHTML =
      `<tr><td colspan="8" class="muted">加载失败：${err.message}</td></tr>`;
  }
}

async function reloadRules() {
  const btn = document.getElementById("btnRuleReload");
  btn.textContent = "重载中…";
  try {
    const d = await (await fetch("/api/rules/reload", { method: "POST" })).json();
    document.getElementById("ruleCount").textContent =
      `共 ${d.stats.total} 条 · 启用 ${d.stats.enabled} 条`;
    loadRules();
    btn.textContent = "已重载";
    setTimeout(() => { btn.textContent = "重载规则"; }, 1200);
  } catch (err) {
    btn.textContent = "重载失败";
  }
}

function initTabs() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
      if (state.incTimer) { clearInterval(state.incTimer); state.incTimer = null; }
      const name = tab.dataset.tab;
      if (name === "incidents") {
        loadIncidents();
        state.incTimer = setInterval(loadIncidents, 4000);   // 只在事件页开着时刷新
      }
      if (name === "rules") loadRules();
      if (name === "analysis") loadAnalysis();
      if (name === "history") loadHistory();
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  renderScenarioBtns();
  initTabs();
  loadMetrics();
  startStream();                                   // 服务端持续推送，不再前端轮询
  setInterval(flushTrend, 2000);
  setInterval(loadMetrics, 10000);                 // 事件计数定期对齐服务端

  document.getElementById("btnLive").addEventListener("click", toggleLive);
  document.getElementById("btnStep").addEventListener("click", fetchBatch);
  document.getElementById("streamRate").addEventListener("change", async (e) => {
    state.streamRate = Number(e.target.value);
    if (state.live) await startStream();            // 改流速后重连，立即生效
  });
  document.getElementById("btnRuleReload").addEventListener("click", reloadRules);
  document.getElementById("btnIncRefresh").addEventListener("click", loadIncidents);
  document.querySelectorAll("#tab-incidents .filters button[data-status]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#tab-incidents .filters button[data-status]")
        .forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.incFilter = btn.dataset.status;
      loadIncidents();
    });
  });
  document.getElementById("closeIncident").addEventListener("click", () => {
    document.getElementById("incidentPanel").classList.remove("open");
  });
  document.getElementById("btnReset").addEventListener("click", resetAll);
  document.getElementById("btnExport").addEventListener("click", exportCsv);
  document.getElementById("btnPcap").addEventListener("click", () => document.getElementById("pcapFile").click());
  document.getElementById("pcapFile").addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (f) uploadPcap(f);
    e.target.value = "";
  });
  document.getElementById("btnReport").addEventListener("click", exportReport);
  document.getElementById("btnHistRefresh").addEventListener("click", loadHistory);
  document.getElementById("btnHistClear").addEventListener("click", clearHistory);
  document.getElementById("btnHistExport").addEventListener("click", exportHistory);
  document.getElementById("histSev").addEventListener("change", (e) => {
    histState.severity = e.target.value;
    histState.offset = 0;
    loadHistory();
  });
  document.getElementById("histPrev").addEventListener("click", () => {
    histState.offset = Math.max(0, histState.offset - histState.limit);
    loadHistory();
  });
  document.getElementById("histNext").addEventListener("click", () => {
    histState.offset += histState.limit;
    loadHistory();
  });
  document.getElementById("closeExplain").addEventListener("click", () => {
    document.getElementById("explainPanel").classList.remove("open");
  });
  document.getElementById("sevFilter").addEventListener("change", (e) => {
    state.filter = e.target.value; renderTable();
  });
  document.getElementById("intensity").addEventListener("change", (e) => {
    state.intensity = e.target.value;
  });
  const sens = document.getElementById("sensRange");
  sens.addEventListener("input", (e) => {
    state.sensitivity = Number(e.target.value) / 100;
    document.getElementById("sensVal").textContent = e.target.value + "%";
    document.getElementById("statSens").textContent = e.target.value + "%";
    fetch(`/api/sensitivity?value=${state.sensitivity}`).catch(() => {});
  });
});
