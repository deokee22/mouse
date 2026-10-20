// NIDS 安全运营控制台 · 前端逻辑
const LABEL_ZH = { normal: "正常", dos: "拒绝服务", port_scan: "端口扫描", brute_force: "暴力破解", exfiltration: "数据外泄" };
const COLORS = { normal: "#3fb950", dos: "#f85149", port_scan: "#d29922", brute_force: "#f0883e", exfiltration: "#a371f7" };
const PROTO_ZH = { 0: "TCP", 1: "UDP", 2: "ICMP" };
const SCEN = [
  { k: "ssh", l: "SSH 爆破" }, { k: "scan", l: "端口扫描" }, { k: "ddos", l: "DDoS" },
  { k: "exfil", l: "数据外泄" }, { k: "mix", l: "混合流量" },
];

const state = {
  total: 0, attack: 0, live: true, timer: null,
  sensitivity: 0.5, scenario: "mix", intensity: "medium",
  labelCount: {}, protoCount: {}, srcAttack: {},
  trendLabels: [], trendAttack: [], trendNormal: [],
  rows: [], filter: "all",
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

  pushTrend(attack, normal);
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

function toggleLive() {
  state.live = !state.live;
  const btn = document.getElementById("btnLive");
  const dot = document.getElementById("liveDot");
  const runDot = document.getElementById("runDot");
  const runText = document.getElementById("runText");
  if (state.live) {
    btn.innerHTML = '<span id="liveDot" class="dot"></span>暂停监控';
    dot.classList.remove("off"); runDot.classList.remove("off"); runText.textContent = "运行中";
    state.timer = setInterval(fetchBatch, 2500);
  } else {
    btn.innerHTML = '<span id="liveDot" class="dot off"></span>继续监控';
    dot.classList.add("off"); runDot.classList.add("off"); runText.textContent = "已暂停";
    clearInterval(state.timer);
  }
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

async function loadMetrics() {
  try {
    const res = await fetch("/api/metrics");
    const m = await res.json();
    if (m.accuracy !== undefined) {
      document.getElementById("statAcc").textContent = (m.accuracy * 100).toFixed(2) + "%";
    }
  } catch (_) { document.getElementById("statAcc").textContent = "—"; }
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
  } catch (err) {
    document.getElementById("cmWrap").innerHTML = '<div class="muted">模型对比数据加载失败：' + err.message + "</div>";
  }
}

function initTabs() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
      if (tab.dataset.tab === "analysis") loadAnalysis();
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  renderScenarioBtns();
  initTabs();
  loadMetrics();
  fetchBatch();
  state.timer = setInterval(fetchBatch, 2500);

  document.getElementById("btnLive").addEventListener("click", toggleLive);
  document.getElementById("btnStep").addEventListener("click", fetchBatch);
  document.getElementById("btnReset").addEventListener("click", resetAll);
  document.getElementById("btnExport").addEventListener("click", exportCsv);
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
