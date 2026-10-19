// NIDS 仪表盘前端逻辑
// 数据流：/api/simulate 拉取一批检测结果 -> 更新统计 / 图表 / 日志表

const state = {
  total: 0,
  attack: 0,
  live: true,
  timer: null,
  labelCount: {},          // 攻击类型累计计数
  trendLabels: [],
  trendAttack: [],
  trendNormal: [],
};

const LABEL_ZH = {
  normal: "正常", dos: "拒绝服务", port_scan: "端口扫描",
  brute_force: "暴力破解", exfiltration: "数据外泄",
};

const COLORS = {
  normal: "#3fb950", dos: "#f85149", port_scan: "#d29922",
  brute_force: "#f0883e", exfiltration: "#a371f7",
};

let trendChart, pieChart;

function initCharts() {
  const trendCtx = document.getElementById("trendChart").getContext("2d");
  trendChart = new Chart(trendCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        { label: "攻击连接", data: [], borderColor: "#f85149", backgroundColor: "rgba(248,81,73,.12)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
        { label: "正常连接", data: [], borderColor: "#3fb950", backgroundColor: "rgba(63,185,80,.10)", fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { labels: { color: "#8b949e", boxWidth: 10, font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: "#8b949e", maxTicksLimit: 8, font: { size: 10 } }, grid: { color: "rgba(255,255,255,.04)" } },
        y: { beginAtZero: true, ticks: { color: "#8b949e", font: { size: 10 } }, grid: { color: "rgba(255,255,255,.04)" } },
      },
    },
  });

  const pieCtx = document.getElementById("pieChart").getContext("2d");
  pieChart = new Chart(pieCtx, {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: "#161b22", borderWidth: 2 }] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, cutout: "62%",
      plugins: { legend: { position: "right", labels: { color: "#8b949e", boxWidth: 10, font: { size: 11 } } } },
    },
  });
}

function updateStats() {
  document.getElementById("statTotal").textContent = state.total;
  document.getElementById("statAttack").textContent = state.attack;
}

function pushTrend(attack, normal) {
  state.trendLabels.push(new Date().toLocaleTimeString("zh-CN", { hour12: false }));
  state.trendAttack.push(attack);
  state.trendNormal.push(normal);
  if (state.trendLabels.length > 20) {
    state.trendLabels.shift(); state.trendAttack.shift(); state.trendNormal.shift();
  }
  trendChart.data.labels = state.trendLabels;
  trendChart.data.datasets[0].data = state.trendAttack;
  trendChart.data.datasets[1].data = state.trendNormal;
  trendChart.update("none");
}

function updatePie() {
  const labels = Object.keys(state.labelCount).filter(k => state.labelCount[k] > 0);
  pieChart.data.labels = labels.map(k => LABEL_ZH[k] || k);
  pieChart.data.datasets[0].data = labels.map(k => state.labelCount[k]);
  pieChart.data.datasets[0].backgroundColor = labels.map(k => COLORS[k] || "#8b949e");
  pieChart.update("none");
}

function rowHtml(e) {
  const r = e.result;
  const badge = r.suspicious && r.label === "normal" ? "medium" : r.severity;
  const badgeText = r.suspicious && r.label === "normal" ? "可疑" : r.label_zh;
  const ruleText = r.rule_hits.length
    ? r.rule_hits.map(h => h.rule).join("、")
    : `异常分 ${r.ml_detail.anomaly_score}`;
  const confPct = Math.round(r.confidence * 100);
  return `<tr>
    <td>${e.ts}</td>
    <td>${e.src}</td>
    <td>${e.dst}:${e.dst_port}</td>
    <td>${badgeText}</td>
    <td><span class="badge ${badge}">${badge.toUpperCase()}</span></td>
    <td><div class="conf-bar"><div class="conf-fill" style="width:${confPct}%"></div></div><span class="muted">${confPct}%</span></td>
    <td class="engine">${r.engine === "rule" ? "规则引擎" : "机器学习"}</td>
    <td class="engine">${ruleText}</td>
  </tr>`;
}

async function fetchBatch(n = 20) {
  try {
    const res = await fetch(`/api/simulate?n=${n}`);
    const data = await res.json();
    const events = data.events || [];
    let attack = 0, normal = 0;

    events.forEach(e => {
      state.total += 1;
      const key = e.result.label === "normal" && !e.result.suspicious ? "normal" : e.result.label;
      state.labelCount[key] = (state.labelCount[key] || 0) + 1;
      if (e.result.is_attack) { attack += 1; state.attack += 1; } else { normal += 1; }
    });

    pushTrend(attack, normal);
    updatePie();
    updateStats();

    const body = document.getElementById("logBody");
    body.insertAdjacentHTML("afterbegin", events.slice().reverse().map(rowHtml).join(""));
    while (body.rows.length > 120) body.deleteRow(body.rows.length - 1);

    document.getElementById("statRate").innerHTML = `${n}<small style="font-size:13px;color:var(--muted)"> 条/批</small>`;
    document.getElementById("lastInfo").textContent =
      `最近更新 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })} · 本批攻击 ${attack} 条`;
  } catch (err) {
    document.getElementById("lastInfo").textContent = "请求失败：" + err.message;
  }
}

async function loadMetrics() {
  try {
    const res = await fetch("/api/metrics");
    const m = await res.json();
    if (m.accuracy !== undefined) {
      document.getElementById("statAcc").textContent = (m.accuracy * 100).toFixed(2) + "%";
    }
  } catch (_) {
    document.getElementById("statAcc").textContent = "—";
  }
}

function toggleLive() {
  state.live = !state.live;
  const btn = document.getElementById("btnLive");
  if (state.live) {
    btn.innerHTML = '<span id="liveDot"></span>持续监控：开';
    state.timer = setInterval(() => fetchBatch(20), 2500);
  } else {
    btn.innerHTML = '<span id="liveDot" style="background:#8b949e"></span>持续监控：关';
    clearInterval(state.timer);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  loadMetrics();
  fetchBatch(20);
  state.timer = setInterval(() => fetchBatch(20), 2500);
  document.getElementById("btnSimulate").addEventListener("click", () => fetchBatch(20));
  document.getElementById("btnLive").addEventListener("click", toggleLive);
});
