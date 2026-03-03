/**
 * ThreatWeaver SOC Dashboard — JavaScript
 * Chart.js visualisations + count-up + auto-refresh + SENTINEL AI
 */

'use strict';

// ============================================================
// Configuration
// ============================================================
const REFRESH_INTERVAL_MS = 30_000;

// Chart.js global dark-theme defaults
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";

// ============================================================
// State
// ============================================================
const charts = {};
let incidentsData = [];
let sortState = { col: 'threat_score', dir: 'desc' };

// ============================================================
// Utilities
// ============================================================
function $(id) { return document.getElementById(id); }

function animateCounter(el, target, decimals = 0, suffix = '') {
  const duration = 1200;
  const start = performance.now();
  const from = 0;
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    const current = from + (target - from) * eased;
    el.textContent = current.toFixed(decimals) + suffix;
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function riskColor(level) {
  switch ((level || '').toUpperCase()) {
    case 'CRITICAL': return '#ff2d2d';
    case 'HIGH':     return '#ff8c00';
    case 'MEDIUM':   return '#ffd600';
    case 'LOW':      return '#00ff88';
    default:         return '#94a3b8';
  }
}

function formatMitrePills(raw) {
  if (!raw) return '—';
  return raw.split(',').map(t => t.trim()).filter(Boolean)
    .map(t => `<span class="mitre-pill">${escapeHtml(t)}</span>`)
    .join('');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function updateLastRefresh() {
  const el = $('last-refresh-label');
  if (el) el.textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
}

function setVerdictBadge(verdict) {
  const el = $('verdict-badge');
  if (!el) return;
  el.textContent = (verdict || '—').replace(/_/g, ' ');
  el.className = 'verdict-badge';
  if ((verdict || '').includes('STRONG'))    el.classList.add('verdict-critical');
  else if ((verdict || '').includes('MODERATE')) el.classList.add('verdict-moderate');
  else if ((verdict || '').includes('LOW'))  el.classList.add('verdict-low');
}

// ============================================================
// Chart helpers
// ============================================================
const CHART_PLUGIN_NODATA = {
  id: 'noDataPlugin',
  afterDraw(chart) {
    const { datasets } = chart.data;
    const hasData = datasets.some(d => d.data && d.data.length > 0 && d.data.some(v => v > 0));
    if (hasData) return;
    const { ctx, width, height } = chart;
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#475569';
    ctx.font = '14px "Segoe UI", system-ui';
    ctx.fillText('No data available', width / 2, height / 2);
    ctx.restore();
  }
};

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

// ============================================================
// API fetch helpers
// ============================================================
async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.json();
}

// ============================================================
// Render functions
// ============================================================

function renderSummary(data) {
  if (data.no_data) {
    $('no-data-banner').classList.remove('hidden');
    return;
  }

  setVerdictBadge(data.machine_verdict);

  const fields = [
    ['kpi-total-events', data.total_events,    0, ''],
    ['kpi-anomalies',    data.total_anomalies, 0, ''],
    ['kpi-anomaly-rate', data.anomaly_rate,    2, '%'],
    ['kpi-avg-score',    data.avg_threat_score,2, ''],
    ['kpi-high-conf',    data.high_confidence_cases, 0, ''],
  ];

  for (const [id, val, dec, sfx] of fields) {
    const el = $(id);
    if (el) animateCounter(el, Number(val) || 0, dec, sfx);
  }

  // Confidence score
  const confEl = $('kpi-confidence');
  const confBar = $('confidence-bar');
  const score = Number(data.confidence_score) || 0;
  if (confEl) confEl.textContent = score + '%';
  if (confBar) setTimeout(() => { confBar.style.width = score + '%'; }, 100);
}

function renderRiskChart(data) {
  if (data.no_data) return;
  destroyChart('risk');
  const ctx = $('chart-risk').getContext('2d');
  charts.risk = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      datasets: [{
        data: [
          data.CRITICAL || 0,
          data.HIGH     || 0,
          data.MEDIUM   || 0,
          data.LOW      || 0,
        ],
        backgroundColor: ['#ff2d2d', '#ff8c00', '#ffd600', '#00ff88'],
        borderColor: '#0a0e1a',
        borderWidth: 3,
        hoverOffset: 8,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { padding: 16, boxWidth: 12, color: '#94a3b8' } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` } }
      },
      animation: { duration: 900, easing: 'easeOutQuart' }
    },
    plugins: [CHART_PLUGIN_NODATA]
  });
}

function renderMitreChart(data) {
  if (data.no_data) return;
  const techs = data.techniques || {};
  const labels = Object.keys(techs).slice(0, 10);
  const values = labels.map(k => techs[k]);
  const colors = ['#00d4ff','#00ff88','#b388ff','#ff8c00','#ffd600','#00e5cc','#ff2d2d','#4dd0e1','#aed581','#ef9a9a'];

  destroyChart('mitre');
  const ctx = $('chart-mitre').getContext('2d');
  charts.mitre = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Occurrences',
        data: values,
        backgroundColor: labels.map((_, i) => colors[i % colors.length] + '33'),
        borderColor:     labels.map((_, i) => colors[i % colors.length]),
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
        y: { grid: { display: false }, ticks: { color: '#e2e8f0', font: { size: 11 } } }
      },
      animation: { duration: 900, easing: 'easeOutQuart' }
    },
    plugins: [CHART_PLUGIN_NODATA]
  });
}

function renderUsersChart(data) {
  if (data.no_data) return;
  const users = data.users || [];
  destroyChart('users');
  const ctx = $('chart-users').getContext('2d');
  charts.users = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: users.map(u => u.username || 'N/A'),
      datasets: [{
        label: 'Max Threat Score',
        data: users.map(u => u.max_threat_score),
        backgroundColor: 'rgba(255,140,0,0.25)',
        borderColor: '#ff8c00',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', maxRotation: 30 } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
      },
      animation: { duration: 900, easing: 'easeOutQuart' }
    },
    plugins: [CHART_PLUGIN_NODATA]
  });
}

function renderIPChart(data) {
  if (data.no_data) return;
  const ips = data.ips || [];
  destroyChart('ips');
  const ctx = $('chart-ips').getContext('2d');
  charts.ips = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ips.map(i => i.ip || 'N/A'),
      datasets: [{
        label: 'Event Count',
        data: ips.map(i => i.count),
        backgroundColor: 'rgba(0,212,255,0.2)',
        borderColor: '#00d4ff',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', maxRotation: 30 } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
      },
      animation: { duration: 900, easing: 'easeOutQuart' }
    },
    plugins: [CHART_PLUGIN_NODATA]
  });
}

function renderTimeline(data) {
  if (data.no_data) return;
  const tl = data.timeline || [];
  destroyChart('timeline');
  const ctx = $('chart-timeline').getContext('2d');
  charts.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: tl.map(t => t.hour),
      datasets: [{
        label: 'Events',
        data: tl.map(t => t.count),
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.08)',
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointBackgroundColor: '#00d4ff',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#94a3b8', maxTicksLimit: 12, maxRotation: 30 }
        },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#94a3b8' } }
      },
      animation: { duration: 900, easing: 'easeOutQuart' }
    },
    plugins: [CHART_PLUGIN_NODATA]
  });
}

// ============================================================
// Incidents table
// ============================================================
function renderTable(data) {
  if (data.no_data) return;
  incidentsData = data.incidents || [];
  updateTableCount(incidentsData.length);
  drawTable(incidentsData);
}

function drawTable(rows) {
  const tbody = $('incidents-tbody');
  if (!tbody) return;

  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="loading-row">No incidents to display</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${escapeHtml(r.username || '—')}</td>
      <td><code>${escapeHtml(r.source_ip || '—')}</code></td>
      <td><span class="risk-badge risk-${escapeHtml(r.risk_level || '')}">${escapeHtml(r.risk_level || '—')}</span></td>
      <td>${Number(r.threat_score || 0).toFixed(0)}</td>
      <td>${formatMitrePills(r.mitre_techniques)}</td>
    </tr>
  `).join('');
}

function updateTableCount(n) {
  const el = $('table-count');
  if (el) el.textContent = `${n} incident${n !== 1 ? 's' : ''}`;
}

// Table search
function initTableSearch() {
  const input = $('table-search');
  if (!input) return;
  input.addEventListener('input', () => {
    const q = input.value.toLowerCase();
    const filtered = incidentsData.filter(r =>
      (r.username || '').toLowerCase().includes(q) ||
      (r.source_ip || '').toLowerCase().includes(q) ||
      (r.risk_level || '').toLowerCase().includes(q) ||
      (r.mitre_techniques || '').toLowerCase().includes(q)
    );
    updateTableCount(filtered.length);
    drawTable(filtered);
  });
}

// Table column sort
function initTableSort() {
  const table = $('incidents-table');
  if (!table) return;
  table.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (sortState.col === col) {
        sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
      } else {
        sortState.col = col;
        sortState.dir = 'desc';
      }
      const sorted = [...incidentsData].sort((a, b) => {
        let av = a[col] ?? '', bv = b[col] ?? '';
        if (typeof av === 'number' || !isNaN(Number(av))) {
          av = Number(av); bv = Number(bv);
        } else {
          av = String(av).toLowerCase(); bv = String(bv).toLowerCase();
        }
        if (av < bv) return sortState.dir === 'asc' ? -1 :  1;
        if (av > bv) return sortState.dir === 'asc' ?  1 : -1;
        return 0;
      });
      drawTable(sorted);
    });
  });
}

// ============================================================
// SENTINEL AI report
// ============================================================
function initSentinel() {
  const btn = $('btn-sentinel');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const loading = $('sentinel-loading');
    const output  = $('sentinel-output');

    btn.disabled = true;
    loading.classList.remove('hidden');
    output.classList.add('hidden');
    output.innerHTML = '';

    try {
      const data = await fetchJSON('/api/sentinel-report');
      loading.classList.add('hidden');
      if (data.error) {
        output.innerHTML = `<div class="sentinel-error"><i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(data.error)}</div>`;
      } else {
        output.innerHTML = renderMarkdown(data.report || '');
      }
      output.classList.remove('hidden');
      typewriterReveal(output);
    } catch (err) {
      loading.classList.add('hidden');
      output.innerHTML = `<div class="sentinel-error"><i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(err.message)}</div>`;
      output.classList.remove('hidden');
    } finally {
      btn.disabled = false;
    }
  });
}

/** Very lightweight markdown → HTML (headings + bold only) */
function renderMarkdown(text) {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>');
}

/** Fade-in the output container word-by-word */
function typewriterReveal(el) {
  el.style.opacity = '0';
  let op = 0;
  const t = setInterval(() => {
    op += 0.05;
    el.style.opacity = String(Math.min(op, 1));
    if (op >= 1) clearInterval(t);
  }, 30);
}

// ============================================================
// Navigation — smooth scroll & active link
// ============================================================
function initNav() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    });
  });

  // Intersection Observer → update active link
  const sections = document.querySelectorAll('section[id]');
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        const link = document.querySelector(`.nav-link[href="#${entry.target.id}"]`);
        if (link) link.classList.add('active');
      }
    }
  }, { threshold: 0.35 });
  sections.forEach(s => observer.observe(s));
}

// ============================================================
// Refresh button
// ============================================================
function initRefreshButton() {
  const btn = $('btn-refresh');
  if (!btn) return;
  btn.addEventListener('click', () => {
    btn.classList.add('spinning');
    loadAll().finally(() => btn.classList.remove('spinning'));
  });
}

// ============================================================
// Main data loader
// ============================================================
async function loadAll() {
  try {
    const [summary, risk, incidents, mitre, timeline, users, ips] = await Promise.all([
      fetchJSON('/api/summary'),
      fetchJSON('/api/risk-distribution'),
      fetchJSON('/api/top-incidents'),
      fetchJSON('/api/mitre-techniques'),
      fetchJSON('/api/timeline'),
      fetchJSON('/api/user-risk'),
      fetchJSON('/api/ip-analysis'),
    ]);

    renderSummary(summary);
    renderRiskChart(risk);
    renderMitreChart(mitre);
    renderTimeline(timeline);
    renderUsersChart(users);
    renderIPChart(ips);
    renderTable(incidents);
    updateLastRefresh();
  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

// ============================================================
// Initialise
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initRefreshButton();
  initTableSearch();
  initTableSort();
  initSentinel();
  loadAll();

  // Auto-refresh every 30 s
  setInterval(loadAll, REFRESH_INTERVAL_MS);
});
