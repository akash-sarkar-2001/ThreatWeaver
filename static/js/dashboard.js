/**
 * ThreatWeaver SOC Dashboard — JavaScript v2
 * Features: Chart.js visualisations · Animated particle canvas ·
 * Counter animations · Table sort/filter/export ·
 * Tooltip layer · SENTINEL AI · auto-refresh (Live DB)
 */

'use strict';

// ================================================================
// Configuration
// ================================================================
const CONFIG = {
  REFRESH_INTERVAL_MS:  30_000, // Auto-refresh every 30 seconds
  COUNTER_DURATION_MS:  1200,
  PARTICLE_COUNT:       55,
  PARTICLE_SPEED_MAX:   0.35,
  PARTICLE_RADIUS_MAX:  2.2,
  PARTICLE_CONNECT_DIST: 130,
};

// ================================================================
// Chart.js — Global dark-theme defaults
// ================================================================
Chart.defaults.color            = '#8a9ab5';
Chart.defaults.borderColor      = 'rgba(255,255,255,0.05)';
Chart.defaults.font.family      = "'Inter', 'Segoe UI', system-ui, sans-serif";
Chart.defaults.font.size        = 12;
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(8, 13, 26, 0.95)';
Chart.defaults.plugins.tooltip.borderColor     = 'rgba(0,212,255,0.3)';
Chart.defaults.plugins.tooltip.borderWidth     = 1;
Chart.defaults.plugins.tooltip.padding         = 10;
Chart.defaults.plugins.tooltip.titleColor      = '#e8edf5';
Chart.defaults.plugins.tooltip.bodyColor       = '#8a9ab5';
Chart.defaults.plugins.tooltip.cornerRadius    = 8;

// ================================================================
// State
// ================================================================
const charts      = {};
let incidentsData = [];
let sortState     = { col: 'threat_score', dir: 'desc' };

// ================================================================
// DOM helpers
// ================================================================
const $ = (id) => document.getElementById(id);

// ================================================================
// Particle background
// ================================================================
(function initParticles() {
  const canvas = $('bg-canvas');
  if (!canvas) return;

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    canvas.style.display = 'none';
    return;
  }

  const ctx  = canvas.getContext('2d');
  let W, H, particles;
  const COLORS = ['rgba(0,212,255,', 'rgba(0,255,136,', 'rgba(179,136,255,'];

  class Particle {
    constructor() { this.reset(true); }
    reset(init = false) {
      this.x  = Math.random() * W;
      this.y  = init ? Math.random() * H : -10;
      this.r  = 0.5 + Math.random() * CONFIG.PARTICLE_RADIUS_MAX;
      this.vx = (Math.random() - 0.5) * CONFIG.PARTICLE_SPEED_MAX;
      this.vy = 0.08 + Math.random() * CONFIG.PARTICLE_SPEED_MAX * 0.6;
      this.alpha = 0.15 + Math.random() * 0.45;
      this.color = COLORS[Math.floor(Math.random() * COLORS.length)];
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;
      if (this.y > H + 10) this.reset();
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = this.color + this.alpha + ')';
      ctx.fill();
    }
  }

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    particles = Array.from({ length: CONFIG.PARTICLE_COUNT }, () => new Particle());
  }

  function drawConnections() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx   = particles[i].x - particles[j].x;
        const dy   = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.PARTICLE_CONNECT_DIST) {
          const opacity = (1 - dist / CONFIG.PARTICLE_CONNECT_DIST) * 0.12;
          ctx.strokeStyle = `rgba(0,212,255,${opacity})`;
          ctx.lineWidth   = 0.6;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    ctx.clearRect(0, 0, W, H);
    drawConnections();
    particles.forEach(p => { p.update(); p.draw(); });
    requestAnimationFrame(animate);
  }

  window.addEventListener('resize', resize, { passive: true });
  resize();
  animate();
})();

// ================================================================
// Tooltip system
// ================================================================
(function initTooltips() {
  const layer = $('tooltip-layer');
  if (!layer) return;

  let hideTimer;
  document.querySelectorAll('[data-tooltip]').forEach(el => {
    el.addEventListener('mouseenter', (e) => {
      clearTimeout(hideTimer);
      layer.textContent = el.dataset.tooltip;
      layer.classList.add('visible');
      layer.setAttribute('aria-hidden', 'false');
      positionTooltip(e);
    });
    el.addEventListener('mousemove', positionTooltip);
    el.addEventListener('mouseleave', () => {
      hideTimer = setTimeout(() => {
        layer.classList.remove('visible');
        layer.setAttribute('aria-hidden', 'true');
      }, 120);
    });
  });

  function positionTooltip(e) {
    const margin = 12;
    let x = e.clientX + margin;
    let y = e.clientY - layer.offsetHeight - margin;
    if (x + layer.offsetWidth > window.innerWidth - 8) x = e.clientX - layer.offsetWidth - margin;
    if (y < 8) y = e.clientY + margin;
    layer.style.left = x + 'px';
    layer.style.top  = y + 'px';
  }
})();

// ================================================================
// Utility functions
// ================================================================

// UPDATED: Now properly formats large numbers with commas
function animateCounter(el, target, decimals = 0, suffix = '') {
  const duration = CONFIG.COUNTER_DURATION_MS;
  const start    = performance.now();
  
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    const currentVal = target * eased;
    
    // Format the number with commas (e.g., 1,234,567)
    const formatted = currentVal.toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals
    });
    
    el.textContent = formatted + suffix;
    
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatMitrePills(raw) {
  if (!raw) return '—';
  return raw.split(',')
    .map(t => t.trim())
    .filter(Boolean)
    .map(t => `<span class="mitre-pill">${escapeHtml(t)}</span>`)
    .join('');
}

function updateLastRefresh() {
  const el = $('last-refresh-label');
  if (el) el.textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
}

function setVerdictBadge(verdict) {
  const el = $('verdict-badge');
  if (!el) return;
  el.textContent = (verdict || '—').replace(/_/g, ' ');
  el.className   = 'verdict-badge';
  const v = (verdict || '').toUpperCase();
  if (v.includes('STRONG'))    el.classList.add('verdict-critical');
  else if (v.includes('MODERATE')) el.classList.add('verdict-moderate');
  else if (v.includes('LOW'))  el.classList.add('verdict-low');
}

// ================================================================
// Chart helpers
// ================================================================
const CHART_GRADIENT_CYAN  = (ctx) => {
  const g = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height);
  g.addColorStop(0, 'rgba(0,212,255,0.35)');
  g.addColorStop(1, 'rgba(0,212,255,0.02)');
  return g;
};

const CHART_PLUGIN_NODATA = {
  id: 'noDataPlugin',
  afterDraw(chart) {
    const hasData = chart.data.datasets.some(
      d => d.data && d.data.length > 0 && d.data.some(v => v > 0)
    );
    if (hasData) return;
    const { ctx, width, height } = chart;
    ctx.save();
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle    = '#3f5070';
    ctx.font         = `500 13px 'Inter', system-ui`;
    ctx.fillText('No data available', width / 2, height / 2);
    ctx.restore();
  },
};

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

const darkScales = (showX = true) => ({
  x: showX ? { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8a9ab5', maxRotation: 30 } } : { display: false },
  y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8a9ab5' } },
});

// ================================================================
// API fetch
// ================================================================
async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.json();
}

// ================================================================
// Render: Summary KPIs
// ================================================================
function renderSummary(data) {
  const noDataBanner = $('no-data-banner');
  if (data.no_data) {
    if (noDataBanner) noDataBanner.classList.remove('hidden');
    return;
  } else {
    if (noDataBanner) noDataBanner.classList.add('hidden');
  }

  setVerdictBadge(data.machine_verdict);

  const fields = [
    ['kpi-total-events', data.total_events,          0, ''],
    ['kpi-anomalies',    data.total_anomalies,       0, ''],
    ['kpi-anomaly-rate', data.anomaly_rate,          2, '%'],
    ['kpi-avg-score',    data.avg_threat_score,      2, ''],
    ['kpi-high-conf',    data.high_confidence_cases, 0, ''],
  ];

  for (const [id, val, dec, sfx] of fields) {
    const el = $(id);
    if (el) animateCounter(el, Number(val) || 0, dec, sfx);
  }

  const confEl  = $('kpi-confidence');
  const confBar = $('confidence-bar');
  const score   = Number(data.confidence_score) || 0;
  if (confEl) confEl.textContent = score + '%';
  if (confBar) {
    setTimeout(() => {
      confBar.style.width = score + '%';
      confBar.closest('[role="progressbar"]')?.setAttribute('aria-valuenow', score);
    }, 120);
  }
}

// ================================================================
// Render: Risk doughnut
// ================================================================
function renderRiskChart(data) {
  if (data.no_data) return;
  destroyChart('risk');
  const canvas = $('chart-risk');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  charts.risk = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      datasets: [{
        data: [data.CRITICAL || 0, data.HIGH || 0, data.MEDIUM || 0, data.LOW || 0],
        backgroundColor: ['rgba(255,51,102,0.85)', 'rgba(255,140,0,0.85)', 'rgba(255,214,0,0.85)', 'rgba(0,255,136,0.85)'],
        borderColor:  '#080d1a', borderWidth:  4, hoverOffset:  12,
        hoverBorderColor: ['#ff3366','#ff8c00','#ffd600','#00ff88'],
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '68%',
      plugins: {
        legend: { position: 'bottom', labels: { padding: 18, boxWidth: 10, color: '#8a9ab5', font: { size: 11 } } },
        tooltip: { callbacks: { label: (ctx) => `  ${ctx.label}: ${ctx.parsed.toLocaleString()}` } },
      },
      animation: { duration: 1000, easing: 'easeOutQuart' },
    },
    plugins: [CHART_PLUGIN_NODATA],
  });
}

// ================================================================
// Render: MITRE horizontal bar
// ================================================================
function renderMitreChart(data) {
  if (data.no_data) return;
  const techs  = data.techniques || {};
  const labels = Object.keys(techs).slice(0, 10);
  const values = labels.map(k => techs[k]);
  const palette = ['#00d4ff','#00ff88','#b388ff','#ff8c00','#ffd600','#00e5cc','#ff3366','#4dd0e1','#aed581','#f472b6'];

  destroyChart('mitre');
  const canvas = $('chart-mitre');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  charts.mitre = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.map(l => l.split(' - ')[0]), // Show short ID for clean UI
      datasets: [{
        label: 'Occurrences', data: values,
        backgroundColor: labels.map((_, i) => palette[i % palette.length] + '28'),
        borderColor: labels.map((_, i) => palette[i % palette.length]),
        borderWidth: 1.5, borderRadius: 5,
      }],
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8a9ab5' } },
        y: { grid: { display: false }, ticks: { color: '#e8edf5', font: { size: 11 } } },
      },
      animation: { duration: 950, easing: 'easeOutQuart' },
    },
    plugins: [CHART_PLUGIN_NODATA],
  });
}

// ================================================================
// Render: Top risky users bar
// ================================================================
function renderUsersChart(data) {
  if (data.no_data) return;
  const users = data.users || [];
  destroyChart('users');
  const canvas = $('chart-users');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  charts.users = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: users.map(u => u.username || 'N/A'),
      datasets: [{
        label: 'Max Threat Score', data: users.map(u => u.max_threat_score),
        backgroundColor: 'rgba(255,140,0,0.22)', borderColor: '#ff8c00',
        borderWidth: 1.5, borderRadius: 5, hoverBackgroundColor: 'rgba(255,140,0,0.38)',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: darkScales(), animation: { duration: 950, easing: 'easeOutQuart' },
    },
    plugins: [CHART_PLUGIN_NODATA],
  });
}

// ================================================================
// Render: Top source IPs bar
// ================================================================
function renderIPChart(data) {
  if (data.no_data) return;
  const ips = data.ips || [];
  destroyChart('ips');
  const canvas = $('chart-ips');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  charts.ips = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ips.map(i => i.ip || 'N/A'),
      datasets: [{
        label: 'Event Count', data: ips.map(i => i.count),
        backgroundColor: 'rgba(0,212,255,0.18)', borderColor: '#00d4ff',
        borderWidth: 1.5, borderRadius: 5, hoverBackgroundColor: 'rgba(0,212,255,0.32)',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: darkScales(), animation: { duration: 950, easing: 'easeOutQuart' },
    },
    plugins: [CHART_PLUGIN_NODATA],
  });
}

// ================================================================
// Render: Timeline area chart
// ================================================================
function renderTimeline(data) {
  if (data.no_data) return;
  const tl = data.timeline || [];
  destroyChart('timeline');
  const canvas = $('chart-timeline');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  charts.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: tl.map(t => t.hour),
      datasets: [{
        label: 'Events', data: tl.map(t => t.count),
        borderColor: '#00d4ff', backgroundColor: CHART_GRADIENT_CYAN(ctx),
        fill: true, tension: 0.42, pointRadius: 4, pointHoverRadius: 7,
        pointBackgroundColor: '#00d4ff', pointBorderColor: '#080d1a', pointBorderWidth: 2, borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8a9ab5', maxTicksLimit: 14, maxRotation: 30 } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8a9ab5' } },
      },
      animation: { duration: 1000, easing: 'easeOutQuart' },
    },
    plugins: [CHART_PLUGIN_NODATA],
  });
}

// ================================================================
// Incidents Table
// ================================================================
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
    tbody.innerHTML = '<tr><td colspan="5" class="loading-row">No incidents match the current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${escapeHtml(r.username || '—')}</td>
      <td><code>${escapeHtml(r.source_ip || '—')}</code></td>
      <td><span class="risk-badge risk-${escapeHtml((r.risk_level || '').toLowerCase())}">${escapeHtml(r.risk_level || '—')}</span></td>
      <td>${Number(r.threat_score || 0).toFixed(0)}</td>
      <td>${formatMitrePills(r.mitre_techniques)}</td>
    </tr>
  `).join('');
}

function updateTableCount(n) {
  const el = $('table-count');
  if (el) el.textContent = `${n.toLocaleString()} incident${n !== 1 ? 's' : ''}`;
}

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

function initTableSort() {
  const table = $('incidents-table');
  if (!table) return;
  table.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      table.querySelectorAll('thead th').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));

      if (sortState.col === col) {
        sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
      } else {
        sortState.col = col; sortState.dir = 'desc';
      }

      th.classList.add(`sorted-${sortState.dir}`);
      const sorted = [...incidentsData].sort((a, b) => {
        let av = a[col] ?? '', bv = b[col] ?? '';
        if (!isNaN(Number(av)) && !isNaN(Number(bv))) { av = Number(av); bv = Number(bv); }
        else { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); }
        if (av < bv) return sortState.dir === 'asc' ? -1 :  1;
        if (av > bv) return sortState.dir === 'asc' ?  1 : -1;
        return 0;
      });
      drawTable(sorted);
    });
  });
}

function initExport() {
  const btn = $('btn-export');
  if (!btn) return;
  btn.addEventListener('click', () => {
    if (!incidentsData.length) return;
    const header = ['username', 'source_ip', 'risk_level', 'threat_score', 'mitre_techniques'];
    const rows   = incidentsData.map(r => header.map(k => JSON.stringify(r[k] ?? '')).join(','));
    const csv  = [header.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `threatweaver_incidents_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
}

// ================================================================
// SENTINEL AI
// ================================================================
function initSentinel() {
  const btn = $('btn-sentinel');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    const loading = $('sentinel-loading');
    const output  = $('sentinel-output');
    const toolbar = $('sentinel-toolbar');

    btn.disabled = true;
    if (loading) loading.classList.remove('hidden');
    if (output) { output.classList.add('hidden'); output.innerHTML = ''; }
    if (toolbar) toolbar.classList.add('hidden');

    try {
      const data = await fetchJSON('/api/sentinel-report');
      if (loading) loading.classList.add('hidden');

      if (data.error) {
        if (output) output.innerHTML = `<div class="sentinel-error"><i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(data.error)}</div>`;
      } else {
        if (output) output.innerHTML = renderMarkdown(data.report || '');
        const ts = $('sentinel-generated-ts');
        if (ts) ts.textContent = 'Generated ' + new Date().toLocaleString();
        if (toolbar) toolbar.classList.remove('hidden');
      }

      if (output) { output.classList.remove('hidden'); fadeIn(output); }
    } catch (err) {
      if (loading) loading.classList.add('hidden');
      if (output) {
        output.innerHTML = `<div class="sentinel-error"><i class="fa-solid fa-circle-exclamation"></i> Failed to connect to AI engine: ${escapeHtml(err.message)}</div>`;
        output.classList.remove('hidden');
      }
    } finally {
      btn.disabled = false;
    }
  });
}

function renderMarkdown(text) {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^#### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^### (.+)$/gm,  '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,   '<h2 style="color:var(--text-primary);margin:16px 0 8px;">$2</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    .replace(/^---$/gm, '<hr style="border:none;border-top:1px solid var(--border);margin:14px 0;">')
    .replace(/\n/g, '<br>');
}

function fadeIn(el, duration = 450) {
  el.style.opacity = '0';
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    el.style.opacity = String(t);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ================================================================
// Navigation & Print
// ================================================================
function initNav() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  const sections = document.querySelectorAll('section[id]');
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        document.querySelectorAll('.nav-link').forEach(l => {
          l.classList.remove('active');
          l.removeAttribute('aria-current');
        });
        const link = document.querySelector(`.nav-link[href="#${entry.target.id}"]`);
        if (link) { link.classList.add('active'); link.setAttribute('aria-current', 'page'); }
      }
    }
  }, { threshold: 0.3, rootMargin: '-60px 0px -60px 0px' });
  sections.forEach(s => observer.observe(s));
}

function initRefreshButton() {
  const btn = $('btn-refresh');
  if (!btn) return;
  btn.addEventListener('click', () => {
    btn.classList.add('spinning');
    loadAll().finally(() => btn.classList.remove('spinning'));
  });
}

function initPrintReport() {
  const btn = $('btn-print-report');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const output = $('sentinel-output');
    if (!output || output.classList.contains('hidden')) return;
    const tsText = $('sentinel-generated-ts')?.textContent || '';
    const header = document.createElement('div');
    header.className = 'print-report-header';
    header.innerHTML = '<h1>&#x1F6E1;&#xFE0F; ThreatWeaver &mdash; SENTINEL AI Threat Intelligence Report</h1><p>' + escapeHtml(tsText) + ' &nbsp;&middot;&nbsp; Confidential &mdash; For SOC Internal Use Only</p>';
    output.prepend(header);
    window.print();
    header.remove();
  });
}

// ================================================================
// Main data loader
// ================================================================
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
    console.error('[ThreatWeaver] Dashboard load error:', err);
  }
}

// ================================================================
// Bootstrap
// ================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initRefreshButton();
  initTableSearch();
  initTableSort();
  initExport();
  initSentinel();
  initPrintReport();
  
  // Initial load
  loadAll();

  // Auto-refresh using Live DB
  setInterval(loadAll, CONFIG.REFRESH_INTERVAL_MS);
});
