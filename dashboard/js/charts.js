/* ═══════════════════════════════════════════════════════
   Charts — Chart.js initialisation and update helpers
   ═══════════════════════════════════════════════════════ */

let activityChart = null;
let distributionChart = null;

/* ── Activity / Attacks Over Time (Line Chart) ──────── */
function initActivityChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;

  const gradient1 = ctx.getContext('2d').createLinearGradient(0, 0, 0, 280);
  gradient1.addColorStop(0, 'rgba(68, 138, 255, 0.25)');
  gradient1.addColorStop(1, 'rgba(68, 138, 255, 0.0)');

  const gradient2 = ctx.getContext('2d').createLinearGradient(0, 0, 0, 280);
  gradient2.addColorStop(0, 'rgba(255, 23, 68, 0.20)');
  gradient2.addColorStop(1, 'rgba(255, 23, 68, 0.0)');

  activityChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [
        {
          label: 'Attacks Detected',
          data: data.attacks,
          borderColor: '#448aff',
          backgroundColor: gradient1,
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: '#448aff',
          pointHoverBorderColor: '#fff',
          pointHoverBorderWidth: 2,
        },
        {
          label: 'Anomalies',
          data: data.anomalies,
          borderColor: '#ff1744',
          backgroundColor: gradient2,
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: '#ff1744',
          pointHoverBorderColor: '#fff',
          pointHoverBorderWidth: 2,
        },
        {
          label: 'Baseline',
          data: data.baseline,
          borderColor: 'rgba(90, 101, 128, 0.5)',
          borderWidth: 1,
          borderDash: [6, 4],
          fill: false,
          tension: 0.4,
          pointRadius: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: {
          display: true,
          position: 'top',
          align: 'end',
          labels: {
            color: '#8b95a9',
            font: { family: 'Inter', size: 11 },
            boxWidth: 12,
            boxHeight: 2,
            padding: 16,
            usePointStyle: false,
          },
        },
        tooltip: {
          backgroundColor: 'rgba(17, 24, 39, 0.95)',
          titleColor: '#e8ecf4',
          bodyColor: '#8b95a9',
          borderColor: 'rgba(255,255,255,0.08)',
          borderWidth: 1,
          padding: 12,
          cornerRadius: 8,
          titleFont: { family: 'Inter', size: 12, weight: '600' },
          bodyFont: { family: 'Inter', size: 11 },
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false },
          ticks: { color: '#5a6580', font: { family: 'Inter', size: 10 }, maxTicksLimit: 12 },
        },
        y: {
          grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false },
          ticks: { color: '#5a6580', font: { family: 'Inter', size: 10 } },
          beginAtZero: true,
        },
      },
    },
  });

  return activityChart;
}

/* ── Attack Distribution (Donut Chart) ──────────────── */
function initDistributionChart(canvasId, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;

  distributionChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d.label),
      datasets: [{
        data: data.map(d => d.value),
        backgroundColor: data.map(d => d.color),
        borderColor: 'transparent',
        borderWidth: 0,
        hoverOffset: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          display: true,
          position: 'right',
          labels: {
            color: '#8b95a9',
            font: { family: 'Inter', size: 11 },
            boxWidth: 10,
            boxHeight: 10,
            padding: 12,
            usePointStyle: true,
            pointStyle: 'circle',
          },
        },
        tooltip: {
          backgroundColor: 'rgba(17, 24, 39, 0.95)',
          titleColor: '#e8ecf4',
          bodyColor: '#8b95a9',
          borderColor: 'rgba(255,255,255,0.08)',
          borderWidth: 1,
          padding: 12,
          cornerRadius: 8,
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.raw} events`,
          },
        },
      },
    },
  });

  return distributionChart;
}

/* ── Update helpers ─────────────────────────────────── */
function updateActivityChart(data) {
  if (!activityChart) return;
  activityChart.data.labels = data.labels;
  activityChart.data.datasets[0].data = data.attacks;
  activityChart.data.datasets[1].data = data.anomalies;
  activityChart.data.datasets[2].data = data.baseline;
  activityChart.update('none');
}

function updateDistributionChart(data) {
  if (!distributionChart) return;
  distributionChart.data.datasets[0].data = data.map(d => d.value);
  distributionChart.update('none');
}

/* ── Exports ────────────────────────────────────────── */
window.DashCharts = {
  initActivityChart,
  initDistributionChart,
  updateActivityChart,
  updateDistributionChart,
};
