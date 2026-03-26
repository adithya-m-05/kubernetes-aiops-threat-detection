/* ═══════════════════════════════════════════════════════
   App — Main entry point, event wiring, real-time loop
   ═══════════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ── State / Data ───────────────────────────────────── */
  let alerts = [];
  let entities = [];
  let responseActions = [];
  let timeSeriesData = null;
  let attackDistribution = [];
  let threatProgression = [];
  let currentSection = 'overview';
  let alertSortKey = 'timestamp';
  let alertSortDir = 'desc';
  let alertSearchTerm = '';
  let alertRiskFilter = 'ALL';

  /* ── DOM refs ───────────────────────────────────────── */
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  /* ── Initialise ─────────────────────────────────────── */
  async function init() {
    // Initial data fetch
    await updateDataFromApi();

    // Render all sections
    renderOverview();
    renderAlerts();
    renderEntities();
    renderResponses();

    // Wire events
    wireNavigation();
    wireThemeToggle();
    wireDetailPanel();
    startClock();
    startRealTimeLoop();

    // Show overview section
    switchSection('overview');
  }

  async function updateDataFromApi() {
    const rawAlerts = await Api.fetchHistory();
    alerts = Api.processAlerts(rawAlerts);
    entities = Api.processEntities(alerts);
    responseActions = Api.processResponseActions(alerts);
    timeSeriesData = Api.processTimeSeries(alerts);
    attackDistribution = Api.processAttackDistribution(alerts);
    threatProgression = Api.processThreatProgression(alerts);
  }

  /* ── Render Sections ────────────────────────────────── */
  function renderOverview() {
    const stats = Api.computeStats(alerts, entities);
    Components.renderSummaryCards($('#summary-cards'), stats);

    // Charts
    DashCharts.initActivityChart('activity-chart', timeSeriesData);
    DashCharts.initDistributionChart('distribution-chart', attackDistribution);

    // Threat progression
    Components.renderThreatProgression($('#threat-progression'), threatProgression);
  }

  function renderAlerts() {
    Components.renderAlertsTable($('#alerts-section-content'), alerts, {
      searchTerm: alertSearchTerm,
      riskFilter: alertRiskFilter,
      sortKey: alertSortKey,
      sortDir: alertSortDir,
    });

    // Rebind table event listeners
    wireAlertTableEvents();
  }

  function renderEntities() {
    Components.renderEntityGrid($('#entities-content'), entities);
  }

  function renderResponses() {
    Components.renderResponseTimeline($('#responses-content'), responseActions);
  }

  /* ── Navigation ─────────────────────────────────────── */
  function wireNavigation() {
    $$('.nav-item[data-section]').forEach(item => {
      item.addEventListener('click', () => {
        switchSection(item.dataset.section);
      });
    });
  }

  function switchSection(section) {
    currentSection = section;

    // Update nav active state
    $$('.nav-item[data-section]').forEach(n => n.classList.remove('active'));
    const active = $(`.nav-item[data-section="${section}"]`);
    if (active) active.classList.add('active');

    // Show/hide sections
    $$('.dashboard-section').forEach(s => s.classList.remove('active'));
    const target = $(`#section-${section}`);
    if (target) target.classList.add('active');

    // Update header title
    const titles = {
      overview: 'Dashboard Overview',
      alerts: 'Live Alerts',
      entities: 'Entity Status',
      responses: 'Response Actions',
    };
    $('#header-title').textContent = titles[section] || 'Dashboard';
  }

  /* ── Theme Toggle ───────────────────────────────────── */
  function wireThemeToggle() {
    const toggle = $('#theme-toggle');
    const iconContainer = $('#theme-icon');

    toggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      iconContainer.innerHTML = next === 'dark' ? Components.Icons.moon : Components.Icons.sun;
    });
  }

  /* ── Alert Table Events ─────────────────────────────── */
  function wireAlertTableEvents() {
    // Sort headers
    $$('#alerts-section-content th[data-sort]').forEach(th => {
      th.addEventListener('click', () => {
        const key = th.dataset.sort;
        if (alertSortKey === key) {
          alertSortDir = alertSortDir === 'asc' ? 'desc' : 'asc';
        } else {
          alertSortKey = key;
          alertSortDir = 'desc';
        }
        renderAlerts();
      });
    });

    // Search
    const search = $('#alert-search');
    if (search) {
      search.addEventListener('input', (e) => {
        alertSearchTerm = e.target.value;
        renderAlerts();
        // Restore focus
        const newSearch = $('#alert-search');
        if (newSearch) { newSearch.focus(); newSearch.selectionStart = newSearch.selectionEnd = newSearch.value.length; }
      });
    }

    // Risk filter
    const filter = $('#risk-filter');
    if (filter) {
      filter.addEventListener('change', (e) => {
        alertRiskFilter = e.target.value;
        renderAlerts();
      });
    }

    // Row clicks → open detail
    $$('#alerts-section-content tr[data-alert-id]').forEach(row => {
      row.addEventListener('click', () => {
        const alert = alerts.find(a => a.id === row.dataset.alertId);
        if (alert) openDetailPanel(alert);
      });
    });
  }

  /* ── Detail Panel ───────────────────────────────────── */
  function wireDetailPanel() {
    const panel = $('#detail-panel');
    const overlay = $('#detail-overlay');
    const closeBtn = $('#detail-close');

    closeBtn.addEventListener('click', () => closeDetailPanel());
    overlay.addEventListener('click', () => closeDetailPanel());

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDetailPanel();
    });
  }

  function openDetailPanel(alert) {
    Components.renderAlertDetail($('#detail-panel'), $('#detail-overlay'), alert);
  }

  function closeDetailPanel() {
    Components.renderAlertDetail($('#detail-panel'), $('#detail-overlay'), null);
  }

  /* ── Clock ──────────────────────────────────────────── */
  function startClock() {
    function update() {
      const now = new Date();
      $('#header-time').textContent = now.toLocaleTimeString('en-US', {
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
      }) + ' UTC';
    }
    update();
    setInterval(update, 1000);
  }

  /* ── Real-Time Simulation ───────────────────────────── */
  function startRealTimeLoop() {
    setInterval(async () => {
      await updateDataFromApi();

      // Update charts
      DashCharts.updateActivityChart(timeSeriesData);
      DashCharts.updateDistributionChart(attackDistribution);
      Components.renderThreatProgression($('#threat-progression'), threatProgression);

      // Re-render current section
      if (currentSection === 'overview') {
        const stats = Api.computeStats(alerts, entities);
        Components.renderSummaryCards($('#summary-cards'), stats);
      } else if (currentSection === 'alerts') {
        renderAlerts();
      } else if (currentSection === 'entities') {
        renderEntities();
      } else if (currentSection === 'responses') {
        renderResponses();
      }

      // Update alert count badge
      const activeCt = alerts.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length;
      const badge = $('#alert-badge');
      if (badge) badge.textContent = activeCt;

    }, 5000);
  }

  /* ── Boot ────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', init);
})();
