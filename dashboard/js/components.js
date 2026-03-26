/* ═══════════════════════════════════════════════════════
   Components — DOM rendering functions
   ═══════════════════════════════════════════════════════ */

/* ── SVG Icons (inline Lucide-style) ────────────────── */
const Icons = {
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  alertTriangle: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  activity: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  server: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
  heart: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z"/></svg>`,
  search: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
  x: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  sun: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  layout: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>`,
  list: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>`,
  box: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>`,
  clock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  zap: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  arrowUp: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>`,
  arrowDown: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>`,
  chevronUp: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="18 15 12 9 6 15"/></svg>`,
  chevronDown: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="6 9 12 15 18 9"/></svg>`,
  target: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`,
};

/* ── Summary Cards ──────────────────────────────────── */
function renderSummaryCards(container, stats) {
  const cards = [
    { key: 'totalThreats', label: 'Total Threats', icon: Icons.shield, variant: 'info', iconVariant: 'info' },
    { key: 'activeThreats', label: 'Active Threats', icon: Icons.alertTriangle, variant: 'critical', iconVariant: 'critical' },
    { key: 'monitoredEntities', label: 'Monitored Entities', icon: Icons.server, variant: 'warning', iconVariant: 'warning' },
    { key: 'systemHealth', label: 'System Health', icon: Icons.heart, variant: stats.systemHealth.level || 'safe', iconVariant: stats.systemHealth.level || 'safe' },
  ];

  container.innerHTML = cards.map(c => {
    const data = stats[c.key];
    return `
      <div class="summary-card summary-card--${c.variant}" id="card-${c.key}">
        <div class="summary-card__icon summary-card__icon--${c.iconVariant}">
          ${c.icon}
        </div>
        <div class="summary-card__body">
          <div class="summary-card__label">${c.label}</div>
          <div class="summary-card__value">${data.value}</div>
          <div class="summary-card__trend summary-card__trend--${data.direction}">
            ${data.direction === 'up' ? Icons.arrowUp : Icons.arrowDown}
            ${data.trend}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

/* ── Alerts Table ───────────────────────────────────── */
function renderAlertsTable(container, alerts, options = {}) {
  const { searchTerm = '', riskFilter = 'ALL', sortKey = 'timestamp', sortDir = 'desc' } = options;

  let filtered = [...alerts];

  if (searchTerm) {
    const q = searchTerm.toLowerCase();
    filtered = filtered.filter(a =>
      a.entity.toLowerCase().includes(q) ||
      a.threatType.toLowerCase().includes(q) ||
      a.id.toLowerCase().includes(q)
    );
  }

  if (riskFilter !== 'ALL') {
    filtered = filtered.filter(a => a.riskLevel === riskFilter);
  }

  filtered.sort((a, b) => {
    let va = a[sortKey], vb = b[sortKey];
    if (sortKey === 'timestamp') { va = new Date(va); vb = new Date(vb); }
    if (sortKey === 'confidence' || sortKey === 'anomalyScore') { va = Number(va); vb = Number(vb); }
    if (typeof va === 'string') { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    if (va < vb) return sortDir === 'asc' ? -1 : 1;
    if (va > vb) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  const sortIcon = (key) => {
    if (sortKey !== key) return `<span class="sort-icon">${Icons.chevronDown}</span>`;
    return `<span class="sort-icon">${sortDir === 'asc' ? Icons.chevronUp : Icons.chevronDown}</span>`;
  };

  const riskClass = (level) => {
    if (level === 'CRITICAL') return 'risk-critical';
    if (level === 'HIGH') return 'risk-high';
    return '';
  };

  const badgeClass = (level) => {
    return level === 'CRITICAL' ? 'badge--critical' :
           level === 'HIGH' ? 'badge--high' :
           level === 'MEDIUM' ? 'badge--medium' : 'badge--low';
  };

  const confidenceColor = (val) => {
    if (val >= 0.9) return 'var(--color-critical)';
    if (val >= 0.7) return 'var(--color-warning)';
    return 'var(--color-info)';
  };

  container.innerHTML = `
    <div class="panel">
      <div class="panel__header">
        <div class="panel__title">${Icons.alertTriangle} Live Alerts <span class="badge badge--critical" style="margin-left:8px">${filtered.length}</span></div>
        <div class="filter-bar">
          <div class="search-input">
            <span class="search-input__icon">${Icons.search}</span>
            <input type="text" id="alert-search" placeholder="Search alerts..." value="${searchTerm}">
          </div>
          <select class="filter-select" id="risk-filter">
            <option value="ALL" ${riskFilter === 'ALL' ? 'selected' : ''}>All Risks</option>
            <option value="CRITICAL" ${riskFilter === 'CRITICAL' ? 'selected' : ''}>Critical</option>
            <option value="HIGH" ${riskFilter === 'HIGH' ? 'selected' : ''}>High</option>
            <option value="MEDIUM" ${riskFilter === 'MEDIUM' ? 'selected' : ''}>Medium</option>
            <option value="LOW" ${riskFilter === 'LOW' ? 'selected' : ''}>Low</option>
          </select>
        </div>
      </div>
      <div class="table-container" style="max-height: 420px; overflow-y: auto;">
        <table class="data-table">
          <thead>
            <tr>
              <th data-sort="timestamp" class="${sortKey === 'timestamp' ? 'sorted' : ''}">Timestamp ${sortIcon('timestamp')}</th>
              <th data-sort="entity" class="${sortKey === 'entity' ? 'sorted' : ''}">Entity ${sortIcon('entity')}</th>
              <th data-sort="threatType" class="${sortKey === 'threatType' ? 'sorted' : ''}">Threat Type ${sortIcon('threatType')}</th>
              <th data-sort="riskLevel" class="${sortKey === 'riskLevel' ? 'sorted' : ''}">Risk ${sortIcon('riskLevel')}</th>
              <th data-sort="confidence" class="${sortKey === 'confidence' ? 'sorted' : ''}">Confidence ${sortIcon('confidence')}</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.length === 0 ? `<tr><td colspan="5" class="empty-state">No alerts match your criteria</td></tr>` :
              filtered.map(a => `
                <tr class="${riskClass(a.riskLevel)}" data-alert-id="${a.id}">
                  <td class="mono text-sm">${Api.formatDateTime(a.timestamp)}</td>
                  <td class="mono">${a.entity}</td>
                  <td>${a.threatType}</td>
                  <td><span class="badge ${badgeClass(a.riskLevel)}">${a.riskLevel}</span></td>
                  <td>
                    <span class="confidence-bar"><span class="confidence-bar__fill" style="width:${a.confidence * 100}%;background:${confidenceColor(a.confidence)}"></span></span>
                    ${(a.confidence * 100).toFixed(0)}%
                  </td>
                </tr>
              `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

/* ── Entity Grid ────────────────────────────────────── */
function renderEntityGrid(container, entities) {
  container.innerHTML = `
    <div class="grid-entity">
      ${entities.map(e => `
        <div class="entity-card">
          <div class="entity-card__header">
            <div class="flex items-center gap-2">
              <span class="entity-card__indicator entity-card__indicator--${e.status}"></span>
              <span class="entity-card__name">${e.name}</span>
            </div>
            <span class="badge badge--${e.status === 'safe' ? 'safe' : e.status === 'compromised' ? 'compromised' : 'isolated'}">${e.status}</span>
          </div>
          <div class="entity-card__meta">
            <span><span style="display:inline-flex;width:14px;height:14px;vertical-align:middle;margin-right:4px">${Icons.clock}</span>Last: ${Api.formatTime(e.lastActivity)}</span>
            <span>CPU: ${e.cpu}%  ·  Mem: ${e.memory}%  ·  Alerts: ${e.alerts}</span>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

/* ── Alert Detail Panel ─────────────────────────────── */
function renderAlertDetail(panel, overlay, alert) {
  if (!alert) {
    panel.classList.remove('open');
    overlay.classList.remove('open');
    return;
  }

  const badgeClass = alert.riskLevel === 'CRITICAL' ? 'badge--critical' :
                     alert.riskLevel === 'HIGH' ? 'badge--high' :
                     alert.riskLevel === 'MEDIUM' ? 'badge--medium' : 'badge--low';

  panel.querySelector('.detail-panel__body').innerHTML = `
    <div class="detail-field">
      <div class="detail-field__label">Alert ID</div>
      <div class="detail-field__value mono">${alert.id}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Timestamp</div>
      <div class="detail-field__value mono">${Api.formatDateTime(alert.timestamp)}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Entity</div>
      <div class="detail-field__value mono">${alert.entity}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Threat Type</div>
      <div class="detail-field__value">${alert.threatType}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Risk Level</div>
      <div class="detail-field__value"><span class="badge ${badgeClass}">${alert.riskLevel}</span></div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Confidence Score</div>
      <div class="detail-field__value flex items-center gap-3">
        <span class="confidence-bar" style="width:120px"><span class="confidence-bar__fill" style="width:${alert.confidence * 100}%;background:var(--color-info)"></span></span>
        <span class="mono">${(alert.confidence * 100).toFixed(1)}%</span>
      </div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Anomaly Score</div>
      <div class="detail-field__value flex items-center gap-3">
        <span class="confidence-bar" style="width:120px"><span class="confidence-bar__fill" style="width:${alert.anomalyScore * 100}%;background:var(--color-warning)"></span></span>
        <span class="mono">${(alert.anomalyScore * 100).toFixed(1)}%</span>
      </div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">MITRE Technique</div>
      <div class="detail-field__value">
        <span class="badge badge--medium">${alert.technique.id}</span>
        <span style="margin-left: 8px">${alert.technique.name}</span>
      </div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Tactic / Stage</div>
      <div class="detail-field__value">${alert.technique.tactic}</div>
    </div>
    <div class="detail-field">
      <div class="detail-field__label">Response Action</div>
      <div class="detail-field__value">
        <span class="badge ${alert.responseAction === 'Isolation' ? 'badge--critical' : alert.responseAction === 'Migration' ? 'badge--high' : 'badge--medium'}">${alert.responseAction}</span>
      </div>
    </div>
  `;

  panel.classList.add('open');
  overlay.classList.add('open');
}

/* ── Response Timeline ──────────────────────────────── */
function renderResponseTimeline(container, actions) {
  const dotClass = (type) => {
    switch (type) {
      case 'Isolation': return 'timeline-item__dot--isolation';
      case 'Migration': return 'timeline-item__dot--migration';
      case 'Monitoring': return 'timeline-item__dot--monitoring';
      case 'Resolved': return 'timeline-item__dot--resolved';
      default: return '';
    }
  };

  container.innerHTML = `
    <div class="panel">
      <div class="panel__header">
        <div class="panel__title">${Icons.zap} Response Actions</div>
      </div>
      <div class="timeline" style="max-height: 500px; overflow-y: auto;">
        ${actions.map(a => `
          <div class="timeline-item">
            <div class="timeline-item__dot ${dotClass(a.type)}"></div>
            <div class="timeline-item__content">
              <div class="timeline-item__header">
                <span class="timeline-item__action">${a.type}</span>
                <span class="badge badge--${a.status === 'completed' ? 'safe' : a.status === 'in-progress' ? 'high' : 'medium'}">${a.status}</span>
              </div>
              <div class="timeline-item__desc">
                <span class="mono text-xs">${a.entity}</span> — ${a.details}
              </div>
              <div class="timeline-item__time">${Api.formatDateTime(a.timestamp)}</div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

/* ── Threat Progression ─────────────────────────────── */
function renderThreatProgression(container, stages) {
  let html = '<div class="panel"><div class="panel__header"><div class="panel__title">' + Icons.target + ' Threat Progression — MITRE ATT&CK</div></div><div class="progression">';

  stages.forEach((s, i) => {
    html += `
      <div class="progression__step ${s.state}">
        <div class="progression__node">${s.abbr}</div>
        <div class="progression__label">${s.name}</div>
      </div>
    `;
    if (i < stages.length - 1) {
      html += `<div class="progression__connector ${s.state === 'completed' ? 'completed' : ''}"></div>`;
    }
  });

  html += '</div></div>';
  container.innerHTML = html;
}

/* ── Exports ────────────────────────────────────────── */
window.Components = {
  Icons,
  renderSummaryCards,
  renderAlertsTable,
  renderEntityGrid,
  renderAlertDetail,
  renderResponseTimeline,
  renderThreatProgression,
};
