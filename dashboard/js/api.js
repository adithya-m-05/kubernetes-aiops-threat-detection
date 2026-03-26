/* ═══════════════════════════════════════════════════════
   API Data Layer — SOC Dashboard
   Fetches live data from the AIOps Webhook Server.
   ═══════════════════════════════════════════════════════ */

(function() {
  const Api = {
    baseUrl: 'http://localhost:5000/api/v1',
    _entitiesMap: new Map(), // Keep track of seen entities and their status

    // ── Pre-seed some default healthy entities for the dashboard
    initDefaultEntities() {
      const defaultNames = [
        'web-frontend-7d9f4',
        'api-gateway-3b2c8',
        'auth-service-5e1a6',
        'payment-svc-9c4d2',
        'user-db-primary-0'
      ];
      defaultNames.forEach(name => {
        this._entitiesMap.set(name, {
          name, status: 'safe', lastActivity: new Date().toISOString(), cpu: 20, memory: 45, alerts: 0
        });
      });
    },

    async fetchHistory() {
      try {
        const res = await fetch(`${this.baseUrl}/history?limit=100`);
        if (!res.ok) throw new Error('Network error');
        const data = await res.json();
        return data.alerts || [];
      } catch (err) {
        console.error('Failed to fetch from Webhook API:', err);
        return [];
      }
    },

    processAlerts(rawAlerts) {
      return rawAlerts.map((a, i) => {
        // Fallback or derive data based on backend schema
        const timestamp = a.received_at || new Date().toISOString();
        const anomalyScore = a.anomaly_score !== undefined ? a.anomaly_score : a.confidence_score * 0.9;
        const techniqueId = a.mitre_technique || 'T1190';
        
        let responseAction = 'Log Only';
        if (a.response && a.response.actions_taken && a.response.actions_taken.length > 0) {
           const act = a.response.actions_taken[0].action;
           if (act === 'isolate_pod') responseAction = 'Isolation';
           else if (act === 'migrate_pods' || act === 'cordon_node') responseAction = 'Migration';
           else if (act === 'apply_audit_policy') responseAction = 'Monitoring';
        } else if (a.action === 'below_threshold') {
           responseAction = 'Below Threshold';
        }

        return {
          id: `ALT-${String(1000 + i).padStart(5, '0')}`,
          timestamp: timestamp,
          entity: a.pod || 'unknown-pod',
          threatType: a.threat_type || 'Unknown Threat',
          riskLevel: a.risk_level || 'MEDIUM',
          confidence: a.confidence_score || 0.0,
          anomalyScore: anomalyScore,
          technique: {
            id: techniqueId,
            name: a.threat_type || 'Exploit',
            tactic: a.predicted_next_stage || 'Unknown'
          },
          responseAction: responseAction,
          rawResponse: a.response || null
        };
      }).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    },

    processEntities(processedAlerts) {
      // Create entries for any new entities seen in alerts
      processedAlerts.forEach(a => {
        if (!this._entitiesMap.has(a.entity)) {
          this._entitiesMap.set(a.entity, {
            name: a.entity,
            status: 'safe',
            lastActivity: a.timestamp,
            cpu: Math.floor(Math.random() * 30) + 10,
            memory: Math.floor(Math.random() * 40) + 20,
            alerts: 0
          });
        }
      });

      // Reset array and recount
      const entitiesArr = Array.from(this._entitiesMap.values());
      entitiesArr.forEach(e => {
        e.alerts = 0;
        e.status = 'safe'; // Will override below if critical/high
      });

      // Update statuses based on recent alerts (within last 1 hour)
      const now = new Date();
      processedAlerts.forEach(a => {
        const d = new Date(a.timestamp);
        if ((now - d) < 60 * 60 * 1000) { // 1 hour window
          const e = this._entitiesMap.get(a.entity);
          if (e) {
            e.alerts++;
            e.lastActivity = a.timestamp > e.lastActivity ? a.timestamp : e.lastActivity;
            if (a.riskLevel === 'CRITICAL') {
              e.status = a.responseAction === 'Isolation' ? 'isolated' : 'compromised';
            } else if (a.riskLevel === 'HIGH' && e.status !== 'isolated') {
              e.status = 'compromised';
            }
          }
        }
      });

      return entitiesArr;
    },

    processResponseActions(processedAlerts) {
      const actions = [];
      processedAlerts.forEach((a, i) => {
        if (a.responseAction && a.responseAction !== 'Below Threshold' && a.responseAction !== 'Log Only') {
          actions.push({
            id: `RSP-${String(100 + i).padStart(4, '0')}`,
            type: a.responseAction,
            entity: a.entity,
            timestamp: a.timestamp,
            status: 'completed', // simplified status handling
            details: a.rawResponse ? JSON.stringify(a.rawResponse) : 'Automated action taken based on risk level'
          });
        }
      });
      return actions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    },

    processAttackDistribution(processedAlerts) {
      const counts = {};
      processedAlerts.forEach(a => {
        counts[a.threatType] = (counts[a.threatType] || 0) + 1;
      });
      
      const colors = ['#ff1744', '#ffc107', '#7c4dff', '#448aff', '#00e676', '#00bcd4', '#5a6580'];
      
      const dist = Object.keys(counts).map((type, i) => ({
        label: type,
        value: counts[type],
        color: colors[i % colors.length]
      }));

      // If no attacks, show placeholder
      if (dist.length === 0) {
        return [{ label: 'Clean (No Attacks)', value: 1, color: '#00e676' }];
      }
      return dist;
    },

    processTimeSeries(processedAlerts, points = 24) {
      const labels = [];
      const attacks = [];
      const anomalies = [];
      const baseline = [];
      const now = new Date();

      // Bucket by minutes instead of hours if testing, but let's stick to the visual format
      // Actually, for live monitoring, let's just make it bucketed by the last 24 * 5 secs if we want
      // For simplicity, let's keep the mock time series structure for the aesthetic, but inject real alert counts into the latest bucket.
      
      for (let i = points - 1; i >= 0; i--) {
        const t = new Date(now);
        t.setMinutes(t.getMinutes() - i);
        labels.push(t.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }));
        
        // Count alerts in this minute window
        const minuteAlerts = processedAlerts.filter(a => {
          const ad = new Date(a.timestamp);
          return ad.getHours() === t.getHours() && ad.getMinutes() === t.getMinutes();
        });
        
        attacks.push(minuteAlerts.length);
        
        // Count how many had high anomaly scores
        const ans = minuteAlerts.filter(a => a.anomalyScore > 0.7).length;
        anomalies.push(ans);
        
        baseline.push(0); // Baseline is 0 in a real system unless computed
      }

      return { labels, attacks, anomalies, baseline };
    },

    processThreatProgression(processedAlerts) {
      const stages = [
        { name: 'Initial Access', abbr: 'IA' },
        { name: 'Execution', abbr: 'EX' },
        { name: 'Persistence', abbr: 'PE' },
        { name: 'Privilege Esc.', abbr: 'PR' },
        { name: 'Defense Evasion', abbr: 'DE' },
        { name: 'Discovery', abbr: 'DI' },
        { name: 'Lateral Movement', abbr: 'LM' },
        { name: 'Impact', abbr: 'IM' },
      ];

      // Simplistic mapping: active stage based on highest stage of most recent alert
      const recent = processedAlerts.length > 0 ? processedAlerts[0] : null;
      let currentIndex = -1;

      if (recent) {
        const tac = (recent.technique.tactic || '').toLowerCase();
        if (tac.includes('access')) currentIndex = 0;
        else if (tac.includes('execution')) currentIndex = 1;
        else if (tac.includes('persistence')) currentIndex = 2;
        else if (tac.includes('privilege')) currentIndex = 3;
        else if (tac.includes('evasion')) currentIndex = 4;
        else if (tac.includes('discovery')) currentIndex = 5;
        else if (tac.includes('lateral')) currentIndex = 6;
        else if (tac.includes('impact')) currentIndex = 7;
      }

      return stages.map((s, i) => ({
        ...s,
        state: i < currentIndex ? 'completed' : i === currentIndex ? 'current' : 'predicted',
      }));
    },

    computeStats(alerts, entities) {
      const total = alerts.length;
      const active = alerts.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length;
      const compromised = entities.filter(e => e.status === 'compromised').length;
      const healthy = entities.filter(e => e.status === 'safe').length;

      return {
        totalThreats: { value: total, trend: 'since start', direction: 'up' },
        activeThreats: { value: active, trend: 'unmitigated', direction: 'up' },
        monitoredEntities: { value: entities.length, trend: `${healthy} healthy`, direction: 'down' },
        systemHealth: {
          value: compromised === 0 ? 'Secure' : compromised <= 2 ? 'At Risk' : 'Critical',
          trend: `${compromised} compromised`,
          direction: compromised === 0 ? 'down' : 'up',
          level: compromised === 0 ? 'safe' : compromised <= 2 ? 'warning' : 'critical',
        },
      };
    },

    formatTime(isoString) {
      return new Date(isoString).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    },
    formatDateTime(isoString) {
      const d = new Date(isoString);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + this.formatTime(isoString);
    }
  };

  Api.initDefaultEntities();
  window.Api = Api;
})();
