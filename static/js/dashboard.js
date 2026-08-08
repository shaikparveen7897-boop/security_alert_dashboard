/**
 * SENTRY - SECURITY ALERT DASHBOARD CLIENT LOGIC
 */

let timelineChart = null;
let knownAlertIds = new Set();

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  fetchAllData();
});

// Update UTC clock every second
function initClock() {
  const clockEl = document.getElementById('utcClock');
  const updateTime = () => {
    const now = new Date();
    const utcStr = now.toISOString().substring(11, 19) + ' UTC';
    if (clockEl) clockEl.textContent = utcStr;
  };
  updateTime();
  setInterval(updateTime, 1000);
}

// Parallel fetch of all dashboard endpoints
async function fetchAllData() {
  try {
    const [summaryRes, timelineRes, ipsRes, alertsRes] = await Promise.all([
      fetch('/api/summary').then(r => r.json()),
      fetch('/api/timeline').then(r => r.json()),
      fetch('/api/suspicious-ips').then(r => r.json()),
      fetch('/api/alerts').then(r => r.json())
    ]);

    renderKPIs(summaryRes);
    renderStatusPill(summaryRes.suspicious_ip_count);
    renderChart(timelineRes);
    renderSuspiciousIPsTable(ipsRes);
    renderAlertFeed(alertsRes);
  } catch (err) {
    console.error('Error fetching Sentry telemetry data:', err);
  }
}

// Render KPI Cards
function renderKPIs(summary) {
  document.getElementById('kpiTotalEvents').textContent = (summary.total_events || 0).toLocaleString();
  document.getElementById('kpiFailedAttempts').textContent = (summary.failed_count || 0).toLocaleString();
  document.getElementById('kpiFailedPct').textContent = `${summary.failed_percentage || 0}%`;
  document.getElementById('kpiSuccessLogins').textContent = (summary.success_count || 0).toLocaleString();
  document.getElementById('kpiFlaggedIps').textContent = (summary.suspicious_ip_count || 0).toLocaleString();
}

// Render Status Pill in Top Bar
function renderStatusPill(threatCount) {
  const pill = document.getElementById('statusPill');
  const pillText = document.getElementById('statusPillText');

  if (!pill || !pillText) return;

  if (threatCount > 0) {
    pill.className = 'status-pill status-threat-active';
    pillText.textContent = `${threatCount} ACTIVE THREAT${threatCount > 1 ? 'S' : ''}`;
  } else {
    pill.className = 'status-pill status-all-clear';
    pillText.textContent = 'ALL CLEAR';
  }
}

// Render or Update 24-Hour Timeline Chart with Chart.js
function renderChart(timelineData) {
  const ctx = document.getElementById('timelineChart');
  if (!ctx) return;

  const labels = timelineData.labels || [];
  const successData = timelineData.success || [];
  const failedData = timelineData.failed || [];

  if (timelineChart) {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = successData;
    timelineChart.data.datasets[1].data = failedData;
    timelineChart.update('none'); // Update smoothly without full reset
    return;
  }

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Successful Logins',
          data: successData,
          borderColor: '#35b8a6',
          backgroundColor: 'rgba(53, 184, 166, 0.08)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointHoverRadius: 6,
          pointBackgroundColor: '#35b8a6'
        },
        {
          label: 'Failed Attempts',
          data: failedData,
          borderColor: '#e0524a',
          backgroundColor: 'rgba(224, 82, 74, 0.12)',
          fill: true,
          tension: 0.35,
          borderWidth: 2.5,
          pointRadius: 3.5,
          pointHoverRadius: 6,
          pointBackgroundColor: '#e0524a'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false // Using custom styled legend in HTML panel header
        },
        tooltip: {
          backgroundColor: '#191d24',
          borderColor: '#2a313b',
          borderWidth: 1,
          titleFont: { family: 'Inter', size: 12 },
          bodyFont: { family: 'Inter', size: 12 },
          padding: 10,
          displayColors: true,
          boxWidth: 8,
          boxHeight: 8
        }
      },
      scales: {
        x: {
          grid: {
            color: '#212731',
            drawTicks: false
          },
          ticks: {
            color: '#8b98a9',
            font: { family: 'Inter', size: 10 },
            maxRotation: 0,
            autoSkip: true,
            maxTicksLimit: 12
          }
        },
        y: {
          beginAtZero: true,
          grid: {
            color: '#212731',
            drawTicks: false
          },
          ticks: {
            color: '#8b98a9',
            font: { family: 'Inter', size: 11 },
            precision: 0
          }
        }
      }
    }
  });
}

// Render Suspicious IPs Table
function renderSuspiciousIPsTable(ipList) {
  const tbody = document.getElementById('suspiciousIpsTableBody');
  const emptyState = document.getElementById('emptyIpsState');
  const badge = document.getElementById('ipCountBadge');

  if (!tbody) return;

  tbody.innerHTML = '';
  if (badge) badge.textContent = `${ipList.length} Threat IP${ipList.length === 1 ? '' : 's'}`;

  if (!ipList || ipList.length === 0) {
    if (emptyState) emptyState.classList.remove('hidden');
    return;
  }

  if (emptyState) emptyState.classList.add('hidden');

  ipList.forEach(item => {
    const tr = document.createElement('tr');

    const riskClass = item.risk_level === 'critical' ? 'risk-critical' : 'risk-high';
    const riskLabel = item.risk_level.toUpperCase();

    const targetedUsersStr = (item.usernames_targeted || []).join(', ');
    const lastAttemptStr = formatTimestamp(item.last_attempt);

    tr.innerHTML = `
      <td><span class="risk-pill ${riskClass}">${riskLabel}</span></td>
      <td><span class="ip-address">${escapeHtml(item.ip)}</span></td>
      <td>${escapeHtml(item.country)}</td>
      <td><span class="count-badge">${item.failed_count}</span></td>
      <td><span class="users-list">${escapeHtml(targetedUsersStr)}</span></td>
      <td><span class="time-readout">${lastAttemptStr}</span></td>
    `;

    tbody.appendChild(tr);
  });
}

// Render Live Terminal Alert Feed
function renderAlertFeed(alerts) {
  const container = document.getElementById('alertFeedContainer');
  if (!container) return;

  container.innerHTML = '';

  if (!alerts || alerts.length === 0) {
    container.innerHTML = '<div style="color: var(--text-dim); text-align: center; padding: 20px;">No suspicious activity events logged.</div>';
    return;
  }

  alerts.forEach(alert => {
    const isNew = !knownAlertIds.has(alert.id);
    knownAlertIds.add(alert.id);

    const logEl = document.createElement('div');
    logEl.className = `log-entry ${isNew ? 'new-entry-flash' : ''}`;

    const timeFormatted = formatTimestamp(alert.timestamp, true);

    logEl.innerHTML = `
      <span class="log-dot"></span>
      <span class="log-time">[${timeFormatted}]</span>
      <div class="log-msg">
        Failed login for <span class="msg-user">${escapeHtml(alert.username)}</span> 
        from <span class="msg-ip">${escapeHtml(alert.ip)}</span> 
        (<span class="msg-country">${escapeHtml(alert.country)}</span>) — 
        <span class="msg-reason">${escapeHtml(alert.reason)}</span>
      </div>
    `;

    container.appendChild(logEl);
  });
}

// Trigger Live Simulated Attack (POST /api/simulate-attack)
async function triggerSimulatedAttack() {
  const btn = document.getElementById('simulateBtn');
  const btnText = document.getElementById('simulateBtnText');

  if (!btn) return;

  try {
    btn.classList.add('loading');
    btnText.textContent = 'Injecting Attack...';

    const response = await fetch('/api/simulate-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    const data = await response.json();
    console.log('Simulated attack status:', data);

    // Re-fetch and update all UI modules live
    await fetchAllData();

  } catch (err) {
    console.error('Failed to simulate attack:', err);
  } finally {
    setTimeout(() => {
      btn.classList.remove('loading');
      btnText.textContent = 'Simulate Attack';
    }, 600);
  }
}

// Download a formatted Excel report, optionally scoped to a time range
function downloadExcelReport() {
  const btn = document.getElementById('excelExportBtn');
  const startInput = document.getElementById('rangeStart');
  const endInput = document.getElementById('rangeEnd');

  const params = new URLSearchParams();

  // datetime-local gives "YYYY-MM-DDTHH:MM" in local time; convert to a
  // full ISO string (with seconds) so the backend can parse it reliably.
  if (startInput && startInput.value) {
    params.set('start', new Date(startInput.value).toISOString());
  }
  if (endInput && endInput.value) {
    params.set('end', new Date(endInput.value).toISOString());
  }

  if (btn) btn.classList.add('loading');

  const url = `/api/export-excel${params.toString() ? '?' + params.toString() : ''}`;
  window.location.href = url;

  setTimeout(() => {
    if (btn) btn.classList.remove('loading');
  }, 800);
}

// Date formatting helper
function formatTimestamp(isoStr, timeOnly = false) {
  if (!isoStr) return '--';
  try {
    const dt = new Date(isoStr);
    if (isNaN(dt.getTime())) return isoStr;

    const hours = String(dt.getUTCHours()).padStart(2, '0');
    const mins = String(dt.getUTCMinutes()).padStart(2, '0');
    const secs = String(dt.getUTCSeconds()).padStart(2, '0');

    if (timeOnly) {
      return `${hours}:${mins}:${secs} UTC`;
    }

    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[dt.getUTCMonth()];
    const day = dt.getUTCDate();

    return `${month} ${day}, ${hours}:${mins}:${secs} UTC`;
  } catch (e) {
    return isoStr;
  }
}

// Utility HTML escape
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
