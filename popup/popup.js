async function send(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

async function loadStats() {
  const stats = await send('GET_STATS');
  document.getElementById('criticalAlerts').textContent = stats.criticalAlerts;
  document.getElementById('threatsToday').textContent = stats.threatsToday;
  document.getElementById('blockedDomains').textContent = stats.blockedDomains;
  document.getElementById('maliciousDownloads').textContent = stats.maliciousDownloads;
}

async function loadAlerts() {
  const alerts = await send('GET_ALERTS', { limit: 5 });
  const container = document.getElementById('alertsList');

  if (!alerts.length) {
    container.innerHTML = '<div class="empty">No alerts yet — monitoring active</div>';
    return;
  }

  container.innerHTML = alerts.map((a) => `
    <div class="alert-item ${a.risk_level?.toLowerCase()}">
      <div class="alert-title">${escapeHtml(a.title)}</div>
      <div class="alert-meta">${escapeHtml(a.domain || '')} · Risk ${a.risk_score} · ${a.technique || '—'}</div>
    </div>
  `).join('');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

document.getElementById('huntBtn').addEventListener('click', async () => {
  const query = document.getElementById('huntInput').value.trim();
  if (!query) return;
  const result = await send('HUNT_QUERY', { query });
  document.getElementById('huntResults').textContent =
    result.error || `Found ${result.count} result(s) for "${result.query}"`;
});

document.getElementById('huntInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('huntBtn').click();
});

document.getElementById('openDashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
});

document.getElementById('openSettings').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html#settings') });
});

loadStats();
loadAlerts();
setInterval(() => { loadStats(); loadAlerts(); }, 10000);
