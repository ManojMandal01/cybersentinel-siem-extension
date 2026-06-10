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
  container.textContent = '';

  if (!alerts.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No alerts yet - monitoring active';
    container.appendChild(empty);
    return;
  }

  for (const alert of alerts) {
    const item = document.createElement('div');
    const level = String(alert.risk_level || 'low').toLowerCase();
    item.className = `alert-item ${['critical', 'high', 'medium', 'low'].includes(level) ? level : 'low'}`;

    const title = document.createElement('div');
    title.className = 'alert-title';
    title.textContent = alert.title || 'Security Alert';
    item.appendChild(title);

    const meta = document.createElement('div');
    meta.className = 'alert-meta';
    meta.textContent = `${alert.domain || ''} | Risk ${alert.risk_score ?? '-'} | ${alert.technique || '-'}`;
    item.appendChild(meta);

    container.appendChild(item);
  }
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
