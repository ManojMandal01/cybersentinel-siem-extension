async function send(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

const views = document.querySelectorAll('.view');
const navLinks = document.querySelectorAll('.nav-link');
const titles = {
  executive: 'Executive View',
  analyst: 'Analyst View',
  timeline: 'Threat Timeline',
  hunting: 'Threat Hunting',
  iocs: 'IOC Table',
  settings: 'Settings'
};

function showView(name) {
  views.forEach((v) => v.classList.remove('active'));
  navLinks.forEach((l) => l.classList.remove('active'));
  document.getElementById(`view-${name}`)?.classList.add('active');
  document.querySelector(`[data-view="${name}"]`)?.classList.add('active');
  document.getElementById('viewTitle').textContent = titles[name] || name;
}

navLinks.forEach((link) => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    showView(link.dataset.view);
  });
});

if (location.hash) {
  const view = location.hash.replace('#', '');
  if (titles[view]) showView(view);
}

function renderTable(container, headers, rows) {
  if (!rows.length) {
    container.innerHTML = '<p style="color:#8b949e;padding:12px">No data</p>';
    return;
  }
  container.innerHTML = `
    <table>
      <thead><tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr></thead>
      <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>
  `;
}

async function refreshExecutive() {
  const stats = await send('GET_STATS');
  document.getElementById('exThreats').textContent = stats.threatsToday;
  document.getElementById('exCritical').textContent = stats.criticalAlerts;
  document.getElementById('exDomains').textContent = stats.blockedDomains;
  document.getElementById('exDownloads').textContent = stats.maliciousDownloads;
}

async function refreshAnalyst() {
  const events = await send('GET_EVENTS', { limit: 100 });
  const mitreRows = events
    .filter((e) => e.technique)
    .slice(0, 20)
    .map((e) => [
      e.event || '—',
      `<span class="badge ${(e.risk_level || 'low').toLowerCase()}">${e.risk_level || '—'}</span>`,
      e.technique
    ]);
  renderTable(document.getElementById('mitreTable'), ['Detection', 'Risk', 'Technique'], mitreRows);

  const feedRows = events
    .filter((e) => e.threat_intel_hit)
    .slice(0, 15)
    .map((e) => [e.domain || '—', e.threat_feed || '—', e.url?.slice(0, 50) || '—']);
  renderTable(document.getElementById('feedHits'), ['Domain', 'Feed', 'URL'], feedRows);

  const activityRows = events.slice(0, 25).map((e) => [
    new Date(e.timestamp).toLocaleTimeString(),
    e.event || '—',
    e.domain || '—',
    String(e.risk_score ?? '—')
  ]);
  renderTable(document.getElementById('userActivity'), ['Time', 'Event', 'Domain', 'Risk'], activityRows);
}

async function refreshTimeline() {
  const events = await send('GET_EVENTS', { limit: 30 });
  const container = document.getElementById('timeline');
  container.innerHTML = events.map((e) => `
    <div class="timeline-item">
      <div class="timeline-time">${new Date(e.timestamp).toLocaleTimeString()}</div>
      <strong>${e.event || 'event'}</strong>
      ${e.domain ? ` — ${e.domain}` : ''}
      ${e.risk_score ? ` <span class="badge ${(e.risk_level || '').toLowerCase()}">${e.risk_score}</span>` : ''}
    </div>
  `).join('') || '<p style="color:#8b949e">No events recorded yet</p>';
}

async function refreshIocs() {
  const iocs = await send('GET_IOCS', { limit: 50 });
  const rows = iocs.map((i) => [i.ioc_type, i.value, i.context || '—', new Date(i.createdAt).toLocaleString()]);
  renderTable(document.getElementById('iocTable'), ['Type', 'Value', 'Context', 'Created'], rows);
}

async function initHunting() {
  const queries = await send('GET_HUNT_QUERIES');
  document.getElementById('huntHints').textContent = `Available: ${queries.join(' | ')}`;

  document.getElementById('dashHuntBtn').addEventListener('click', async () => {
    const query = document.getElementById('dashHuntInput').value.trim();
    if (!query) return;
    const result = await send('HUNT_QUERY', { query });
    const rows = (result.results || []).slice(0, 30).map((r) => [
      r.title || r.event || r.domain || '—',
      r.domain || r.value || '—',
      String(r.risk_score ?? r.risk_level ?? '—')
    ]);
    renderTable(
      document.getElementById('dashHuntResults'),
      ['Item', 'Domain/Value', 'Risk'],
      result.error ? [] : rows
    );
    if (result.error) {
      document.getElementById('dashHuntResults').innerHTML = `<p style="color:#f85149">${result.error}</p>`;
    }
  });
}

async function initSettings() {
  const config = await send('GET_CONFIG');
  document.getElementById('splunkEnabled').checked = config.splunk?.enabled || false;
  document.getElementById('splunkUrl').value = config.splunk?.hecUrl || '';
  document.getElementById('splunkToken').value = config.splunk?.hecToken || '';
  document.getElementById('splunkIndex').value = config.splunk?.index || 'cybersentinel';
  document.getElementById('browserPopup').checked = config.alerts?.browserPopup !== false;
  document.getElementById('discordWebhook').value = config.alerts?.discordWebhook || '';
  document.getElementById('phishingEnabled').checked = config.detection?.phishingEnabled !== false;
  document.getElementById('scriptAnalysis').checked = config.detection?.scriptAnalysisEnabled !== false;
  document.getElementById('formMonitoring').checked = config.detection?.formMonitoringEnabled !== false;
  document.getElementById('threatIntel').checked = config.detection?.threatIntelEnabled !== false;

  document.getElementById('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    await send('SET_CONFIG', {
      config: {
        splunk: {
          enabled: document.getElementById('splunkEnabled').checked,
          hecUrl: document.getElementById('splunkUrl').value,
          hecToken: document.getElementById('splunkToken').value,
          index: document.getElementById('splunkIndex').value,
          sourcetype: 'cybersentinel:browser'
        },
        alerts: {
          browserPopup: document.getElementById('browserPopup').checked,
          discordWebhook: document.getElementById('discordWebhook').value
        },
        detection: {
          phishingEnabled: document.getElementById('phishingEnabled').checked,
          scriptAnalysisEnabled: document.getElementById('scriptAnalysis').checked,
          formMonitoringEnabled: document.getElementById('formMonitoring').checked,
          threatIntelEnabled: document.getElementById('threatIntel').checked
        }
      }
    });
    alert('Configuration saved');
  });
}

async function refresh() {
  await refreshExecutive();
  await refreshAnalyst();
  await refreshTimeline();
  await refreshIocs();
}

initHunting();
initSettings();
refresh();
setInterval(refresh, 15000);
