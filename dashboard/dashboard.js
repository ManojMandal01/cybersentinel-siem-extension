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

function createRiskBadge(level) {
  const span = document.createElement('span');
  const normalized = (level || 'low').toLowerCase();
  span.className = `badge ${normalized}`;
  span.textContent = level || '-';
  return span;
}

function renderTable(container, headers, rows) {
  container.textContent = '';
  if (!rows.length) {
    const p = document.createElement('p');
    p.style.color = '#8b949e';
    p.style.padding = '12px';
    p.textContent = 'No data';
    container.appendChild(p);
    return;
  }
  
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const trHead = document.createElement('tr');
  for (const h of headers) {
    const th = document.createElement('th');
    th.textContent = h;
    trHead.appendChild(th);
  }
  thead.appendChild(trHead);
  table.appendChild(thead);
  
  const tbody = document.createElement('tbody');
  for (const r of rows) {
    const tr = document.createElement('tr');
    for (const c of r) {
      const td = document.createElement('td');
      if (c instanceof HTMLElement) {
        td.appendChild(c);
      } else {
        td.textContent = c === undefined || c === null ? '' : String(c);
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
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
      e.event || '-',
      createRiskBadge(e.risk_level),
      e.technique
    ]);
  renderTable(document.getElementById('mitreTable'), ['Detection', 'Risk', 'Technique'], mitreRows);

  const feedRows = events
    .filter((e) => e.threat_intel_hit)
    .slice(0, 15)
    .map((e) => [e.domain || '-', e.threat_feed || '-', e.url?.slice(0, 50) || '-']);
  renderTable(document.getElementById('feedHits'), ['Domain', 'Feed', 'URL'], feedRows);

  const activityRows = events.slice(0, 25).map((e) => [
    new Date(e.timestamp).toLocaleTimeString(),
    e.event || '-',
    e.domain || '-',
    String(e.risk_score ?? '-')
  ]);
  renderTable(document.getElementById('userActivity'), ['Time', 'Event', 'Domain', 'Risk'], activityRows);
}

async function refreshTimeline() {
  const events = await send('GET_EVENTS', { limit: 30 });
  const container = document.getElementById('timeline');
  container.textContent = '';
  
  if (!events.length) {
    const p = document.createElement('p');
    p.style.color = '#8b949e';
    p.textContent = 'No events recorded yet';
    container.appendChild(p);
    return;
  }
  
  for (const e of events) {
    const item = document.createElement('div');
    item.className = 'timeline-item';
    
    const time = document.createElement('div');
    time.className = 'timeline-time';
    time.textContent = new Date(e.timestamp).toLocaleTimeString();
    item.appendChild(time);
    
    const strong = document.createElement('strong');
    strong.textContent = e.event || 'event';
    item.appendChild(strong);
    
    if (e.domain) {
      const textNode = document.createTextNode(` - ${e.domain}`);
      item.appendChild(textNode);
    }
    
    if (e.risk_score) {
      const badge = createRiskBadge(e.risk_level);
      badge.textContent = String(e.risk_score);
      item.appendChild(badge);
    }
    
    container.appendChild(item);
  }
}

async function refreshIocs() {
  const iocs = await send('GET_IOCS', { limit: 50 });
  const rows = iocs.map((i) => [i.ioc_type, i.value, i.context || '-', new Date(i.createdAt).toLocaleString()]);
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
      r.title || r.event || r.domain || '-',
      r.domain || r.value || '-',
      String(r.risk_score ?? r.risk_level ?? '-')
    ]);
    renderTable(
      document.getElementById('dashHuntResults'),
      ['Item', 'Domain/Value', 'Risk'],
      result.error ? [] : rows
    );
    if (result.error) {
      const p = document.createElement('p');
      p.style.color = '#f85149';
      p.textContent = result.error;
      const resultsDiv = document.getElementById('dashHuntResults');
      resultsDiv.textContent = '';
      resultsDiv.appendChild(p);
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
  document.getElementById('monitoringScope').value = config.detection?.monitoringScope || 'all';
  document.getElementById('allowlistDomains').value = (config.detection?.allowlistDomains || []).join(', ');
  document.getElementById('blocklistDomains').value = (config.detection?.blocklistDomains || []).join(', ');

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
          threatIntelEnabled: document.getElementById('threatIntel').checked,
          monitoringScope: document.getElementById('monitoringScope').value,
          allowlistDomains: document.getElementById('allowlistDomains').value.split(',').map((d) => d.trim()).filter(Boolean),
          blocklistDomains: document.getElementById('blocklistDomains').value.split(',').map((d) => d.trim()).filter(Boolean)
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
