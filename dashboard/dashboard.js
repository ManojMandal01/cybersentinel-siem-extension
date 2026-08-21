async function send(type, payload = {}) { return chrome.runtime.sendMessage({ type, ...payload }); }
const views = document.querySelectorAll('.view');
const navLinks = document.querySelectorAll('.nav-link');
const titles = { executive: 'Executive View', analyst: 'Analyst View', timeline: 'Threat Timeline', hunting: 'Threat Hunting', iocs: 'IOC Explorer', incidentgraph: 'Incident Graph', settings: 'Settings' };

function showView(name) { views.forEach((v) => v.classList.remove('active')); navLinks.forEach((l) => l.classList.remove('active')); document.getElementById(`view-${name}`)?.classList.add('active'); document.querySelector(`[data-view="${name}"]`)?.classList.add('active'); document.getElementById('viewTitle').textContent = titles[name] || name; }
navLinks.forEach((link) => link.addEventListener('click', (e) => { if (!link.dataset.view) return; e.preventDefault(); showView(link.dataset.view); }));
if (location.hash) { const view = location.hash.replace('#', ''); if (titles[view]) showView(view); }

function createRiskBadge(level) { const span = document.createElement('span'); span.className = `badge ${(level || 'low').toLowerCase()}`; span.textContent = level || '-'; return span; }
function renderTable(container, headers, rows) { container.textContent = ''; if (!rows.length) { const p = document.createElement('p'); p.style.color = '#8b949e'; p.style.padding = '12px'; p.textContent = 'No data'; container.appendChild(p); return; } const table = document.createElement('table'); const thead = document.createElement('thead'); const trHead = document.createElement('tr'); headers.forEach((h) => { const th = document.createElement('th'); th.textContent = h; trHead.appendChild(th); }); thead.appendChild(trHead); table.appendChild(thead); const tbody = document.createElement('tbody'); rows.forEach((r) => { const tr = document.createElement('tr'); r.forEach((c) => { const td = document.createElement('td'); if (c instanceof HTMLElement) td.appendChild(c); else td.textContent = c == null ? '' : String(c); tr.appendChild(td); }); tbody.appendChild(tr); }); table.appendChild(tbody); container.appendChild(table); }

async function refreshExecutive() { const stats = await send('GET_STATS'); if (stats?.error) return; document.getElementById('exThreats').textContent = stats.threatsToday; document.getElementById('exCritical').textContent = stats.criticalAlerts; document.getElementById('exDomains').textContent = stats.blockedDomains; document.getElementById('exDownloads').textContent = stats.maliciousDownloads; }
async function refreshMitreHeatmap() { const cells = await send('GET_MITRE_HEATMAP', { limit: 500 }); const container = document.getElementById('mitreHeatmap'); if (!container) return; container.innerHTML = Array.isArray(cells) ? renderHeatmapMarkup(cells) : ''; }
function renderHeatmapMarkup(cells) {
  const levelColors = ['#12161d', '#2b2210', '#4a3712', '#7a4d10', '#ff4d4f'];
  return `<div class="heatmap-grid">${cells.map((c) => `<div class="heatmap-cell" style="background:${levelColors[c.level]};border-color:#232a34" title="${c.count} hit(s)${c.peakRisk ? ' · peak risk ' + c.peakRisk : ''}"><strong>${c.technique}</strong><span>${c.name}</span><em>${c.tactic}</em><b>${c.count} hit${c.count === 1 ? '' : 's'}</b></div>`).join('')}</div>`;
}
async function refreshIncidentGraph() { const graph = await send('GET_INCIDENT_GRAPH', { limit: 500 }); const container = document.getElementById('incidentGraph'); if (!container) return; if (!graph || !graph.nodes || !graph.nodes.length) { container.innerHTML = '<p style="color:#8b949e;padding:12px">No correlated incidents yet</p>'; return; } container.innerHTML = renderIncidentGraphMarkup(graph); }
function riskColor(score) { if (score >= 76) return '#ff4d4f'; if (score >= 51) return '#f2a93b'; if (score >= 26) return '#4fa3ff'; return '#35c48c'; }
function renderIncidentGraphMarkup(graph) {
  const { nodes, edges } = graph;
  const size = Math.max(420, 90 * nodes.length);
  const cx = size / 2, cy = size / 2, ringRadius = size / 2 - 70;
  const positions = new Map();
  nodes.forEach((node, i) => { const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2; positions.set(node.id, { x: cx + ringRadius * Math.cos(angle), y: cy + ringRadius * Math.sin(angle) }); });
  const lines = edges.map((edge) => { const a = positions.get(edge.source); const b = positions.get(edge.target); if (!a || !b) return ''; return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#232a34" stroke-width="1.5"><title>${edge.shared.join(', ')}</title></line>`; }).join('');
  const circles = nodes.map((node) => { const p = positions.get(node.id); const r = 14 + Math.min(20, node.events * 2); return `<g><circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${riskColor(node.maxRisk)}" fill-opacity="0.85" stroke="#0a0d12" stroke-width="2"><title>${node.id}\n${node.primaryDomain}\n${node.events} events, peak risk ${node.maxRisk}</title></circle><text x="${p.x}" y="${p.y + r + 14}" fill="#e7ecf3" font-size="10" text-anchor="middle">${node.primaryDomain}</text></g>`; }).join('');
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">${lines}${circles}</svg>`;
}
async function refreshAnalyst() { await refreshMitreHeatmap(); const events = await send('GET_EVENTS', { limit: 100 }); const mitreRows = events.filter((e) => e.technique).slice(0, 20).map((e) => [e.event || '-', createRiskBadge(e.risk_level), e.technique, e.incident_id || '-']); renderTable(document.getElementById('mitreTable'), ['Detection', 'Risk', 'Technique', 'Incident'], mitreRows); const feedRows = events.filter((e) => e.threat_intel_hit).slice(0, 15).map((e) => [e.domain || '-', e.threat_feed || '-', e.url?.slice(0, 50) || '-', e.incident_id || '-']); renderTable(document.getElementById('feedHits'), ['Domain', 'Feed', 'URL', 'Incident'], feedRows); const activityRows = events.slice(0, 25).map((e) => [new Date(e.timestamp).toLocaleTimeString(), e.event || '-', e.domain || '-', String(e.risk_score ?? '-'), e.incident_id || '-']); renderTable(document.getElementById('userActivity'), ['Time', 'Event', 'Domain', 'Risk', 'Incident'], activityRows); }
async function refreshIncidents() { const alerts = await send('GET_ALERTS', { limit: 25 }); const rows = alerts.map((a) => { const select = document.createElement('select'); ['new', 'triaged', 'investigating', 'confirmed', 'resolved'].forEach((state) => { const option = document.createElement('option'); option.value = state; option.textContent = state; option.selected = a.triageState === state; select.appendChild(option); }); select.addEventListener('change', async () => { await send('UPDATE_ALERT', { id: a.id, patch: { triageState: select.value } }); }); return [a.title || 'Security Alert', createRiskBadge(a.risk_level), a.domain || '-', a.incident_id || '-', select]; }); renderTable(document.getElementById('incidentQueue'), ['Alert', 'Risk', 'Domain', 'Incident', 'Triage'], rows); }
async function refreshTimeline() { const events = await send('GET_EVENTS', { limit: 30 }); const container = document.getElementById('timeline'); container.textContent = ''; if (!events.length) { const p = document.createElement('p'); p.style.color = '#8b949e'; p.textContent = 'No events recorded yet'; container.appendChild(p); return; } events.forEach((e) => { const item = document.createElement('div'); item.className = 'timeline-item'; const time = document.createElement('div'); time.className = 'timeline-time'; time.textContent = new Date(e.timestamp).toLocaleTimeString(); item.appendChild(time); const strong = document.createElement('strong'); strong.textContent = e.event || 'event'; item.appendChild(strong); if (e.domain) item.appendChild(document.createTextNode(` - ${e.domain}`)); if (e.incident_id) { const incident = document.createElement('span'); incident.className = 'incident-tag'; incident.textContent = e.incident_id; item.appendChild(incident); } if (e.risk_score) { const badge = createRiskBadge(e.risk_level); badge.textContent = String(e.risk_score); item.appendChild(badge); } container.appendChild(item); }); }
async function refreshIocs() {
  const filter = { limit: 200, search: document.getElementById('iocSearch')?.value.trim() || '', type: document.getElementById('iocTypeFilter')?.value || '', reputation: document.getElementById('iocReputationFilter')?.value || '' };
  const iocs = await send('GET_IOC_EXPLORER', { filter });
  const rows = (Array.isArray(iocs) ? iocs : []).map((i) => { const rep = document.createElement('span'); rep.className = `badge ${i.reputation === 'malicious' ? 'critical' : 'low'}`; rep.textContent = i.reputation; return [i.ioc_type, i.value, i.context || '-', rep, new Date(i.createdAt).toLocaleString()]; });
  renderTable(document.getElementById('iocTable'), ['Type', 'Value', 'Context', 'Reputation', 'Created'], rows);
}
function initIocExplorer() { let debounce; const trigger = () => { clearTimeout(debounce); debounce = setTimeout(refreshIocs, 200); }; document.getElementById('iocSearch')?.addEventListener('input', trigger); document.getElementById('iocTypeFilter')?.addEventListener('change', refreshIocs); document.getElementById('iocReputationFilter')?.addEventListener('change', refreshIocs); }
async function refreshFeedHealth() { const feeds = await send('GET_FEED_STATUS'); const rows = (feeds || []).map((feed) => [feed.name, feed.enabled ? 'Enabled' : 'Disabled', feed.reason || (feed.enabled ? 'Active' : 'Not configured')]); renderTable(document.getElementById('feedHealth'), ['Provider', 'State', 'Status'], rows); }
async function exportStix() { const bundle = await send('EXPORT_STIX'); if (!bundle || bundle.error) { alert(bundle?.error || 'STIX export failed'); return; } const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `cybersentinel-iocs-${new Date().toISOString().replace(/[:.]/g, '-')}.stix.json`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
document.getElementById('exportStixBtn')?.addEventListener('click', exportStix);

async function initHunting() { const queries = await send('GET_HUNT_QUERIES'); document.getElementById('huntHints').textContent = `Available: ${queries.join(' | ')}`; document.getElementById('dashHuntBtn').addEventListener('click', async () => { const query = document.getElementById('dashHuntInput').value.trim(); if (!query) return; const result = await send('HUNT_QUERY', { query }); const rows = (result.results || []).slice(0, 30).map((r) => [r.title || r.event || r.domain || '-', r.domain || r.value || '-', String(r.risk_score ?? r.risk_level ?? '-'), r.incident_id || '-']); renderTable(document.getElementById('dashHuntResults'), ['Item', 'Domain/Value', 'Risk', 'Incident'], result.error ? [] : rows); if (result.error) { const p = document.createElement('p'); p.style.color = '#f85149'; p.textContent = result.error; const div = document.getElementById('dashHuntResults'); div.textContent = ''; div.appendChild(p); } }); }

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
  document.getElementById('aiEnabled').checked = config.ai?.enabled || false;
  document.getElementById('aiEndpoint').value = config.ai?.endpoint || '';
  document.getElementById('aiApiKey').value = config.ai?.apiKey || '';
  document.getElementById('settingsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const result = await send('SET_CONFIG', { config: {
      splunk: { enabled: document.getElementById('splunkEnabled').checked, hecUrl: document.getElementById('splunkUrl').value, hecToken: document.getElementById('splunkToken').value, index: document.getElementById('splunkIndex').value, sourcetype: 'cybersentinel:browser' },
      alerts: { browserPopup: document.getElementById('browserPopup').checked, discordWebhook: document.getElementById('discordWebhook').value },
      detection: { phishingEnabled: document.getElementById('phishingEnabled').checked, scriptAnalysisEnabled: document.getElementById('scriptAnalysis').checked, formMonitoringEnabled: document.getElementById('formMonitoring').checked, threatIntelEnabled: document.getElementById('threatIntel').checked, monitoringScope: document.getElementById('monitoringScope').value, allowlistDomains: document.getElementById('allowlistDomains').value.split(',').map((d) => d.trim()).filter(Boolean), blocklistDomains: document.getElementById('blocklistDomains').value.split(',').map((d) => d.trim()).filter(Boolean) },
      ai: { enabled: document.getElementById('aiEnabled').checked, endpoint: document.getElementById('aiEndpoint').value, apiKey: document.getElementById('aiApiKey').value }
    }});
    if (result?.ok) alert('Configuration saved'); else alert(`Configuration rejected: ${(result?.errors || ['unknown error']).join('; ')}`);
  });
}

function showDetectionDetailsModal(e) { const modal = document.getElementById('detailsModal'); const codeEl = document.getElementById('modalJson'); codeEl.textContent = JSON.stringify({ event_id: e.id || e.event_id, incident_id: e.incident_id || null, url: e.url || '', risk_score: e.risk_score ?? 0, mitre: e.technique || null, timestamp: e.timestamp || e.storedAt, evidence: e.evidence || [], correlation: e.correlation || null }, null, 2); modal.classList.add('active'); }
document.getElementById('modalClose')?.addEventListener('click', () => document.getElementById('detailsModal')?.classList.remove('active')); window.addEventListener('click', (event) => { const modal = document.getElementById('detailsModal'); if (event.target === modal) modal.classList.remove('active'); });
async function refresh() { await refreshExecutive(); await refreshAnalyst(); await refreshIncidents(); await refreshTimeline(); await refreshIocs(); await refreshIncidentGraph(); await refreshFeedHealth(); }
initHunting(); initSettings(); initIocExplorer(); refresh(); setInterval(refresh, 15000);