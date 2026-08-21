import { getEvents, getAlerts, getIocs } from '../shared/storage.js';

const QUERY_LIMIT = 1000;
const DEFAULT_RESULT_LIMIT = 100;
const QUERY_DEFINITIONS = {
  'phishing alerts': (events, alerts) => alerts.filter((a) => a.title?.toLowerCase().includes('phishing') || a.technique === 'T1566'),
  'malicious domains': (events) => [...new Map(events.filter((e) => e.risk_score >= 51 || e.threat_intel_hit).filter((e) => e.domain).map((e) => [e.domain, e])).values()],
  downloads: (events) => events.filter((e) => e.event === 'download'),
  'credential forms': (events) => events.filter((e) => e.event === 'credential_form_detected' || e.isCredentialForm),
  'suspicious scripts': (events) => events.filter((e) => e.event === 'suspicious_script' || e.hasObfuscation),
  'critical alerts': (_, alerts) => alerts.filter((a) => a.risk_level === 'Critical'),
  'threat feed hits': (events) => events.filter((e) => e.threat_intel_hit),
  incidents: (events, alerts) => [...new Map([...events, ...alerts].filter((r) => r.incident_id).map((r) => [r.incident_id, r])).values()],
  iocs: async () => getIocs(100)
};

function parseQuery(queryText) {
  const normalized = String(queryText || '').trim().replace(/\s+/g, ' ');
  const withoutShow = normalized.replace(/^show\s+/i, '').trim();
  const [basePart, ...filterParts] = withoutShow.split(/\s+where\s+/i);
  const filters = {};
  if (filterParts.length) {
    for (const clause of filterParts.join(' where ').split(/\s+and\s+/i)) {
      const match = clause.trim().match(/^([a-z_]+)\s*(=|>=|<=|>|<|:)\s*(.+)$/i);
      if (!match) return { error: `Invalid filter: ${clause.trim()}` };
      const [, key, operator, rawValue] = match;
      filters[key.toLowerCase()] = { operator, value: rawValue.trim().replace(/^['"]|['"]$/g, '') };
    }
  }
  return { base: basePart.trim().toLowerCase(), filters };
}

function parseTime(value) {
  const text = String(value).toLowerCase().trim();
  const relative = text.match(/^(\d+)(m|h|d)$/);
  if (relative) {
    const amount = Number(relative[1]);
    const multiplier = relative[2] === 'm' ? 60000 : relative[2] === 'h' ? 3600000 : 86400000;
    return Date.now() - amount * multiplier;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function matchesFilter(record, key, condition) {
  if (!record) return false;
  const { operator, value } = condition;
  if (key === 'risk_score') {
    const actual = Number(record[key]); const expected = Number(value);
    if (!Number.isFinite(actual) || !Number.isFinite(expected)) return false;
    if (operator === '>') return actual > expected;
    if (operator === '>=') return actual >= expected;
    if (operator === '<') return actual < expected;
    if (operator === '<=') return actual <= expected;
    return actual === expected;
  }
  if (key === 'timestamp_since' || key === 'timestamp_until') {
    const timestamp = new Date(record.timestamp || record.storedAt || record.createdAt || 0).getTime();
    const target = parseTime(value);
    if (!Number.isFinite(target) || !Number.isFinite(timestamp)) return false;
    return key === 'timestamp_since' ? timestamp >= target : timestamp <= target;
  }
  const actual = String(record[key] ?? '').toLowerCase(); const expected = String(value).toLowerCase();
  if (operator === ':') return actual.includes(expected);
  if (operator === '=') return actual === expected;
  return false;
}

function applyFilters(results, filters) {
  const aliases = { domain: 'domain', event: 'event', event_type: 'event_type', incident: 'incident_id', incident_id: 'incident_id', technique: 'technique', mitre: 'technique', risk: 'risk_score', risk_score: 'risk_score', state: 'triageState', level: 'risk_level', risk_level: 'risk_level', feed: 'threat_feed', source: 'source', since: 'timestamp_since', until: 'timestamp_until' };
  return results.filter((record) => Object.entries(filters).every(([key, condition]) => { const field = aliases[key]; return field ? matchesFilter(record, field, condition) : false; }));
}

export async function executeHuntQuery(queryText) {
  const parsed = parseQuery(queryText);
  if (parsed.error) return { query: queryText, results: [], count: 0, error: parsed.error };
  const events = await getEvents({ limit: QUERY_LIMIT }); const alerts = await getAlerts(200); const handler = QUERY_DEFINITIONS[parsed.base];
  if (!handler) return { query: queryText, results: [], count: 0, error: `Unknown query. Try: ${getAvailableQueries().join(', ')}` };
  const rawResults = await handler(events, alerts); const results = applyFilters(rawResults, parsed.filters).slice(0, DEFAULT_RESULT_LIMIT);
  return { query: queryText, results, count: results.length, filters: parsed.filters };
}

export function getAvailableQueries() {
  return [...Object.keys(QUERY_DEFINITIONS).map((q) => `show ${q}`), 'show phishing alerts where risk>=51', 'show incidents where incident_id:inc_', 'show malicious domains where domain:example.com', 'show critical alerts where state:investigating', 'show phishing alerts where risk>=51 and since:24h', 'show threat feed hits where feed:OpenPhish and since:7d'];
}
