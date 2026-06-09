import { getEvents, getAlerts, getIocs } from '../shared/storage.js';

const QUERIES = {
  'phishing alerts': (events, alerts) => alerts.filter((a) =>
    a.title?.toLowerCase().includes('phishing') || a.technique === 'T1566'
  ),
  'malicious domains': (events) => {
    const domains = events.filter((e) => e.risk_score >= 51 || e.threat_intel_hit);
    return [...new Map(domains.map((e) => [e.domain, e])).values()];
  },
  downloads: (events) => events.filter((e) => e.event === 'download'),
  'credential forms': (events) => events.filter((e) =>
    e.event === 'credential_form_detected' || e.isCredentialForm
  ),
  'suspicious scripts': (events) => events.filter((e) =>
    e.event === 'suspicious_script' || e.hasObfuscation
  ),
  'critical alerts': (_, alerts) => alerts.filter((a) => a.risk_level === 'Critical'),
  'threat feed hits': (events) => events.filter((e) => e.threat_intel_hit),
  iocs: async () => getIocs(100)
};

export async function executeHuntQuery(queryText) {
  const normalized = queryText.toLowerCase().replace(/^show\s+/, '').trim();
  const events = await getEvents({ limit: 1000 });
  const alerts = await getAlerts(200);

  if (normalized === 'iocs') {
    return { query: queryText, results: await QUERIES.iocs(), count: (await getIocs(100)).length };
  }

  const handler = QUERIES[normalized];
  if (!handler) {
    return {
      query: queryText,
      results: [],
      count: 0,
      error: `Unknown query. Try: ${Object.keys(QUERIES).join(', ')}`
    };
  }

  const results = handler(events, alerts);
  return { query: queryText, results, count: results.length };
}

export function getAvailableQueries() {
  return Object.keys(QUERIES).map((q) => `show ${q}`);
}
