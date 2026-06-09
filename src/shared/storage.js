import { STORAGE_KEYS } from './constants.js';

const MAX_EVENTS = 5000;
const MAX_ALERTS = 500;
const MAX_IOCS = 1000;

export async function getConfig() {
  const result = await chrome.storage.local.get(STORAGE_KEYS.CONFIG);
  return result[STORAGE_KEYS.CONFIG] || null;
}

export async function setConfig(config) {
  await chrome.storage.local.set({ [STORAGE_KEYS.CONFIG]: config });
}

export async function appendEvent(event) {
  const events = await getEvents();
  events.unshift({ ...event, id: crypto.randomUUID(), storedAt: new Date().toISOString() });
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  await chrome.storage.local.set({ [STORAGE_KEYS.EVENTS]: events });
  return events[0];
}

export async function getEvents(filter = {}) {
  const result = await chrome.storage.local.get(STORAGE_KEYS.EVENTS);
  let events = result[STORAGE_KEYS.EVENTS] || [];

  if (filter.eventType) {
    events = events.filter((e) => e.event === filter.eventType || e.event_type === filter.eventType);
  }
  if (filter.since) {
    events = events.filter((e) => new Date(e.timestamp) >= new Date(filter.since));
  }
  if (filter.limit) {
    events = events.slice(0, filter.limit);
  }
  return events;
}

export async function appendAlert(alert) {
  const alerts = await getAlerts();
  alerts.unshift({ ...alert, id: crypto.randomUUID(), storedAt: new Date().toISOString() });
  if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS;
  await chrome.storage.local.set({ [STORAGE_KEYS.ALERTS]: alerts });
  return alerts[0];
}

export async function getAlerts(limit = 100) {
  const result = await chrome.storage.local.get(STORAGE_KEYS.ALERTS);
  const alerts = result[STORAGE_KEYS.ALERTS] || [];
  return limit ? alerts.slice(0, limit) : alerts;
}

export async function appendIoc(ioc) {
  const iocs = await getIocs();
  const exists = iocs.some((i) => i.ioc_type === ioc.ioc_type && i.value === ioc.value);
  if (exists) return null;
  iocs.unshift({ ...ioc, id: crypto.randomUUID(), createdAt: new Date().toISOString() });
  if (iocs.length > MAX_IOCS) iocs.length = MAX_IOCS;
  await chrome.storage.local.set({ [STORAGE_KEYS.IOCS]: iocs });
  return iocs[0];
}

export async function getIocs(limit = 200) {
  const result = await chrome.storage.local.get(STORAGE_KEYS.IOCS);
  const iocs = result[STORAGE_KEYS.IOCS] || [];
  return limit ? iocs.slice(0, limit) : iocs;
}

export async function getThreatCache() {
  const result = await chrome.storage.local.get(STORAGE_KEYS.THREAT_CACHE);
  return result[STORAGE_KEYS.THREAT_CACHE] || { urls: {}, domains: {}, ips: {}, lastUpdated: null };
}

export async function setThreatCache(cache) {
  await chrome.storage.local.set({ [STORAGE_KEYS.THREAT_CACHE]: cache });
}

export async function getStats() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const events = await getEvents({ since: today.toISOString() });
  const alerts = await getAlerts();
  const todayAlerts = alerts.filter((a) => new Date(a.timestamp) >= today);

  return {
    threatsToday: events.filter((e) => e.risk_score >= 51).length,
    criticalAlerts: todayAlerts.filter((a) => a.risk_level === 'Critical').length,
    blockedDomains: new Set(
      events.filter((e) => e.blocked).map((e) => e.domain)
    ).size,
    maliciousDownloads: events.filter((e) => e.event === 'download' && e.risk_score >= 51).length,
    totalEvents: events.length,
    totalAlerts: todayAlerts.length
  };
}
