import { STORAGE_KEYS } from './constants.js';

const DB_NAME = 'cybersentinel_siem';
const DB_VERSION = 1;
const STORE_EVENTS = 'events';
const STORE_ALERTS = 'alerts';
const STORE_IOCS = 'iocs';
const MIGRATION_KEY = 'cybersentinel_indexeddb_migrated_v1';

const MAX_EVENTS = 5000;
const MAX_ALERTS = 500;
const MAX_IOCS = 1000;

let dbPromise = null;

function canUseIndexedDb() {
  return typeof indexedDB !== 'undefined';
}

function openDb() {
  if (!canUseIndexedDb()) return Promise.resolve(null);
  if (dbPromise) return dbPromise;

  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      for (const storeName of [STORE_EVENTS, STORE_ALERTS, STORE_IOCS]) {
        if (!db.objectStoreNames.contains(storeName)) {
          const store = db.createObjectStore(storeName, { keyPath: 'id' });
          store.createIndex('storedAt', 'storedAt');
          store.createIndex('createdAt', 'createdAt');
          store.createIndex('timestamp', 'timestamp');
          store.createIndex('event', 'event');
          store.createIndex('risk_level', 'risk_level');
        }
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  }).catch((err) => {
    dbPromise = null;
    console.warn('[CyberSentinel] IndexedDB unavailable, falling back to chrome.storage:', err);
    return null;
  });

  return dbPromise;
}

async function withStore(storeName, mode, callback) {
  const db = await openDb();
  if (!db) return null;

  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    const store = tx.objectStore(storeName);
    const result = callback(store);

    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

async function getAllFromStore(storeName) {
  const db = await openDb();
  if (!db) return null;

  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const request = tx.objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

async function putRecord(storeName, record) {
  await withStore(storeName, 'readwrite', (store) => {
    store.put(record);
  });
  return record;
}

async function deleteRecord(storeName, id) {
  await withStore(storeName, 'readwrite', (store) => {
    store.delete(id);
  });
}

function sortNewestFirst(records) {
  return [...records].sort((a, b) => {
    const left = new Date(a.storedAt || a.createdAt || a.timestamp || 0).getTime();
    const right = new Date(b.storedAt || b.createdAt || b.timestamp || 0).getTime();
    return right - left;
  });
}

async function trimStore(storeName, maxRecords) {
  const records = sortNewestFirst(await getAllFromStore(storeName));
  const overflow = records.slice(maxRecords);
  await Promise.all(overflow.map((record) => deleteRecord(storeName, record.id)));
}

async function migrateArray(storageKey, storeName, timestampField) {
  const result = await chrome.storage.local.get(storageKey);
  const records = result[storageKey] || [];
  for (const record of records) {
    await putRecord(storeName, {
      ...record,
      id: record.id || crypto.randomUUID(),
      [timestampField]: record[timestampField] || record.storedAt || record.createdAt || new Date().toISOString()
    });
  }
}

async function ensureMigrated() {
  if (!canUseIndexedDb()) return false;

  const result = await chrome.storage.local.get(MIGRATION_KEY);
  if (result[MIGRATION_KEY]) return true;

  const db = await openDb();
  if (!db) return false;

  await migrateArray(STORAGE_KEYS.EVENTS, STORE_EVENTS, 'storedAt');
  await migrateArray(STORAGE_KEYS.ALERTS, STORE_ALERTS, 'storedAt');
  await migrateArray(STORAGE_KEYS.IOCS, STORE_IOCS, 'createdAt');
  await chrome.storage.local.set({ [MIGRATION_KEY]: true });
  return true;
}

async function getLegacyArray(storageKey) {
  const result = await chrome.storage.local.get(storageKey);
  return result[storageKey] || [];
}

async function setLegacyArray(storageKey, records) {
  await chrome.storage.local.set({ [storageKey]: records });
}

export async function getConfig() {
  const result = await chrome.storage.local.get(STORAGE_KEYS.CONFIG);
  return result[STORAGE_KEYS.CONFIG] || null;
}

export async function setConfig(config) {
  await chrome.storage.local.set({ [STORAGE_KEYS.CONFIG]: config });
}

export async function appendEvent(event) {
  const stored = { ...event, id: crypto.randomUUID(), storedAt: new Date().toISOString() };

  if (await ensureMigrated()) {
    await putRecord(STORE_EVENTS, stored);
    await trimStore(STORE_EVENTS, MAX_EVENTS);
    return stored;
  }

  const events = await getEvents();
  events.unshift(stored);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  await setLegacyArray(STORAGE_KEYS.EVENTS, events);
  return stored;
}

export async function getEvents(filter = {}) {
  let events;
  if (await ensureMigrated()) {
    events = sortNewestFirst(await getAllFromStore(STORE_EVENTS));
  } else {
    events = await getLegacyArray(STORAGE_KEYS.EVENTS);
  }

  if (filter.eventType) {
    events = events.filter((e) => e.event === filter.eventType || e.event_type === filter.eventType);
  }
  if (filter.since) {
    events = events.filter((e) => new Date(e.timestamp || e.storedAt) >= new Date(filter.since));
  }
  if (filter.limit) {
    events = events.slice(0, filter.limit);
  }
  return events;
}

export async function appendAlert(alert) {
  const stored = {
    triageState: 'new',
    analystComment: '',
    ...alert,
    id: crypto.randomUUID(),
    storedAt: new Date().toISOString()
  };

  if (await ensureMigrated()) {
    await putRecord(STORE_ALERTS, stored);
    await trimStore(STORE_ALERTS, MAX_ALERTS);
    return stored;
  }

  const alerts = await getAlerts();
  alerts.unshift(stored);
  if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS;
  await setLegacyArray(STORAGE_KEYS.ALERTS, alerts);
  return stored;
}

export async function getAlerts(limit = 100) {
  let alerts;
  if (await ensureMigrated()) {
    alerts = sortNewestFirst(await getAllFromStore(STORE_ALERTS));
  } else {
    alerts = await getLegacyArray(STORAGE_KEYS.ALERTS);
  }
  return limit ? alerts.slice(0, limit) : alerts;
}

export async function appendIoc(ioc) {
  const iocs = await getIocs();
  const exists = iocs.some((i) => i.ioc_type === ioc.ioc_type && i.value === ioc.value);
  if (exists) return null;

  const stored = { ...ioc, id: crypto.randomUUID(), createdAt: new Date().toISOString() };

  if (await ensureMigrated()) {
    await putRecord(STORE_IOCS, stored);
    await trimStore(STORE_IOCS, MAX_IOCS);
    return stored;
  }

  iocs.unshift(stored);
  if (iocs.length > MAX_IOCS) iocs.length = MAX_IOCS;
  await setLegacyArray(STORAGE_KEYS.IOCS, iocs);
  return stored;
}

export async function getIocs(limit = 200) {
  let iocs;
  if (await ensureMigrated()) {
    iocs = sortNewestFirst(await getAllFromStore(STORE_IOCS));
  } else {
    iocs = await getLegacyArray(STORAGE_KEYS.IOCS);
  }
  return limit ? iocs.slice(0, limit) : iocs;
}

export async function getThreatCache() {
  const result = await chrome.storage.local.get(STORAGE_KEYS.THREAT_CACHE);
  return result[STORAGE_KEYS.THREAT_CACHE] || { urls: {}, domains: {}, ips: {}, feeds: {}, lastUpdated: null };
}

export async function setThreatCache(cache) {
  await chrome.storage.local.set({ [STORAGE_KEYS.THREAT_CACHE]: cache });
}

export async function getStats() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const events = await getEvents({ since: today.toISOString() });
  const alerts = await getAlerts();
  const todayAlerts = alerts.filter((a) => new Date(a.timestamp || a.storedAt) >= today);

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
