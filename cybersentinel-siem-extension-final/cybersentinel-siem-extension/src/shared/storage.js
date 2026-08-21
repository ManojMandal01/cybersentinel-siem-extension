import { STORAGE_KEYS } from './constants.js';
import { normalizeSecurityEvent, sanitizeEventForStorage } from './event-schema.js';
import { getIndexedThreatCache, setIndexedThreatCache, clearIndexedThreatCache } from '../intel/threat-cache-store.js';

const DB_NAME = 'cybersentinel_siem';
const DB_VERSION = 1;
const STORE_EVENTS = 'events';
const STORE_ALERTS = 'alerts';
const STORE_IOCS = 'iocs';
const MIGRATION_KEY = 'cybersentinel_indexeddb_migrated_v1';
const THREAT_CACHE_MIGRATION_KEY = 'cybersentinel_threat_cache_migrated_v2';
const MAX_EVENTS = 5000;
const MAX_ALERTS = 500;
const MAX_IOCS = 1000;
const TRIAGE_STATES = new Set(['new', 'triaged', 'investigating', 'confirmed', 'resolved']);
let dbPromise = null;

function canUseIndexedDb() { return typeof indexedDB !== 'undefined'; }
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
          store.createIndex('storedAt', 'storedAt'); store.createIndex('createdAt', 'createdAt'); store.createIndex('timestamp', 'timestamp'); store.createIndex('event', 'event'); store.createIndex('risk_level', 'risk_level');
        }
      }
    };
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  }).catch((err) => { dbPromise = null; console.warn('[CyberSentinel] IndexedDB unavailable, falling back to chrome.storage:', err?.message || err); return null; });
  return dbPromise;
}
async function withStore(storeName, mode, callback) { const db = await openDb(); if (!db) return null; return new Promise((resolve, reject) => { const tx = db.transaction(storeName, mode); const result = callback(tx.objectStore(storeName)); tx.oncomplete = () => resolve(result); tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error); }); }
async function getAllFromStore(storeName) { const db = await openDb(); if (!db) return null; return new Promise((resolve, reject) => { const tx = db.transaction(storeName, 'readonly'); const request = tx.objectStore(storeName).getAll(); request.onsuccess = () => resolve(request.result || []); request.onerror = () => reject(request.error); }); }
async function getRecord(storeName, id) { const db = await openDb(); if (!db) return null; return new Promise((resolve, reject) => { const tx = db.transaction(storeName, 'readonly'); const request = tx.objectStore(storeName).get(id); request.onsuccess = () => resolve(request.result || null); request.onerror = () => reject(request.error); }); }
async function putRecord(storeName, record) { await withStore(storeName, 'readwrite', (store) => store.put(record)); return record; }
async function deleteRecord(storeName, id) { await withStore(storeName, 'readwrite', (store) => store.delete(id)); }
function sortNewestFirst(records) { return [...records].sort((a, b) => new Date(b.storedAt || b.createdAt || b.timestamp || 0) - new Date(a.storedAt || a.createdAt || a.timestamp || 0)); }
async function trimStore(storeName, maxRecords) { const records = sortNewestFirst(await getAllFromStore(storeName)); await Promise.all(records.slice(maxRecords).map((record) => deleteRecord(storeName, record.id))); }
async function migrateArray(storageKey, storeName, timestampField) { const result = await chrome.storage.local.get(storageKey); const records = Array.isArray(result[storageKey]) ? result[storageKey] : []; for (const record of records) await putRecord(storeName, { ...record, id: record.id || crypto.randomUUID(), [timestampField]: record[timestampField] || record.storedAt || record.createdAt || new Date().toISOString() }); }
async function ensureMigrated() { if (!canUseIndexedDb()) return false; const result = await chrome.storage.local.get(MIGRATION_KEY); if (result[MIGRATION_KEY]) return true; const db = await openDb(); if (!db) return false; await migrateArray(STORAGE_KEYS.EVENTS, STORE_EVENTS, 'storedAt'); await migrateArray(STORAGE_KEYS.ALERTS, STORE_ALERTS, 'storedAt'); await migrateArray(STORAGE_KEYS.IOCS, STORE_IOCS, 'createdAt'); await chrome.storage.local.set({ [MIGRATION_KEY]: true }); return true; }
async function getLegacyArray(storageKey) { const result = await chrome.storage.local.get(storageKey); return Array.isArray(result[storageKey]) ? result[storageKey] : []; }
async function setLegacyArray(storageKey, records) { await chrome.storage.local.set({ [storageKey]: records }); }

export async function getConfig() { const result = await chrome.storage.local.get(STORAGE_KEYS.CONFIG); return result[STORAGE_KEYS.CONFIG] || null; }
export async function setConfig(config) { await chrome.storage.local.set({ [STORAGE_KEYS.CONFIG]: config }); }
export async function appendEvent(event) { const normalized = normalizeSecurityEvent(event); const stored = { ...normalized, id: normalized.event_id, storedAt: new Date().toISOString() }; if (await ensureMigrated()) { await putRecord(STORE_EVENTS, stored); await trimStore(STORE_EVENTS, MAX_EVENTS); return stored; } const events = await getEvents(); events.unshift(stored); if (events.length > MAX_EVENTS) events.length = MAX_EVENTS; await setLegacyArray(STORAGE_KEYS.EVENTS, events); return stored; }
export async function getEvents(filter = {}) { let events = await ensureMigrated() ? sortNewestFirst(await getAllFromStore(STORE_EVENTS)) : await getLegacyArray(STORAGE_KEYS.EVENTS); if (filter.eventType) events = events.filter((e) => e.event === filter.eventType || e.event_type === filter.eventType); if (filter.since) events = events.filter((e) => new Date(e.timestamp || e.storedAt) >= new Date(filter.since)); if (filter.limit) events = events.slice(0, filter.limit); return events; }

export async function appendAlert(alert) {
  const safeAlert = sanitizeEventForStorage(alert);
  const stored = { triageState: 'new', analystComment: '', ...safeAlert, id: crypto.randomUUID(), storedAt: new Date().toISOString() };
  if (await ensureMigrated()) { await putRecord(STORE_ALERTS, stored); await trimStore(STORE_ALERTS, MAX_ALERTS); return stored; }
  const alerts = await getAlerts(); alerts.unshift(stored); if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS; await setLegacyArray(STORAGE_KEYS.ALERTS, alerts); return stored;
}
export async function updateAlert(id, patch = {}) { if (!id) return null; const safePatch = {}; if (typeof patch.triageState === 'string' && TRIAGE_STATES.has(patch.triageState)) safePatch.triageState = patch.triageState; if (typeof patch.analystComment === 'string') safePatch.analystComment = patch.analystComment.slice(0, 2000); if (!Object.keys(safePatch).length) return null; if (await ensureMigrated()) { const existing = await getRecord(STORE_ALERTS, id); if (!existing) return null; return putRecord(STORE_ALERTS, { ...existing, ...safePatch, updatedAt: new Date().toISOString() }); } const alerts = await getAlerts(0); const index = alerts.findIndex((alert) => alert.id === id); if (index === -1) return null; alerts[index] = { ...alerts[index], ...safePatch, updatedAt: new Date().toISOString() }; await setLegacyArray(STORAGE_KEYS.ALERTS, alerts); return alerts[index]; }
export async function getAlerts(limit = 100) { const alerts = await ensureMigrated() ? sortNewestFirst(await getAllFromStore(STORE_ALERTS)) : await getLegacyArray(STORAGE_KEYS.ALERTS); return limit ? alerts.slice(0, limit) : alerts; }
export async function appendIoc(ioc) { const iocs = await getIocs(); if (iocs.some((i) => i.ioc_type === ioc.ioc_type && i.value === ioc.value)) return null; const stored = { ...ioc, id: crypto.randomUUID(), createdAt: new Date().toISOString() }; if (await ensureMigrated()) { await putRecord(STORE_IOCS, stored); await trimStore(STORE_IOCS, MAX_IOCS); return stored; } iocs.unshift(stored); if (iocs.length > MAX_IOCS) iocs.length = MAX_IOCS; await setLegacyArray(STORAGE_KEYS.IOCS, iocs); return stored; }
export async function getIocs(limit = 200) { const iocs = await ensureMigrated() ? sortNewestFirst(await getAllFromStore(STORE_IOCS)) : await getLegacyArray(STORAGE_KEYS.IOCS); return limit ? iocs.slice(0, limit) : iocs; }

const EMPTY_THREAT_CACHE = Object.freeze({ urls: {}, domains: {}, ips: {}, feeds: {}, lastUpdated: null });
export async function getThreatCache() {
  try { const indexed = await getIndexedThreatCache(); if (indexed) return indexed; } catch (err) { console.warn('[CyberSentinel] Threat-cache read failed:', err?.message || err); }
  try {
    const marker = await chrome.storage.local.get(THREAT_CACHE_MIGRATION_KEY);
    if (!marker[THREAT_CACHE_MIGRATION_KEY]) {
      const legacy = await chrome.storage.local.get(STORAGE_KEYS.THREAT_CACHE); const cache = legacy[STORAGE_KEYS.THREAT_CACHE];
      if (cache && typeof cache === 'object') {
        try { await setIndexedThreatCache(cache); } catch (err) { console.warn('[CyberSentinel] Threat-cache migration failed:', err?.message || err); }
        try { await chrome.storage.local.remove(STORAGE_KEYS.THREAT_CACHE); } catch { /* best effort */ }
        try { await chrome.storage.local.set({ [THREAT_CACHE_MIGRATION_KEY]: true }); } catch { /* best effort */ }
        return cache;
      }
      try { await chrome.storage.local.set({ [THREAT_CACHE_MIGRATION_KEY]: true }); } catch { /* best effort */ }
    }
  } catch (err) { console.warn('[CyberSentinel] Legacy threat-cache migration skipped:', err?.message || err); }
  return { ...EMPTY_THREAT_CACHE, urls: {}, domains: {}, ips: {}, feeds: {} };
}
export async function setThreatCache(cache) { try { const stored = await setIndexedThreatCache(cache); if (!stored) console.warn('[CyberSentinel] Threat cache could not be persisted to IndexedDB'); return stored; } catch (err) { console.warn('[CyberSentinel] Threat-cache write failed:', err?.message || err); return false; } }
export async function clearThreatCache() { try { await clearIndexedThreatCache(); } catch (err) { console.warn('[CyberSentinel] Threat-cache clear failed:', err?.message || err); } try { await chrome.storage.local.remove(STORAGE_KEYS.THREAT_CACHE); } catch { /* best effort */ } }
export async function getStats() { const today = new Date(); today.setHours(0,0,0,0); const events = await getEvents({ since: today.toISOString() }); const alerts = await getAlerts(); const todayAlerts = alerts.filter((a) => new Date(a.timestamp || a.storedAt) >= today); return { threatsToday: events.filter((e) => e.risk_score >= 51).length, criticalAlerts: todayAlerts.filter((a) => a.risk_level === 'Critical').length, blockedDomains: new Set(events.filter((e) => e.blocked).map((e) => e.domain)).size, maliciousDownloads: events.filter((e) => e.event === 'download' && e.risk_score >= 51).length, totalEvents: events.length, totalAlerts: todayAlerts.length }; }
