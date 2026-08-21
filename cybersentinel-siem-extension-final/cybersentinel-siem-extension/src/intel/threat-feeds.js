import { THREAT_FEEDS } from '../shared/constants.js';
import { extractDomain, isLegitimateDomain, normalizeDomain } from '../shared/utils.js';
import { getThreatCache, setThreatCache } from '../shared/storage.js';

const CACHE_TTL_MS = 60 * 60 * 1000;
const FEED_BACKOFF_MS = 15 * 60 * 1000;
const FEED_TIMEOUT_MS = 8000;
const MAX_FEED_BYTES = 4 * 1024 * 1024;
const MAX_FEED_ITEMS = 15000;
const MAX_CACHE_URLS = 30000;
const MAX_CACHE_DOMAINS = 15000;
const MAX_CACHE_IPS = 5000;
let refreshPromise = null;

function normalizeCache(cache) {
  return {
    urls: cache?.urls && typeof cache.urls === 'object' ? cache.urls : {},
    domains: cache?.domains && typeof cache.domains === 'object' ? cache.domains : {},
    ips: cache?.ips && typeof cache.ips === 'object' ? cache.ips : {},
    feeds: cache?.feeds && typeof cache.feeds === 'object' ? cache.feeds : {},
    lastUpdated: cache?.lastUpdated || null
  };
}

function feedTimestamp(feed) {
  const value = feed?.lastUpdated || feed?.checkedAt;
  const timestamp = value ? new Date(value).getTime() : 0;
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function isFeedFresh(cache, feedName, now) {
  const feed = cache.feeds[feedName];
  return feed?.ok === true && now - feedTimestamp(feed) < CACHE_TTL_MS;
}

function shouldSkipFeed(cache, feedName, now) {
  const feed = cache.feeds[feedName];
  return Boolean(feed?.lastErrorAt && now - new Date(feed.lastErrorAt).getTime() < FEED_BACKOFF_MS);
}

function recordFeedStatus(cache, feedName, status) {
  cache.feeds[feedName] = {
    ...(cache.feeds[feedName] || {}),
    ...status,
    checkedAt: new Date().toISOString()
  };
}

function updateCacheTimestamp(cache) {
  const successfulTimes = Object.values(cache.feeds)
    .filter((feed) => feed?.ok === true && feed.lastUpdated)
    .map(feedTimestamp)
    .filter(Boolean);
  if (successfulTimes.length) cache.lastUpdated = new Date(Math.max(...successfulTimes)).toISOString();
}

const APPROVED_FEED_ENDPOINTS = new Set(
  Object.values(THREAT_FEEDS).map((feed) => feed?.url).filter(Boolean)
);

function isApprovedFeedEndpoint(url) {
  try {
    const candidate = new URL(url);
    return [...APPROVED_FEED_ENDPOINTS].some((approved) => {
      const target = new URL(approved);
      return candidate.protocol === target.protocol
        && candidate.hostname === target.hostname
        && candidate.port === target.port
        && candidate.pathname === target.pathname
        && candidate.search === target.search;
    });
  } catch {
    return false;
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = FEED_TIMEOUT_MS) {
  if (!isApprovedFeedEndpoint(url)) throw new Error(`blocked non-approved threat-feed endpoint: ${url}`);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // Some approved feeds legitimately redirect to their canonical download endpoint.
    // Follow redirects, then verify the final URL remains the exact approved endpoint.
    const response = await fetch(url, { ...options, redirect: 'follow', signal: controller.signal });
    if (!isApprovedFeedEndpoint(response.url)) {
      throw new Error(`blocked threat-feed redirect: ${response.url}`);
    }
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function readTextLimited(response, maxBytes = MAX_FEED_BYTES) {
  if (!response.body?.getReader) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) throw new Error('feed response exceeds size limit');
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error('feed response exceeds size limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock?.();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function addThreatUrl(cache, url, source) {
  if (!url || !/^https?:\/\//i.test(url) || Object.keys(cache.urls).length >= MAX_CACHE_URLS) return false;
  cache.urls[url] = { source, malicious: true };
  const domain = extractDomain(url);
  if (domain && !isLegitimateDomain(domain) && Object.keys(cache.domains).length < MAX_CACHE_DOMAINS) {
    cache.domains[domain] = { source, malicious: true };
  }
  return true;
}

export function refreshThreatFeeds() {
  if (refreshPromise) return refreshPromise;
  refreshPromise = refreshThreatFeedsInternal().finally(() => { refreshPromise = null; });
  return refreshPromise;
}

async function refreshThreatFeedsInternal() {
  const cache = normalizeCache(await getThreatCache());
  const now = Date.now();
  const fetchers = [
    ['OpenPhish', THREAT_FEEDS.OPENPHISH, fetchOpenPhish],
    ['PhishTank', THREAT_FEEDS.PHISHTANK, fetchPhishTank],
    ['URLhaus', THREAT_FEEDS.URLHAUS, fetchUrlhaus]
  ];

  for (const [feedName, feedConfig, fetcher] of fetchers) {
    if (!feedConfig || feedConfig.enabled === false) {
      recordFeedStatus(cache, feedName, {
        ok: false,
        disabled: true,
        reason: feedConfig?.reason || 'disabled',
        lastError: null,
        lastErrorAt: null
      });
      continue;
    }
    if (isFeedFresh(cache, feedName, now) || shouldSkipFeed(cache, feedName, now)) continue;
    try {
      const urls = (await fetcher()).slice(0, MAX_FEED_ITEMS);
      let added = 0;
      for (const url of urls) if (addThreatUrl(cache, url, feedName)) added++;
      recordFeedStatus(cache, feedName, {
        ok: true,
        disabled: false,
        itemCount: added,
        lastUpdated: new Date().toISOString(),
        lastError: null,
        lastErrorAt: null
      });
    } catch (err) {
      recordFeedStatus(cache, feedName, {
        ok: false,
        disabled: false,
        lastError: err.message || String(err),
        lastErrorAt: new Date().toISOString()
      });
      console.warn(`[CyberSentinel] ${feedName} refresh failed:`, err?.name === 'AbortError' ? 'timeout' : err?.message || err);
    }
  }

  updateCacheTimestamp(cache);
  await setThreatCache(cache);
  return cache;
}

async function fetchOpenPhish() {
  const response = await fetchWithTimeout(
    THREAT_FEEDS.OPENPHISH.url,
    { headers: { 'User-Agent': 'CyberSentinel-SIEM/0.2' } }
  );
  if (!response.ok) throw new Error(`OpenPhish HTTP ${response.status}`);
  return (await readTextLimited(response)).split('\n').map((line) => line.trim()).filter((line) => /^https?:\/\//i.test(line));
}

async function fetchPhishTank() {
  const response = await fetchWithTimeout(
    THREAT_FEEDS.PHISHTANK.url,
    { headers: { 'User-Agent': THREAT_FEEDS.PHISHTANK.userAgent || 'CyberSentinel-SIEM/0.2' } }
  );
  if (!response.ok) throw new Error(`PhishTank HTTP ${response.status}`);
  const data = JSON.parse(await readTextLimited(response));
  return Array.isArray(data)
    ? data.map((entry) => entry?.url || entry?.phish_detail_url).filter((url) => typeof url === 'string' && /^https?:\/\//i.test(url))
    : [];
}

async function fetchUrlhaus() {
  const response = await fetchWithTimeout(
    THREAT_FEEDS.URLHAUS.url,
    { headers: { 'User-Agent': 'CyberSentinel-SIEM/0.2' } }
  );
  if (!response.ok) throw new Error(`URLhaus HTTP ${response.status}`);
  return (await readTextLimited(response))
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => parseCsvLine(line)[2]?.replace(/^\"|\"$/g, ''))
    .filter((url) => typeof url === 'string' && /^https?:\/\//i.test(url));
}

function isSafeTextResource(url) {
  try {
    const parsed = new URL(url);
    if (!['github.com', 'raw.githubusercontent.com', 'gitlab.com'].includes(parsed.hostname)) return true;
    const path = parsed.pathname.toLowerCase();
    if (path.includes('/releases/download/') || path.includes('/archive/') || /\.(zip|tar|gz|tgz|7z|rar|exe|msi|dmg|iso|deb|rpm|bin)(?:$|\?)/i.test(path)) return false;
    return /\.(txt|csv|json|list|ioc|log)(?:$|\?)/i.test(path) || parsed.hostname === 'raw.githubusercontent.com';
  } catch {
    return false;
  }
}

export function getRawUrl(url) {
  if (!isSafeTextResource(url)) return null;
  try {
    const parsed = new URL(url);
    if (parsed.hostname === 'github.com') {
      const parts = parsed.pathname.split('/').filter(Boolean);
      if (parts.length >= 5 && (parts[2] === 'blob' || parts[2] === 'raw')) return `https://raw.githubusercontent.com/${parts[0]}/${parts[1]}/${parts[3]}/${parts.slice(4).join('/')}`;
    }
    if (parsed.hostname === 'gitlab.com') {
      const parts = parsed.pathname.split('/').filter(Boolean);
      const blobIdx = parts.indexOf('blob');
      if (blobIdx !== -1 && parts[blobIdx - 1] === '-') {
        parts[blobIdx] = 'raw';
        return `https://gitlab.com/${parts.join('/')}`;
      }
    }
    return isSafeTextResource(url) ? url : null;
  } catch {
    return null;
  }
}

export function extractUrlsAndDomains(text) {
  const results = [];
  for (let line of String(text || '').split('\n')) {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    line = line.split(/\s+#/)[0].trim();
    const hostsMatch = line.match(/^(?:127\.0\.0\.1|0\.0\.0\.0)\s+(\S+)/);
    if (hostsMatch) {
      const domain = hostsMatch[1].trim();
      if (domain && domain !== 'localhost') results.push(`https://${domain}`);
      continue;
    }
    if (/^https?:\/\//i.test(line)) {
      results.push(line);
      continue;
    }
    if (/^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,24}(?:\/.*)?$/.test(line)) results.push(`https://${line}`);
  }
  return results.slice(0, MAX_FEED_ITEMS);
}

function parseCsvLine(line) {
  const columns = [];
  let current = '';
  let quoted = false;
  for (const char of line) {
    if (char === '"') quoted = !quoted;
    else if (char === ',' && !quoted) { columns.push(current); current = ''; }
    else current += char;
  }
  columns.push(current);
  return columns.map((value) => value.trim());
}

export async function checkReputation(url) {
  const cache = await refreshThreatFeeds();
  const normalizedUrl = String(url || '');
  const domain = extractDomain(normalizedUrl);
  if (cache.urls[normalizedUrl]) return { malicious: true, source: cache.urls[normalizedUrl].source, type: 'url', entity: cache.urls[normalizedUrl].source };
  if (!isLegitimateDomain(domain) && cache.domains[domain]) return { malicious: true, source: cache.domains[domain].source, type: 'domain', entity: cache.domains[domain].source };
  return { malicious: false, source: null, type: null, entity: null };
}

export function getThreatFeedEntities() { return Object.values(THREAT_FEEDS).map((feed) => feed.name); }

export async function getThreatFeedStatus() {
  const cache = normalizeCache(await getThreatCache());
  return Object.values(THREAT_FEEDS).map((feed) => {
    const status = cache.feeds[feed.name] || {};
    return {
      name: feed.name,
      enabled: feed.enabled !== false,
      ok: status.ok ?? null,
      disabled: feed.enabled === false,
      reason: feed.reason || status.lastError || (status.ok ? 'healthy' : 'not_checked'),
      itemCount: status.itemCount || 0,
      checkedAt: status.checkedAt || null
    };
  });
}

export async function sanitizeThreatCache() {
  const cache = normalizeCache(await getThreatCache());
  let changed = false;
  for (const domain of Object.keys(cache.domains)) {
    const normalized = normalizeDomain(domain);
    if (normalized !== domain) {
      cache.domains[normalized] = cache.domains[domain];
      delete cache.domains[domain];
      changed = true;
    }
    if (isLegitimateDomain(normalized)) {
      delete cache.domains[domain];
      delete cache.domains[normalized];
      changed = true;
    }
  }
  if (Object.keys(cache.urls).length > MAX_CACHE_URLS) {
    cache.urls = Object.fromEntries(Object.entries(cache.urls).slice(-MAX_CACHE_URLS));
    changed = true;
  }
  if (Object.keys(cache.domains).length > MAX_CACHE_DOMAINS) {
    cache.domains = Object.fromEntries(Object.entries(cache.domains).slice(-MAX_CACHE_DOMAINS));
    changed = true;
  }
  if (Object.keys(cache.ips).length > MAX_CACHE_IPS) {
    cache.ips = Object.fromEntries(Object.entries(cache.ips).slice(-MAX_CACHE_IPS));
    changed = true;
  }
  if (changed) await setThreatCache(cache);
  return cache;
}
