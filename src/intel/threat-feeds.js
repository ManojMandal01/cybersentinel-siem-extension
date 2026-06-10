import { THREAT_FEEDS } from '../shared/constants.js';
import { extractDomain, isLegitimateDomain, normalizeDomain } from '../shared/utils.js';
import { getThreatCache, setThreatCache } from '../shared/storage.js';

const CACHE_TTL_MS = 60 * 60 * 1000;
const FEED_BACKOFF_MS = 15 * 60 * 1000;

function normalizeCache(cache) {
  return {
    urls: cache?.urls || {},
    domains: cache?.domains || {},
    ips: cache?.ips || {},
    feeds: cache?.feeds || {},
    lastUpdated: cache?.lastUpdated || null
  };
}

function shouldSkipFeed(cache, feedName, now) {
  const feed = cache.feeds[feedName];
  return feed?.lastErrorAt && now - new Date(feed.lastErrorAt).getTime() < FEED_BACKOFF_MS;
}

function recordFeedStatus(cache, feedName, status) {
  cache.feeds[feedName] = {
    ...(cache.feeds[feedName] || {}),
    ...status,
    checkedAt: new Date().toISOString()
  };
}

function addThreatUrl(cache, url, source) {
  if (!url || !url.startsWith('http')) return false;

  cache.urls[url] = { source, malicious: true };
  const domain = extractDomain(url);
  if (domain && !isLegitimateDomain(domain)) {
    cache.domains[domain] = { source, malicious: true };
  }
  return true;
}

export async function refreshThreatFeeds() {
  const cache = normalizeCache(await getThreatCache());
  const now = Date.now();

  if (cache.lastUpdated && now - new Date(cache.lastUpdated).getTime() < CACHE_TTL_MS) {
    return cache;
  }

  const fetchers = [
    ['OpenPhish', fetchOpenPhish],
    ['PhishTank', fetchPhishTank],
    ['URLhaus', fetchUrlhaus]
  ];

  for (const [feedName, fetcher] of fetchers) {
    if (shouldSkipFeed(cache, feedName, now)) continue;

    try {
      const urls = await fetcher();
      let added = 0;
      for (const url of urls) {
        if (addThreatUrl(cache, url, feedName)) added++;
      }
      recordFeedStatus(cache, feedName, {
        ok: true,
        itemCount: added,
        lastUpdated: new Date().toISOString(),
        lastError: null,
        lastErrorAt: null
      });
    } catch (err) {
      recordFeedStatus(cache, feedName, {
        ok: false,
        lastError: err.message || String(err),
        lastErrorAt: new Date().toISOString()
      });
      console.warn(`[CyberSentinel] ${feedName} refresh failed:`, err);
    }
  }

  cache.lastUpdated = new Date().toISOString();
  await setThreatCache(cache);
  return cache;
}

async function fetchOpenPhish() {
  const response = await fetch(THREAT_FEEDS.OPENPHISH.url);
  if (!response.ok) throw new Error(`OpenPhish HTTP ${response.status}`);
  const text = await response.text();
  return text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('http'));
}

async function fetchPhishTank() {
  const response = await fetch(THREAT_FEEDS.PHISHTANK.url);
  if (!response.ok) throw new Error(`PhishTank HTTP ${response.status}`);
  const data = await response.json();
  if (!Array.isArray(data)) return [];
  return data
    .map((entry) => entry.url || entry.phish_detail_url)
    .filter((url) => typeof url === 'string' && url.startsWith('http'));
}

async function fetchUrlhaus() {
  const response = await fetch(THREAT_FEEDS.URLHAUS.url);
  if (!response.ok) throw new Error(`URLhaus HTTP ${response.status}`);
  const text = await response.text();
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const columns = parseCsvLine(line);
      return columns[2]?.replace(/^"|"$/g, '');
    })
    .filter((url) => typeof url === 'string' && url.startsWith('http'));
}

function parseCsvLine(line) {
  const columns = [];
  let current = '';
  let quoted = false;

  for (const char of line) {
    if (char === '"') {
      quoted = !quoted;
    } else if (char === ',' && !quoted) {
      columns.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  columns.push(current);
  return columns.map((value) => value.trim());
}

export async function checkReputation(url) {
  const cache = await refreshThreatFeeds();
  const domain = extractDomain(url);

  if (cache.urls[url]) {
    return { malicious: true, source: cache.urls[url].source, type: 'url', entity: cache.urls[url].source };
  }
  if (!isLegitimateDomain(domain) && cache.domains[domain]) {
    return { malicious: true, source: cache.domains[domain].source, type: 'domain', entity: cache.domains[domain].source };
  }

  return { malicious: false, source: null, type: null, entity: null };
}

export function getThreatFeedEntities() {
  return Object.values(THREAT_FEEDS).map((f) => f.name);
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

  if (changed) await setThreatCache(cache);
  return cache;
}
