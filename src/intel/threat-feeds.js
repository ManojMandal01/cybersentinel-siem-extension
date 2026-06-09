import { THREAT_FEEDS } from '../shared/constants.js';
import { extractDomain } from '../shared/utils.js';
import { getThreatCache, setThreatCache } from '../shared/storage.js';

const CACHE_TTL_MS = 60 * 60 * 1000;

export async function refreshThreatFeeds() {
  const cache = await getThreatCache();
  const now = Date.now();

  if (cache.lastUpdated && now - new Date(cache.lastUpdated).getTime() < CACHE_TTL_MS) {
    return cache;
  }

  try {
    const openPhishUrls = await fetchOpenPhish();
    for (const url of openPhishUrls) {
      cache.urls[url] = { source: 'OpenPhish', malicious: true };
      cache.domains[extractDomain(url)] = { source: 'OpenPhish', malicious: true };
    }
    cache.lastUpdated = new Date().toISOString();
    await setThreatCache(cache);
  } catch (err) {
    console.warn('[CyberSentinel] Threat feed refresh failed:', err);
  }

  return cache;
}

async function fetchOpenPhish() {
  try {
    const response = await fetch(THREAT_FEEDS.OPENPHISH.url);
    const text = await response.text();
    return text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('http'));
  } catch {
    return [];
  }
}

export async function checkReputation(url) {
  const cache = await refreshThreatFeeds();
  const domain = extractDomain(url);

  if (cache.urls[url]) {
    return { malicious: true, source: cache.urls[url].source, type: 'url', entity: cache.urls[url].source };
  }
  if (cache.domains[domain]) {
    return { malicious: true, source: cache.domains[domain].source, type: 'domain', entity: cache.domains[domain].source };
  }

  return { malicious: false, source: null, type: null, entity: null };
}

export function getThreatFeedEntities() {
  return Object.values(THREAT_FEEDS).map((f) => f.name);
}
