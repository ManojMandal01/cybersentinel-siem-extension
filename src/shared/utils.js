import { LEGITIMATE_DOMAINS } from './constants.js';

const INTERNAL_URL_SCHEMES = /^(chrome|chrome-extension|edge|about|moz-extension|brave|devtools):/i;

export function now() {
  return new Date().toISOString();
}

export function isInternalBrowserUrl(url) {
  if (!url) return false;
  return INTERNAL_URL_SCHEMES.test(url);
}

export function isLegitimateDomain(domain) {
  const host = normalizeDomain(domain);
  if (!host) return false;
  const allLegit = Object.values(LEGITIMATE_DOMAINS).flat();
  return allLegit.some((d) => host === d || host.endsWith('.' + d));
}

export function normalizeDomain(value) {
  if (!value) return '';
  const input = String(value).trim().toLowerCase().replace(/\.$/, '');
  if (!input) return '';

  try {
    return new URL(input.includes('://') ? input : `https://${input}`).hostname
      .toLowerCase()
      .replace(/\.$/, '');
  } catch {
    return input
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .split(':')[0]
      .replace(/\.$/, '');
  }
}

export function domainMatches(candidate, rule) {
  const host = normalizeDomain(candidate);
  const normalizedRule = normalizeDomain(rule);
  if (!host || !normalizedRule) return false;
  return host === normalizedRule || host.endsWith('.' + normalizedRule);
}

export function extractDomain(url) {
  try {
    return normalizeDomain(new URL(url).hostname);
  } catch {
    return normalizeDomain(url);
  }
}

export function extractTld(domain) {
  const parts = domain.split('.');
  if (parts.length < 2) return '';
  return '.' + parts[parts.length - 1];
}

export function urlEntropy(url) {
  const str = url.replace(/^https?:\/\//, '');
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

export function levenshtein(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = a[j - 1] === b[i - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[b.length][a.length];
}

export function hasHomograph(domain) {
  const homographs = /[а-яА-Я\u0430-\u044f\u0410-\u042f\u03b1-\u03c9\u0391-\u03a9]/;
  const cyrillic = /[\u0400-\u04FF]/;
  const mixed = /[a-zA-Z]/.test(domain) && (homographs.test(domain) || cyrillic.test(domain));
  const confusables = /[0oO1lI]/.test(domain) && /paypa|g00gle|micr0soft|arnazon/i.test(domain);
  return mixed || confusables;
}

export function detectBrandInDomain(domain) {
  const normalized = domain.replace(/[^a-z0-9]/gi, '').toLowerCase();
  for (const brand of ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix', 'chase', 'coinbase', 'office365', 'outlook']) {
    if (normalized.includes(brand.replace(/[^a-z0-9]/gi, ''))) {
      return brand;
    }
  }
  return null;
}

export function isIpAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
}

export function getRiskLevel(score) {
  if (score >= 76) return 'Critical';
  if (score >= 51) return 'High';
  if (score >= 26) return 'Medium';
  return 'Low';
}

export function sanitizeForLog(obj) {
  return JSON.parse(JSON.stringify(obj));
}
