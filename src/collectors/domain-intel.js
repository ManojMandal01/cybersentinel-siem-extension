import { SUSPICIOUS_TLDS } from '../shared/constants.js';
import { extractDomain, extractTld, hasHomograph, isIpAddress, isLegitimateDomain, now } from '../shared/utils.js';

const CACHE_TTL_MS = 10 * 60 * 1000;
const domainCache = new Map();

function getCached(domain) {
  const entry = domainCache.get(domain);
  if (!entry || Date.now() - entry.cachedAt > CACHE_TTL_MS) return null;
  return entry.value;
}

function setCached(domain, value) {
  domainCache.set(domain, { value, cachedAt: Date.now() });
  if (domainCache.size > 500) {
    const oldest = [...domainCache.entries()].sort((a, b) => a[1].cachedAt - b[1].cachedAt)[0]?.[0];
    if (oldest) domainCache.delete(oldest);
  }
}

export function analyzeDomain(url) {
  const domain = extractDomain(url);
  if (!domain) return null;

  const tld = extractTld(domain);
  const analysis = {
    domain,
    tld,
    ip: isIpAddress(domain) ? domain : null,
    isSuspiciousTld: SUSPICIOUS_TLDS.has(tld),
    isHomograph: hasHomograph(domain),
    isIpDirect: isIpAddress(domain),
    isPunycode: domain.includes('xn--'),
    subdomainCount: Math.max(0, domain.split('.').length - 2),
    domainLength: domain.length,
    hasHyphens: domain.includes('-'),
    timestamp: now()
  };

  analysis.flags = [];
  if (analysis.isSuspiciousTld) analysis.flags.push('suspicious_tld');
  if (analysis.isHomograph) analysis.flags.push('homograph_attack');
  if (analysis.isPunycode) analysis.flags.push('punycode_domain');
  if (analysis.isIpDirect) analysis.flags.push('ip_direct_access');
  if (analysis.subdomainCount > 3) analysis.flags.push('excessive_subdomains');
  if (analysis.hasHyphens && analysis.domainLength > 25) analysis.flags.push('long_hyphenated_domain');
  return analysis;
}

async function fetchJson(url, timeoutMs = 4000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal, headers: { Accept: 'application/dns-json, application/rdap+json, application/json' } });
    if (!response.ok) return null;
    return await response.json();
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function resolveDomainIp(domain) {
  if (isIpAddress(domain)) return domain;
  const cached = getCached(`dns:${domain}`);
  if (cached !== null) return cached;
  try {
    const data = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
    const record = data?.Answer?.find((a) => a.type === 1) || data?.Answer?.[0];
    const ip = record?.data?.replace(/\.$/, '') || null;
    setCached(`dns:${domain}`, ip);
    return ip;
  } catch {
    setCached(`dns:${domain}`, null);
    return null;
  }
}

async function lookupRdap(domain) {
  const cached = getCached(`rdap:${domain}`);
  if (cached !== null) return cached;
  try {
    const data = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    const registration = data?.events?.find((event) => event.eventAction === 'registration');
    const expiration = data?.events?.find((event) => event.eventAction === 'expiration');
    const result = {
      registrar: data?.entities?.find((entity) => entity.roles?.includes('registrar'))?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || null,
      registeredAt: registration?.eventDate || null,
      expiresAt: expiration?.eventDate || null,
      status: data?.status || []
    };
    setCached(`rdap:${domain}`, result);
    return result;
  } catch {
    setCached(`rdap:${domain}`, null);
    return null;
  }
}

export async function enrichDomainIntel(url) {
  const analysis = analyzeDomain(url);
  if (!analysis) return null;

  const cached = getCached(`intel:${analysis.domain}`);
  if (cached) return cached;

  const suspicious = analysis.isSuspiciousTld || analysis.isHomograph || analysis.isPunycode || analysis.isIpDirect || analysis.flags.length >= 2;
  const ip = isLegitimateDomain(analysis.domain) && !analysis.isIpDirect ? null : await resolveDomainIp(analysis.domain);
  const rdap = suspicious && !analysis.isIpDirect ? await lookupRdap(analysis.domain) : null;

  const result = {
    ...analysis,
    ip,
    domain_age: rdap?.registeredAt ? Math.max(0, Math.floor((Date.now() - new Date(rdap.registeredAt).getTime()) / 86400000)) : 'unknown',
    registeredAt: rdap?.registeredAt || null,
    registrar: rdap?.registrar || null,
    expiresAt: rdap?.expiresAt || null
  };
  setCached(`intel:${analysis.domain}`, result);
  return result;
}
