import { SUSPICIOUS_TLDS } from '../shared/constants.js';
import { extractDomain, extractTld, hasHomograph, isIpAddress, now } from '../shared/utils.js';

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
    subdomainCount: domain.split('.').length - 2,
    domainLength: domain.length,
    hasHyphens: domain.includes('-'),
    timestamp: now()
  };

  analysis.flags = [];
  if (analysis.isSuspiciousTld) analysis.flags.push('suspicious_tld');
  if (analysis.isHomograph) analysis.flags.push('homograph_attack');
  if (analysis.isIpDirect) analysis.flags.push('ip_direct_access');
  if (analysis.subdomainCount > 3) analysis.flags.push('excessive_subdomains');
  if (analysis.hasHyphens && analysis.domainLength > 25) analysis.flags.push('long_hyphenated_domain');

  return analysis;
}

export async function resolveDomainIp(domain) {
  if (isIpAddress(domain)) return domain;
  try {
    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const data = await response.json();
    return data.Answer?.[0]?.data || null;
  } catch {
    return null;
  }
}

export async function enrichDomainIntel(url) {
  const analysis = analyzeDomain(url);
  if (!analysis) return null;

  const ip = await resolveDomainIp(analysis.domain);
  return { ...analysis, ip, domain_age: 'unknown' };
}
