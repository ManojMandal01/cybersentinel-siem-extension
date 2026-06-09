import { extractDomain } from '../shared/utils.js';

export function analyzeRedirectChain(chain) {
  if (!chain || chain.length < 2) {
    return { isSuspicious: false, hops: 0, domains: [] };
  }

  const domains = chain.map(extractDomain).filter(Boolean);
  const uniqueDomains = [...new Set(domains)];
  const crossDomainHops = uniqueDomains.length;

  const flags = [];
  if (chain.length >= 4) flags.push('long_chain');
  if (crossDomainHops >= 3) flags.push('multiple_cross_domain');
  if (domains.some((d) => d.includes('-') && d.length > 30)) flags.push('suspicious_intermediate');

  const lastDomain = domains[domains.length - 1];
  const firstDomain = domains[0];
  if (firstDomain && lastDomain && firstDomain !== lastDomain) {
    flags.push('domain_change');
  }

  return {
    isSuspicious: flags.length >= 2 || chain.length >= 5,
    hops: chain.length - 1,
    domains: uniqueDomains,
    chain,
    flags,
    severity: flags.length >= 2 ? 'high' : flags.length === 1 ? 'medium' : 'low'
  };
}
