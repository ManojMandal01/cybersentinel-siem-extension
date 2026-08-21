import { BRAND_KEYWORDS, LEGITIMATE_DOMAINS, SUSPICIOUS_TLDS } from '../shared/constants.js';
import {
  detectBrandInDomain, domainMatches, extractDomain, hasHomograph, levenshtein, urlEntropy
} from '../shared/utils.js';

const SIGNAL_WEIGHTS = {
  typosquatting: 35,
  homograph: 40,
  brand_impersonation: 35,
  login_on_impersonated_domain: 25,
  at_symbol_redirect: 25,
  ip_in_url: 20,
  suspicious_tld: 15,
  high_entropy: 10,
  long_url: 5
};

function getRegistrableLabel(domain) {
  const labels = domain.split('.').filter(Boolean);
  return labels.length ? labels[labels.length - 2] || labels[0] : '';
}

function isLocalOrPrivateHost(domain) {
  const normalized = domain.toLowerCase().trim();

  if (
    normalized === 'localhost' ||
    normalized === 'localhost.localdomain' ||
    normalized === '::1' ||
    normalized === '0.0.0.0'
  ) {
    return true;
  }

  const ipv4 = normalized.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4) return false;

  const [, a, b, c, d] = ipv4.map(Number);
  if ([a, b, c, d].some((part) => part > 255)) return false;

  // RFC1918 private IPv4 ranges and loopback.
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;

  return false;
}

export function checkTyposquatting(domain) {
  const results = [];
  const normalized = domain.toLowerCase();
  const label = getRegistrableLabel(normalized);

  for (const brand of BRAND_KEYWORDS) {
    const legitList = LEGITIMATE_DOMAINS[brand] || [`${brand}.com`];
    if (legitList.some((legit) => domainMatches(normalized, legit))) continue;

    for (const legit of legitList) {
      const legitLabel = getRegistrableLabel(legit);
      const distance = levenshtein(label, legitLabel);
      if (distance > 0 && distance <= 2) {
        results.push({ brand, legitimate: legit, distance, method: 'levenshtein' });
      }
    }
  }
  return results;
}

export function analyzeUrl(url) {
  const domain = extractDomain(url);
  if (!domain) return { isPhishing: false, phishingScore: 0, features: {}, signals: [] };

  const features = {
    urlLength: url.length,
    domainLength: domain.length,
    entropy: urlEntropy(url),
    hyphenCount: (domain.match(/-/g) || []).length,
    digitCount: (domain.match(/\d/g) || []).length,
    subdomainCount: Math.max(0, domain.split('.').length - 2),
    hasAtSymbol: url.includes('@'),
    hasIpAddress: /^(https?):\/\/(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/i.test(url),
    suspiciousKeywords: BRAND_KEYWORDS.filter((kw) => domain.includes(kw)),
    suspiciousTld: [...SUSPICIOUS_TLDS].some((tld) => domain.endsWith(tld))
  };

  // Local/private hosts are development or internal addresses, not public
  // Internet domains. Keep their URL features for telemetry, but do not
  // apply public-domain phishing heuristics such as typosquatting or IP-in-URL.
  if (isLocalOrPrivateHost(domain)) {
    return {
      isPhishing: false,
      phishingScore: 0,
      features,
      signals: [],
      domain,
      impersonatedBrand: null
    };
  }

  const signals = [];
  const typosquats = checkTyposquatting(domain);
  const impersonatedBrand = detectBrandInDomain(domain);

  if (typosquats.length > 0) signals.push({ type: 'typosquatting', details: typosquats });
  if (hasHomograph(domain)) signals.push({ type: 'homograph', details: domain });
  if (features.entropy > 4.5) signals.push({ type: 'high_entropy', value: features.entropy });
  if (features.urlLength > 100) signals.push({ type: 'long_url', value: features.urlLength });
  if (features.hasAtSymbol) signals.push({ type: 'at_symbol_redirect' });
  if (features.hasIpAddress) signals.push({ type: 'ip_in_url' });
  if (features.suspiciousTld) signals.push({ type: 'suspicious_tld' });

  if (impersonatedBrand) {
    const legitDomains = LEGITIMATE_DOMAINS[impersonatedBrand] || [];
    const isLegit = legitDomains.some((d) => domainMatches(domain, d));
    if (!isLegit) signals.push({ type: 'brand_impersonation', brand: impersonatedBrand });
  }

  const phishingScore = Math.min(100, signals.reduce((sum, signal) => sum + (SIGNAL_WEIGHTS[signal.type] || 0), 0));
  const isPhishing = phishingScore >= 35;

  return { isPhishing, phishingScore, features, signals, domain, impersonatedBrand };
}

export function detectPhishing(url, pageContext = {}) {
  const urlAnalysis = analyzeUrl(url);
  const signals = [...urlAnalysis.signals];

  if (pageContext.hasLoginForm && urlAnalysis.impersonatedBrand) {
    const legitDomains = LEGITIMATE_DOMAINS[urlAnalysis.impersonatedBrand] || [];
    const isLegit = legitDomains.some((d) => domainMatches(urlAnalysis.domain, d));
    if (!isLegit) {
      signals.push({ type: 'login_on_impersonated_domain', brand: urlAnalysis.impersonatedBrand });
    }
  }

  const phishingScore = Math.min(100, signals.reduce((sum, signal) => sum + (SIGNAL_WEIGHTS[signal.type] || 0), 0));
  const isPhishing = phishingScore >= 35;

  return {
    classification: isPhishing ? 'phishing' : 'benign',
    confidence: isPhishing ? Math.min(99, phishingScore + 10) : Math.min(60, 20 + phishingScore),
    phishingScore,
    ...urlAnalysis,
    signals
  };
}
