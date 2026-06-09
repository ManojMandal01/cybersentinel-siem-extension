import { BRAND_KEYWORDS, LEGITIMATE_DOMAINS } from '../shared/constants.js';
import {
  detectBrandInDomain, extractDomain, hasHomograph, levenshtein, urlEntropy
} from '../shared/utils.js';

export function checkTyposquatting(domain) {
  const results = [];
  const baseDomain = domain.replace(/^www\./, '');

  for (const brand of BRAND_KEYWORDS) {
    const legitList = LEGITIMATE_DOMAINS[brand] || [`${brand}.com`];
    for (const legit of legitList) {
      const distance = levenshtein(baseDomain, legit);
      const containsBrand = baseDomain.includes(brand) && baseDomain !== legit;
      if ((distance > 0 && distance <= 2) || containsBrand) {
        results.push({ brand, legitimate: legit, distance, method: containsBrand ? 'substring' : 'levenshtein' });
      }
    }
  }
  return results;
}

export function analyzeUrl(url) {
  const domain = extractDomain(url);
  if (!domain) return { isPhishing: false, features: {}, signals: [] };

  const features = {
    urlLength: url.length,
    domainLength: domain.length,
    entropy: urlEntropy(url),
    hyphenCount: (domain.match(/-/g) || []).length,
    digitCount: (domain.match(/\d/g) || []).length,
    subdomainCount: domain.split('.').length - 2,
    hasAtSymbol: url.includes('@'),
    hasIpAddress: /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(url),
    suspiciousKeywords: BRAND_KEYWORDS.filter((kw) => domain.includes(kw))
  };

  const signals = [];
  const typosquats = checkTyposquatting(domain);
  const impersonatedBrand = detectBrandInDomain(domain);

  if (typosquats.length > 0) signals.push({ type: 'typosquatting', details: typosquats });
  if (hasHomograph(domain)) signals.push({ type: 'homograph', details: domain });
  if (features.entropy > 4.5) signals.push({ type: 'high_entropy', value: features.entropy });
  if (features.urlLength > 100) signals.push({ type: 'long_url', value: features.urlLength });
  if (features.hasAtSymbol) signals.push({ type: 'at_symbol_redirect' });
  if (features.hasIpAddress) signals.push({ type: 'ip_in_url' });
  if (impersonatedBrand) {
    const isLegit = (LEGITIMATE_DOMAINS[impersonatedBrand] || []).some((d) => domain.endsWith(d));
    if (!isLegit) signals.push({ type: 'brand_impersonation', brand: impersonatedBrand });
  }

  const isPhishing = signals.some((s) =>
    ['typosquatting', 'homograph', 'brand_impersonation', 'at_symbol_redirect'].includes(s.type)
  );

  return { isPhishing, features, signals, domain, impersonatedBrand };
}

export function detectPhishing(url, pageContext = {}) {
  const urlAnalysis = analyzeUrl(url);
  const signals = [...urlAnalysis.signals];

  if (pageContext.hasLoginForm && urlAnalysis.impersonatedBrand) {
    signals.push({ type: 'login_on_impersonated_domain', brand: urlAnalysis.impersonatedBrand });
  }

  const isPhishing = signals.length >= 1 && (
    urlAnalysis.isPhishing ||
    signals.some((s) => ['login_on_impersonated_domain', 'brand_impersonation'].includes(s.type))
  );

  return {
    classification: isPhishing ? 'phishing' : 'benign',
    confidence: Math.min(95, 40 + signals.length * 15),
    ...urlAnalysis,
    signals
  };
}
