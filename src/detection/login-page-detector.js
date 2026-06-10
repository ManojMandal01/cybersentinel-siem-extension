import { LEGITIMATE_DOMAINS } from '../shared/constants.js';
import { detectBrandInDomain, domainMatches, extractDomain } from '../shared/utils.js';

export function detectLoginPage(url, pageContext) {
  const domain = extractDomain(url);
  const brand = detectBrandInDomain(domain) || pageContext.detectedBrand;
  const hasLoginForm = pageContext.hasLoginForm || pageContext.hasPassword;
  const hasPassword = pageContext.hasPassword;

  if (!hasLoginForm && !hasPassword) {
    return { isLoginPage: false, isPotentialPhishing: false };
  }

  let impersonatedBrand = brand;
  if (!impersonatedBrand && pageContext.pageTitle) {
    const title = pageContext.pageTitle.toLowerCase();
    for (const [key, domains] of Object.entries(LEGITIMATE_DOMAINS)) {
      if (title.includes(key)) {
        impersonatedBrand = key;
        const isLegitDomain = domains.some((d) => domainMatches(domain, d));
        if (!isLegitDomain) {
          return {
            isLoginPage: true,
            isPotentialPhishing: true,
            brand: key,
            pageDomain: domain,
            alert: `Potential phishing page impersonating ${key}`,
            legitimateDomains: domains
          };
        }
      }
    }
  }

  if (impersonatedBrand) {
    const legitDomains = LEGITIMATE_DOMAINS[impersonatedBrand] || [];
    const isLegit = legitDomains.some((d) => domainMatches(domain, d));
    if (!isLegit) {
      return {
        isLoginPage: true,
        isPotentialPhishing: true,
        brand: impersonatedBrand,
        pageDomain: domain,
        alert: `Potential phishing page impersonating ${impersonatedBrand}`,
        legitimateDomains: legitDomains
      };
    }
  }

  return {
    isLoginPage: hasLoginForm || hasPassword,
    isPotentialPhishing: false,
    brand: impersonatedBrand,
    pageDomain: domain
  };
}
