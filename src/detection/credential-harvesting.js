import { LEGITIMATE_DOMAINS } from '../shared/constants.js';
import { extractDomain } from '../shared/utils.js';

export function detectCredentialHarvesting(url, context) {
  const domain = extractDomain(url);
  const hasPasswordForm = context.hasPassword || context.formType === 'login';
  const hasOtp = context.hasOtp;
  const reputation = context.reputation || 'unknown';

  if (!hasPasswordForm && !hasOtp) {
    return { detected: false };
  }

  const isKnownDomain = Object.values(LEGITIMATE_DOMAINS)
    .flat()
    .some((d) => domain.endsWith(d));

  const signals = [];
  if (hasPasswordForm) signals.push('password_form');
  if (hasOtp) signals.push('otp_field');
  if (!isKnownDomain) signals.push('unknown_domain');
  if (reputation === 'malicious') signals.push('malicious_reputation');
  if (context.isSuspiciousTld) signals.push('suspicious_tld');
  if (context.impersonatedBrand) signals.push('brand_impersonation');

  const detected = hasPasswordForm && !isKnownDomain && (
    reputation === 'malicious' ||
    context.isSuspiciousTld ||
    context.impersonatedBrand ||
    signals.length >= 3
  );

  return {
    detected,
    signals,
    domain,
    isKnownDomain,
    alert: detected ? 'Credential Harvesting Attempt' : null,
    severity: detected ? 'critical' : signals.includes('unknown_domain') ? 'medium' : 'low'
  };
}
