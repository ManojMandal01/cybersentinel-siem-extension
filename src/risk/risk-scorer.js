import { RISK_WEIGHTS } from '../shared/constants.js';
import { getRiskLevel, isLegitimateDomain } from '../shared/utils.js';

export function scoreEvent(event, detections = {}) {
  const domain = event.domain || '';
  if (isLegitimateDomain(domain) && event.event !== 'download' && !detections.malwareDelivery?.detected) {
    return { risk_score: 0, risk_level: 'Low', factors: [] };
  }

  let score = 0;
  const factors = [];

  const add = (factor, weight) => {
    score += weight;
    factors.push({ factor, weight });
  };

  if (detections.phishing?.classification === 'phishing') {
    add('phishing_detected', RISK_WEIGHTS.BRAND_IMPERSONATION);
  }
  if (detections.phishing?.signals?.some((s) => s.type === 'typosquatting')) {
    add('typosquatting', RISK_WEIGHTS.TYPOSQUATTING);
  }
  if (detections.phishing?.signals?.some((s) => s.type === 'homograph')) {
    add('homograph', RISK_WEIGHTS.HOMOGRAPH);
  }
  if (event.isSuspiciousTld || detections.domainIntel?.isSuspiciousTld) {
    add('suspicious_tld', RISK_WEIGHTS.SUSPICIOUS_TLD);
  }
  if (event.isCredentialForm || event.hasPassword) {
    add('login_form', RISK_WEIGHTS.LOGIN_FORM);
  }
  if (detections.scriptAnalysis?.hasObfuscation) {
    add('obfuscated_js', RISK_WEIGHTS.OBFUSCATED_JS);
  }
  if (detections.threatIntel?.malicious) {
    add('malicious_reputation', RISK_WEIGHTS.MALICIOUS_REPUTATION);
  }
  if (event.isSuspicious || detections.malwareDelivery?.detected) {
    add('suspicious_download', RISK_WEIGHTS.SUSPICIOUS_DOWNLOAD);
  }
  if (detections.redirectAnalysis?.isSuspicious) {
    add('redirect_chain', RISK_WEIGHTS.REDIRECT_CHAIN);
  }
  if (detections.credentialHarvesting?.detected) {
    add('credential_harvesting', RISK_WEIGHTS.CREDENTIAL_ON_UNKNOWN_DOMAIN);
  }
  if (detections.loginPage?.isPotentialPhishing) {
    add('login_page_phishing', RISK_WEIGHTS.BRAND_IMPERSONATION);
  }
  if (detections.ai?.classification === 'phishing') {
    add('ai_phishing', Math.round(detections.ai.confidence * 0.3));
  }

  score = Math.min(100, score);

  return {
    risk_score: score,
    risk_level: getRiskLevel(score),
    factors
  };
}
