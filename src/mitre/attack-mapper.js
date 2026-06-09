import { MITRE_TECHNIQUES } from '../shared/constants.js';

const DETECTION_MAP = [
  { match: (e, d) => d.phishing?.classification === 'phishing' || d.loginPage?.isPotentialPhishing, technique: MITRE_TECHNIQUES.PHISHING, name: 'Phishing' },
  { match: (e, d) => d.scriptAnalysis?.results?.some((r) => r.detections.some((x) => ['eval', 'new Function'].includes(x.name))), technique: MITRE_TECHNIQUES.JS_PAYLOAD, name: 'JavaScript Payload' },
  { match: (e, d) => d.scriptAnalysis?.hasObfuscation, technique: MITRE_TECHNIQUES.OBFUSCATION, name: 'Obfuscation' },
  { match: (e, d) => d.credentialHarvesting?.detected || e.event === 'credential_form_detected', technique: MITRE_TECHNIQUES.CREDENTIAL_THEFT, name: 'Credential Theft' },
  { match: (e, d) => d.malwareDelivery?.detected || (e.event === 'download' && e.isSuspicious), technique: MITRE_TECHNIQUES.TOOL_DOWNLOAD, name: 'Tool Download' },
  { match: (e, d) => e.event === 'permission_access' && e.clipboard_access, technique: MITRE_TECHNIQUES.DATA_FROM_LOCAL, name: 'Data from Local System' }
];

export function mapToMitre(event, detections = {}) {
  const techniques = [];

  for (const rule of DETECTION_MAP) {
    if (rule.match(event, detections)) {
      techniques.push({ technique: rule.technique, name: rule.name });
    }
  }

  return {
    techniques,
    primary: techniques[0] || null,
    technique: techniques[0]?.technique || null
  };
}
