import { getEvents } from '../shared/storage.js';
import { extractDomain, normalizeDomain, now } from '../shared/utils.js';

const CORRELATION_WINDOW_MS = 10 * 60 * 1000;
const MAX_RELATED_EVENTS = 12;

function hash(value) {
  let result = 0;
  for (let i = 0; i < value.length; i += 1) {
    result = ((result << 5) - result + value.charCodeAt(i)) | 0;
  }
  return Math.abs(result).toString(36);
}

function getSignalTypes(event = {}) {
  const signals = new Set();
  if (event.risk_score >= 26) signals.add('elevated_risk');
  if (event.threat_intel_hit) signals.add('threat_intel');
  if (event.event === 'credential_form_detected' || event.isCredentialForm) signals.add('credential_form');
  if (event.event === 'suspicious_script' || event.hasObfuscation) signals.add('suspicious_script');
  if (event.event === 'download' && event.isSuspicious) signals.add('suspicious_download');
  if (event.event === 'url_redirect' || event.redirectChain?.length > 1) signals.add('redirect');
  if (event.detections?.phishing === 'phishing') signals.add('phishing');
  if (event.detections?.credentialHarvesting) signals.add('credential_harvesting');
  if (event.detections?.malwareDelivery) signals.add('malware_delivery');
  return signals;
}

const SECURITY_SIGNALS = new Set([
  'threat_intel',
  'credential_form',
  'suspicious_script',
  'suspicious_download',
  'redirect',
  'phishing',
  'credential_harvesting',
  'malware_delivery'
]);

// A correlation must be anchored by a strong signal on the CURRENT event.
// This prevents a benign event from inheriting a strong anchor from another
// event on the same domain. Redirects, login forms, and suspicious scripts
// alone are not sufficient because legitimate sites routinely generate them.
const STRONG_SECURITY_ANCHORS = new Set([
  'threat_intel',
  'phishing',
  'credential_harvesting',
  'malware_delivery',
  'suspicious_download'
]);

function hasSecuritySignal(signals) {
  return [...signals].some((signal) => SECURITY_SIGNALS.has(signal));
}

function countSecuritySignals(signals) {
  return [...signals].filter((signal) => SECURITY_SIGNALS.has(signal)).length;
}

function hasStrongSecurityAnchor(signals) {
  return [...signals].some((signal) => STRONG_SECURITY_ANCHORS.has(signal));
}

export async function correlateEvent(event, detections = {}) {
  const domain = normalizeDomain(event.domain || extractDomain(event.url || ''));
  if (!domain) return null;

  const cutoff = Date.now() - CORRELATION_WINDOW_MS;
  const recent = await getEvents({ limit: 300 });
  const related = recent.filter((candidate) => {
    const candidateDomain = normalizeDomain(candidate.domain || extractDomain(candidate.url || ''));
    const time = new Date(candidate.timestamp || candidate.storedAt || 0).getTime();
    return candidateDomain === domain && time >= cutoff;
  });

  const current = {
    ...event,
    threat_intel_hit: event.threat_intel_hit || detections.threatIntel?.malicious,
    detections: {
      phishing: detections.phishing?.classification,
      credentialHarvesting: detections.credentialHarvesting?.detected,
      malwareDelivery: detections.malwareDelivery?.detected
    }
  };

  const currentSignals = getSignalTypes(current);

  // The event must itself contain a security signal and a strong anchor.
  // Never borrow a strong anchor from a previous event on the same domain.
  if (!hasSecuritySignal(currentSignals)) return null;
  if (!hasStrongSecurityAnchor(currentSignals)) return null;

  const signalTypes = new Set(currentSignals);
  const relatedEventIds = [];
  for (const candidate of related) {
    for (const signal of getSignalTypes(candidate)) signalTypes.add(signal);
    if (candidate.id || candidate.event_id) relatedEventIds.push(candidate.id || candidate.event_id);
  }

  // Require at least two distinct concrete security signals across the
  // current event and its recent related activity. This preserves useful
  // correlation for genuine attacks while preventing ordinary login pages,
  // scripts, and redirects from becoming incidents.
  if (countSecuritySignals(signalTypes) < 2) return null;

  const bucket = Math.floor(Date.now() / CORRELATION_WINDOW_MS);
  const incidentId = `inc_${hash(`${domain}:${bucket}`)}`;

  return {
    incident_id: incidentId,
    correlation_key: domain,
    first_seen: related.length
      ? new Date(Math.min(...related.map((e) => new Date(e.timestamp || e.storedAt || now()).getTime()))).toISOString()
      : event.timestamp || now(),
    last_seen: event.timestamp || now(),
    signal_count: signalTypes.size,
    signals: [...signalTypes],
    related_event_ids: [...new Set(relatedEventIds)].slice(0, MAX_RELATED_EVENTS),
    correlated: true
  };
}
