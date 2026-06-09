import { extractDomain } from '../shared/utils.js';

export function generateIocs(event, detections = {}) {
  const iocs = [];
  const seen = new Set();

  const add = (ioc_type, value, context = '') => {
    const key = `${ioc_type}:${value}`;
    if (!value || seen.has(key)) return;
    seen.add(key);
    iocs.push({ ioc_type, value, context, source_event: event.event, timestamp: event.timestamp });
  };

  if (event.url) add('url', event.url, 'from_event');
  if (event.domain) add('domain', event.domain, 'from_event');
  else if (event.url) add('domain', extractDomain(event.url), 'extracted');

  if (event.ip || detections.domainIntel?.ip) {
    add('ip', event.ip || detections.domainIntel.ip, 'domain_resolution');
  }

  if (event.file) add('filename', event.file, 'download');
  if (event.fileHash) add('hash', event.fileHash, 'file_hash');

  if (detections.phishing?.domain) {
    add('domain', detections.phishing.domain, 'phishing_detection');
  }

  if (event.redirectChain) {
    for (const url of event.redirectChain) {
      add('url', url, 'redirect_chain');
      add('domain', extractDomain(url), 'redirect_chain');
    }
  }

  if (detections.scriptAnalysis?.results) {
    for (const script of detections.scriptAnalysis.results) {
      if (script.sourceUrl) add('url', script.sourceUrl, 'suspicious_script');
    }
  }

  return iocs;
}
