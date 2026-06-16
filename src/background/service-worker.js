import { initUrlCollector } from '../collectors/url-collector.js';
import { initDownloadMonitor } from '../collectors/download-monitor.js';
import { initExtensionMonitor } from '../collectors/extension-monitor.js';
import { processFormDetection } from '../collectors/form-monitor.js';
import { processPermissionMessage } from '../collectors/permission-monitor.js';
import { enrichDomainIntel } from '../collectors/domain-intel.js';
import { detectPhishing } from '../detection/phishing-detector.js';
import { detectLoginPage } from '../detection/login-page-detector.js';
import { analyzeRedirectChain } from '../detection/redirect-analyzer.js';
import { analyzeScriptsFromPage } from '../detection/script-analyzer.js';
import { detectCredentialHarvesting } from '../detection/credential-harvesting.js';
import { analyzeMalwareDelivery } from '../detection/malware-delivery.js';
import { scoreEvent } from '../risk/risk-scorer.js';
import { mapToMitre } from '../mitre/attack-mapper.js';
import { generateIocs } from '../ioc/ioc-generator.js';
import { createAlert, shouldAlert } from '../alerts/alert-engine.js';
import { checkReputation, refreshThreatFeeds, sanitizeThreatCache } from '../intel/threat-feeds.js';
import { analyzeWithAi } from '../ai/analysis-engine.js';
import { sendToSplunk } from '../siem/splunk-client.js';
import { executeHuntQuery, getAvailableQueries } from '../hunting/query-engine.js';
import {
  appendEvent, appendIoc, getConfig, setConfig, getStats, getEvents, getAlerts, getIocs
} from '../shared/storage.js';
import { DEFAULT_CONFIG } from '../shared/constants.js';
import { domainMatches, extractDomain, isInternalBrowserUrl, normalizeDomain } from '../shared/utils.js';

export let config = { ...DEFAULT_CONFIG };

let initPromise = null;

function mergeConfig(defaults, stored = {}) {
  return {
    ...defaults,
    ...stored,
    splunk: { ...defaults.splunk, ...(stored.splunk || {}) },
    alerts: { ...defaults.alerts, ...(stored.alerts || {}) },
    detection: { ...defaults.detection, ...(stored.detection || {}) },
    ai: { ...defaults.ai, ...(stored.ai || {}) }
  };
}

async function init() {
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const stored = await getConfig();
    if (stored) config = mergeConfig(DEFAULT_CONFIG, stored);
    else await setConfig(config);

    await sanitizeThreatCache();
    await refreshThreatFeeds();

    chrome.alarms.create('threatFeedRefresh', { periodInMinutes: 60 });
  })();

  try {
    return await initPromise;
  } catch (err) {
    initPromise = null;
    throw err;
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'threatFeedRefresh') refreshThreatFeeds();
});

export async function processSecurityPipeline(rawEvent, pageContext = {}) {
  if (isInternalBrowserUrl(rawEvent.url)) {
    return { skipped: true, reason: 'internal_browser_url' };
  }

  // Check monitoring scope
  const domain = normalizeDomain(rawEvent.domain) || extractDomain(rawEvent.url || '');
  if (domain) {
    const scope = config.detection?.monitoringScope || 'all';
    const allowlist = config.detection?.allowlistDomains || [];
    const blocklist = config.detection?.blocklistDomains || [];

    if (scope === 'allowlist') {
      const isAllowed = allowlist.some((d) => domainMatches(domain, d));
      if (!isAllowed) {
        return { skipped: true, reason: 'not_in_allowlist' };
      }
    } else if (scope === 'blocklist') {
      const isBlocked = blocklist.some((d) => domainMatches(domain, d));
      if (isBlocked) {
        return { skipped: true, reason: 'in_blocklist' };
      }
    }
  }

  const detections = {};

  if (rawEvent.url) {
    detections.domainIntel = await enrichDomainIntel(rawEvent.url);
    if (config.detection?.phishingEnabled !== false) {
      detections.phishing = detectPhishing(rawEvent.url, pageContext);
      detections.loginPage = detectLoginPage(rawEvent.url, pageContext);
    }
    if (config.detection?.threatIntelEnabled !== false) {
      detections.threatIntel = await checkReputation(rawEvent.url);
    }
  }

  if (rawEvent.redirectChain && config.detection?.phishingEnabled !== false) {
    detections.redirectAnalysis = analyzeRedirectChain(rawEvent.redirectChain);
  }

  if (pageContext.scripts && config.detection?.scriptAnalysisEnabled !== false) {
    detections.scriptAnalysis = analyzeScriptsFromPage(pageContext.scripts);
  }

  if ((rawEvent.isCredentialForm || rawEvent.hasPassword) && config.detection?.formMonitoringEnabled !== false) {
    detections.credentialHarvesting = detectCredentialHarvesting(rawEvent.url || '', {
      ...pageContext,
      ...rawEvent,
      reputation: detections.threatIntel?.malicious ? 'malicious' : 'unknown',
      isSuspiciousTld: detections.domainIntel?.isSuspiciousTld,
      impersonatedBrand: detections.phishing?.impersonatedBrand
    });
  }

  if (rawEvent.event === 'download') {
    detections.malwareDelivery = analyzeMalwareDelivery(rawEvent);
  }

  if (rawEvent.url && pageContext && config.ai?.enabled) {
    detections.ai = await analyzeWithAi({ ...pageContext, url: rawEvent.url }, config);
  }

  const scoring = scoreEvent(
    { ...rawEvent, ...detections.domainIntel, threat_intel_hit: detections.threatIntel?.malicious },
    detections
  );
  const mitre = mapToMitre(rawEvent, detections);

  const evidence = [];
  if (rawEvent.event === 'credential_form_detected') {
    if (rawEvent.hasPassword) {
      evidence.push('password field found');
    }
    const currentDomain = rawEvent.domain || (rawEvent.url ? extractDomain(rawEvent.url) : '');
    let hasExternalSubmit = false;
    if (rawEvent.forms && Array.isArray(rawEvent.forms)) {
      hasExternalSubmit = rawEvent.forms.some((f) => {
        if (!f.action) return false;
        try {
          const actionDomain = new URL(f.action, rawEvent.url).hostname;
          return actionDomain && actionDomain !== currentDomain;
        } catch {
          return false;
        }
      });
    }
    if (hasExternalSubmit) {
      evidence.push('external submit action');
    }
  }

  const enrichedEvent = {
    ...rawEvent,
    risk_score: scoring.risk_score,
    risk_level: scoring.risk_level,
    technique: mitre.technique,
    threat_intel_hit: detections.threatIntel?.malicious || false,
    threat_feed: detections.threatIntel?.entity,
    evidence: evidence.length > 0 ? evidence : undefined,
    detections: {
      phishing: detections.phishing?.classification,
      credentialHarvesting: detections.credentialHarvesting?.detected,
      malwareDelivery: detections.malwareDelivery?.detected
    }
  };

  await appendEvent(enrichedEvent);

  const iocs = generateIocs(enrichedEvent, detections);
  for (const ioc of iocs) {
    await appendIoc(ioc);
  }

  if (shouldAlert(scoring, config)) {
    await createAlert(enrichedEvent, scoring, mitre, detections, config);
  }

  if (config.splunk?.enabled) {
    await sendToSplunk(enrichedEvent, scoring, mitre, config);
  }

  return { event: enrichedEvent, scoring, mitre, detections, iocs };
}

function safeHandleEvent(event) {
  handleCollectedEvent(event).catch((err) => {
    console.error('[CyberSentinel] Unhandled pipeline error:', err);
  });
}

async function handleCollectedEvent(event) {
  try {
    await processSecurityPipeline(event);
  } catch (err) {
    console.error('[CyberSentinel] Pipeline error:', err);
    try {
      await appendEvent(event);
    } catch (storeErr) {
      console.error('[CyberSentinel] Failed to store event:', storeErr);
    }
  }
}

initUrlCollector(safeHandleEvent);
initDownloadMonitor(safeHandleEvent);
initExtensionMonitor(safeHandleEvent);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((err) => {
    sendResponse({ error: err.message });
  });
  return true;
});

async function handleMessage(message, sender) {
  switch (message.type) {
    case 'FORM_DETECTED': {
      let domain = message.domain;
      try {
        if (sender.tab?.url) domain = new URL(sender.tab.url).hostname;
      } catch {
        domain = message.domain || '';
      }
      const event = processFormDetection({
        ...message,
        url: sender.tab?.url || message.url,
        domain
      });
      return processSecurityPipeline(event, message);
    }
    case 'PERMISSION_DETECTED':
      return processSecurityPipeline(processPermissionMessage(message));
    case 'SCRIPT_ANALYSIS':
      return processSecurityPipeline(
        { event: 'suspicious_script', url: message.url, domain: message.domain, timestamp: message.timestamp },
        message
      );
    case 'PAGE_ANALYSIS':
      return processSecurityPipeline(
        { event: 'url_visit', url: message.url, domain: message.domain, timestamp: message.timestamp },
        message
      );
    case 'GET_STATS':
      return getStats();
    case 'GET_EVENTS':
      return getEvents(message.filter || {});
    case 'GET_ALERTS':
      return getAlerts(message.limit);
    case 'GET_IOCS':
      return getIocs(message.limit);
    case 'GET_CONFIG':
      return config;
    case 'SET_CONFIG': {
      config = { ...config, ...message.config };
      await setConfig(config);
      return { ok: true };
    }
    case 'HUNT_QUERY':
      return executeHuntQuery(message.query);
    case 'GET_HUNT_QUERIES':
      return getAvailableQueries();
    default:
      return { error: 'unknown_message_type' };
  }
}

chrome.runtime.onInstalled.addListener(() => {
  init()
    .then(() => console.log('[CyberSentinel] SIEM extension initialized'))
    .catch((err) => console.error('[CyberSentinel] Init failed:', err));
});

chrome.runtime.onStartup.addListener(() => {
  init().catch((err) => console.error('[CyberSentinel] Startup init failed:', err));
});

init().catch((err) => console.error('[CyberSentinel] Init failed:', err));
