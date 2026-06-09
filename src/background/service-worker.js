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
import { checkReputation, refreshThreatFeeds } from '../intel/threat-feeds.js';
import { analyzeWithAi } from '../ai/analysis-engine.js';
import { sendToSplunk } from '../siem/splunk-client.js';
import { executeHuntQuery, getAvailableQueries } from '../hunting/query-engine.js';
import {
  appendEvent, appendIoc, getConfig, setConfig, getStats, getEvents, getAlerts, getIocs
} from '../shared/storage.js';
import { DEFAULT_CONFIG } from '../shared/constants.js';

let config = { ...DEFAULT_CONFIG };

async function init() {
  const stored = await getConfig();
  if (stored) config = { ...DEFAULT_CONFIG, ...stored };
  else await setConfig(config);

  await refreshThreatFeeds();

  chrome.alarms.create('threatFeedRefresh', { periodInMinutes: 60 });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'threatFeedRefresh') refreshThreatFeeds();
});

async function processSecurityPipeline(rawEvent, pageContext = {}) {
  const detections = {};

  if (rawEvent.url) {
    detections.domainIntel = await enrichDomainIntel(rawEvent.url);
    detections.phishing = detectPhishing(rawEvent.url, pageContext);
    detections.threatIntel = await checkReputation(rawEvent.url);
    detections.loginPage = detectLoginPage(rawEvent.url, pageContext);
  }

  if (rawEvent.redirectChain) {
    detections.redirectAnalysis = analyzeRedirectChain(rawEvent.redirectChain);
  }

  if (pageContext.scripts) {
    detections.scriptAnalysis = analyzeScriptsFromPage(pageContext.scripts);
  }

  if (rawEvent.isCredentialForm || rawEvent.hasPassword) {
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

  if (rawEvent.url && pageContext) {
    detections.ai = await analyzeWithAi({ ...pageContext, url: rawEvent.url }, config);
  }

  const scoring = scoreEvent(
    { ...rawEvent, ...detections.domainIntel, threat_intel_hit: detections.threatIntel?.malicious },
    detections
  );
  const mitre = mapToMitre(rawEvent, detections);

  const enrichedEvent = {
    ...rawEvent,
    risk_score: scoring.risk_score,
    risk_level: scoring.risk_level,
    technique: mitre.technique,
    threat_intel_hit: detections.threatIntel?.malicious || false,
    threat_feed: detections.threatIntel?.entity,
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

async function handleCollectedEvent(event) {
  try {
    await processSecurityPipeline(event);
  } catch (err) {
    console.error('[CyberSentinel] Pipeline error:', err);
    await appendEvent(event);
  }
}

initUrlCollector(handleCollectedEvent);
initDownloadMonitor(handleCollectedEvent);
initExtensionMonitor(handleCollectedEvent);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((err) => {
    sendResponse({ error: err.message });
  });
  return true;
});

async function handleMessage(message, sender) {
  switch (message.type) {
    case 'FORM_DETECTED': {
      const event = processFormDetection({
        ...message,
        url: sender.tab?.url,
        domain: sender.tab?.url ? new URL(sender.tab.url).hostname : message.domain
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

chrome.runtime.onInstalled.addListener(async () => {
  await init();
  console.log('[CyberSentinel] SIEM extension initialized');
});

init();
