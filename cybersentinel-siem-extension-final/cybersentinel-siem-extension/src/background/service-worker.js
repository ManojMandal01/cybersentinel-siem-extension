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
import { buildStixBundle } from '../ioc/stix-export.js';
import { createAlert, shouldAlert } from '../alerts/alert-engine.js';
import { checkReputation, refreshThreatFeeds, sanitizeThreatCache, getThreatFeedStatus } from '../intel/threat-feeds.js';
import { analyzeWithAi } from '../ai/analysis-engine.js';
import { sendToSplunk } from '../siem/splunk-client.js';
import { executeHuntQuery, getAvailableQueries } from '../hunting/query-engine.js';
import { correlateEvent } from '../correlation/correlation-engine.js';
import { appendEvent, appendIoc, getConfig, setConfig, getStats, getEvents, getAlerts, getIocs, updateAlert, getThreatCache } from '../shared/storage.js';
import { DEFAULT_CONFIG } from '../shared/constants.js';
import { domainMatches, extractDomain, isInternalBrowserUrl, normalizeDomain } from '../shared/utils.js';
import { normalizeConfig, validateConfig } from '../shared/config-validator.js';
import { RUNTIME_BUILD } from '../shared/runtime-build.js';
import { computeMitreHeatmap } from '../visualization/mitre-heatmap.js';
import { buildIncidentGraph } from '../visualization/incident-graph.js';

export let config = { ...DEFAULT_CONFIG };
let initPromise = null;
const recentEventKeys = new Map();
const EVENT_DEDUP_MS = 2000;

function mergeConfig(defaults, stored = {}) { return normalizeConfig({ ...defaults, ...stored, splunk:{...defaults.splunk,...(stored.splunk||{})}, alerts:{...defaults.alerts,...(stored.alerts||{})}, detection:{...defaults.detection,...(stored.detection||{})}, ai:{...defaults.ai,...(stored.ai||{})} }); }
function isDuplicateEvent(event = {}) { const key=[event.event||event.event_type||'unknown',event.url||'',event.domain||'',event.downloadId||'',Array.isArray(event.forms)?event.forms.length:''].join('|');const nowMs=Date.now();const previous=recentEventKeys.get(key);recentEventKeys.set(key,nowMs);for(const [storedKey,storedAt] of recentEventKeys)if(nowMs-storedAt>EVENT_DEDUP_MS)recentEventKeys.delete(storedKey);return previous!=null&&nowMs-previous<EVENT_DEDUP_MS; }

async function init() {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    let stored = null;
    try { stored = await getConfig(); } catch (err) { console.warn('[CyberSentinel] Config read skipped:', err?.message || err); }
    if (stored) config = mergeConfig(DEFAULT_CONFIG, stored);
    else { try { await setConfig(config); } catch (err) { console.warn('[CyberSentinel] Config persistence skipped:', err?.message || err); } }
    const errors = validateConfig(config); if (errors.length) console.warn('[CyberSentinel] Configuration warnings:', errors.join('; '));
    try { await sanitizeThreatCache(); } catch (err) { console.warn('[CyberSentinel] Threat-cache sanitization skipped:', err?.message || err); }
    try { chrome.alarms.create('threatFeedRefresh', { periodInMinutes: 60 }); } catch (err) { console.warn('[CyberSentinel] Alarm setup skipped:', err?.message || err); }
    console.info('[CyberSentinel] Runtime build:', { ...RUNTIME_BUILD, manifestVersion: chrome.runtime.getManifest().version });
    refreshThreatFeeds().catch((err) => console.warn('[CyberSentinel] Background threat-feed refresh failed:', err?.message || err));
    getThreatFeedStatus().then((feeds) => console.info('[CyberSentinel] Threat-feed status:', feeds)).catch((err) => console.warn('[CyberSentinel] Feed-status read failed:', err?.message || err));
  })();
  try { return await initPromise; } catch (err) { initPromise = null; throw err; }
}
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === 'threatFeedRefresh') refreshThreatFeeds().catch((err) => console.warn('[CyberSentinel] Scheduled feed refresh failed:', err?.message || err)); });

export async function processSecurityPipeline(rawEvent = {}, pageContext = {}) {
  if (!rawEvent || typeof rawEvent !== 'object') return { skipped:true, reason:'invalid_event' };
  if (isInternalBrowserUrl(rawEvent.url)) return { skipped:true, reason:'internal_browser_url' };
  if (isDuplicateEvent(rawEvent)) return { skipped:true, reason:'duplicate_event' };
  const domain=normalizeDomain(rawEvent.domain)||extractDomain(rawEvent.url||'');
  if(domain){const scope=config.detection?.monitoringScope||'all';const allowlist=config.detection?.allowlistDomains||[];const blocklist=config.detection?.blocklistDomains||[];if(scope==='allowlist'&&!allowlist.some(d=>domainMatches(domain,d)))return{skipped:true,reason:'not_in_allowlist'};if(scope==='blocklist'&&blocklist.some(d=>domainMatches(domain,d)))return{skipped:true,reason:'in_blocklist'};}
  const detections={};
  if(rawEvent.url){detections.domainIntel=await enrichDomainIntel(rawEvent.url);if(config.detection?.phishingEnabled!==false){detections.phishing=detectPhishing(rawEvent.url,pageContext);detections.loginPage=detectLoginPage(rawEvent.url,pageContext);}if(config.detection?.threatIntelEnabled!==false)detections.threatIntel=await checkReputation(rawEvent.url);}
  if(rawEvent.redirectChain&&config.detection?.phishingEnabled!==false)detections.redirectAnalysis=analyzeRedirectChain(rawEvent.redirectChain);
  if(pageContext.scripts&&config.detection?.scriptAnalysisEnabled!==false)detections.scriptAnalysis=analyzeScriptsFromPage(pageContext.scripts);
  if((rawEvent.isCredentialForm||rawEvent.hasPassword)&&config.detection?.formMonitoringEnabled!==false)detections.credentialHarvesting=detectCredentialHarvesting(rawEvent.url||'',{...pageContext,...rawEvent,reputation:detections.threatIntel?.malicious?'malicious':'unknown',isSuspiciousTld:detections.domainIntel?.isSuspiciousTld,impersonatedBrand:detections.phishing?.impersonatedBrand});
  if(rawEvent.event==='download')detections.malwareDelivery=analyzeMalwareDelivery(rawEvent);
  const aiCandidate=Boolean(config.ai?.enabled&&rawEvent.url&&(detections.phishing?.classification==='phishing'||detections.phishing?.classification==='suspicious'||detections.loginPage?.isPotentialPhishing||detections.domainIntel?.isSuspiciousTld||detections.domainIntel?.isPunycode||detections.credentialHarvesting?.detected||detections.malwareDelivery?.detected||rawEvent.event==='suspicious_script'||rawEvent.event==='download'));if(aiCandidate)detections.ai=await analyzeWithAi({...pageContext,url:rawEvent.url},config);
  let enrichedEvent={...rawEvent,domain,threat_intel_hit:Boolean(detections.threatIntel?.malicious),detections:{phishing:detections.phishing?.classification,credentialHarvesting:Boolean(detections.credentialHarvesting?.detected),malwareDelivery:Boolean(detections.malwareDelivery?.detected)}};
  const correlation=await correlateEvent(enrichedEvent,detections);if(correlation)enrichedEvent={...enrichedEvent,incident_id:correlation.incident_id,correlation};
  const scoring=scoreEvent({...enrichedEvent,...detections.domainIntel},detections);const mitre=mapToMitre(enrichedEvent,detections);const evidence=[];
  if(rawEvent.event==='credential_form_detected'){if(rawEvent.hasPassword)evidence.push('password field found');const currentDomain=rawEvent.domain||(rawEvent.url?extractDomain(rawEvent.url):'');if(Array.isArray(rawEvent.forms)){const hasExternalSubmit=rawEvent.forms.some(f=>{if(!f.action)return false;try{return new URL(f.action,rawEvent.url).hostname!==currentDomain;}catch{return false;}});if(hasExternalSubmit)evidence.push('external submit action');}}
  enrichedEvent={...enrichedEvent,risk_score:scoring.risk_score,risk_level:scoring.risk_level,technique:mitre.technique,techniques:mitre.techniques,threat_feed:detections.threatIntel?.entity||null,evidence:evidence.length?evidence:undefined};
  await appendEvent(enrichedEvent);const iocs=generateIocs(enrichedEvent,detections);for(const ioc of iocs)await appendIoc(ioc);if(shouldAlert(scoring,config))await createAlert(enrichedEvent,scoring,mitre,detections,config);if(config.splunk?.enabled)await sendToSplunk(enrichedEvent,scoring,mitre,config);return{event:enrichedEvent,scoring,mitre,detections,iocs};
}
async function getMitreHeatmap(limit = 500) { const events = await getEvents({ limit }); return computeMitreHeatmap(events); }
async function getIncidentGraph(limit = 500) { const events = await getEvents({ limit }); return buildIncidentGraph(events); }
async function getIocExplorer({ limit = 200, search = '', type = '', reputation = '' } = {}) {
  const [iocs, threatCache] = await Promise.all([getIocs(limit), getThreatCache()]);
  const reputationLookup = (value) => {
    if (threatCache?.urls?.[value] || threatCache?.domains?.[value] || threatCache?.ips?.[value]) return 'malicious';
    return 'unknown';
  };
  let enriched = iocs.map((ioc) => ({ ...ioc, reputation: reputationLookup(ioc.value) }));
  if (search) { const needle = search.toLowerCase(); enriched = enriched.filter((i) => i.value?.toLowerCase().includes(needle) || i.context?.toLowerCase().includes(needle)); }
  if (type) enriched = enriched.filter((i) => i.ioc_type === type);
  if (reputation) enriched = enriched.filter((i) => i.reputation === reputation);
  return enriched;
}
function safeHandleEvent(event){handleCollectedEvent(event).catch(err=>console.error('[CyberSentinel] Unhandled pipeline error:',err));}
async function handleCollectedEvent(event){try{await processSecurityPipeline(event);}catch(err){console.error('[CyberSentinel] Pipeline error:',err);try{await appendEvent(event);}catch(storeErr){console.error('[CyberSentinel] Failed to store event:',storeErr);}}}
initUrlCollector(safeHandleEvent);initDownloadMonitor(safeHandleEvent);initExtensionMonitor(safeHandleEvent);
chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{handleMessage(message,sender).then(sendResponse).catch(err=>sendResponse({error:err.message}));return true;});
async function handleMessage(message={},sender){if(!message||typeof message.type!=='string'||message.type.length>64)return{error:'invalid_message'};switch(message.type){case'FORM_DETECTED':{let domain=message.domain;try{if(sender.tab?.url)domain=new URL(sender.tab.url).hostname;}catch{domain=message.domain||'';}return processSecurityPipeline(processFormDetection({...message,url:sender.tab?.url||message.url,domain}),message);}case'PERMISSION_DETECTED':return processSecurityPipeline(processPermissionMessage(message));case'SCRIPT_ANALYSIS':return processSecurityPipeline({event:'suspicious_script',url:message.url,domain:message.domain,timestamp:message.timestamp},message);case'PAGE_ANALYSIS':return processSecurityPipeline({event:'url_visit',url:message.url,domain:message.domain,timestamp:message.timestamp},message);case'GET_STATS':return getStats();case'GET_EVENTS':return getEvents(message.filter||{});case'GET_ALERTS':return getAlerts(message.limit);case'UPDATE_ALERT':return updateAlert(message.id,message.patch||{});case'GET_IOCS':return getIocs(message.limit);case'GET_IOC_EXPLORER':return getIocExplorer(message.filter||{});case'GET_MITRE_HEATMAP':return getMitreHeatmap(message.limit);case'GET_INCIDENT_GRAPH':return getIncidentGraph(message.limit);case'EXPORT_STIX':return buildStixBundle(await getIocs(1000),{source:'CyberSentinel dashboard'});case'GET_FEED_STATUS':return getThreatFeedStatus();case'GET_CONFIG':return config;case'SET_CONFIG':{const nextConfig=mergeConfig(DEFAULT_CONFIG,message.config||config);const errors=validateConfig(nextConfig);if(errors.length)return{ok:false,errors};config=nextConfig;try{await setConfig(config);}catch(err){console.warn('[CyberSentinel] Config persistence failed:',err?.message||err);}return{ok:true,config};}case'HUNT_QUERY':return executeHuntQuery(message.query);case'GET_HUNT_QUERIES':return getAvailableQueries();default:return{error:'unknown_message_type'};}}
chrome.runtime.onInstalled.addListener(()=>init().then(()=>console.log('[CyberSentinel] SIEM extension initialized')).catch(err=>console.error('[CyberSentinel] Init failed:',err)));chrome.runtime.onStartup.addListener(()=>init().catch(err=>console.error('[CyberSentinel] Startup init failed:',err)));init().catch(err=>console.error('[CyberSentinel] Init failed:',err));
