import { now } from '../shared/utils.js';
import { sanitizeEventForStorage } from '../shared/event-schema.js';

const HEC_TIMEOUT_MS = 5000;

export async function sendToSplunk(event, scoring, mitre, config) {
  if (!config?.splunk?.enabled || !config?.splunk?.hecUrl || !config?.splunk?.hecToken) return { sent:false, reason:'splunk_not_configured' };
  const payload = buildSplunkEvent(event, scoring, mitre, config);
  const url = config.splunk.hecUrl.replace(/\/$/, '') + '/services/collector/event';
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), HEC_TIMEOUT_MS);
  try {
    const response = await fetch(url, { method:'POST', headers:{ Authorization:`Splunk ${config.splunk.hecToken}`, 'Content-Type':'application/json' }, body:JSON.stringify(payload), signal:controller.signal });
    return { sent:response.ok, status:response.status };
  } catch (err) { const reason=err?.name==='AbortError'?'timeout':err?.message||'request_failed'; console.error('[CyberSentinel] Splunk HEC failed:',reason); return { sent:false,error:reason }; }
  finally { clearTimeout(timeoutId); }
}

function buildSplunkEvent(event, scoring, mitre, config) {
  const safeEvent = sanitizeEventForStorage(event);
  return { time:Math.floor(Date.now()/1000), host:'cybersentinel-browser', source:'cybersentinel-extension', sourcetype:config.splunk.sourcetype||'cybersentinel:browser', index:config.splunk.index||'cybersentinel', event:{ event_id:safeEvent.id||safeEvent.event_id, event_type:safeEvent.event_type||safeEvent.event, timestamp:safeEvent.timestamp||now(), incident_id:safeEvent.incident_id||null, risk_score:scoring.risk_score, risk_level:scoring.risk_level, technique:mitre.technique, techniques:mitre.techniques, domain:safeEvent.domain, url:safeEvent.url, threat_intel_hit:Boolean(safeEvent.threat_intel_hit), threat_feed:safeEvent.threat_feed||null, evidence:safeEvent.evidence||[], correlation:safeEvent.correlation||null, factors:scoring.factors, detections:safeEvent.detections||{}, raw:safeEvent } };
}

export async function sendToElastic(event, scoring, mitre, endpoint) {
  if (!endpoint) return { sent:false };
  try {
    const safeEvent=sanitizeEventForStorage(event);
    const controller=new AbortController(); const timeoutId=setTimeout(()=>controller.abort(),HEC_TIMEOUT_MS);
    const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({'@timestamp':safeEvent.timestamp||now(),event:{kind:'alert',category:['web'],type:['info'],dataset:'cybersentinel.browser'},cybersentinel:{event_id:safeEvent.id||safeEvent.event_id,event_type:safeEvent.event,incident_id:safeEvent.incident_id||null,risk_score:scoring.risk_score,risk_level:scoring.risk_level,mitre_technique:mitre.technique,threat_intel_hit:Boolean(safeEvent.threat_intel_hit),threat_feed:safeEvent.threat_feed||null},url:{full:safeEvent.url,domain:safeEvent.domain}}),signal:controller.signal});
    clearTimeout(timeoutId); return { sent:response.ok };
  } catch { return { sent:false }; }
}

export async function sendToWazuh(event, scoring, mitre, endpoint) { return sendToElastic(event, scoring, mitre, endpoint); }
