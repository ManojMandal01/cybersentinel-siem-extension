import { now } from '../shared/utils.js';

export async function sendToSplunk(event, scoring, mitre, config) {
  if (!config?.splunk?.enabled || !config?.splunk?.hecUrl || !config?.splunk?.hecToken) {
    return { sent: false, reason: 'splunk_not_configured' };
  }

  const payload = buildSplunkEvent(event, scoring, mitre, config);

  try {
    const url = config.splunk.hecUrl.replace(/\/$/, '') + '/services/collector/event';
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Splunk ${config.splunk.hecToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    return { sent: response.ok, status: response.status };
  } catch (err) {
    console.error('[CyberSentinel] Splunk HEC failed:', err);
    return { sent: false, error: err.message };
  }
}

function buildSplunkEvent(event, scoring, mitre, config) {
  return {
    time: Math.floor(Date.now() / 1000),
    host: 'cybersentinel-browser',
    source: 'cybersentinel-extension',
    sourcetype: config.splunk.sourcetype || 'cybersentinel:browser',
    index: config.splunk.index || 'cybersentinel',
    event: {
      event_type: event.event_type || event.event,
      risk_score: scoring.risk_score,
      risk_level: scoring.risk_level,
      technique: mitre.technique,
      techniques: mitre.techniques,
      domain: event.domain,
      url: event.url,
      timestamp: event.timestamp || now(),
      factors: scoring.factors,
      raw: event
    }
  };
}

export async function sendToElastic(event, scoring, mitre, endpoint) {
  if (!endpoint) return { sent: false };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        '@timestamp': event.timestamp || now(),
        event: {
          kind: 'alert',
          category: ['web'],
          type: ['info'],
          dataset: 'cybersentinel.browser'
        },
        cybersentinel: {
          event_type: event.event,
          risk_score: scoring.risk_score,
          risk_level: scoring.risk_level,
          mitre_technique: mitre.technique
        },
        url: { full: event.url, domain: event.domain }
      })
    });
    return { sent: response.ok };
  } catch {
    return { sent: false };
  }
}

export async function sendToWazuh(event, scoring, mitre, endpoint) {
  return sendToElastic(event, scoring, mitre, endpoint);
}
