function validRemoteUrl(value, field) {
  if (!value) return null;
  try {
    const url = new URL(String(value));
    if (!['http:', 'https:'].includes(url.protocol)) return `${field} must use http or https`;
    if (url.username || url.password) return `${field} must not contain embedded credentials`;
    return null;
  } catch {
    return `${field} must be a valid URL`;
  }
}

function normalizeDomains(value) {
  return [...new Set((Array.isArray(value) ? value : [])
    .map((domain) => String(domain).trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 500))];
}

export function validateConfig(config = {}) {
  const errors = [];
  for (const [section, fields] of Object.entries({
    splunk: ['hecUrl'],
    ai: ['endpoint'],
    alerts: ['discordWebhook']
  })) {
    for (const field of fields) {
      if (config[section]?.[field]) {
        const error = validRemoteUrl(config[section][field], `${section}.${field}`);
        if (error) errors.push(error);
      }
    }
  }
  if (config.splunk?.enabled && (!config.splunk.hecUrl || !config.splunk.hecToken)) errors.push('splunk requires HEC URL and token when enabled');
  if (config.ai?.enabled && !config.ai.endpoint) errors.push('ai requires an endpoint when enabled');
  if (typeof config.splunk?.index === 'string' && !/^[A-Za-z0-9_.:-]{1,100}$/.test(config.splunk.index)) errors.push('splunk.index contains unsupported characters');
  if (!['all', 'allowlist', 'blocklist'].includes(config.detection?.monitoringScope || 'all')) errors.push('detection.monitoringScope is invalid');
  return errors;
}

export function normalizeConfig(config = {}) {
  const normalized = typeof structuredClone === 'function' ? structuredClone(config) : JSON.parse(JSON.stringify(config));
  normalized.splunk ||= {};
  normalized.alerts ||= {};
  normalized.detection ||= {};
  normalized.ai ||= {};
  normalized.splunk.hecUrl = String(normalized.splunk.hecUrl || '').trim();
  normalized.splunk.hecToken = String(normalized.splunk.hecToken || '').trim().slice(0, 500);
  normalized.splunk.index = String(normalized.splunk.index || 'cybersentinel').trim().slice(0, 100);
  normalized.alerts.discordWebhook = String(normalized.alerts.discordWebhook || '').trim();
  normalized.ai.endpoint = String(normalized.ai.endpoint || '').trim();
  normalized.ai.apiKey = String(normalized.ai.apiKey || '').trim().slice(0, 1000);
  normalized.detection.allowlistDomains = normalizeDomains(normalized.detection.allowlistDomains);
  normalized.detection.blocklistDomains = normalizeDomains(normalized.detection.blocklistDomains);
  return normalized;
}
