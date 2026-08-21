import { clearIndexedThreatCache } from '../src/intel/threat-cache-store.js';

const mockStorage = {
  cybersentinel_config: {
    splunk: { enabled: false },
    alerts: { browserPopup: false },
    detection: {
      phishingEnabled: true,
      scriptAnalysisEnabled: true,
      formMonitoringEnabled: true,
      threatIntelEnabled: true,
      monitoringScope: 'all',
      allowlistDomains: [],
      blocklistDomains: []
    }
  },
  cybersentinel_events: [],
  cybersentinel_alerts: [],
  cybersentinel_iocs: [],
  cybersentinel_threat_cache: { urls: {}, domains: {}, ips: {}, feeds: {}, lastUpdated: null },
  cybersentinel_threat_cache_migrated_v2: false
};

const stub = { addListener: () => {}, removeListener: () => {} };

globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => typeof key === 'string'
        ? { [key]: mockStorage[key] }
        : Array.isArray(key)
          ? Object.fromEntries(key.map((item) => [item, mockStorage[item]]))
          : { ...mockStorage },
      set: async (values) => Object.assign(mockStorage, values),
      remove: async (key) => {
        for (const item of (Array.isArray(key) ? key : [key])) delete mockStorage[item];
      }
    }
  },
  runtime: {
    getURL: (path) => path,
    getManifest: () => ({ version: '0.2.3' }),
    onMessage: stub,
    onInstalled: stub,
    onStartup: stub
  },
  webNavigation: { onCommitted: stub, onBeforeNavigate: stub },
  tabs: { onCreated: stub, onRemoved: stub, get: async () => ({}) },
  downloads: { onCreated: stub, onChanged: stub },
  permissions: { contains: (options, callback) => callback(true) },
  management: { onInstalled: stub, onEnabled: stub, onDisabled: stub },
  alarms: { create: () => {}, onAlarm: stub },
  notifications: { create: async () => {} }
};

await clearIndexedThreatCache();

globalThis.fetch = async (url) => {
  const value = String(url);
  if (value.includes('dns.google')) {
    return { ok: true, status: 200, json: async () => ({ Answer: [{ type: 1, data: '203.0.113.10' }] }) };
  }
  if (value.includes('raw.githubusercontent.com/openphish/public_feed')) {
    return { ok: true, status: 200, url: value, text: async () => 'https://test-phish.xyz/login\n' };
  }
  if (value.includes('urlhaus.abuse.ch')) {
    return {
      ok: true,
      status: 200,
      url: value,
      text: async () => '# urlhaus\n"1","2026-01-01 00:00:00","https://github.com/owner/repo/releases/download/v1/tool.zip","online","threat"\n'
    };
  }
  return { ok: true, status: 200, url: value, text: async () => '', json: async () => ({}) };
};
