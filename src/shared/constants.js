export const EVENT_TYPES = {
  URL_VISIT: 'url_visit',
  URL_REDIRECT: 'url_redirect',
  TAB_OPENED: 'tab_opened',
  TAB_CLOSED: 'tab_closed',
  DOWNLOAD: 'download',
  CREDENTIAL_FORM: 'credential_form_detected',
  PERMISSION_ACCESS: 'permission_access',
  EXTENSION_CHANGE: 'extension_change',
  SCRIPT_SUSPICIOUS: 'suspicious_script',
  PHISHING_DETECTED: 'phishing_detected',
  CREDENTIAL_HARVESTING: 'credential_harvesting',
  MALWARE_DELIVERY: 'malware_delivery',
  THREAT_INTEL_HIT: 'threat_intel_hit',
  ALERT: 'alert',
  IOC_CREATED: 'ioc_created'
};

export const RISK_WEIGHTS = {
  SUSPICIOUS_DOMAIN: 25,
  LOGIN_FORM: 20,
  OBFUSCATED_JS: 30,
  MALICIOUS_REPUTATION: 25,
  TYPOSQUATTING: 30,
  HOMOGRAPH: 35,
  NEW_DOMAIN: 20,
  SUSPICIOUS_TLD: 15,
  SUSPICIOUS_DOWNLOAD: 25,
  REDIRECT_CHAIN: 15,
  BRAND_IMPERSONATION: 30,
  CREDENTIAL_ON_UNKNOWN_DOMAIN: 35
};

export const RISK_LEVELS = {
  LOW: { min: 0, max: 25, label: 'Low' },
  MEDIUM: { min: 26, max: 50, label: 'Medium' },
  HIGH: { min: 51, max: 75, label: 'High' },
  CRITICAL: { min: 76, max: 100, label: 'Critical' }
};

export const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.club', '.work', '.click', '.link', '.gq', '.ml',
  '.cf', '.tk', '.ga', '.buzz', '.rest', '.monster', '.sbs', '.cam'
]);

export const SUSPICIOUS_EXTENSIONS = new Set([
  '.exe', '.msi', '.zip', '.rar', '.js', '.bat', '.vbs', '.ps1',
  '.scr', '.cmd', '.hta', '.jar', '.iso', '.dmg'
]);

export const BRAND_KEYWORDS = [
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
  'instagram', 'netflix', 'chase', 'wellsfargo', 'bankofamerica',
  'office365', 'outlook', 'dropbox', 'linkedin', 'twitter', 'coinbase'
];

export const LEGITIMATE_DOMAINS = {
  paypal: ['paypal.com'],
  google: ['google.com', 'gmail.com', 'youtube.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'aws.amazon.com'],
  facebook: ['facebook.com', 'fb.com', 'meta.com'],
  netflix: ['netflix.com'],
  chase: ['chase.com'],
  coinbase: ['coinbase.com']
};

export const MITRE_TECHNIQUES = {
  PHISHING: 'T1566',
  JS_PAYLOAD: 'T1059',
  OBFUSCATION: 'T1027',
  CREDENTIAL_THEFT: 'T1056',
  TOOL_DOWNLOAD: 'T1105',
  BRUTE_FORCE: 'T1110',
  DATA_FROM_LOCAL: 'T1005'
};

export const THREAT_FEEDS = {
  OPENPHISH: {
    name: 'OpenPhish',
    url: 'https://openphish.com/feed.txt',
    type: 'url'
  },
  PHISHTANK: {
    name: 'PhishTank',
    url: 'https://data.phishtank.com/data/online-valid.json',
    type: 'url'
  }
};

export const STORAGE_KEYS = {
  EVENTS: 'cybersentinel_events',
  ALERTS: 'cybersentinel_alerts',
  IOCS: 'cybersentinel_iocs',
  CONFIG: 'cybersentinel_config',
  THREAT_CACHE: 'cybersentinel_threat_cache',
  BASELINE: 'cybersentinel_baseline'
};

export const DEFAULT_CONFIG = {
  splunk: {
    enabled: false,
    hecUrl: '',
    hecToken: '',
    index: 'cybersentinel',
    sourcetype: 'cybersentinel:browser'
  },
  alerts: {
    browserPopup: true,
    discordWebhook: '',
    email: ''
  },
  detection: {
    phishingEnabled: true,
    scriptAnalysisEnabled: true,
    formMonitoringEnabled: true,
    threatIntelEnabled: true
  },
  ai: {
    enabled: false,
    endpoint: '',
    apiKey: ''
  }
};
