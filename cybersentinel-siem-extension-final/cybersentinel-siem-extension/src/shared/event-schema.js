import { extractDomain, normalizeDomain, now } from './utils.js';

export const EVENT_SCHEMA_VERSION = 3;

const SENSITIVE_QUERY_KEYS = new Set([
  'password', 'pass', 'passwd', 'pwd', 'token', 'access_token', 'refresh_token',
  'id_token', 'auth', 'authorization', 'api_key', 'apikey', 'key', 'secret',
  'code', 'otp', 'mfa', 'session', 'sessionid', 'sid', 'cookie', 'credential'
]);

const SENSITIVE_FIELD_NAMES = /(password|passwd|passcode|pwd|token|secret|authorization|cookie|otp|mfa|session|credential|inputvalue|fieldvalue|authvalue|apikey|api_key)/i;
const URL_FIELD_NAMES = /^(url|sourceurl|targeturl|pageurl|referrer|action|href|src|link|endpoint)$/i;
const MAX_STRING_LENGTH = 10000;
const MAX_ARRAY_ITEMS = 100;
const MAX_OBJECT_KEYS = 100;

export function sanitizeUrl(value) {
  if (!value) return value;
  try {
    const url = new URL(String(value));
    url.username = '';
    url.password = '';
    for (const key of [...url.searchParams.keys()]) {
      if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) url.searchParams.set(key, '[REDACTED]');
    }
    url.hash = '';
    return url.toString();
  } catch {
    return String(value).replace(/[?#].*$/, '');
  }
}

function sanitizeValue(value, key = '') {
  if (SENSITIVE_FIELD_NAMES.test(key)) return '[REDACTED]';
  if (typeof value === 'string') {
    const bounded = value.length > MAX_STRING_LENGTH ? `${value.slice(0, MAX_STRING_LENGTH)}...[TRUNCATED]` : value;
    return URL_FIELD_NAMES.test(key) ? sanitizeUrl(bounded) : bounded;
  }
  if (Array.isArray(value)) return value.slice(0, MAX_ARRAY_ITEMS).map((item) => sanitizeValue(item, key));
  if (value && typeof value === 'object') {
    const result = {};
    for (const [childKey, childValue] of Object.entries(value).slice(0, MAX_OBJECT_KEYS)) result[childKey] = sanitizeValue(childValue, childKey);
    return result;
  }
  return value;
}

export function sanitizeEventForStorage(event = {}) {
  const sanitized = sanitizeValue(event);
  const urlFields = ['url', 'sourceUrl', 'targetUrl', 'pageUrl', 'referrer'];
  for (const field of urlFields) if (sanitized[field]) sanitized[field] = sanitizeUrl(sanitized[field]);
  if (sanitized.domain) sanitized.domain = normalizeDomain(sanitized.domain);
  if (sanitized.url && !sanitized.domain) sanitized.domain = extractDomain(sanitized.url);
  return sanitized;
}

export function normalizeSecurityEvent(event = {}, source = 'browser') {
  const sanitized = sanitizeEventForStorage(event);
  return {
    schema_version: EVENT_SCHEMA_VERSION,
    event_id: sanitized.event_id || crypto.randomUUID(),
    timestamp: sanitized.timestamp || now(),
    source: sanitized.source || source,
    event_type: sanitized.event_type || sanitized.event || 'unknown',
    ...sanitized
  };
}
