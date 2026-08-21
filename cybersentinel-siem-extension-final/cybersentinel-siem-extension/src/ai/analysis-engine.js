import { BRAND_KEYWORDS } from '../shared/constants.js';
import { detectBrandInDomain, extractDomain, isLegitimateDomain } from '../shared/utils.js';
import { sanitizeUrl } from '../shared/event-schema.js';

const AI_TIMEOUT_MS = 7000;
const MAX_HTML = 5000;
const MAX_SCRIPT_SAMPLES = 3;
const MAX_SCRIPT_LENGTH = 2000;
const SECRET_PATTERN = /(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|otp|session)\s*[:=]\s*['\"]?[^\s,'\";}]+/gi;

function sanitizeText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value.slice(0, maxLength).replace(SECRET_PATTERN, '$1=[REDACTED]');
}

function buildSafeContext(context = {}) {
  return {
    url: sanitizeUrl(context.url || ''),
    html: sanitizeText(context.html, MAX_HTML),
    forms: Array.isArray(context.forms) ? context.forms.slice(0, 20).map((form) => ({
      action: sanitizeUrl(form.action || ''),
      method: sanitizeText(form.method, 20),
      hasPassword: Boolean(form.hasPassword),
      hasUsername: Boolean(form.hasUsername)
    })) : [],
    scripts: Array.isArray(context.scripts) ? context.scripts.slice(0, MAX_SCRIPT_SAMPLES).map((script) => sanitizeText(typeof script === 'string' ? script : script?.content || '', MAX_SCRIPT_LENGTH)) : [],
    pageTitle: sanitizeText(context.pageTitle, 500)
  };
}

function validateAiResult(result) {
  if (!result || typeof result !== 'object') return null;
  const classification = ['benign', 'suspicious', 'phishing'].includes(result.classification) ? result.classification : null;
  if (!classification) return null;
  const confidence = Number(result.confidence);
  return { classification, confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(100, confidence)) : 0, signals: Array.isArray(result.signals) ? result.signals.slice(0, 20).map((signal) => String(signal).slice(0, 200)) : [], method: 'external_ai' };
}

export async function analyzeWithAi(context, config) {
  if (!config?.ai?.enabled || !config?.ai?.endpoint) return analyzeHeuristic(context);
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const safeContext = buildSafeContext(context);
    const response = await fetch(config.ai.endpoint, { method:'POST', headers:{'Content-Type':'application/json', ...(config.ai.apiKey ? { Authorization:`Bearer ${config.ai.apiKey}` } : {})}, body:JSON.stringify(safeContext), signal:controller.signal });
    if (response.ok) { const result = validateAiResult(await response.json()); if (result) return result; }
  } catch (err) { console.warn('[CyberSentinel] AI analysis failed, using heuristic:', err?.name === 'AbortError' ? 'timeout' : err?.message || err); }
  finally { clearTimeout(timeoutId); }
  return analyzeHeuristic(context);
}

function analyzeHeuristic(context) {
  const domain = extractDomain(context.url || ''); const brand = detectBrandInDomain(domain); let score = 0; const signals = [];
  if (brand && context.hasLoginForm && !isLegitimateDomain(domain)) { score += 40; signals.push('brand_login_form'); }
  if (context.pageTitle) for (const kw of BRAND_KEYWORDS) { if (context.pageTitle.toLowerCase().includes(kw) && !domain.includes(kw)) { score += 25; signals.push('title_domain_mismatch'); break; } }
  if (context.hasObfuscatedScript) { score += 20; signals.push('obfuscated_script'); }
  if (context.forms?.some((f) => f.hasPassword)) { score += 15; signals.push('password_field'); }
  const classification = score >= 50 ? 'phishing' : score >= 25 ? 'suspicious' : 'benign';
  return { classification, confidence: Math.min(96, score + signals.length * 5), signals, method:'heuristic' };
}

export async function analyzeScreenshot(imageData, config) {
  if (!config?.ai?.enabled || !config?.ai?.endpoint) return { analysis:'screenshot_capture_only', brandImpersonation:false, fakeLogo:false, method:'disabled' };
  if (typeof imageData !== 'string' || !imageData.startsWith('data:image/')) return { analysis:'invalid_image', brandImpersonation:false, fakeLogo:false, method:'validation' };
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const response = await fetch(config.ai.endpoint, { method:'POST', headers:{'Content-Type':'application/json', ...(config.ai.apiKey ? { Authorization:`Bearer ${config.ai.apiKey}` } : {})}, body:JSON.stringify({ task:'visual_phishing_analysis', image:imageData.slice(0,2000000) }), signal:controller.signal });
    if (response.ok) { const result = await response.json(); return { analysis:String(result.analysis || result.classification || 'completed').slice(0,500), brandImpersonation:Boolean(result.brandImpersonation), fakeLogo:Boolean(result.fakeLogo), confidence:Math.max(0,Math.min(100,Number(result.confidence)||0)), method:'external_ai' }; }
  } catch (err) { console.warn('[CyberSentinel] AI screenshot analysis failed:', err?.name === 'AbortError' ? 'timeout' : err?.message || err); }
  finally { clearTimeout(timeoutId); }
  return { analysis:'ai_unavailable', brandImpersonation:false, fakeLogo:false, method:'fallback' };
}
