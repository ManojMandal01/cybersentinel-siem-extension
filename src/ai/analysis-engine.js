import { BRAND_KEYWORDS } from '../shared/constants.js';
import { detectBrandInDomain, extractDomain } from '../shared/utils.js';

export async function analyzeWithAi(context, config) {
  if (!config?.ai?.enabled || !config?.ai?.endpoint) {
    return analyzeHeuristic(context);
  }

  try {
    const response = await fetch(config.ai.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(config.ai.apiKey ? { Authorization: `Bearer ${config.ai.apiKey}` } : {})
      },
      body: JSON.stringify({
        url: context.url,
        html: context.html?.slice(0, 5000),
        forms: context.forms,
        scripts: context.scripts?.slice(0, 3),
        pageTitle: context.pageTitle
      })
    });

    if (response.ok) {
      return await response.json();
    }
  } catch (err) {
    console.warn('[CyberSentinel] AI analysis failed, using heuristic:', err);
  }

  return analyzeHeuristic(context);
}

function analyzeHeuristic(context) {
  const domain = extractDomain(context.url || '');
  const brand = detectBrandInDomain(domain);
  let score = 0;
  const signals = [];

  if (brand && context.hasLoginForm) {
    score += 40;
    signals.push('brand_login_form');
  }
  if (context.pageTitle) {
    for (const kw of BRAND_KEYWORDS) {
      if (context.pageTitle.toLowerCase().includes(kw) && !domain.includes(kw)) {
        score += 25;
        signals.push('title_domain_mismatch');
        break;
      }
    }
  }
  if (context.hasObfuscatedScript) {
    score += 20;
    signals.push('obfuscated_script');
  }
  if (context.forms?.some((f) => f.hasPassword)) {
    score += 15;
    signals.push('password_field');
  }

  const classification = score >= 50 ? 'phishing' : score >= 25 ? 'suspicious' : 'benign';

  return {
    classification,
    confidence: Math.min(96, score + signals.length * 5),
    signals,
    method: 'heuristic'
  };
}

export async function analyzeScreenshot(imageData, config) {
  if (!config?.ai?.enabled) {
    return { analysis: 'screenshot_capture_only', brandImpersonation: false, fakeLogo: false };
  }
  return {
    analysis: 'pending_ai_integration',
    brandImpersonation: false,
    fakeLogo: false,
    note: 'Connect AI vision endpoint in config for screenshot analysis'
  };
}
