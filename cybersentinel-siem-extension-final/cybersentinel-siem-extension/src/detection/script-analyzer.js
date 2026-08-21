const DANGEROUS_PATTERNS = [
  { pattern: /\beval\s*\(/g, name: 'eval', weight: 25 },
  { pattern: /\batob\s*\(/g, name: 'atob', weight: 15 },
  { pattern: /\bbtoa\s*\(/g, name: 'btoa', weight: 10 },
  { pattern: /document\.write\s*\(/g, name: 'document.write', weight: 20 },
  { pattern: /fromCharCode/g, name: 'fromCharCode', weight: 15 },
  { pattern: /unescape\s*\(/g, name: 'unescape', weight: 15 },
  { pattern: /new\s+Function\s*\(/g, name: 'new Function', weight: 25 },
  { pattern: /crypto\s*\.\s*getRandomValues/g, name: 'crypto_random', weight: 5 },
  { pattern: /coinhive|cryptonight|minero|webmine/i, name: 'crypto_miner', weight: 40 },
  { pattern: /XMLHttpRequest|fetch\s*\(/g, name: 'network_request', weight: 5 }
];

const OBFUSCATION_INDICATORS = [
  /\\x[0-9a-fA-F]{2}/g,
  /\\u[0-9a-fA-F]{4}/g,
  /[A-Za-z0-9+/]{50,}={0,2}/g,
  /(?:eval|Function)\s*\(\s*['"][^'"]{100,}['"]/g
];

export function analyzeScriptContent(scriptContent, sourceUrl = '') {
  if (!scriptContent || scriptContent.length < 10) {
    return { isSuspicious: false, detections: [], obfuscated: false };
  }

  const detections = [];
  let totalWeight = 0;

  for (const { pattern, name, weight } of DANGEROUS_PATTERNS) {
    const matches = scriptContent.match(pattern);
    if (matches) {
      detections.push({ name, count: matches.length, weight });
      totalWeight += weight * Math.min(matches.length, 3);
    }
  }

  let obfuscationScore = 0;
  for (const pattern of OBFUSCATION_INDICATORS) {
    const matches = scriptContent.match(pattern);
    if (matches) obfuscationScore += matches.length;
  }
  const obfuscated = obfuscationScore >= 3 || (scriptContent.length > 5000 && detections.some((d) => d.name === 'eval'));

  if (obfuscated) {
    detections.push({ name: 'obfuscation', count: obfuscationScore, weight: 30 });
    totalWeight += 30;
  }

  const base64Payloads = (scriptContent.match(/[A-Za-z0-9+/]{80,}={0,2}/g) || []).length;
  if (base64Payloads > 0) {
    detections.push({ name: 'base64_payload', count: base64Payloads, weight: 20 });
    totalWeight += 20;
  }

  return {
    isSuspicious: totalWeight >= 25 || obfuscated,
    detections,
    obfuscated,
    obfuscationScore,
    sourceUrl,
    scriptLength: scriptContent.length,
    totalWeight
  };
}

export function analyzeScriptsFromPage(scripts) {
  const results = scripts.map((s) => analyzeScriptContent(s.content, s.src || s.inline));
  const suspicious = results.filter((r) => r.isSuspicious);
  return {
    totalScripts: scripts.length,
    suspiciousCount: suspicious.length,
    results: suspicious,
    hasObfuscation: suspicious.some((r) => r.obfuscated),
    hasCryptoMiner: suspicious.some((r) => r.detections.some((d) => d.name === 'crypto_miner'))
  };
}
