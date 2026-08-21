(function () {
  'use strict';

  function getDomain() {
    return window.location.hostname;
  }

  let lastFieldsSerialized = '';

  function scanForms() {
    const forms = document.querySelectorAll('form');
    const fields = [];

    document.querySelectorAll('input, textarea, select').forEach((el) => {
      fields.push({
        type: el.type || el.tagName.toLowerCase(),
        name: el.name || '',
        id: el.id || '',
        autocomplete: el.autocomplete || ''
      });
    });

    if (fields.length === 0) return;

    const fieldsSerialized = JSON.stringify(fields);
    if (fieldsSerialized === lastFieldsSerialized) return;
    lastFieldsSerialized = fieldsSerialized;

    const hasPassword = fields.some((f) => f.type === 'password');
    const hasLogin = hasPassword || fields.some((f) =>
      /user|email|login/i.test(f.name || f.id || '')
    );

    if (hasLogin || hasPassword) {
      chrome.runtime.sendMessage({
        type: 'FORM_DETECTED',
        timestamp: new Date().toISOString(),
        domain: getDomain(),
        url: window.location.href,
        pageTitle: document.title,
        fields,
        forms: Array.from(forms).map((f) => ({ action: f.action || '' })),
        hasPassword,
        hasLoginForm: hasLogin
      });
    }
  }

  function scanScripts() {
    const scripts = [];
    const inlineScripts = document.querySelectorAll('script:not([src])');

    inlineScripts.forEach((script, i) => {
      const content = script.textContent || '';
      if (content.length > 50) {
        scripts.push({ content: content.slice(0, 10000), inline: `inline-${i}` });
      }
    });

    document.querySelectorAll('script[src]').forEach((script) => {
      scripts.push({ content: '', src: script.src });
    });

    if (scripts.length === 0) return;

    const dangerous = /eval\s*\(|atob\s*\(|document\.write|coinhive|cryptonight/i;
    const hasObfuscated = scripts.some((s) =>
      dangerous.test(s.content) || /\\x[0-9a-f]{2}/i.test(s.content)
    );

    if (hasObfuscated || scripts.filter((s) => s.content.length > 500).length > 2) {
      chrome.runtime.sendMessage({
        type: 'SCRIPT_ANALYSIS',
        timestamp: new Date().toISOString(),
        domain: getDomain(),
        url: window.location.href,
        scripts: scripts.slice(0, 10),
        hasObfuscatedScript: hasObfuscated
      });
    }
  }

  function monitorPermissions() {
    const originalGetUserMedia = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);
    if (originalGetUserMedia) {
      navigator.mediaDevices.getUserMedia = function (constraints) {
        const type = constraints?.video ? 'camera' : constraints?.audio ? 'microphone' : 'media';
        chrome.runtime.sendMessage({
          type: 'PERMISSION_DETECTED',
          permissionType: type,
          domain: getDomain(),
          url: window.location.href
        });
        return originalGetUserMedia(constraints);
      };
    }

    const originalWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard);
    if (originalWriteText) {
      navigator.clipboard.writeText = function (text) {
        chrome.runtime.sendMessage({
          type: 'PERMISSION_DETECTED',
          permissionType: 'clipboard',
          domain: getDomain(),
          url: window.location.href
        });
        return originalWriteText(text);
      };
    }
  }

  function sendPageAnalysis() {
    chrome.runtime.sendMessage({
      type: 'PAGE_ANALYSIS',
      timestamp: new Date().toISOString(),
      domain: getDomain(),
      url: window.location.href,
      pageTitle: document.title,
      hasLoginForm: !!document.querySelector('input[type="password"]'),
      hasPassword: !!document.querySelector('input[type="password"]'),
      forms: Array.from(document.querySelectorAll('form')).map((f) => ({
        action: f.action,
        method: f.method,
        fieldCount: f.querySelectorAll('input').length
      }))
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  function init() {
    scanForms();
    scanScripts();
    monitorPermissions();
    sendPageAnalysis();

    let scanTimeout;
    const observer = new MutationObserver(() => {
      clearTimeout(scanTimeout);
      scanTimeout = setTimeout(scanForms, 250);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
