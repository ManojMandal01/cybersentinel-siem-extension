import { now } from '../shared/utils.js';

const SUSPICIOUS_PERMISSIONS = ['webRequest', 'webRequestBlocking', 'proxy', 'debugger', 'nativeMessaging'];

export function analyzeExtension(ext) {
  const perms = [...(ext.permissions || []), ...(ext.hostPermissions || [])];
  const suspicious = perms.filter((p) =>
    SUSPICIOUS_PERMISSIONS.some((sp) => p.includes(sp)) || p === '<all_urls>'
  );

  return {
    event: 'extension_change',
    timestamp: now(),
    extensionId: ext.id,
    name: ext.name,
    version: ext.version,
    enabled: ext.enabled,
    permissions: perms,
    suspiciousPermissions: suspicious,
    isSuspicious: suspicious.length >= 2 || (suspicious.includes('<all_urls>') && perms.length > 3),
    installType: ext.installType
  };
}

export async function scanExtensions() {
  if (!chrome.management) return [];
  return new Promise((resolve) => {
    chrome.management.getAll((extensions) => {
      resolve(extensions.map(analyzeExtension));
    });
  });
}

export function initExtensionMonitor(onEvent) {
  if (!chrome.management) return;

  chrome.management.onInstalled.addListener((ext) => {
    onEvent({ ...analyzeExtension(ext), changeType: 'installed' });
  });

  chrome.management.onEnabled.addListener((ext) => {
    onEvent({ ...analyzeExtension(ext), changeType: 'enabled' });
  });

  chrome.management.onDisabled.addListener((ext) => {
    onEvent({ ...analyzeExtension(ext), changeType: 'disabled' });
  });
}
