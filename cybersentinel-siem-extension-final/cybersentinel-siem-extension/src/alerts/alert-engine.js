import { appendAlert } from '../shared/storage.js';
import { now } from '../shared/utils.js';

const DISCORD_TIMEOUT_MS = 5000;

export async function createAlert(event, scoring, mitre, detections, config) {
  const alert = {
    event_type: event.event_type || event.event,
    title: buildAlertTitle(event, scoring, detections),
    message: buildAlertMessage(event, scoring, detections),
    domain: event.domain,
    url: event.url,
    risk_score: scoring.risk_score,
    risk_level: scoring.risk_level,
    technique: mitre.technique,
    techniques: mitre.techniques,
    incident_id: event.incident_id,
    correlation: event.correlation,
    timestamp: now(),
    factors: scoring.factors
  };
  const stored = await appendAlert(alert);
  if (config?.alerts?.browserPopup !== false) await showBrowserAlert(alert);
  if (config?.alerts?.discordWebhook) await sendDiscordWebhook(config.alerts.discordWebhook, alert);
  return stored;
}

function buildAlertTitle(event, scoring, detections) {
  if (event.correlation?.correlated && event.correlation.signal_count >= 3) return 'Correlated Security Incident';
  if (detections.credentialHarvesting?.detected) return 'Credential Harvesting Attempt';
  if (detections.phishing?.classification === 'phishing') return 'Phishing Detected';
  if (detections.malwareDelivery?.detected) return 'Malware Delivery Detected';
  if (detections.loginPage?.isPotentialPhishing) return 'Potential Phishing Login Page';
  if (event.event === 'download' && event.isSuspicious) return 'Suspicious Download';
  if (detections.scriptAnalysis?.hasObfuscation) return 'Obfuscated JavaScript Detected';
  return `${scoring.risk_level} ${scoringLabel(event)} Alert`;
}
function scoringLabel(event) { return (event.event || 'Security').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()); }
function buildAlertMessage(event, scoring, detections) { const parts = []; if (event.domain) parts.push(`Domain: ${event.domain}`); parts.push(`Risk: ${scoring.risk_score}/100 (${scoring.risk_level})`); if (event.incident_id) parts.push(`Incident: ${event.incident_id}`); if (event.correlation?.signals?.length) parts.push(`Signals: ${event.correlation.signals.join(', ')}`); if (detections.phishing?.impersonatedBrand) parts.push(`Brand: ${detections.phishing.impersonatedBrand}`); if (event.evidence?.length) parts.push(`Evidence: ${event.evidence.join('; ')}`); return parts.join('\n'); }

async function showBrowserAlert(alert) {
  try {
    const iconUrl = chrome.runtime.getURL('icons/icon128.png');
    await chrome.notifications.create({ type: 'basic', iconUrl, title: `${alert.risk_level.toUpperCase()} ALERT: ${alert.title}`, message: alert.message, priority: alert.risk_level === 'Critical' ? 2 : 1 });
  } catch (err) { console.warn('[CyberSentinel] Notification failed:', err); }
}

async function sendDiscordWebhook(webhookUrl, alert) {
  const url = new URL(webhookUrl);
  if (url.protocol !== 'https:' || !url.hostname.endsWith('discord.com')) { console.warn('[CyberSentinel] Refusing non-Discord webhook URL'); return; }
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), DISCORD_TIMEOUT_MS);
  try {
    await fetch(url.toString(), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal,
      body: JSON.stringify({ embeds: [{ title: `${alert.risk_level} - ${alert.title}`, description: alert.message, fields: [{ name: 'Risk Score', value: String(alert.risk_score), inline: true }, { name: 'MITRE', value: alert.technique || 'N/A', inline: true }, { name: 'Incident', value: alert.incident_id || 'N/A', inline: true }], timestamp: alert.timestamp }] })
    });
  } catch (err) { console.error('[CyberSentinel] Discord webhook failed:', err?.name === 'AbortError' ? 'timeout' : err?.message || err); }
  finally { clearTimeout(timeoutId); }
}

export function shouldAlert(scoring, config) { if (!config?.detection) return scoring.risk_score >= 51; return scoring.risk_score >= 26; }
