import { appendAlert } from '../shared/storage.js';
import { now } from '../shared/utils.js';

export async function createAlert(event, scoring, mitre, detections, config) {
  const alert = {
    event_type: event.event_type || event.event,
    title: buildAlertTitle(event, detections),
    message: buildAlertMessage(event, scoring, detections),
    domain: event.domain,
    url: event.url,
    risk_score: scoring.risk_score,
    risk_level: scoring.risk_level,
    technique: mitre.technique,
    techniques: mitre.techniques,
    timestamp: now(),
    factors: scoring.factors
  };

  const stored = await appendAlert(alert);

  if (config?.alerts?.browserPopup !== false) {
    await showBrowserAlert(alert);
  }

  if (config?.alerts?.discordWebhook) {
    await sendDiscordWebhook(config.alerts.discordWebhook, alert);
  }

  return stored;
}

function buildAlertTitle(event, detections) {
  if (detections.credentialHarvesting?.detected) return 'Credential Harvesting Attempt';
  if (detections.phishing?.classification === 'phishing') return 'Phishing Detected';
  if (detections.malwareDelivery?.detected) return 'Malware Delivery Detected';
  if (detections.loginPage?.isPotentialPhishing) return 'Potential Phishing Login Page';
  if (event.event === 'download' && event.isSuspicious) return 'Suspicious Download';
  if (detections.scriptAnalysis?.hasObfuscation) return 'Obfuscated JavaScript Detected';
  return `${scoringLabel(event)} Alert`;
}

function scoringLabel(event) {
  return (event.event || 'Security').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function buildAlertMessage(event, scoring, detections) {
  const parts = [];
  if (event.domain) parts.push(`Domain: ${event.domain}`);
  parts.push(`Risk: ${scoring.risk_score}/100 (${scoring.risk_level})`);
  if (detections.phishing?.impersonatedBrand) {
    parts.push(`Brand: ${detections.phishing.impersonatedBrand}`);
  }
  return parts.join('\n');
}

async function showBrowserAlert(alert) {
  const iconUrl = chrome.runtime.getURL('icons/icon128.png');
  await chrome.notifications.create({
    type: 'basic',
    iconUrl,
    title: `${alert.risk_level.toUpperCase()} ALERT: ${alert.title}`,
    message: alert.message,
    priority: alert.risk_level === 'Critical' ? 2 : 1
  });
}

async function sendDiscordWebhook(webhookUrl, alert) {
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title: `${alert.risk_level} — ${alert.title}`,
          description: alert.message,
          color: alert.risk_level === 'Critical' ? 0xff0000 : alert.risk_level === 'High' ? 0xff6600 : 0xffcc00,
          fields: [
            { name: 'Risk Score', value: String(alert.risk_score), inline: true },
            { name: 'MITRE', value: alert.technique || 'N/A', inline: true }
          ],
          timestamp: alert.timestamp
        }]
      })
    });
  } catch (err) {
    console.error('[CyberSentinel] Discord webhook failed:', err);
  }
}

export function shouldAlert(scoring, config) {
  if (!config?.detection) return scoring.risk_score >= 51;
  return scoring.risk_score >= 26;
}
