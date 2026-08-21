import { MITRE_TECHNIQUES } from '../shared/constants.js';

// Static catalogue so every technique appears in the heatmap even with zero hits.
const TECHNIQUE_CATALOGUE = [
  { technique: MITRE_TECHNIQUES.PHISHING, name: 'Phishing', tactic: 'Initial Access' },
  { technique: MITRE_TECHNIQUES.JS_PAYLOAD, name: 'Command & Scripting', tactic: 'Execution' },
  { technique: MITRE_TECHNIQUES.OBFUSCATION, name: 'Obfuscated Files', tactic: 'Defense Evasion' },
  { technique: MITRE_TECHNIQUES.CREDENTIAL_THEFT, name: 'Input Capture', tactic: 'Credential Access' },
  { technique: MITRE_TECHNIQUES.TOOL_DOWNLOAD, name: 'Ingress Tool Transfer', tactic: 'Command & Control' },
  { technique: MITRE_TECHNIQUES.BRUTE_FORCE, name: 'Brute Force', tactic: 'Credential Access' },
  { technique: MITRE_TECHNIQUES.DATA_FROM_LOCAL, name: 'Data from Local System', tactic: 'Collection' }
];

/**
 * Aggregate technique hit counts from stored security events.
 * Accepts events shaped like { technique, techniques, risk_score }.
 * Returns cells sorted by tactic, each with a 0-4 intensity level.
 */
export function computeMitreHeatmap(events = []) {
  const counts = new Map();
  const maxRisk = new Map();

  for (const event of events) {
    const hits = Array.isArray(event.techniques) && event.techniques.length
      ? event.techniques.map((t) => t.technique)
      : (event.technique ? [event.technique] : []);
    for (const technique of hits) {
      counts.set(technique, (counts.get(technique) || 0) + 1);
      maxRisk.set(technique, Math.max(maxRisk.get(technique) || 0, event.risk_score || 0));
    }
  }

  const maxCount = Math.max(1, ...counts.values());

  return TECHNIQUE_CATALOGUE.map((entry) => {
    const count = counts.get(entry.technique) || 0;
    const level = count === 0 ? 0 : Math.min(4, Math.ceil((count / maxCount) * 4));
    return { ...entry, count, level, peakRisk: maxRisk.get(entry.technique) || 0 };
  }).sort((a, b) => a.tactic.localeCompare(b.tactic) || b.count - a.count);
}

const LEVEL_COLORS = ['#12161d', '#2b2210', '#4a3712', '#7a4d10', '#ff4d4f'];

function escapeXml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[ch]));
}

/**
 * Render heatmap cells as a self-contained SVG string (no external deps, MV3-CSP safe).
 */
export function renderMitreHeatmapSvg(cells) {
  const cols = 4;
  const cellWidth = 170;
  const cellHeight = 64;
  const gap = 8;
  const rows = Math.ceil(cells.length / cols);
  const width = cols * (cellWidth + gap) + gap;
  const height = rows * (cellHeight + gap) + gap;

  const rects = cells.map((cell, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const x = gap + col * (cellWidth + gap);
    const y = gap + row * (cellHeight + gap);
    const fill = LEVEL_COLORS[cell.level];
    const textColor = cell.level >= 3 ? '#0d1117' : '#e6edf3';
    return `
      <g class="mitre-cell" data-technique="${escapeXml(cell.technique)}">
        <rect x="${x}" y="${y}" width="${cellWidth}" height="${cellHeight}" rx="6" fill="${fill}" stroke="#30363d" />
        <text x="${x + 10}" y="${y + 20}" fill="${textColor}" font-size="11" font-weight="600">${escapeXml(cell.technique)} · ${escapeXml(cell.tactic)}</text>
        <text x="${x + 10}" y="${y + 38}" fill="${textColor}" font-size="12">${escapeXml(cell.name)}</text>
        <text x="${x + 10}" y="${y + 55}" fill="${textColor}" font-size="11" opacity="0.85">${cell.count} hit${cell.count === 1 ? '' : 's'}${cell.peakRisk ? ` · peak risk ${cell.peakRisk}` : ''}</text>
      </g>`;
  }).join('');

  return `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="MITRE ATT&amp;CK heatmap">${rects}</svg>`;
}
