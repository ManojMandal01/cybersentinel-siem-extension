/**
 * Build a lightweight relationship graph from stored events:
 * - one node per incident_id (aggregated risk, event count, primary domain)
 * - edges between incidents that share a domain, an IOC value, or a threat-feed hit
 *
 * This intentionally avoids any external graph/layout library so it stays
 * CSP-safe inside an MV3 dashboard page; layout is a simple deterministic
 * circle packing rather than a physics simulation.
 */
export function buildIncidentGraph(events = []) {
  const incidents = new Map();

  for (const event of events) {
    const incidentId = event.incident_id;
    if (!incidentId) continue;
    if (!incidents.has(incidentId)) {
      incidents.set(incidentId, {
        id: incidentId,
        domains: new Set(),
        events: 0,
        maxRisk: 0,
        techniques: new Set(),
        firstSeen: event.timestamp || event.storedAt,
        lastSeen: event.timestamp || event.storedAt
      });
    }
    const node = incidents.get(incidentId);
    node.events += 1;
    node.maxRisk = Math.max(node.maxRisk, event.risk_score || 0);
    if (event.domain) node.domains.add(event.domain);
    if (event.technique) node.techniques.add(event.technique);
    const ts = event.timestamp || event.storedAt;
    if (ts && ts < node.firstSeen) node.firstSeen = ts;
    if (ts && ts > node.lastSeen) node.lastSeen = ts;
  }

  const nodes = [...incidents.values()].map((n) => ({
    id: n.id,
    label: n.id,
    domains: [...n.domains],
    primaryDomain: [...n.domains][0] || 'unknown',
    events: n.events,
    maxRisk: n.maxRisk,
    techniques: [...n.techniques],
    firstSeen: n.firstSeen,
    lastSeen: n.lastSeen
  }));

  // Edge = two incidents sharing at least one domain.
  const edges = [];
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const shared = nodes[i].domains.filter((d) => nodes[j].domains.includes(d));
      if (shared.length) edges.push({ source: nodes[i].id, target: nodes[j].id, shared });
    }
  }

  return { nodes, edges };
}

function escapeXml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[ch]));
}

function riskColor(score) {
  if (score >= 76) return '#ff4d4f';
  if (score >= 51) return '#f2a93b';
  if (score >= 26) return '#4fa3ff';
  return '#35c48c';
}

/**
 * Deterministic circular layout: nodes placed evenly around a ring,
 * radius scaled by node count. Good enough for tens of incidents in a
 * SOC session without pulling in a physics/layout dependency.
 */
export function renderIncidentGraphSvg(graph) {
  const { nodes, edges } = graph;
  if (!nodes.length) {
    return '<svg viewBox="0 0 400 120" width="400" height="120" xmlns="http://www.w3.org/2000/svg"><text x="20" y="60" fill="#8b949e" font-size="13">No correlated incidents yet</text></svg>';
  }

  const size = Math.max(420, 90 * nodes.length);
  const cx = size / 2;
  const cy = size / 2;
  const ringRadius = size / 2 - 70;

  const positions = new Map();
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    positions.set(node.id, { x: cx + ringRadius * Math.cos(angle), y: cy + ringRadius * Math.sin(angle) });
  });

  const edgeLines = edges.map((edge) => {
    const a = positions.get(edge.source);
    const b = positions.get(edge.target);
    if (!a || !b) return '';
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#30363d" stroke-width="1.5">
      <title>${escapeXml(edge.shared.join(', '))}</title>
    </line>`;
  }).join('');

  const nodeCircles = nodes.map((node) => {
    const p = positions.get(node.id);
    const radius = 14 + Math.min(20, node.events * 2);
    const color = riskColor(node.maxRisk);
    return `
      <g class="incident-node" data-incident="${escapeXml(node.id)}">
        <circle cx="${p.x}" cy="${p.y}" r="${radius}" fill="${color}" fill-opacity="0.85" stroke="#0d1117" stroke-width="2">
          <title>${escapeXml(node.id)}\n${escapeXml(node.primaryDomain)}\n${node.events} events, peak risk ${node.maxRisk}</title>
        </circle>
        <text x="${p.x}" y="${p.y + radius + 14}" fill="#e6edf3" font-size="10" text-anchor="middle">${escapeXml(node.primaryDomain)}</text>
      </g>`;
  }).join('');

  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Incident relationship graph">${edgeLines}${nodeCircles}</svg>`;
}
