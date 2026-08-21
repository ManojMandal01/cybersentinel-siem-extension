function stixId(type, value) {
  const normalized = `${type}:${value}`;
  let hash = 2166136261;
  for (let i = 0; i < normalized.length; i += 1) {
    hash ^= normalized.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `${type}--${(hash >>> 0).toString(16).padStart(8, '0')}-${normalized.length.toString(16).padStart(4, '0')}-4000-8000-${Math.abs(hash).toString(16).padStart(12, '0').slice(-12)}`;
}

function toStixObject(ioc) {
  const value = String(ioc.value || '').trim();
  const type = String(ioc.ioc_type || '').toLowerCase();
  const mapping = {
    domain: 'domain-name',
    ip: 'ipv4-addr',
    ipv4: 'ipv4-addr',
    ipv6: 'ipv6-addr',
    url: 'url',
    hash: 'file'
  };
  const objectType = mapping[type];
  if (!objectType || !value) return null;
  const object = {
    type: objectType,
    id: stixId(objectType, value),
    spec_version: '2.1',
    created: ioc.createdAt || new Date().toISOString(),
    modified: ioc.createdAt || new Date().toISOString(),
    labels: ['cybersentinel', 'malicious-activity'],
    external_references: ioc.context ? [{ source_name: 'CyberSentinel', description: String(ioc.context).slice(0, 500) }] : []
  };
  if (objectType === 'domain-name') object.value = value;
  else if (objectType === 'url') object.value = value;
  else if (objectType === 'ipv4-addr' || objectType === 'ipv6-addr') object.value = value;
  else if (objectType === 'file') object.hashes = { SHA256: value };
  return object;
}

export function buildStixBundle(iocs = [], metadata = {}) {
  const objects = iocs.map(toStixObject).filter(Boolean);
  const identity = {
    type: 'identity',
    id: stixId('identity', 'CyberSentinel'),
    spec_version: '2.1',
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
    identity_class: 'application',
    name: 'CyberSentinel SIEM Browser Extension'
  };
  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    objects: [identity, ...objects],
    x_cybersentinel: {
      exported_at: new Date().toISOString(),
      object_count: objects.length,
      ...metadata
    }
  };
}

export function stixJson(iocs = [], metadata = {}) {
  return JSON.stringify(buildStixBundle(iocs, metadata), null, 2);
}
