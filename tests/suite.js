import { detectPhishing } from '../src/detection/phishing-detector.js';
import { domainMatches, isLegitimateDomain } from '../src/shared/utils.js';
import { scoreEvent } from '../src/risk/risk-scorer.js';
import { mapToMitre } from '../src/mitre/attack-mapper.js';
import { executeHuntQuery } from '../src/hunting/query-engine.js';
import { appendEvent, appendAlert, getAlerts } from '../src/shared/storage.js';
import { config, processSecurityPipeline } from '../src/background/service-worker.js';

const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function assertEquals(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

test('detectPhishing: benign domain', () => {
  const result = detectPhishing('https://paypal.com/signin');
  assertEquals(result.classification, 'benign');
  assert(result.confidence < 50, 'Confidence should be low for legitimate domain');
});

test('detectPhishing: homograph attack', () => {
  const result = detectPhishing('https://paypaI.com/login');
  assertEquals(result.classification, 'phishing');
  assert(result.signals.some((s) => s.type === 'homograph'), 'Should flag homograph');
});

test('detectPhishing: typosquatting', () => {
  const result = detectPhishing('https://g00gle.com/signin');
  assertEquals(result.classification, 'phishing');
  assert(result.signals.some((s) => s.type === 'typosquatting'), 'Should flag typosquatting');
});

test('domain matching: prevents suffix bypass', () => {
  assert(isLegitimateDomain('paypal.com'), 'paypal.com should be trusted');
  assert(isLegitimateDomain('login.paypal.com'), 'login.paypal.com should be trusted');
  assert(!isLegitimateDomain('attackerpaypal.com'), 'attackerpaypal.com should not be trusted');
  assert(!isLegitimateDomain('my-paypal.com'), 'my-paypal.com should not be trusted');
  assert(domainMatches('https://login.company.com/path', 'company.com'), 'URLs should normalize before matching');
  assert(!domainMatches('evilcompany.com', 'company.com'), 'Suffix-only spoof should not match');
});

test('detectPhishing: brand-specific legitimacy', () => {
  const result = detectPhishing('https://paypal.google.com/login');
  assertEquals(result.classification, 'phishing');
  assert(result.signals.some((s) => s.type === 'brand_impersonation'), 'Should not trust a different legitimate brand domain');
});

test('scoreEvent: benign event', () => {
  const event = { event: 'url_visit', domain: 'google.com', url: 'https://google.com/' };
  const scoring = scoreEvent(event, {});
  assertEquals(scoring.risk_score, 0);
  assertEquals(scoring.risk_level, 'Low');
});

test('scoreEvent: phishing detection event', () => {
  const event = { event: 'url_visit', domain: 'g00gle.com', url: 'https://g00gle.com/' };
  const detections = {
    phishing: { classification: 'phishing', signals: [{ type: 'typosquatting' }] }
  };
  const scoring = scoreEvent(event, detections);
  assert(scoring.risk_score > 0, 'Risk score should be greater than zero');
  assert(scoring.factors.some((f) => f.factor === 'phishing_detected'), 'Should list phishing factor');
});

test('mapToMitre: phishing mapping', () => {
  const event = { event: 'url_visit', domain: 'g00gle.com' };
  const detections = {
    phishing: { classification: 'phishing' }
  };
  const mapping = mapToMitre(event, detections);
  assertEquals(mapping.technique, 'T1566');
  assert(mapping.techniques.some((t) => t.name === 'Phishing'), 'Should include Phishing');
});

test('mapToMitre: script obfuscation', () => {
  const event = { event: 'suspicious_script' };
  const detections = {
    scriptAnalysis: { hasObfuscation: true }
  };
  const mapping = mapToMitre(event, detections);
  assertEquals(mapping.technique, 'T1027');
});

test('storage: append and retrieve alerts', async () => {
  const event = {
    event: 'url_visit',
    domain: 'test-phish.xyz',
    timestamp: new Date().toISOString()
  };
  const storedEvent = await appendEvent(event);
  assert(storedEvent.id, 'Stored event should have generated ID');

  const alert = {
    title: 'Phishing Alert Test',
    domain: 'test-phish.xyz',
    risk_level: 'Critical',
    timestamp: new Date().toISOString(),
    technique: 'T1566'
  };
  await appendAlert(alert);

  const freshAlerts = await getAlerts();
  assert(freshAlerts.length > 0, 'Should return stored alerts');
  assertEquals(freshAlerts[0].title, 'Phishing Alert Test');
  assertEquals(freshAlerts[0].triageState, 'new');
});

test('queryEngine: show phishing alerts', async () => {
  const queryResult = await executeHuntQuery('show phishing alerts');
  assert(queryResult.results.length > 0, 'Should find phishing alert from previous test');
  assert(queryResult.count > 0);
  assertEquals(queryResult.results[0].technique, 'T1566');
});

test('queryEngine: invalid query handles error', async () => {
  const queryResult = await executeHuntQuery('show something invalid');
  assert(queryResult.error, 'Should return error message');
  assert(queryResult.results.length === 0);
});

test('pipeline: config toggle disable phishing', async () => {
  config.detection.phishingEnabled = false;
  const rawEvent = { event: 'url_visit', url: 'https://paypaI.com/login' };
  const res = await processSecurityPipeline(rawEvent, { hasLoginForm: true });
  assertEquals(res.detections.phishing, undefined, 'Phishing detection should be bypassed');
  assertEquals(res.detections.loginPage, undefined, 'Login page detection should be bypassed');
  config.detection.phishingEnabled = true;
});

test('pipeline: monitoring scope allowlist', async () => {
  config.detection.monitoringScope = 'allowlist';
  config.detection.allowlistDomains = ['company.com'];

  const inScopeEvent = { event: 'url_visit', url: 'https://login.company.com/' };
  const outScopeEvent = { event: 'url_visit', url: 'https://evilcompany.com/' };

  const inRes = await processSecurityPipeline(inScopeEvent);
  const outRes = await processSecurityPipeline(outScopeEvent);

  assert(!inRes.skipped, 'Allowed domain should not be skipped');
  assertEquals(outRes.skipped, true);
  assertEquals(outRes.reason, 'not_in_allowlist');

  config.detection.monitoringScope = 'all';
});

test('pipeline: monitoring scope blocklist', async () => {
  config.detection.monitoringScope = 'blocklist';
  config.detection.blocklistDomains = ['private.local'];

  const inScopeEvent = { event: 'url_visit', url: 'https://company.com/' };
  const outScopeEvent = { event: 'url_visit', url: 'https://private.local/' };

  const inRes = await processSecurityPipeline(inScopeEvent);
  const outRes = await processSecurityPipeline(outScopeEvent);

  assert(!inRes.skipped, 'Non-blocked domain should not be skipped');
  assertEquals(outRes.skipped, true);
  assertEquals(outRes.reason, 'in_blocklist');

  config.detection.monitoringScope = 'all';
});

async function runAll() {
  const listElement = document.getElementById('testList');
  const statsElement = document.getElementById('stats');
  listElement.textContent = '';

  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    const item = document.createElement('li');
    item.className = 'test-item';

    const header = document.createElement('div');
    header.className = 'test-header';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'test-name';
    nameSpan.textContent = t.name;
    header.appendChild(nameSpan);

    const statusSpan = document.createElement('span');
    statusSpan.className = 'test-status';
    header.appendChild(statusSpan);
    item.appendChild(header);

    try {
      await t.fn();
      item.classList.add('pass');
      statusSpan.textContent = 'pass';
      passed++;
    } catch (err) {
      item.classList.add('fail');
      statusSpan.textContent = 'fail';
      failed++;

      const errorDiv = document.createElement('div');
      errorDiv.className = 'test-error';
      errorDiv.textContent = err.stack || err.message || String(err);
      item.appendChild(errorDiv);
    }

    listElement.appendChild(item);
  }

  statsElement.textContent = '';
  const pass = document.createElement('span');
  pass.className = 'pass-count';
  pass.textContent = `${passed} passed`;
  const fail = document.createElement('span');
  fail.className = 'fail-count';
  fail.textContent = `${failed} failed`;
  statsElement.append(pass, ' | ', fail);
}

runAll().catch((err) => console.error('Error running test suite:', err));
