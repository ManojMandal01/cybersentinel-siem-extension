import { appendEvent } from '../src/shared/storage.js';
import { correlateEvent } from '../src/correlation/correlation-engine.js';

const cases = [];
function test(name, fn) { cases.push({ name, fn }); }
function assert(condition, message) { if (!condition) throw new Error(message || 'Assertion failed'); }

// Legitimate login forms must not become incidents by themselves.
test('legitimate login form does not create incident', async () => {
  const result = await correlateEvent({
    event: 'credential_form_detected',
    domain: 'www.instagram.com',
    risk_score: 20,
    timestamp: new Date().toISOString()
  });
  assert(result === null, 'credential_form_detected alone must not correlate');
});

test('legitimate suspicious script does not create incident', async () => {
  const result = await correlateEvent({
    event: 'suspicious_script',
    domain: 'www.google.com',
    risk_score: 10,
    timestamp: new Date().toISOString()
  }, { scriptAnalysis: { hasObfuscation: true } });
  assert(result === null, 'suspicious_script alone must not correlate');
});

test('legitimate redirect does not create incident', async () => {
  const result = await correlateEvent({
    event: 'url_redirect',
    domain: 'www.facebook.com',
    risk_score: 10,
    redirectChain: ['https://www.facebook.com/', 'https://www.facebook.com/']
  });
  assert(result === null, 'redirect alone must not correlate');
});

test('phishing plus credential signal creates incident', async () => {
  const domain = `regression-phish-${Date.now()}.example.test`;
  await appendEvent({
    event: 'credential_form_detected',
    domain,
    risk_score: 20,
    timestamp: new Date().toISOString()
  });

  const result = await correlateEvent({
    event: 'url_visit',
    domain,
    risk_score: 70,
    timestamp: new Date().toISOString()
  }, {
    phishing: { classification: 'phishing' }
  });

  assert(result?.correlated === true, 'strong phishing signal should correlate with related credential activity');
  assert(result.signals.includes('phishing'), 'incident must contain phishing signal');
  assert(result.signals.includes('credential_form'), 'incident must contain credential_form signal');
});

async function run() {
  const box = document.createElement('section');
  box.className = 'test-item';
  box.style.marginTop = '24px';
  const title = document.createElement('h2');
  title.textContent = 'Correlation Regression Tests';
  box.appendChild(title);

  let passed = 0;
  for (const item of cases) {
    const row = document.createElement('div');
    row.style.padding = '8px 0';
    try {
      await item.fn();
      row.textContent = `PASS — ${item.name}`;
      passed += 1;
    } catch (error) {
      row.textContent = `FAIL — ${item.name}: ${error.message || error}`;
      row.style.color = '#ff7b72';
    }
    box.appendChild(row);
  }

  const summary = document.createElement('strong');
  summary.textContent = `${passed}/${cases.length} correlation regression tests passed`;
  box.insertBefore(summary, box.children[1]);
  document.querySelector('.container').appendChild(box);
}

run().catch((error) => console.error('Correlation regression tests failed:', error));
