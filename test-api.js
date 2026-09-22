/**
 * test-api.js — Quick functional test script for the Phishing Inspector API.
 * Run with: node test-api.js
 */

'use strict';

const BASE_URL = 'http://localhost:3000';

const TESTS = [
  // ── Text analysis tests ────────────────────────────────────
  {
    name: 'T01 — Empty text input',
    body: { mode: 'text', content: '' },
    expectError: true,
  },
  {
    name: 'T02 — Normal job offer (no red flags)',
    body: {
      mode: 'text',
      content: 'Dear Candidate, We are happy to offer you the position of Software Engineer at Acme Corp. Your start date will be 1st October. Please bring your documents on the first day. Salary: ₹8 LPA. Regards, HR Team.',
    },
    expectScore: { max: 20 },
  },
  {
    name: 'T03 — Payment demand message',
    body: {
      mode: 'text',
      content: 'Congratulations! You have been selected. Please pay ₹3,000 registration fee to confirm your appointment. Transfer the amount within 24 hours.',
    },
    expectSignals: ['explicit_payment_demand', 'fee_before_employment', 'urgency_pressure'],
    expectScore: { min: 40 },
  },
  {
    name: 'T04 — Equipment fee demand',
    body: {
      mode: 'text',
      content: 'You must purchase your own laptop before joining. The equipment fee is ₹15,000 which will be deducted from your first salary.',
    },
    expectSignals: ['equipment_fee'],
  },
  {
    name: 'T05 — Security deposit request',
    body: {
      mode: 'text',
      content: 'To confirm the rental, please pay a security deposit of ₹50,000 in advance. This is a fully refundable deposit after 11 months.',
    },
    expectSignals: ['security_deposit'],
  },
  {
    name: 'T06 — Cryptocurrency payment',
    body: {
      mode: 'text',
      content: 'Send payment in Bitcoin to wallet address 1A2B3C4D5E to complete your registration process.',
    },
    expectSignals: ['cryptocurrency_payment'],
    expectScore: { min: 20 },
  },
  {
    name: 'T07 — Urgency + spam formatting',
    body: {
      mode: 'text',
      content: 'URGENT!!! ACT NOW!!! LIMITED SEATS AVAILABLE!!! RESPOND WITHIN 24 HOURS OR LOSE THIS OPPORTUNITY!!!',
    },
    expectSignals: ['urgency_pressure', 'spam_formatting'],
  },
  {
    name: 'T08 — Sensitive info request',
    body: {
      mode: 'text',
      content: 'Please share your bank account number, IFSC code, and Aadhaar number to process your joining documents.',
    },
    expectSignals: ['sensitive_info_request'],
  },
  // ── URL analysis tests ─────────────────────────────────────
  {
    name: 'T09 — Valid HTTPS URL (google.com)',
    body: { mode: 'url', content: 'https://www.google.com' },
    expectScore: { max: 20 },
  },
  {
    name: 'T10 — HTTP URL (insecure)',
    body: { mode: 'url', content: 'http://example.com/jobs' },
    expectSignals: ['insecure_protocol'],
  },
  {
    name: 'T11 — IP-based URL',
    body: { mode: 'url', content: 'http://192.168.1.100/job-offer' },
    expectSignals: ['ip_based_url', 'insecure_protocol'],
    expectScore: { min: 25 },
  },
  {
    name: 'T12 — URL shortener',
    body: { mode: 'url', content: 'https://bit.ly/fakejoboffer123' },
    expectSignals: ['url_shortener'],
  },
  {
    name: 'T13 — Suspicious TLD',
    body: { mode: 'url', content: 'https://jobs-offer-india.xyz/apply-now' },
    expectSignals: ['suspicious_tld'],
  },
  {
    name: 'T14 — Lookalike domain (g00gle)',
    body: { mode: 'url', content: 'https://g00gle.com/jobs' },
    expectSignals: ['lookalike_domain'],
  },
  {
    name: 'T15 — Malformed URL',
    body: { mode: 'url', content: 'not a url at all !@#' },
    expectError: true,
  },
  {
    name: 'T16 — Invalid mode',
    body: { mode: 'invalid', content: 'test' },
    expectError: true,
  },
  {
    name: 'T17 — XSS attempt in text',
    body: { mode: 'text', content: '<script>alert("xss")</script> pay registration fee ₹5000 immediately.' },
    expectScore: { min: 0 }, // Should not crash, and should detect payment signal
  },
  {
    name: 'T18 — Health endpoint',
    url: '/api/health',
    method: 'GET',
    expectHealth: true,
  },
];

/**
 * Makes a fetch request and returns the parsed response.
 */
async function callApi(test) {
  const url   = BASE_URL + (test.url || '/api/analyze');
  const init  = test.method === 'GET'
    ? {}
    : {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(test.body),
      };

  const response = await fetch(url, init);
  const data     = await response.json();
  return { status: response.status, data };
}

/**
 * Validates the result of a test against expectations.
 */
function validateResult(test, status, data) {
  const issues = [];

  if (test.expectHealth) {
    if (data.status !== 'ok') issues.push('Health status is not "ok"');
    return issues;
  }

  if (test.expectError) {
    if (status < 400) issues.push(`Expected error status but got ${status}`);
    if (!data.error)  issues.push('Expected error=true in response');
    return issues;
  }

  if (status !== 200) {
    issues.push(`Expected 200 but got ${status}: ${data.message}`);
    return issues;
  }

  if (typeof data.score !== 'number') issues.push('score is missing or not a number');
  if (!data.riskLevel)                issues.push('riskLevel is missing');
  if (!Array.isArray(data.signals))   issues.push('signals array is missing');
  if (!data.disclaimer)               issues.push('disclaimer is missing');

  if (test.expectScore) {
    if (test.expectScore.min !== undefined && data.score < test.expectScore.min) {
      issues.push(`Expected score >= ${test.expectScore.min} but got ${data.score}`);
    }
    if (test.expectScore.max !== undefined && data.score > test.expectScore.max) {
      issues.push(`Expected score <= ${test.expectScore.max} but got ${data.score}`);
    }
  }

  if (test.expectSignals) {
    const detectedIds = (data.signals || []).map(s => s.id);
    for (const sigId of test.expectSignals) {
      if (!detectedIds.includes(sigId)) {
        issues.push(`Expected signal "${sigId}" not detected (got: [${detectedIds.join(', ')}])`);
      }
    }
  }

  return issues;
}

/**
 * Runs all tests and prints a report.
 */
async function runTests() {
  console.log('\n=== Phishing Inspector — Functional Test Suite ===\n');

  let passed = 0;
  let failed  = 0;

  for (const test of TESTS) {
    try {
      const { status, data } = await callApi(test);
      const issues           = validateResult(test, status, data);

      if (issues.length === 0) {
        const scoreInfo = data.score !== undefined ? ` | STI: ${data.score}% (${data.riskLevel})` : '';
        const sigInfo   = data.signals ? ` | Signals: ${data.signals.length}` : '';
        console.log(`✅ PASS  ${test.name}${scoreInfo}${sigInfo}`);
        passed++;
      } else {
        console.log(`❌ FAIL  ${test.name}`);
        issues.forEach(i => console.log(`        → ${i}`));
        if (data && data.score !== undefined) {
          console.log(`        Score: ${data.score}%, Risk: ${data.riskLevel}`);
          console.log(`        Signals: [${(data.signals || []).map(s => s.id).join(', ')}]`);
        }
        failed++;
      }
    } catch (err) {
      console.log(`💥 ERROR ${test.name}: ${err.message}`);
      failed++;
    }
  }

  console.log(`\n${'─'.repeat(52)}`);
  console.log(`Results: ${passed} passed, ${failed} failed out of ${TESTS.length} tests`);

  if (failed > 0) process.exit(1);
}

runTests();
