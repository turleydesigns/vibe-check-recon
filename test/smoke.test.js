'use strict';
// Smoke test for vibe-check-recon. Runs against example.com (which should
// always be available and should return clean findings — it's a static IANA
// reference page).
const assert = require('assert');
const { runRecon, pickTopFinding } = require('../lib/recon');

(async () => {
  console.log('vibe-check-recon smoke test');
  console.log('---------------------------');

  // 1. Result shape
  const r = await runRecon('https://example.com');
  assert.strictEqual(r.ok, true, 'recon should succeed on example.com');
  assert.strictEqual(typeof r.url, 'string', 'result has url');
  assert.strictEqual(Array.isArray(r.findings), true, 'findings is an array');
  assert.strictEqual(typeof r.stack_signals, 'object', 'stack_signals is an object');
  assert.strictEqual(typeof r.contacts, 'object', 'contacts is an object');
  console.log('  ✓ result shape valid');
  console.log(`    findings: ${r.findings.length}, subdomains: ${r.subdomains_found}, buckets: ${r.bucket_urls_found}`);

  // 2. pickTopFinding sorts by severity
  const findings = [
    { severity: 'low', title: 'low' },
    { severity: 'critical', title: 'crit' },
    { severity: 'medium', title: 'med' },
  ];
  const top = pickTopFinding(findings);
  assert.strictEqual(top.severity, 'critical', 'critical should outrank medium');
  console.log('  ✓ pickTopFinding ranks by severity');

  // 3. Empty findings → null top
  assert.strictEqual(pickTopFinding([]), null, 'empty findings → null');
  assert.strictEqual(pickTopFinding(null), null, 'null findings → null');
  console.log('  ✓ pickTopFinding handles empty input');

  // 4. Invalid URL → ok=false
  const bad = await runRecon('not-a-url::///');
  assert.strictEqual(bad.ok, false, 'invalid url returns ok=false');
  console.log('  ✓ invalid URL returns ok=false');

  console.log('---------------------------');
  console.log('All smoke tests passed.');
})().catch(e => {
  console.error('smoke test failed:', e);
  process.exit(1);
});
