'use strict';
// Fixture-based tests. Exercises the finding logic without hitting the network.
// Each test sets up a fetchUrl mock that returns canned responses for a synthetic
// site, runs runRecon, and asserts the expected findings.

const assert = require('assert');
const recon = require('../lib/recon');

const SPA_HEADERS = { 'content-type': 'text/html; charset=utf-8' };
const SPA_HTML = '<!DOCTYPE html><html><head><title>App</title></head><body><div id="root"></div></body></html>';

function makeFetchMock(routes) {
  return async (target, _opts = {}) => {
    if (routes[target]) return routes[target];
    if (routes['*']) return routes['*'];
    return { status: 404, headers: {}, body: '' };
  };
}

function spaFallback() {
  return { status: 200, headers: SPA_HEADERS, body: SPA_HTML };
}

let pass = 0;
let fail = 0;
async function t(name, fn) {
  try { await fn(); pass++; console.log(`  ✓ ${name}`); }
  catch (e) { fail++; console.log(`  ✗ ${name}\n      ${e.message}`); }
}

(async () => {
  console.log('vibe-check-recon fixture tests');
  console.log('------------------------------');

  // No-op subdomain enumerator across all tests — we test subdomain logic
  // separately and don't want crt.sh in the loop.
  recon.__setEnumerateSubdomainsForTest(async () => []);

  // 1. .git/HEAD exposed → high severity, "Git metadata exposed" title.
  await t('.git/HEAD exposed → high severity (not critical, not "Full")', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': spaFallback(),
      'https://test.app/.git/HEAD': { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ref: refs/heads/main\n' },
      'https://test.app/.git/config': { status: 200, headers: { 'content-type': 'text/plain' }, body: '[core]\n\trepositoryformatversion = 0\n' },
    }));
    const r = await recon.runRecon('https://test.app');
    const git = r.findings.find(f => f.title.toLowerCase().includes('git metadata'));
    assert.ok(git, `expected git metadata finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(git.severity, 'high', `expected high, got ${git.severity}`);
    assert.ok(!git.title.toLowerCase().includes('full'), `title should not say 'Full': ${git.title}`);
  });

  // 2. SPA fallback at /.git/HEAD → no false positive.
  await t('SPA fallback at /.git/HEAD → no false positive', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': spaFallback(),
      'https://test.app/.git/HEAD': spaFallback(),
      '*': spaFallback(),
    }));
    const r = await recon.runRecon('https://test.app');
    const git = r.findings.find(f => f.title.toLowerCase().includes('git'));
    assert.strictEqual(git, undefined, `expected no git finding, got: ${git?.title}`);
  });

  // 3. /.env served with real content → critical.
  await t('/.env served publicly → critical', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': spaFallback(),
      'https://test.app/.env': { status: 200, headers: { 'content-type': 'text/plain' }, body: 'OPENAI_API_KEY=sk-real-key-here\nDATABASE_URL=postgres://...\n' },
    }));
    const r = await recon.runRecon('https://test.app');
    const env = r.findings.find(f => f.title.startsWith('/.env'));
    assert.ok(env, `expected /.env finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(env.severity, 'critical');
  });

  // Test fixtures construct synthetic keys at runtime instead of inlining
  // the literal `sk_test_<chars>` / `sk_live_<chars>` strings, because
  // GitHub's push-protection secret scanning blocks even synthetic Stripe
  // keys when they appear contiguously in committed source. The regex
  // still matches when the body is built and scanned at test time.
  const SK_PREFIX = 'sk_';
  const TEST_SUFFIX = 'test_abcdefghijklmnopqrstuvwx';
  const LIVE_SUFFIX = 'live_abcdefghijklmnopqrstuvwx';

  // 4. Stripe sk_test_ key in bundle → low severity, NOT critical.
  await t('Stripe sk_test_ key → low severity (not critical)', async () => {
    const html = '<!DOCTYPE html><script src="/assets/index-abc.js"></script>';
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': { status: 200, headers: SPA_HEADERS, body: html },
      'https://test.app/assets/index-abc.js': {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        body: `const k = "${SK_PREFIX + TEST_SUFFIX}";`,
      },
    }));
    const r = await recon.runRecon('https://test.app');
    const stripe = r.findings.find(f => f.title.toLowerCase().includes('stripe_test'));
    assert.ok(stripe, `expected stripe_test finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(stripe.severity, 'low', `sk_test_ should be low, got ${stripe.severity}`);
  });

  // 5. Stripe sk_live_ → critical.
  await t('Stripe sk_live_ key → critical', async () => {
    const html = '<!DOCTYPE html><script src="/assets/index-abc.js"></script>';
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': { status: 200, headers: SPA_HEADERS, body: html },
      'https://test.app/assets/index-abc.js': {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        body: `const k = "${SK_PREFIX + LIVE_SUFFIX}";`,
      },
    }));
    const r = await recon.runRecon('https://test.app');
    const stripe = r.findings.find(f => f.title.toLowerCase().includes('stripe_live'));
    assert.ok(stripe, `expected stripe_live finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(stripe.severity, 'critical');
  });

  // 6. Vercel SPA root with CORS:* → no finding (platform-default suppression).
  await t('Vercel SPA root CORS:* → suppressed', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': { status: 200, headers: { ...SPA_HEADERS, server: 'Vercel', 'access-control-allow-origin': '*' }, body: SPA_HTML },
    }));
    const r = await recon.runRecon('https://test.app');
    const cors = r.findings.find(f => f.title.toLowerCase().includes('cors wide open'));
    assert.strictEqual(cors, undefined, `Vercel CORS:* should be suppressed, got: ${cors?.title}`);
  });

  // 7. API route reflecting attacker Origin + ACAC: true → critical.
  await t('API CORS reflection + credentials → critical', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': spaFallback(),
      'https://test.app/api/me': {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': 'https://attacker.example.com',
          'access-control-allow-credentials': 'true',
        },
        body: '{"id":1}',
      },
    }));
    const r = await recon.runRecon('https://test.app');
    const apiCors = r.findings.find(f => f.title.toLowerCase().includes('origin-reflecting cors with credentials'));
    assert.ok(apiCors, `expected critical API CORS finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(apiCors.severity, 'critical');
  });

  // 8. Source map via //# sourceMappingURL= directive → medium.
  // Map body needs to be >200 chars to pass the recon's size threshold
  // (filters out tiny placeholder maps).
  await t('Source map via sourceMappingURL directive → medium', async () => {
    const html = '<!DOCTYPE html><script src="/assets/main-xyz.js"></script>';
    const bundleBody = 'console.log(1);\n//# sourceMappingURL=main-xyz.js.map\n';
    const mapBody = JSON.stringify({
      version: 3,
      sources: ['src/index.tsx', 'src/components/App.tsx', 'src/lib/auth.ts'],
      sourcesContent: ['import React from "react";\n// large enough body\n'.repeat(20)],
      mappings: 'AAAA;'.repeat(50),
      names: ['useState', 'useEffect', 'render', 'mount'],
    });
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': { status: 200, headers: SPA_HEADERS, body: html },
      'https://test.app/assets/main-xyz.js': { status: 200, headers: { 'content-type': 'application/javascript' }, body: bundleBody },
      'https://test.app/assets/main-xyz.js.map': { status: 200, headers: { 'content-type': 'application/json' }, body: mapBody },
    }));
    const r = await recon.runRecon('https://test.app');
    const smap = r.findings.find(f => f.title.toLowerCase().includes('source map'));
    assert.ok(smap, `expected source map finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(smap.severity, 'medium');
  });

  // 9. pickTopFinding handles edges.
  await t('pickTopFinding handles edges', async () => {
    assert.strictEqual(recon.pickTopFinding([]), null);
    assert.strictEqual(recon.pickTopFinding(null), null);
    assert.strictEqual(recon.pickTopFinding(undefined), null);
  });

  // 10. pickTopFinding ranks by severity.
  await t('pickTopFinding ranks by severity', async () => {
    const findings = [
      { severity: 'low', title: 'a' },
      { severity: 'critical', title: 'b' },
      { severity: 'high', title: 'c' },
    ];
    assert.strictEqual(recon.pickTopFinding(findings).severity, 'critical');
  });

  // 11. Weak CSP with unsafe-inline → low/medium severity finding.
  await t('CSP with unsafe-inline → finding', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': {
        status: 200,
        headers: { ...SPA_HEADERS, 'content-security-policy': "script-src 'unsafe-inline'" },
        body: SPA_HTML,
      },
    }));
    const r = await recon.runRecon('https://test.app');
    const csp = r.findings.find(f => f.title.toLowerCase().includes('weak csp'));
    assert.ok(csp, `expected weak-CSP finding, got: ${r.findings.map(f => f.title).join(', ')}`);
  });

  // 12. Auth cookie missing HttpOnly → medium.
  await t('Auth cookie missing security flags → medium', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': {
        status: 200,
        headers: { ...SPA_HEADERS, 'set-cookie': ['session_id=abc123; Path=/'] },
        body: SPA_HTML,
      },
    }));
    const r = await recon.runRecon('https://test.app');
    const cookie = r.findings.find(f => f.title.toLowerCase().includes('cookie'));
    assert.ok(cookie, `expected cookie security finding, got: ${r.findings.map(f => f.title).join(', ')}`);
    assert.strictEqual(cookie.severity, 'medium');
  });

  // 13. Vercel Security Checkpoint → bot_protection set, no findings, ok=true.
  await t('Vercel Security Checkpoint → bot_protection surfaced, no findings', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': {
        status: 200,
        headers: SPA_HEADERS,
        body: '<!DOCTYPE html><html><head><title>Vercel Security Checkpoint</title></head><body>...</body></html>',
      },
    }));
    const r = await recon.runRecon('https://test.app');
    assert.strictEqual(r.ok, true, 'ok should be true (we got a response)');
    assert.ok(r.bot_protection, 'expected bot_protection field');
    assert.strictEqual(r.bot_protection.type, 'vercel_security_checkpoint');
    assert.strictEqual(r.findings.length, 0, 'should not surface findings when blocked');
  });

  // 14. Cloudflare interactive challenge → bot_protection.type=cloudflare_challenge.
  await t('Cloudflare "Just a moment..." → bot_protection.type=cloudflare_challenge', async () => {
    recon.__setFetchUrlForTest(makeFetchMock({
      'https://test.app/': {
        status: 200,
        headers: SPA_HEADERS,
        body: '<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script>cf-chl-bypass</script></body></html>',
      },
    }));
    const r = await recon.runRecon('https://test.app');
    assert.strictEqual(r.ok, true);
    assert.ok(r.bot_protection);
    assert.strictEqual(r.bot_protection.type, 'cloudflare_challenge');
  });

  console.log('------------------------------');
  console.log(`Passed: ${pass} / ${pass + fail}`);
  if (fail > 0) process.exit(1);
})().catch(e => {
  console.error('test runner crashed:', e);
  process.exit(1);
});
