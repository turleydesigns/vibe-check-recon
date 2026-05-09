#!/usr/bin/env node
'use strict';

const { runRecon, pickTopFinding } = require('../lib/recon');
const { toSarif, toJUnitXml } = require('../lib/output');

const args = process.argv.slice(2);
const flagJson = args.includes('--json');
const flagTop = args.includes('--top');
const flagSarif = args.includes('--sarif');
const flagJUnit = args.includes('--junit');
const flagPermission = args.includes('--i-have-permission');
const flagYes = args.includes('--yes') || args.includes('-y');
const flagVersion = args.includes('--version') || args.includes('-V');
const flagScopeOwn = args.includes('--scope=own-domain-only') ||
                    (args.indexOf('--scope') >= 0 && args[args.indexOf('--scope') + 1] === 'own-domain-only');
const timeoutIdx = args.indexOf('--timeout');
const flagTimeoutMs = timeoutIdx >= 0 ? Math.max(1000, parseInt(args[timeoutIdx + 1] || '0', 10) || 0) : 0;
const url = args.find(a => !a.startsWith('--') && !a.startsWith('-') && a !== 'own-domain-only');

if (flagVersion) {
  console.log(require('../package.json').version);
  process.exit(0);
}

if (!url || args.includes('--help') || args.includes('-h')) {
  console.log(`vibe-check-recon — read-only public-surface security recon for AI-built apps.

USAGE:
  npx vibe-check-recon <url>                Pretty-print findings
  npx vibe-check-recon <url> --json         Output full JSON
  npx vibe-check-recon <url> --top          Output only the highest-severity finding
  npx vibe-check-recon <url> --sarif        Emit SARIF v2.1.0 (GitHub Code Scanning)
  npx vibe-check-recon <url> --junit        Emit JUnit XML (CI test runners)
  npx vibe-check-recon --version            Print version

SCOPE:
  --scope own-domain-only   Skip subdomain enumeration (crt.sh + Brave +
                            spicy-sub probe). Faster scan; only checks
                            the URL you provided.
  --timeout <ms>            Cap total scan wall time. Best-effort.

PERMISSION:
  --i-have-permission       Skip the consent prompt (you've confirmed you
                            own the target or have permission to test it).
  --yes / -y                Same as --i-have-permission.

EXAMPLES:
  npx vibe-check-recon https://my-app.com
  npx vibe-check-recon mysite.com --json
  npx vibe-check-recon https://my-app.com --sarif > findings.sarif
  npx vibe-check-recon https://my-app.com --scope own-domain-only --timeout 30000
  npx vibe-check-recon https://staging.my-app.com --i-have-permission

OPTIONAL ENV:
  BRAVE_API_KEY     Enables Brave-search-augmented URL discovery
                    (find dev/staging subdomains beyond CT log).

This is a public-surface check. It only reads what your server already
serves publicly. No injection, no fuzzing, no auth attempts. Catches
the obvious stuff (.git/ exposed, leaked API keys in client bundles,
public S3 buckets, weak CSP, etc).

Use it on apps you own. Use it on apps you have permission to test.
Don't point it at random third-party sites you haven't been authorized
to check — even passive recon can constitute unauthorized access under
some interpretations of CFAA + state computer-fraud laws.

For the things only a human reviewer can catch (subtle RLS holes,
business-logic auth bypasses, payment race conditions, UX red flags),
see https://uxcontinuum.com/vibe-audit
`);
  process.exit(url ? 0 : 1);
}

// Consent gate. Tools used for finding security issues against arbitrary
// third-party sites are CFAA-gray; the explicit confirmation is both an
// honest expectations-set and a paper trail. Skip via --i-have-permission
// or --yes (or set VIBE_CHECK_RECON_AUTHORIZED=1 in env for CI).
async function confirmAuthorization(targetUrl) {
  if (flagPermission || flagYes) return true;
  if (process.env.VIBE_CHECK_RECON_AUTHORIZED === '1') return true;
  if (!process.stdin.isTTY) {
    // Non-interactive context (CI, pipe). Refuse without explicit flag.
    console.error(`
vibe-check-recon refuses to run non-interactively without explicit authorization.

Re-run with --i-have-permission (or set VIBE_CHECK_RECON_AUTHORIZED=1) to
confirm you own the target or have permission to test it:

  npx vibe-check-recon ${targetUrl} --i-have-permission

This tool reads only what the server already serves publicly, but pointing
it at third-party sites you haven't been authorized to test can still
constitute unauthorized access under some interpretations of CFAA + state
computer-fraud laws.
`);
    process.exit(2);
  }
  return new Promise(resolve => {
    process.stdout.write(`
About to run passive recon against:
  ${targetUrl}

This sends ~30-50 unauthenticated GET requests to that origin (homepage,
common exposed paths, JS bundles, API route probes, Brave-discovered
subdomains, crt.sh-discovered subdomains). It does NOT inject payloads,
fuzz, or attempt authentication. But pointing this at sites you haven't
been authorized to test can still cross legal lines you don't want to cross.

Do you own this target or have permission to test it? [y/N] `);
    const onData = data => {
      const answer = data.toString().trim().toLowerCase();
      process.stdin.removeListener('data', onData);
      process.stdin.pause();
      resolve(answer === 'y' || answer === 'yes');
    };
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

(async () => {
  const authorized = await confirmAuthorization(url);
  if (!authorized) {
    console.log('\nAborted. Run with --i-have-permission once you have authorization.\n');
    process.exit(0);
  }

  // Apply --timeout best-effort with a hard wall-clock kill.
  const reconPromise = runRecon(url, {
    skipSubdomains: flagScopeOwn,
  });
  let result;
  if (flagTimeoutMs > 0) {
    result = await Promise.race([
      reconPromise,
      new Promise(resolve => setTimeout(() => resolve({ ok: false, error: 'timeout', url, findings: [] }), flagTimeoutMs)),
    ]);
  } else {
    result = await reconPromise;
  }

  if (!result.ok) {
    console.error(`Error: ${result.error}`);
    process.exit(1);
  }

  if (flagSarif) {
    const pkg = require('../package.json');
    console.log(JSON.stringify(toSarif(result, pkg.version), null, 2));
    return;
  }

  if (flagJUnit) {
    const pkg = require('../package.json');
    console.log(toJUnitXml(result, pkg.version));
    return;
  }

  if (flagJson) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (flagTop) {
    const top = pickTopFinding(result.findings);
    console.log(JSON.stringify({
      ok: result.ok,
      url: result.url,
      stack_signals: result.stack_signals,
      top_finding: top,
      finding_count: result.findings.length,
    }, null, 2));
    return;
  }

  // Pretty output
  const sevColor = { critical: '\x1b[1;31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[2m', info: '\x1b[2m' };
  const reset = '\x1b[0m';

  console.log('');
  console.log(`vibe-check-recon — ${result.url}`);
  console.log('─'.repeat(72));
  console.log(`Stack:        ${JSON.stringify(result.stack_signals)}`);
  console.log(`Subdomains:   ${result.subdomains_found || 0} via crt.sh${result.brave_related_found ? `, +${result.brave_related_found} via Brave` : ''}`);
  console.log(`Buckets:      ${result.bucket_urls_found || 0}`);
  console.log(`Contacts:     ${Object.keys(result.contacts || {}).length ? JSON.stringify(result.contacts) : '(none found)'}`);
  console.log('');

  if (result.bot_protection) {
    console.log(`  ⚠ Bot protection active: ${result.bot_protection.type}`);
    console.log(`    ${result.bot_protection.detail}`);
    console.log('');
    console.log('  No findings reported because the recon never got past the gate.');
    console.log('  This is NOT the same as "clean" — re-run from a real browser, an');
    console.log('  allow-listed IP, or an authenticated session to get a real signal.');
    console.log('');
    return;
  }

  if (!result.findings.length) {
    console.log('  ✓ No findings. Public surface looks clean.');
    console.log('');
    console.log('  Reminder: this is the obvious stuff. Things only a human reviewer');
    console.log('  catches (RLS holes, auth bypasses, payment race conditions) need a');
    console.log('  full audit: https://uxcontinuum.com/vibe-audit');
    console.log('');
    return;
  }

  console.log(`Findings (${result.findings.length}):`);
  console.log('');
  for (const f of result.findings) {
    const c = sevColor[f.severity] || '';
    console.log(`  ${c}[${f.severity.toUpperCase()}]${reset} ${f.title}`);
    if (f.url) console.log(`         ${f.url}`);
    if (f.detail) console.log(`         ${f.detail}`);
    if (f.remediation) console.log(`         fix: ${f.remediation}`);
    console.log('');
  }

  console.log('─'.repeat(72));
  console.log('This is a public-surface check. The full audit covers 7 categories');
  console.log('(auth, data exposure, DB security, payments, env, performance, UX)');
  console.log('and finds what only a human reviewer can: https://uxcontinuum.com/vibe-audit');
  console.log('');
})().catch(e => {
  console.error('recon failed:', e.message);
  process.exit(1);
});
