#!/usr/bin/env node
'use strict';

const { runRecon, pickTopFinding } = require('../lib/recon');

const args = process.argv.slice(2);
const flagJson = args.includes('--json');
const flagTop = args.includes('--top');
const url = args.find(a => !a.startsWith('--'));

if (!url || args.includes('--help') || args.includes('-h')) {
  console.log(`vibe-check-recon — read-only public-surface security recon for AI-built apps.

USAGE:
  npx vibe-check-recon <url>           Pretty-print findings
  npx vibe-check-recon <url> --json    Output full JSON
  npx vibe-check-recon <url> --top     Output only the highest-severity finding

EXAMPLES:
  npx vibe-check-recon https://my-app.com
  npx vibe-check-recon mysite.com --json

OPTIONAL ENV:
  BRAVE_API_KEY     Enables Brave-search-augmented URL discovery
                    (find dev/staging subdomains beyond CT log).

This is a public-surface check. It only reads what your server already
serves publicly. No injection, no fuzzing, no auth attempts. Catches
the obvious stuff (.git/ exposed, leaked API keys in client bundles,
public S3 buckets, weak CSP, etc).

For the things only a human reviewer can catch (subtle RLS holes,
business-logic auth bypasses, payment race conditions, UX red flags),
see https://uxcontinuum.com/vibe-audit
`);
  process.exit(url ? 0 : 1);
}

(async () => {
  const result = await runRecon(url);

  if (!result.ok) {
    console.error(`Error: ${result.error}`);
    process.exit(1);
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
