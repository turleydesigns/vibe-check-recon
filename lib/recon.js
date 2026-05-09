#!/usr/bin/env node
'use strict';
/**
 * passive-recon.js — Read-only recon for vibe-audit lead URLs.
 *
 * Strictly passive — only reads what the target server already serves publicly.
 * No injection payloads, no fuzzing, no auth attempts, no user-data access,
 * no rate-pushing. The goal is to surface ONE concrete finding the DM can
 * lead with so the cold outreach has real value attached: "Saw your launch,
 * heads up that .git/ is exposed at /your-url/.git/HEAD — full audit catches
 * more like this."
 *
 * Wired 2026-05-08 (Matt: "search any launch post.. any vibe coded website
 * url.. run the scan... DM with 1 finding (not all if we find more).. and
 * pitch.").
 *
 * Usage:
 *   node passive-recon.js <url>                        # dump JSON to stdout
 *   const { runRecon, pickTopFinding } = require('./passive-recon');
 *
 * Findings shape:
 *   { severity, category, title, detail, url, remediation? }
 *
 * Severity tiers (rank used for pickTopFinding):
 *   critical = source/secrets fully exposed, immediate disclosure warranted
 *   high     = sensitive config served, needs fast fix
 *   medium   = misconfig with credible attack surface
 *   low      = best-practice gap, mention only if other findings exist
 *   info     = stack signal for the DM context, not a vulnerability
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const tldts = require('tldts');

// Brave Search API — optional. Set BRAVE_API_KEY env to enable
// related-URL discovery (catches subdomains and related deploys that
// aren't in the CT log). Without it, recon still works; it just
// skips the Brave-augmented subdomain probe.
function loadBraveKey() {
  return process.env.BRAVE_API_KEY || process.env.BRAVE_SEARCH_API_KEY || null;
}
const BRAVE_KEY = loadBraveKey();

const COMMON_EXPOSURE_PATHS = [
  // Env / config
  '/.env', '/.env.local', '/.env.production', '/.env.development',
  // VCS
  '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/store/00manifest.i',
  // Firebase
  '/firestore.rules', '/firebase.json', '/.firebaserc',
  // Build manifests
  '/package.json', '/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml',
  '/composer.json', '/composer.lock', '/Gemfile', '/Gemfile.lock',
  '/next.config.js', '/.DS_Store',
  '/.next/server/pages-manifest.json', '/.next/required-server-files.json',
  '/.vercel/project.json',
  // DB dumps (catastrophic when present)
  '/backup.sql', '/dump.sql', '/database.sql', '/db.sql', '/backup.zip',
  // API documentation that leaks the route surface
  '/swagger.json', '/swagger-ui', '/api/docs', '/api/openapi.json',
  '/openapi.json', '/redoc',
];

// Patterns scanned in JS bundles. Each gets one match per bundle max.
// `skipIfFirebase: true` means "ignore this match if we already detected
// Firebase" because Firebase web API keys are intentionally public —
// the security model lives in Firestore Rules, not the key.
// Secret patterns. Severities split live-vs-test where relevant — flagging a
// `sk_test_` key as critical burns credibility (test keys can't move money,
// most are intentionally checked into demo repos).
const SECRET_PATTERNS = [
  { name: 'anthropic_oauth_token',
    re: /sk-ant-oat[A-Za-z0-9_-]{30,}/,
    severity: 'critical' },
  { name: 'anthropic_api_key',
    re: /sk-ant-api[A-Za-z0-9_-]{30,}/,
    severity: 'critical' },
  { name: 'openai_project_key',
    re: /sk-proj-[A-Za-z0-9_-]{40,}/,
    severity: 'critical' },
  { name: 'stripe_live_secret_key',
    re: /sk_live_[A-Za-z0-9]{20,}/,
    severity: 'critical' },
  { name: 'stripe_test_secret_key',
    re: /sk_test_[A-Za-z0-9]{20,}/,
    severity: 'low' },
  { name: 'google_or_firebase_api_key',
    re: /AIza[A-Za-z0-9_-]{30,}/,
    // Firebase web API keys are public by design (security lives in Firestore
    // Rules). Other Google API keys may or may not be restricted. We surface
    // the presence rather than asserting it's a leak.
    severity: 'info',
    skipIfFirebase: false },
  { name: 'supabase_url',
    re: /https:\/\/[a-z0-9]{20,}\.supabase\.co/,
    severity: 'info' },
];

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

let fetchUrl = function (target, opts = {}) {
  return new Promise(resolve => {
    let parsed;
    try { parsed = new URL(target); } catch { return resolve(null); }
    const lib = parsed.protocol === 'http:' ? http : https;
    const reqHeaders = {
      'User-Agent': 'Mozilla/5.0 (compatible; vibe-audit-recon/1.0; passive-only)',
      ...(opts.headers || {}),
    };
    if (opts.body && !reqHeaders['content-length'] && !reqHeaders['Content-Length']) {
      reqHeaders['Content-Length'] = Buffer.byteLength(opts.body);
    }
    const req = lib.request({
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
      path:     (parsed.pathname || '/') + (parsed.search || ''),
      method:   opts.method || 'GET',
      headers:  reqHeaders,
      timeout: opts.timeout || 8000,
    }, (res) => {
      let data = '';
      const limit = opts.maxBytes || 1024 * 1024;
      let truncated = false;
      res.on('data', chunk => {
        if (truncated) return;
        const remaining = limit - Buffer.byteLength(data);
        if (remaining <= 0) { truncated = true; return; }
        const text = chunk.toString('utf8');
        // Only append up to the byte budget — a single large chunk could
        // otherwise overshoot by the entire chunk size.
        if (Buffer.byteLength(text) <= remaining) {
          data += text;
        } else {
          data += text.slice(0, remaining);
          truncated = true;
        }
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data, truncated }));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
};

// Bounded-concurrency map. Runs `worker(item)` against every item in `items`
// with at most `limit` concurrent calls in flight. Returns the array of
// resolved results in the original order. Used so we don't sit serially
// through 20+ exposure-path probes when most of them will finish in <1s.
async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let i = 0;
  async function run() {
    while (true) {
      const idx = i++;
      if (idx >= items.length) return;
      try { results[idx] = await worker(items[idx], idx); }
      catch (e) { results[idx] = null; }
    }
  }
  const runners = [];
  for (let r = 0; r < Math.min(limit, items.length); r++) runners.push(run());
  await Promise.all(runners);
  return results;
}

function isSpaFallback(resp, baseline) {
  if (!resp || !resp.body) return true;
  const ct = (resp.headers && resp.headers['content-type'] || '').toLowerCase();
  // Strong signal: an explicitly non-HTML content-type means the server knows
  // what it's serving (JSON, JS, plain text). Don't treat that as a fallback
  // even if the body length happens to coincide with the SPA shell.
  if (ct.includes('application/json') || ct.includes('application/javascript') ||
      ct.includes('text/javascript') || ct.includes('text/plain') ||
      ct.includes('application/xml') || ct.includes('text/xml')) {
    return false;
  }
  const b = resp.body.trimStart();
  if (b.startsWith('<!doctype') || b.startsWith('<!DOCTYPE') || b.startsWith('<html')) return true;
  // Heuristic: same byte length as the / response (text/html only) = SPA fallback.
  if (baseline && ct.includes('text/html') &&
      Math.abs(resp.body.length - baseline.body.length) < 32) return true;
  return false;
}

function extractJsBundles(html) {
  const re = /\/_next\/static\/[^"'\s)>]+\.js|\/static\/js\/[^"'\s)>]+\.js|\/assets\/[^"'\s)>]+\.js/g;
  const out = new Set();
  let m;
  while ((m = re.exec(html)) !== null) out.add(m[0]);
  return [...out].slice(0, 12);
}

// crt.sh result cache — file-backed so multiple recon runs don't hammer it.
// crt.sh is flaky (502s often) so we retry up to 3x with backoff.
const CRT_CACHE_PATH = '/tmp/vibe-audit-crt-cache.json';
const CRT_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h
function loadCrtCache() {
  try { return JSON.parse(fs.readFileSync(CRT_CACHE_PATH, 'utf8')); } catch { return {}; }
}
function saveCrtCache(c) {
  try { fs.writeFileSync(CRT_CACHE_PATH, JSON.stringify(c)); } catch {}
}

// Subdomain enumeration via crt.sh — the public Certificate Transparency
// log. Returns every subdomain that's ever been issued a TLS cert for the
// apex domain. Catches admin/dev/staging/api hosts founders forget to
// password-protect or remove. Strictly read-only, public data.
//
// Reliability: crt.sh frequently returns 502 Bad Gateway. Cache results for
// 24h and retry 3x with backoff before giving up.
let enumerateSubdomains = async function (apexDomain) {
  const cache = loadCrtCache();
  const cached = cache[apexDomain];
  if (cached && (Date.now() - cached.ts) < CRT_CACHE_TTL_MS) {
    return cached.subs;
  }
  const fetchOnce = () => new Promise(resolve => {
    const req = https.request({
      hostname: 'crt.sh',
      path: `/?q=%25.${encodeURIComponent(apexDomain)}&output=json`,
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; vibe-audit-recon/1.0)' },
      timeout: 18000,
    }, res => {
      let data = '';
      res.on('data', c => {
        // Bound the buffer — single large chunks can otherwise overshoot.
        const text = c.toString('utf8');
        const remaining = 2_000_000 - data.length;
        if (remaining <= 0) return;
        data += text.length <= remaining ? text : text.slice(0, remaining);
      });
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve(null);
        try {
          const arr = JSON.parse(data);
          const subs = new Set();
          for (const row of arr) {
            for (const name of (row.name_value || '').split('\n')) {
              const trimmed = name.trim().toLowerCase();
              if (!trimmed || trimmed.startsWith('*')) continue;
              if (trimmed === apexDomain || trimmed === `www.${apexDomain}`) continue;
              if (!trimmed.endsWith(apexDomain)) continue;
              subs.add(trimmed);
            }
          }
          resolve([...subs].slice(0, 30));
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
  let subs = null;
  for (let attempt = 0; attempt < 3 && subs === null; attempt++) {
    if (attempt) await new Promise(r => setTimeout(r, 1500 * attempt));
    subs = await fetchOnce();
  }
  subs = subs || [];
  cache[apexDomain] = { ts: Date.now(), subs };
  saveCrtCache(cache);
  return subs;
};

// Brave Search — paid API, used for URL discovery beyond what's reachable
// via crt.sh + bundle scanning. Surfaces dev URLs, staging deploys, GitHub
// repos, public traces of the project the founder may not realize exist.
async function braveSearch(query, count = 5) {
  if (!BRAVE_KEY) return null;
  return new Promise(resolve => {
    const req = https.request({
      hostname: 'api.search.brave.com',
      path: `/res/v1/web/search?q=${encodeURIComponent(query)}&count=${count}`,
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-Subscription-Token': BRAVE_KEY,
      },
      timeout: 12000,
    }, res => {
      let data = '';
      res.on('data', c => {
        const text = c.toString('utf8');
        const remaining = 200_000 - data.length;
        if (remaining <= 0) return;
        data += text.length <= remaining ? text : text.slice(0, remaining);
      });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// Brave-driven URL discovery: search for the apex domain to surface other
// hosts/paths the founder owns. Returns deduped list of related URLs that
// share the apex (or a known related apex).
async function discoverRelatedUrls(apexDomain) {
  if (!BRAVE_KEY) return [];
  const queries = [
    `site:${apexDomain}`,
    `"${apexDomain}" dev OR staging OR admin OR api`,
  ];
  const found = new Set();
  for (const q of queries) {
    const r = await braveSearch(q, 8);
    const results = r?.web?.results || [];
    for (const item of results) {
      const u = item.url || '';
      if (!u) continue;
      try {
        const parsed = new URL(u);
        const host = parsed.hostname.toLowerCase();
        if (host.endsWith(apexDomain) && host !== apexDomain && host !== `www.${apexDomain}`) {
          found.add(parsed.protocol + '//' + host);
        }
      } catch {}
    }
  }
  return [...found].slice(0, 8);
}

// Probe each subdomain with a HEAD-equivalent quick check. Flag the spicy
// ones (admin/dev/staging/internal/test/api/db) that respond with 200 or 401.
const SPICY_SUB_RES = /^(admin|dev|staging|stage|test|qa|preview|internal|secret|private|debug|api|db|database|sql|panel|console|backend|cms|wp-admin)\b/i;
async function probeSubdomains(subs) {
  // Filter to spicy ones first, then probe in parallel (bounded to 5).
  const spicy = subs.slice(0, 12).filter(s => SPICY_SUB_RES.test(s.split('.')[0]));
  const probed = await mapWithConcurrency(spicy, 5, async s => {
    const r = await fetchUrl(`https://${s}/`, { timeout: 6000 });
    return { s, r };
  });
  const findings = [];
  for (const { s, r } of probed) {
    if (!r) continue;
    if (r.status === 200) {
      findings.push({
        severity: 'high',
        category: 'data_exposure',
        title: `Sensitive subdomain reachable: ${s}`,
        detail: `${s} responded HTTP 200 to an unauthenticated request. Subdomains starting with admin/dev/staging/test/api shouldn't be publicly reachable.`,
        url: `https://${s}/`,
        remediation: 'Restrict by IP allowlist, basic auth, or move behind a VPN.',
      });
    } else if (r.status === 401 || r.status === 403) {
      findings.push({
        severity: 'low',
        category: 'data_exposure',
        title: `Auth-gated subdomain: ${s}`,
        detail: `${s} returned HTTP ${r.status}. Auth gate is in place; verify it's not Basic Auth with a default password and that brute force is rate-limited.`,
        url: `https://${s}/`,
      });
    }
  }
  return findings;
}

// Cloud storage bucket detection. Pulls bucket URLs out of the homepage
// and JS bundles, then probes each for public listing. Public buckets with
// user data are critical findings.
function extractBucketUrls(html) {
  const out = new Set();
  if (!html) return [];
  const patterns = [
    /https?:\/\/[a-z0-9-]+\.s3\.amazonaws\.com/gi,
    /https?:\/\/s3[.-][a-z0-9-]+\.amazonaws\.com\/[a-z0-9-]+/gi,
    /https?:\/\/storage\.googleapis\.com\/[a-z0-9._-]+/gi,
    /https?:\/\/[a-z0-9-]+\.r2\.cloudflarestorage\.com/gi,
    /https?:\/\/[a-z0-9-]+\.b-cdn\.net/gi,
    /https?:\/\/[a-z0-9-]+\.blob\.core\.windows\.net/gi,
    /https?:\/\/[a-z0-9-]+\.digitaloceanspaces\.com/gi,
  ];
  for (const re of patterns) {
    for (const m of (html.match(re) || [])) out.add(m);
  }
  return [...out].slice(0, 6);
}

async function probePublicBuckets(bucketUrls) {
  const findings = [];
  for (const u of bucketUrls) {
    let listingUrl = u;
    if (u.includes('s3.amazonaws.com')) listingUrl = u + '/?list-type=2';
    else if (u.includes('storage.googleapis.com')) listingUrl = u + '/?list';
    const r = await fetchUrl(listingUrl, { timeout: 8000, maxBytes: 20_000 });
    if (!r || r.status !== 200) continue;
    const body = r.body || '';
    if (/<ListBucketResult|<Contents>|<Key>|<Items>/.test(body) ||
        body.includes('"items":') || body.includes('"Contents":')) {
      findings.push({
        severity: 'critical',
        category: 'data_exposure',
        title: 'Public cloud storage bucket lists publicly',
        detail: `${u} responded with a directory listing. Anyone can enumerate stored objects.`,
        url: listingUrl,
        remediation: 'Set the bucket ACL to private. If the bucket is intentionally public for asset serving, disable list permissions while keeping object reads.',
      });
    }
  }
  return findings;
}

// CSP quality grade. Detects unsafe-inline, unsafe-eval, missing default-src,
// wildcard script-src. Only fires if CSP is present (otherwise we already
// flag it as missing in the headers check).
function gradeCsp(csp) {
  if (!csp) return null;
  const issues = [];
  if (/(?:'unsafe-inline'|unsafe-inline)/i.test(csp)) issues.push('unsafe-inline');
  if (/(?:'unsafe-eval'|unsafe-eval)/i.test(csp)) issues.push('unsafe-eval');
  if (!/default-src\b/i.test(csp)) issues.push('missing default-src');
  if (/script-src[^;]*\*[^.;]/i.test(csp)) issues.push('wildcard script-src');
  if (!issues.length) return null;
  return {
    severity: issues.includes('unsafe-eval') || issues.includes('wildcard script-src') ? 'medium' : 'low',
    category: 'env_config',
    title: `Weak CSP: ${issues.join(', ')}`,
    detail: 'CSP is present but its directives leave gaps an XSS payload could exploit.',
    remediation: 'Remove unsafe-inline/unsafe-eval. Pin script-src to specific origins. Add a default-src as a fallback.',
  };
}

// Cookie security flag parsing. Set-Cookie headers without HttpOnly /
// Secure / SameSite leak session protection.
function gradeCookies(setCookieHeader) {
  if (!setCookieHeader) return null;
  const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  const issues = [];
  for (const c of cookies) {
    const name = (c.split('=')[0] || '').trim();
    const lower = c.toLowerCase();
    // Only flag session/auth-shaped cookies — analytics cookies don't matter
    if (!/(session|sess|auth|token|jwt|sid|csrf|user)/i.test(name)) continue;
    const flagsMissing = [];
    if (!/httponly/.test(lower)) flagsMissing.push('HttpOnly');
    if (!/secure/.test(lower)) flagsMissing.push('Secure');
    if (!/samesite=/.test(lower)) flagsMissing.push('SameSite');
    if (flagsMissing.length) issues.push(`${name}: missing ${flagsMissing.join(', ')}`);
  }
  if (!issues.length) return null;
  return {
    severity: 'medium',
    category: 'auth',
    title: `Auth/session cookie missing security flags`,
    detail: issues.join('; '),
    remediation: 'Set HttpOnly + Secure + SameSite=Lax (or Strict) on every auth-shaped cookie.',
  };
}

// Extract social/contact channels from homepage HTML so every finding can
// be paired with a way to reach the owner. The signal density of marketing
// pages includes a Twitter/X link in the footer ~70% of the time.
function extractContactChannels(html) {
  if (!html) return {};
  const out = {};
  // X / Twitter handles
  const x = html.match(/(?:twitter\.com|x\.com)\/(?!share|intent|hashtag|home)([A-Za-z0-9_]{2,15})\b/i);
  if (x) out.x = '@' + x[1];
  // LinkedIn
  const li = html.match(/linkedin\.com\/(?:in|company)\/([A-Za-z0-9_-]{2,80})/i);
  if (li) out.linkedin = li[0];
  // Email (skip obvious placeholders like you@email.com, test@example.com)
  const PLACEHOLDER_LOCAL = /^(you|your|me|test|sample|name|user|email|admin|info)$/i;
  const PLACEHOLDER_DOMAIN = /^(email|example|test|sample|domain|yourdomain|localhost|noreply)\./i;
  const emailMatches = html.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || [];
  for (const em of emailMatches) {
    const [local, domain] = em.split('@');
    if (PLACEHOLDER_LOCAL.test(local)) continue;
    if (PLACEHOLDER_DOMAIN.test(domain)) continue;
    if (/sentry|noreply|no-reply/i.test(em)) continue;
    out.email = em;
    break;
  }
  // GitHub repo or org
  const gh = html.match(/github\.com\/([A-Za-z0-9_-]+(?:\/[A-Za-z0-9._-]+)?)/i);
  if (gh) out.github = gh[0];
  return out;
}

// Detect bot-protection challenge pages. These look like 403/200 responses
// to non-browser User-Agents and block the recon from getting useful signal.
// Returning a 'bot_protection' field on the result lets callers know "0
// findings" means "blocked," not "clean."
function detectBotProtection(resp) {
  if (!resp) return null;
  const body = (resp.body || '').slice(0, 4000);
  const headers = resp.headers || {};
  // Vercel Security Checkpoint (default-on for non-custom-domain previews)
  if (/<title>Vercel Security Checkpoint<\/title>/i.test(body)) {
    return { type: 'vercel_security_checkpoint', detail: 'Vercel default bot challenge on the deploy. Add a custom domain to disable, or use a real browser to scan.' };
  }
  // Cloudflare interactive challenge
  if (/<title>Just a moment\.\.\.<\/title>/i.test(body) ||
      /cf-chl-bypass|__cf_chl_/i.test(body) ||
      headers['cf-mitigated'] === 'challenge') {
    return { type: 'cloudflare_challenge', detail: 'Cloudflare bot challenge active. Operator can disable Bot Fight Mode for known scanners or run the scan from a real browser.' };
  }
  // Cloudflare access-denied (rule-based block, not challenge)
  if (/<title>Access denied \| /i.test(body) || /Cloudflare Ray ID/i.test(body) && resp.status === 403) {
    return { type: 'cloudflare_blocked', detail: 'Cloudflare WAF rule denied the request (no challenge offered). Likely a country/IP/UA block.' };
  }
  // Akamai Bot Manager
  if (/_abck=/i.test(headers['set-cookie'] || '') || /akamaibotmanager|reference #18\.[a-f0-9]/i.test(body)) {
    return { type: 'akamai_bot_manager', detail: 'Akamai Bot Manager active.' };
  }
  // AWS WAF
  if (/aws-waf-token|<title>AWS WAF<\/title>/i.test(body)) {
    return { type: 'aws_waf', detail: 'AWS WAF challenge active.' };
  }
  // PerimeterX / HUMAN
  if (/_px2|_pxhd|<title>PerimeterX<\/title>/i.test(body) || /pxsuid/i.test(headers['set-cookie'] || '')) {
    return { type: 'perimeterx_human', detail: 'PerimeterX/HUMAN bot challenge active.' };
  }
  return null;
}

async function runRecon(rawUrl, opts = {}) {
  let parsed;
  try {
    parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
  } catch {
    return { ok: false, error: 'invalid_url', url: rawUrl, findings: [] };
  }
  const base = parsed.protocol + '//' + parsed.hostname;

  const findings = [];
  const stack = {};

  // 1. Root fetch — establishes the SPA-fallback baseline + stack signals
  const root = await fetchUrl(base + '/');
  if (!root) {
    return { ok: false, error: 'root_fetch_failed', url: base, findings: [] };
  }
  // Detect bot-protection challenges. If active, the recon can't see past
  // the gate and returning "0 findings" would be misleading. We surface a
  // bot_protection field so callers (CLI, batch scanner, MC) know.
  const botProtection = detectBotProtection(root);
  if (botProtection) {
    return {
      ok: true,
      url: base,
      scanned_at: new Date().toISOString(),
      stack_signals: stack,
      bot_protection: botProtection,
      contacts: {},
      subdomains_found: 0,
      bucket_urls_found: 0,
      findings: [],
    };
  }
  if (root.status >= 400) {
    return { ok: false, error: 'root_fetch_failed', url: base, status: root.status, findings: [] };
  }

  // Contact channels — extracted from homepage HTML AND the largest JS
  // bundle (SPA shells often have empty root HTML; the contact info lives
  // in the bundle). Wired 2026-05-08 (Matt: "need a way to direct message").
  let contacts = extractContactChannels(root.body);
  if (!contacts.x && !contacts.email && !contacts.linkedin) {
    // Scan up to 2 bundles for contacts — usually finds team page links,
    // X handles in the footer JSX, contact emails in support links.
    const bundlesForContact = extractJsBundles(root.body).slice(0, 2);
    for (const b of bundlesForContact) {
      const bResp = await fetchUrl(base + b, { maxBytes: 1024 * 1024 });
      if (!bResp || bResp.status !== 200) continue;
      const bundleContacts = extractContactChannels(bResp.body);
      contacts = { ...bundleContacts, ...contacts }; // root-level contacts win
      if (contacts.x || contacts.email || contacts.linkedin) break;
    }
  }

  // Stack detection
  if ((root.headers['x-powered-by'] || '').includes('Next.js')) stack.framework = 'next.js';
  if (/firebaseapp\.com|firestore|firebasejs/i.test(root.body)) stack.db = 'firebase';
  if (/@supabase\/|supabase\.co/i.test(root.body)) stack.db = 'supabase';
  if (/next-auth/i.test(root.body)) stack.auth = 'next-auth';
  if (root.headers['server']) stack.server = root.headers['server'];

  // Security headers — only flagged if 2+ missing AND we have other findings
  const missingHeaders = [];
  for (const h of ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options']) {
    if (!root.headers[h]) missingHeaders.push(h);
  }

  // 2. Common exposure paths — probed in parallel (bounded to 6 concurrent).
  // Was serial; with 24 paths and 8s timeouts this could take ~3 minutes
  // worst-case. Bounded concurrency drops worst-case to ~30s.
  const pathProbes = await mapWithConcurrency(COMMON_EXPOSURE_PATHS, 6, async p => {
    const r = await fetchUrl(base + p);
    return { p, r };
  });
  for (const { p, r } of pathProbes) {
    if (!r || r.status !== 200) continue;
    if (isSpaFallback(r, root)) continue;

    let severity = 'high';
    let title = `${p} served publicly`;
    let remediation = `Block ${p} at the deploy layer (Vercel header rule, firebase.json ignore, .gitignore + nginx deny).`;
    if (p.startsWith('/.git/')) {
      // Single HEAD/config response proves git metadata exposure, not full
      // repo cloneability — that requires reachable refs/objects/packs too.
      severity = 'high';
      title = 'Git metadata exposed (.git/ directory served publicly)';
      remediation = 'Verify whether the full repo is recoverable (try git-dumper). Either way, add .git to your build-output ignore list and redeploy. If the repo turns out to be cloneable, rotate any secrets that ever lived in commit history.';
    } else if (p === '/firestore.rules') {
      severity = 'medium';
      title = 'firestore.rules served publicly';
      remediation = 'Auth boundaries are visible to attackers before they probe. Add firestore.rules to firebase.json hosting.ignore.';
    } else if (p.startsWith('/.env')) {
      severity = 'critical';
      title = `${p} served publicly (likely contains live secrets)`;
      remediation = 'Rotate every secret in the file immediately. Add .env* to deploy ignore.';
    } else if (p === '/.DS_Store') {
      severity = 'low';
      title = '.DS_Store served publicly (directory listing leak)';
    }
    findings.push({
      severity, category: 'data_exposure', title,
      detail: (r.body || '').slice(0, 120).replace(/\s+/g, ' '),
      url: base + p,
      remediation,
    });
  }

  // 3. CORS check on root + likely API routes.
  //
  // Two separate concerns:
  //   (a) ACAO=* on the ROOT of a static-host SPA (Vercel, Netlify, CF Pages,
  //       GitHub Pages) is the PLATFORM DEFAULT for static asset serving and
  //       not a finding. We suppress these to avoid the bookit.fyi-shaped
  //       false positive (Matt's peer DM got a "fair callout but CORS:* on
  //       the SPA is just the Vercel default" reply).
  //   (b) Same-origin /api/* routes that REFLECT the Origin header AND set
  //       Access-Control-Allow-Credentials: true. This is the dangerous
  //       pattern the GPT review flagged — attacker.example pointed at a
  //       script in their own page can hit the victim's API in their
  //       browser and read the response with cookies attached. ACAO=* is
  //       harmless without credentials; ACAO=<reflected origin> WITH
  //       credentials is a critical CORS misconfiguration.
  //
  // We probe a small list of common API paths separately and check for
  // origin reflection there.
  const ATTACKER_ORIGIN = 'https://attacker.example.com';
  const apiPathsToProbe = ['/api', '/api/health', '/api/me', '/api/user', '/v1', '/graphql', '/trpc'];
  for (const apiPath of apiPathsToProbe) {
    const apiResp = await fetchUrl(base + apiPath, {
      headers: { 'Origin': ATTACKER_ORIGIN },
      timeout: 6000,
      maxBytes: 4096,
    });
    if (!apiResp || apiResp.status >= 500) continue;
    if (isSpaFallback(apiResp, root)) continue; // route doesn't exist, served the SPA shell
    const apiAcao = apiResp.headers['access-control-allow-origin'];
    const apiAcac = apiResp.headers['access-control-allow-credentials'];
    if (apiAcao === ATTACKER_ORIGIN) {
      // Origin is being reflected. With credentials, this is critical.
      if (apiAcac === 'true') {
        findings.push({
          severity: 'critical',
          category: 'data_exposure',
          title: 'API origin-reflecting CORS with credentials',
          detail: `${apiPath} reflects an attacker-supplied Origin (${ATTACKER_ORIGIN}) AND sends Access-Control-Allow-Credentials: true. Any logged-in user visiting an attacker-controlled page can have their session-authenticated API responses read by the attacker.`,
          url: base + apiPath,
          remediation: 'Pin Access-Control-Allow-Origin to your own origins explicitly. Never combine origin reflection with allow-credentials=true.',
        });
        break;
      } else {
        findings.push({
          severity: 'medium',
          category: 'data_exposure',
          title: 'API reflects arbitrary Origin in CORS headers',
          detail: `${apiPath} reflects an attacker-supplied Origin (${ATTACKER_ORIGIN}) without credentials. Without credentials this is mostly safe, but it indicates the CORS config is permissive — verify nothing protected is reachable.`,
          url: base + apiPath,
          remediation: 'Pin Access-Control-Allow-Origin to a known origin allowlist instead of reflecting whatever Origin came in.',
        });
        break;
      }
    }
    if (apiAcao === '*' && apiAcac === 'true') {
      findings.push({
        severity: 'high',
        category: 'data_exposure',
        title: 'API CORS misconfig: ACAO=* with credentials',
        detail: `${apiPath} returns Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. Browsers reject this combo as invalid, but it indicates the server's CORS config is broken in a way that may expose other paths.`,
        url: base + apiPath,
      });
      break;
    }
  }

  const corsResp = await fetchUrl(base + '/', { headers: { 'Origin': 'https://example.com' } });
  const acao = corsResp?.headers['access-control-allow-origin'];
  if (acao === '*') {
    const platformHeaders = [
      root.headers['server'] || '',
      root.headers['x-powered-by'] || '',
      root.headers['x-vercel-id'] || '',
      root.headers['x-nf-request-id'] || '',
    ].join(' ').toLowerCase();
    // Static-host platforms whose default for static assets is CORS:*. Match
    // both the .io and .com forms because GitHub Pages reports `server:
    // GitHub.com`, and the fediverse of platform headers varies.
    const isStaticPlatform = /vercel|netlify|cloudflare|github\.(io|com)|pages\.dev|gh-pages|fastly/.test(platformHeaders);
    const looksLikeHtml = (root.headers['content-type'] || '').toLowerCase().includes('text/html');
    if (isStaticPlatform && looksLikeHtml) {
      // Platform-default for static SPA hosting; record as info, not a finding.
      // Recon hint only — the real CORS concern lives on the API origin which
      // we don't know without the user telling us.
    } else {
      findings.push({
        severity: 'medium',
        category: 'data_exposure',
        title: 'CORS wide open (Access-Control-Allow-Origin: *)',
        detail: 'Any origin can read responses from this domain. Verify whether this surface serves API responses or only static assets.',
        url: base + '/',
        remediation: 'Pin Access-Control-Allow-Origin to your own domain(s) or remove the header for the public surface.',
      });
    }
  }

  // 4. JS bundle scan + source map probes
  const bundles = extractJsBundles(root.body);
  for (const b of bundles) {
    const bundleResp = await fetchUrl(base + b, { maxBytes: 2 * 1024 * 1024 });
    if (!bundleResp || bundleResp.status !== 200) continue;

    // Secret scan — one finding per bundle max
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.skipIfFirebase && stack.db === 'firebase') continue;
      const m = bundleResp.body.match(pattern.re);
      if (!m) continue;
      findings.push({
        severity: pattern.severity,
        category: 'env_config',
        title: `Possible ${pattern.name} in client bundle`,
        detail: m[0].slice(0, 14) + '…(redacted)',
        url: base + b,
        remediation: 'Move the key to server-side env, rotate the leaked one, never expose secrets via NEXT_PUBLIC_* or client builds.',
      });
      break;
    }

    // Source map probe — try the conventional <bundle>.map URL first, then
    // parse any //# sourceMappingURL=<path> directive at the tail of the
    // bundle (some toolchains publish maps under non-standard names).
    let smapUrl = base + b + '.map';
    let smap = await fetchUrl(smapUrl, { maxBytes: 4096 });
    if (!smap || smap.status !== 200 || isSpaFallback(smap, root)) {
      // Try the directive at the end of the bundle.
      const tail = bundleResp.body.slice(-2048);
      const m = tail.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"<>]+)/);
      if (m) {
        const ref = m[1];
        try {
          smapUrl = ref.startsWith('http') ? ref :
                    ref.startsWith('/') ? base + ref :
                    base + b.replace(/[^/]+$/, '') + ref;
          smap = await fetchUrl(smapUrl, { maxBytes: 4096 });
        } catch { smap = null; }
      }
    }
    if (smap?.status === 200 && smap.body.length > 200 && !isSpaFallback(smap, root)) {
      findings.push({
        severity: 'medium',
        category: 'data_exposure',
        title: 'Source map exposed in production',
        detail: 'Full unminified source available at the .map URL.',
        url: smapUrl,
        remediation: 'Disable source-map publishing in your build (vite: build.sourcemap=false; next: productionBrowserSourceMaps=false).',
      });
      break; // one source-map finding is enough
    }
  }

  // 5. CSP quality grade. If CSP is present, parse it for unsafe-inline /
  // unsafe-eval / wildcard / missing default-src.
  const cspFinding = gradeCsp(root.headers['content-security-policy'] || '');
  if (cspFinding) findings.push({ ...cspFinding, url: base + '/' });

  // 6. Cookie security — auth/session cookies missing HttpOnly/Secure/SameSite.
  const cookieFinding = gradeCookies(root.headers['set-cookie']);
  if (cookieFinding) findings.push({ ...cookieFinding, url: base + '/' });

  // 7. Cloud bucket detection. Pull S3/GCS/R2/Azure/DO Spaces URLs from the
  // homepage HTML and probe each for public listing.
  const bucketUrls = extractBucketUrls(root.body);
  if (bucketUrls.length) {
    const bucketFindings = await probePublicBuckets(bucketUrls);
    findings.push(...bucketFindings);
  }

  // 8. Subdomain enumeration via crt.sh + spicy-subdomain probe.
  // Catches admin/dev/staging/api/test that founders forget about.
  // Only runs for hostnames with a real TLD (skip ip addresses + localhost).
  // Use tldts for proper public-suffix handling — naive `.replace(/^www\./)`
  // would turn `app.foo.co.uk` into `app.foo.co.uk` (wrong) instead of
  // `foo.co.uk`. tldts knows the public suffix list.
  const tldtsParsed = tldts.parse(parsed.hostname);
  const apex = tldtsParsed.domain || parsed.hostname.replace(/^www\./i, '');
  let subdomains = [];
  let braveRelated = [];
  // --scope own-domain-only opts out of subdomain enumeration entirely.
  // Self-scans don't usually want their sibling envs probed; org policies
  // may also forbid touching crt.sh / Brave with the org's apex domain.
  if (opts.skipSubdomains) {
    // skip
  } else if (/[a-z]\.[a-z]{2,}$/i.test(apex) && !apex.match(/^\d+\./)) {
    subdomains = await enumerateSubdomains(apex);
    if (subdomains.length) {
      const subFindings = await probeSubdomains(subdomains);
      findings.push(...subFindings);
    }
    // Augment with Brave search results — catches subdomains that are
    // indexed but not in the CT log, plus alternate hosts (Vercel preview
    // URLs, custom domains pointing at the same project).
    if (BRAVE_KEY) {
      try {
        braveRelated = await discoverRelatedUrls(apex);
        // Probe the spicy ones not already in subdomains
        const subdomainSet = new Set(subdomains.map(s => `https://${s}`));
        const newOnes = braveRelated.filter(u => !subdomainSet.has(u));
        for (const u of newOnes.slice(0, 5)) {
          const subHost = new URL(u).hostname.split('.')[0];
          if (!SPICY_SUB_RES.test(subHost)) continue;
          const probed = await fetchUrl(u + '/', { timeout: 6000 });
          if (probed?.status === 200) {
            findings.push({
              severity: 'high',
              category: 'data_exposure',
              title: `Brave-discovered sensitive subdomain reachable: ${new URL(u).hostname}`,
              detail: `Found via Brave search of ${apex}. Responded HTTP 200 to unauthenticated request.`,
              url: u + '/',
              remediation: 'Restrict by IP allowlist, basic auth, or move behind a VPN.',
            });
          }
        }
      } catch {}
    }
  }

  // 8b. Storybook left in production. The static build at /storybook/ or
  // /storybook-static/ exposes the entire component library, design tokens,
  // and any prop fixtures (which sometimes include real PII). Medium severity
  // because it's not directly exploitable but leaks UI internals.
  // Note: isSpaFallback bails on any <!DOCTYPE-prefixed HTML, but storybook
  // IS HTML — so we skip that gate and discriminate on signature markers
  // (sb-show-main / storybook-preview-iframe) which won't appear in a regular
  // SPA shell.
  const storybookProbes = ['/storybook/', '/storybook/index.html', '/storybook-static/index.html', '/__stories__/', '/_storybook/'];
  for (const sbPath of storybookProbes) {
    const r = await fetchUrl(base + sbPath, { timeout: 5000, maxBytes: 8192 });
    if (!r || r.status !== 200) continue;
    const body = r.body || '';
    // Strict signature match — won't false-positive on the SPA shell, which
    // contains none of these tokens.
    if (/sb-show-main|storybook-preview-iframe|"\/storybook-static\/"|name="storybook"/i.test(body)) {
      findings.push({
        severity: 'medium',
        category: 'data_exposure',
        title: 'Storybook served publicly in production',
        detail: `Storybook static build is reachable at ${sbPath}. This exposes the entire component library, design tokens, and any prop fixtures (which sometimes include real customer data used for visual testing).`,
        url: base + sbPath,
        remediation: 'Storybook is a dev tool. Delete the storybook-static directory from production builds, or block the path at the CDN.',
      });
      break; // one finding is enough
    }
  }

  // 8c. GraphQL introspection enabled. POSTs the standard introspection
  // query to common GraphQL endpoints. If the schema comes back, the entire
  // API surface (queries, mutations, types, resolver names) is enumerable —
  // a major recon win for an attacker even without auth.
  const gqlPaths = ['/graphql', '/api/graphql', '/v1/graphql', '/query'];
  const introspectionQuery = JSON.stringify({
    query: '{ __schema { queryType { name } mutationType { name } types { name } } }',
  });
  for (const gqlPath of gqlPaths) {
    const r = await fetchUrl(base + gqlPath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: introspectionQuery,
      timeout: 6000,
      maxBytes: 32 * 1024,
    });
    if (!r || r.status >= 400) continue;
    const body = r.body || '';
    // Look for a real introspection response, not a generic SPA shell.
    if (/"__schema"\s*:\s*\{/.test(body) && /"queryType"/.test(body)) {
      findings.push({
        severity: 'medium',
        category: 'data_exposure',
        title: 'GraphQL introspection enabled in production',
        detail: `${gqlPath} returns the full schema in response to a public introspection query. An attacker can enumerate every query, mutation, type, and field name without auth.`,
        url: base + gqlPath,
        remediation: 'Disable introspection in production (Apollo: introspection=false; Yoga: disable __schema). Keep it on in dev/staging only.',
      });
      break;
    }
  }

  // 8d. robots.txt sensitive-path leak. robots.txt is meant to tell crawlers
  // what NOT to index, which means founders sometimes list admin/internal
  // paths there as the "I don't want Google in here" signal — but the paths
  // themselves are still publicly reachable. We fetch the file, parse the
  // Disallow lines, probe each, and flag any 200 responses on paths that
  // pattern-match as administrative.
  const robotsResp = await fetchUrl(base + '/robots.txt', { timeout: 5000, maxBytes: 16 * 1024 });
  if (robotsResp && robotsResp.status === 200 && /^\s*Disallow:/im.test(robotsResp.body || '')) {
    const disallows = (robotsResp.body || '').split('\n')
      .map(l => l.trim())
      .filter(l => /^Disallow:/i.test(l))
      .map(l => l.replace(/^Disallow:\s*/i, '').trim())
      .filter(p => p && p !== '/' && p.startsWith('/'))
      .slice(0, 12); // cap probe budget
    const SENSITIVE_PATH_RE = /\/(admin|dashboard|internal|private|staff|backstage|console|panel|cms|wp-admin|backup|db|sql|secret|key|api\/admin|users?|payments?|orders?|customers?)(\/|$)/i;
    for (const dPath of disallows) {
      if (!SENSITIVE_PATH_RE.test(dPath)) continue;
      const probed = await fetchUrl(base + dPath, { timeout: 5000, maxBytes: 4096 });
      if (!probed || probed.status !== 200) continue;
      // isSpaFallback's <!DOCTYPE-prefix shortcut would mask real admin
      // pages here. Use a stricter discriminator: length must differ
      // meaningfully from the root SPA shell, OR body must contain admin/
      // login-flavored content that the shell wouldn't.
      const probedBody = probed.body || '';
      const lenDelta = Math.abs(probedBody.length - (root.body || '').length);
      const hasAdminContent = /<title>[^<]*(admin|dashboard|login|sign[\s-]?in|console|panel)/i.test(probedBody) ||
                              /<form[^>]*(login|password|signin)/i.test(probedBody);
      if (lenDelta < 64 && !hasAdminContent) continue; // looks like SPA fallback
      findings.push({
        severity: 'low',
        category: 'data_exposure',
        title: `robots.txt-listed sensitive path reachable: ${dPath}`,
        detail: `${dPath} is listed in /robots.txt as Disallow (so the operator knew to keep crawlers out) but the path returns HTTP 200 to unauthenticated requests. Worth verifying this is the intended public-facing version.`,
        url: base + dPath,
        remediation: 'Either move the path behind auth, or remove from robots.txt if it really is meant to be public (robots.txt is a "please don\'t index" hint, not access control).',
      });
    }
  }

  // 9. Add the security-headers finding only if we already have 1+ findings
  // (otherwise it reads as nitpicking on a clean site)
  if (findings.length > 0 && missingHeaders.length >= 2) {
    findings.push({
      severity: 'low',
      category: 'env_config',
      title: `Missing ${missingHeaders.length} security headers`,
      detail: `Missing: ${missingHeaders.join(', ')}.`,
      url: base + '/',
      remediation: 'Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options at the CDN or framework config.',
    });
  }

  return {
    ok: true,
    url: base,
    scanned_at: new Date().toISOString(),
    stack_signals: stack,
    contacts,
    subdomains_found: subdomains.length,
    brave_related_found: braveRelated.length,
    bucket_urls_found: bucketUrls.length,
    findings,
  };
}

function pickTopFinding(findings) {
  if (!findings || !findings.length) return null;
  return findings.slice().sort(
    (a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
  )[0];
}

// Format a finding into a 1-2 sentence DM-ready blurb.
function formatFindingForDm(finding) {
  if (!finding) return null;
  const url = finding.url ? ` at ${finding.url.replace(/^https?:\/\//, '')}` : '';
  return `${finding.title}${url}.`;
}

if (require.main === module) {
  const url = process.argv[2];
  if (!url) {
    console.error('Usage: node passive-recon.js <url>');
    process.exit(1);
  }
  runRecon(url).then(r => {
    if (process.argv.includes('--top')) {
      const top = pickTopFinding(r.findings);
      console.log(JSON.stringify({ ok: r.ok, url: r.url, stack_signals: r.stack_signals, top_finding: top, finding_count: r.findings.length }, null, 2));
    } else {
      console.log(JSON.stringify(r, null, 2));
    }
  }).catch(e => {
    console.error('recon failed:', e.message);
    process.exit(1);
  });
}

module.exports = {
  runRecon, pickTopFinding, formatFindingForDm,
  // Test hooks. Not part of the stable API — used only by test/fixtures.test.js
  // to swap in mock fetch / subdomain implementations. Don't rely on them in
  // production code.
  __setFetchUrlForTest: (fn) => { fetchUrl = fn; },
  __setEnumerateSubdomainsForTest: (fn) => { enumerateSubdomains = fn; },
};
