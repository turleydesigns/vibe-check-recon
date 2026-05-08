# vibe-check-recon

Read-only public-surface security recon for AI-built apps.

You shipped your MVP with Cursor / Lovable / Bolt / v0 / Windsurf / Claude Code. Before more users find it, run this to catch what your build agent and hosting platform exposed by default.

```bash
npx vibe-check-recon https://my-app.com
```

## What it finds

| Category | Examples |
|---|---|
| **Source / config exposure** | `.git/` directory served publicly, `.env` files reachable, `firestore.rules` exposed, `.svn/`, build manifests, DB dumps left in the public dir |
| **Leaked keys** | OpenAI / Anthropic / Stripe secret keys / Google API keys in client JS bundles |
| **Cloud storage** | Public S3 / GCS / R2 / Azure / DigitalOcean buckets that list publicly |
| **Subdomain hygiene** | `admin.X`, `dev.X`, `staging.X`, `api.X` surfaced via Certificate Transparency log + Brave search, then probed for unauthenticated 200s |
| **Web security headers** | Missing CSP / HSTS / X-Frame-Options / X-Content-Type-Options |
| **CSP quality** | Beyond present/absent: detects `unsafe-inline`, `unsafe-eval`, missing `default-src`, wildcard `script-src` |
| **Cookie security** | Auth/session cookies missing `HttpOnly` / `Secure` / `SameSite` flags |
| **Source maps in production** | Full unminified source available at the `.map` URL |
| **CORS misconfigs** | `Access-Control-Allow-Origin: *` on real APIs (with platform-default suppression for Vercel/Netlify/CF Pages/GitHub Pages SPAs) |
| **API doc / route disclosure** | `/swagger.json`, `/api/docs`, `/openapi.json` revealing your full route surface |

## What it does NOT do

This is **passive reconnaissance only**. It reads what the target server already serves publicly. It does not:

- Send injection payloads (SQL / XSS / SSRF)
- Brute force or fuzz endpoints
- Attempt authentication
- Touch any data that isn't already public
- Generate load on the target

It's safe to run against your own apps and apps you have permission to test.

## What this *isn't*

This is the **30-second public-surface check**. It reads what your server already serves and flags the obvious classes of mistake (`.git/` exposed, API keys in the bundle, public buckets, weak headers, etc).

It does NOT touch the inside of your application. The interesting bugs live there.

### Free finding vs paid finding — concrete example

You build a Lovable app. It uses Supabase. You ship it. You run `npx vibe-check-recon https://yourapp.com`.

**What the free recon finds:**

> [info] Possible supabase_url in client bundle
>   `https://abcd1234.supabase.co`
>   This is expected — Supabase anon keys + URLs are public by design when paired with correct Row Level Security policies.

That's a true positive but a low-impact one. It just confirms the stack. The real question is whether the RLS policies are *actually* correct.

**What the paid [Vibe Audit](https://uxcontinuum.com/vibe-audit) finds, on the same app:**

> [critical] RLS policy on `bookings` table grants `select` to `authenticated` role unconditionally
>   `create policy "Users can view bookings" on bookings for select to authenticated using (true);`
>   Any logged-in user (including freshly-signed-up attackers) can read every row in the `bookings` table, including other users' contact details, party sizes, and payment status. The intended policy was almost certainly `using (auth.uid() = user_id)`. Verified by signing in as a test account and querying `bookings` directly via the anon key.
>   **Patch:**
>   ```sql
>   drop policy "Users can view bookings" on bookings;
>   create policy "Users can view their own bookings" on bookings
>     for select to authenticated using (auth.uid() = user_id);
>   ```

Same stack. Same recon output. Different layer.

The free tool finds public surface. The paid audit reads your actual code, validates intent against the schema, and writes you the patch. That's the diff.

If your app has users, payments, or accounts — get the [Vibe Audit](https://uxcontinuum.com/vibe-audit). $99 founder special, 12-hour turnaround, ranked written report covering auth, data exposure, DB security, payments, env config, performance, and UX red flags.

## Install

```bash
# One-shot
npx vibe-check-recon https://my-app.com

# Or install
npm install -g vibe-check-recon
vibe-check-recon https://my-app.com
```

Requires Node 18+.

## Usage

```bash
# Pretty output
npx vibe-check-recon https://my-app.com

# JSON for programmatic use
npx vibe-check-recon https://my-app.com --json

# Just the highest-severity finding
npx vibe-check-recon https://my-app.com --top

# Help
npx vibe-check-recon --help
```

## Optional environment

```bash
# Enables Brave-search-powered subdomain discovery beyond crt.sh
export BRAVE_API_KEY=BSAxxx
```

Without `BRAVE_API_KEY`, recon still works. It just skips the Brave-augmented URL discovery and relies on the public Certificate Transparency log alone.

## Output format

JSON shape:

```json
{
  "ok": true,
  "url": "https://my-app.com",
  "scanned_at": "2026-05-08T20:42:00.000Z",
  "stack_signals": { "framework": "next.js", "db": "supabase", "server": "Vercel" },
  "contacts": { "x": "@founder", "email": "hi@my-app.com", "linkedin": "..." },
  "subdomains_found": 4,
  "bucket_urls_found": 0,
  "findings": [
    {
      "severity": "critical",
      "category": "data_exposure",
      "title": "Full .git/ directory exposed",
      "detail": "ref: refs/heads/main",
      "url": "https://my-app.com/.git/HEAD",
      "remediation": "Anyone can clone the entire repo via git-dumper. Add .git to your build-output ignore list and redeploy."
    }
  ]
}
```

Severity tiers:

- **critical** — source or secrets fully exposed; immediate disclosure warranted
- **high** — sensitive config served; needs fast fix
- **medium** — misconfig with credible attack surface
- **low** — best-practice gap; mention only when other findings exist
- **info** — stack signal, not a vulnerability

## Origin

Built from the recon module that powers the manual [Vibe Audit](https://uxcontinuum.com/vibe-audit) service. Open-sourced because the public-surface check should be free for every founder shipping an MVP — and because the things this *can't* catch are exactly what a paid audit is for.

If recon finds something you didn't expect, that's the moment to ask whether the rest of your code has the same shape of issue. That's the audit.

## License

MIT. Use it on your apps. Use it on your clients' apps with their permission. Don't use it as a launching point for active attacks.

## Author

[Matt Turley](https://uxcontinuum.com) — Fractional CTO, 20+ years. Audits AI-built apps before launch. [uxcontinuum.com/vibe-audit](https://uxcontinuum.com/vibe-audit).
