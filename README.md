# Is My App Safe?

**A passive surface-security scanner for web apps.** Enter a URL, get an instant read-only security check — mapped to every relevant chapter of the [Agent Security Playbook](https://github.com/MohammedAl-Alimi/agent-security-playbook).

It's the "SSL Labs / Mozilla Observatory" idea, but the findings speak the playbook's language and it's honest about the large set of things a URL scan physically cannot see.

---

## What it checks (passively, from the outside)

| Check | Playbook chapter |
|---|---|
| HTTPS enforced + HTTP→HTTPS upgrade | ch25 / ch10 |
| Security headers: HSTS, CSP (flags `unsafe-inline`), X-Frame-Options, nosniff, Referrer-Policy | ch10 |
| Cookie flags — HttpOnly, Secure, SameSite | ch01 |
| CORS — reflected-origin and `*`-with-credentials misconfig | ch10 |
| **Exposed files** — `/.env`, `/.git/config`, `/.aws/credentials`, `/openapi.json`, `/docs`, `.DS_Store`, … | ch05 / ch25 |
| **Secrets in client JS** — AWS/Stripe/Google/Slack/GitHub keys, private keys, JWTs, `service_role`, misused `NEXT_PUBLIC_` | ch05 / ch17 |
| Public source maps | ch17 |
| Version/stack disclosure headers | ch25 |
| `security.txt` presence | ch25 |
| DMARC record + policy strength | ch23 |

## What it can't check (and says so)

A URL scan only sees the public surface. The most catastrophic vibe-coding failures live server-side and are invisible from outside: **Row-Level Security (ch04), per-request authorization / IDOR (ch02), password hashing & JWT signing (ch06), webhook signature verification (ch08), business-logic abuse (ch19), agent/RAG authorization (ch21).** The tool lists these as explicit blind spots and points you at the playbook's code-level self-audit for them.

## Safety & ethics

- **Passive only.** It fetches public pages the way a browser does. No fuzzing, no injection, no authentication attempts, no scanning behind a login. It never attacks a site.
- **SSRF-guarded.** The scanner fetches user-supplied URLs server-side, so it enforces the playbook's own ch13 rule on itself: DNS is resolved and every address is checked against private/loopback/link-local/cloud-metadata ranges before any request is made.
- **Nothing stored.** Scans run in-memory and are returned directly; no database, no logging of scanned URLs.
- Best-effort in-memory rate limiting (see the honest note in `app/api/scan/route.ts`; production scale would use `@upstash/ratelimit` per ch07).

## Stack

Next.js (App Router) · React 19 · TypeScript · Zod · deployed on Vercel. No database, no secrets, minimal attack surface — the app practices the headers/validation/SSRF rules it checks for.

## Run locally

```bash
npm install
npm run dev      # http://localhost:3000
```

## License

[MIT](LICENSE). The findings link to the [Agent Security Playbook](https://github.com/MohammedAl-Alimi/agent-security-playbook) — a surface check is a starting point, not a certificate.
