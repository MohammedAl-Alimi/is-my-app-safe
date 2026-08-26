# Security Policy

This app is a security tool, so it holds itself to the [Agent Security Playbook](https://github.com/MohammedAl-Alimi/agent-security-playbook) it links to.

## Reporting a vulnerability

Please report privately via [GitHub Security Advisories](https://github.com/MohammedAl-Alimi/is-my-app-safe/security/advisories/new). Do not open a public issue for a security bug.

## Self-audit against the playbook

The codebase was reviewed against every applicable chapter. This is a static Next.js app with **no database, no auth, no user accounts, no secrets, no payments, no webhooks, no file uploads, and no email**, so most chapters are not applicable. The relevant ones:

| Chapter | Status |
|---|---|
| ch03 Input validation | `/api/scan` validates its body with Zod; the target URL is re-validated by the SSRF guard (`lib/url-guard.ts`). |
| ch10 Headers, CSP & CORS | Security headers set in `next.config.ts` (HSTS, CSP, frame-ancestors, nosniff, Referrer-Policy). CSP still allows `unsafe-inline` for framework scripts — the one item the tool flags on itself; a nonce-based CSP is the tracked improvement. |
| ch13 SSRF | The core risk: the app fetches user-supplied URLs server-side. `lib/url-guard.ts` resolves DNS and rejects private/loopback/link-local/cloud-metadata ranges; `safeFetch` follows redirects **manually** and re-validates every hop, so a `302 → 169.254.169.254` can't bypass the guard. |
| ch18 Output encoding & XSS | Findings can echo values from the scanned site. The UI renders them as React text/`<code>` nodes — no `dangerouslySetInnerHTML` anywhere. |
| ch07 Rate limiting | Best-effort in-memory limiter in `app/api/scan/route.ts`. Honest limitation: per-instance only; a global store (`@upstash/ratelimit`) is the production upgrade. |
| ch09 Logging & errors | The API returns generic error messages; no stack traces or internals reach the client. |
| ch25 Deployment | No debug/docs endpoints; browser source maps not published; Next.js kept patched (Vercel blocks vulnerable versions on deploy). |

## Known limitations

- **DNS rebinding on the initial connection.** The guard validates the resolved address, then `fetch` resolves again independently. The redirect path is pinned per-hop; the very first connection is not IP-pinned. Accepted for a passive, low-value scanner; a hardened build would pin the resolved IP into the connection.
- **Rate limiting is per-instance.** See ch07 note above.
