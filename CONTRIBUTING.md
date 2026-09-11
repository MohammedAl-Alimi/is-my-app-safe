# Contributing

Thanks for helping make **Is My App Safe?** better. The most useful contributions are **new passive checks** and **fewer false positives** — both are well-scoped and easy to review.

## Ground rules

1. **Passive only.** Checks fetch public pages the way a browser does. No fuzzing, no injection, no auth attempts, no scanning behind a login. If a check would *attack* a site, it doesn't belong here.
2. **SSRF-safe.** All outbound requests go through `safeFetch` in `lib/checks.ts`, which follows redirects manually and re-validates every hop via `lib/url-guard.ts`. Never call `fetch` directly on a target URL.
3. **Every finding maps to a playbook chapter** and carries a concrete `fix` when it fails.
4. **Low false positives.** A noisy check that cries wolf is worse than no check. Prefer a confident `pass`/`fail` over a guess; use `info` when you genuinely can't tell.

## Add a new check (the common case)

1. Write a `checkX(...)` function in [`lib/checks.ts`](lib/checks.ts) that returns a `Finding` (see [`lib/types.ts`](lib/types.ts)).
2. Give it a `chapter` number and add the chapter's URL to `chapterLink()` in `lib/types.ts` if it isn't there yet.
3. Call it from `runScan()` and push the result into `findings`.
4. Assign a `severity` — it feeds the score weighting.
5. Test locally against a site you know passes *and* one you know fails.

```bash
npm install
npm run dev            # http://localhost:3000
# or hit the API directly:
curl -s -X POST localhost:3000/api/scan -H 'content-type: application/json' -d '{"url":"example.com"}' | jq
```

## Good first issues

- A new security header check (Permissions-Policy directives, COOP/COEP, `Cross-Origin-Resource-Policy`).
- More exposed-path signatures (framework-specific debug endpoints, `.svn/`, `.hg/`, backup extensions).
- Additional client-bundle secret patterns (new provider key formats) — keep them high-signal to avoid false positives.
- SPF/BIMI DNS checks alongside the existing DMARC check.

## Opening a PR

Keep PRs focused (one check or one fix). Describe what site behavior the check detects and why it matters. See [`SECURITY.md`](SECURITY.md) for the project's own security posture.
