import { assertSafeTarget, UnsafeUrlError } from "./url-guard";
import type { Finding, ScanResult } from "./types";

const UA = "is-my-app-safe/1.0 (+https://github.com/MohammedAl-Alimi/agent-security-playbook)";
const TIMEOUT_MS = 8000;
const MAX_BYTES = 2_000_000; // cap every body we read

type Fetched = {
  res: Response;
  headers: Headers;
  status: number;
  body: string;
};

async function safeFetch(url: string, opts: RequestInit = {}): Promise<Fetched | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      redirect: opts.redirect ?? "follow",
      headers: { "User-Agent": UA, ...(opts.headers || {}) },
    });
    // Read at most MAX_BYTES so a huge/streamed body can't exhaust us.
    const reader = res.body?.getReader();
    let body = "";
    if (reader) {
      const dec = new TextDecoder();
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        body += dec.decode(value, { stream: true });
        if (total >= MAX_BYTES) {
          await reader.cancel();
          break;
        }
      }
    }
    return { res, headers: res.headers, status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function has(h: Headers, name: string): string | null {
  return h.get(name);
}

// ---- individual checks ---------------------------------------------------

function checkHttps(finalUrl: string, httpProbe: Fetched | null | "n/a"): Finding {
  const isHttps = finalUrl.startsWith("https://");
  if (!isHttps) {
    return {
      id: "https", title: "HTTPS enforced", status: "fail", severity: "critical",
      chapter: 25, chapterTitle: "Deployment & Infrastructure",
      detail: "The site served the final response over plain HTTP.",
      fix: "Serve everything over HTTPS and redirect HTTP → HTTPS.",
    };
  }
  if (httpProbe && httpProbe !== "n/a") {
    // httpProbe followed redirects; if it ended on https the site upgrades HTTP.
    const endedHttps = httpProbe.res.url.startsWith("https://");
    if (!endedHttps && httpProbe.status >= 200) {
      return {
        id: "https", title: "HTTP → HTTPS redirect", status: "warn", severity: "medium",
        chapter: 10, chapterTitle: "Headers, CSP & CORS",
        detail: "The plain-HTTP version served content instead of redirecting to HTTPS.",
        fix: "Add a 301/308 redirect from http:// straight to the https:// origin.",
      };
    }
  }
  return {
    id: "https", title: "HTTPS enforced", status: "pass", severity: "none",
    chapter: 25, chapterTitle: "Deployment & Infrastructure",
    detail: "The site is served over HTTPS with a valid certificate.",
  };
}

function checkHeader(
  h: Headers, name: string, id: string, title: string, chapter: number, chapterTitle: string,
  severity: Finding["severity"], fix: string, validate?: (v: string) => Finding | null,
): Finding {
  const v = has(h, name);
  if (!v) {
    return { id, title, status: "fail", severity, chapter, chapterTitle,
      detail: `The \`${name}\` header is missing.`, fix };
  }
  if (validate) {
    const custom = validate(v);
    if (custom) return custom;
  }
  return { id, title, status: "pass", severity: "none", chapter, chapterTitle,
    detail: `Present: \`${v.slice(0, 120)}\`` };
}

function checkCookies(h: Headers): Finding {
  // getSetCookie is available on undici Headers (Node 20+)
  const raw = (h as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  const cookies = raw.length ? raw : (has(h, "set-cookie") ? [has(h, "set-cookie")!] : []);
  if (cookies.length === 0) {
    return { id: "cookies", title: "Cookie flags", status: "info", severity: "none",
      chapter: 1, chapterTitle: "Authentication",
      detail: "No cookies were set on the landing response (nothing to check here)." };
  }
  const bad: string[] = [];
  for (const c of cookies) {
    const lc = c.toLowerCase();
    const name = c.split("=")[0].trim();
    const missing: string[] = [];
    if (!lc.includes("httponly")) missing.push("HttpOnly");
    if (!lc.includes("secure")) missing.push("Secure");
    if (!lc.includes("samesite")) missing.push("SameSite");
    if (missing.length) bad.push(`\`${name}\` (missing ${missing.join(", ")})`);
  }
  if (bad.length === 0) {
    return { id: "cookies", title: "Cookie flags", status: "pass", severity: "none",
      chapter: 1, chapterTitle: "Authentication",
      detail: `All ${cookies.length} cookie(s) set HttpOnly, Secure, and SameSite.` };
  }
  return { id: "cookies", title: "Cookie flags", status: "fail", severity: "high",
    chapter: 1, chapterTitle: "Authentication",
    detail: `Cookies missing protective flags: ${bad.join("; ")}.`,
    fix: "Set HttpOnly + Secure + SameSite on every cookie; use __Host- prefix for session cookies." };
}

async function checkCors(url: URL): Promise<Finding> {
  const evil = "https://scanner-probe.example.com";
  const f = await safeFetch(url.toString(), { headers: { Origin: evil } });
  if (!f) {
    return { id: "cors", title: "CORS policy", status: "info", severity: "none",
      chapter: 10, chapterTitle: "Headers, CSP & CORS", detail: "Could not test CORS." };
  }
  const acao = has(f.headers, "access-control-allow-origin");
  const acac = has(f.headers, "access-control-allow-credentials");
  if (!acao) {
    return { id: "cors", title: "CORS policy", status: "pass", severity: "none",
      chapter: 10, chapterTitle: "Headers, CSP & CORS",
      detail: "No cross-origin access granted to an arbitrary origin." };
  }
  if (acao === "*" && acac?.toLowerCase() === "true") {
    return { id: "cors", title: "CORS policy", status: "fail", severity: "high",
      chapter: 10, chapterTitle: "Headers, CSP & CORS",
      detail: "Wildcard `Access-Control-Allow-Origin: *` combined with credentials — invalid and unsafe.",
      fix: "Never combine `*` with credentials; use an exact-origin allowlist." };
  }
  if (acao === evil) {
    return { id: "cors", title: "CORS policy", status: "fail", severity: "high",
      chapter: 10, chapterTitle: "Headers, CSP & CORS",
      detail: "The server reflected an arbitrary `Origin` back in `Access-Control-Allow-Origin`.",
      fix: "Validate Origin against an exact allowlist; never reflect it blindly." };
  }
  return { id: "cors", title: "CORS policy", status: "pass", severity: "none",
    chapter: 10, chapterTitle: "Headers, CSP & CORS",
    detail: `Access-Control-Allow-Origin is scoped (\`${acao}\`), not reflecting arbitrary origins.` };
}

const EXPOSED_PATHS: { path: string; label: string; sev: Finding["severity"] }[] = [
  { path: "/.env", label: "environment file", sev: "critical" },
  { path: "/.env.production", label: "production environment file", sev: "critical" },
  { path: "/.env.local", label: "local environment file", sev: "critical" },
  { path: "/.git/config", label: "git config", sev: "critical" },
  { path: "/.git/HEAD", label: "git repository", sev: "critical" },
  { path: "/config.json", label: "config file", sev: "high" },
  { path: "/.aws/credentials", label: "AWS credentials", sev: "critical" },
  { path: "/openapi.json", label: "OpenAPI schema", sev: "low" },
  { path: "/docs", label: "API docs UI", sev: "low" },
  { path: "/.DS_Store", label: "macOS directory listing", sev: "low" },
  { path: "/server-status", label: "Apache server-status", sev: "medium" },
];

function looksLikeRealFile(path: string, body: string): boolean {
  const b = body.slice(0, 4000);
  if (path.startsWith("/.env")) return /^[A-Z0-9_]+=.+/m.test(b) && !/<html/i.test(b);
  if (path.startsWith("/.git/config")) return /\[core\]|\[remote/i.test(b);
  if (path.startsWith("/.git/HEAD")) return /^ref:\s+refs\//m.test(b);
  if (path === "/openapi.json") return /"openapi"\s*:/.test(b) || /"swagger"\s*:/.test(b);
  if (path === "/docs") return /swagger|redoc|openapi/i.test(b);
  if (path === "/.DS_Store") return body.includes("Bud1") || / /.test(body.slice(0, 100));
  if (path.endsWith("credentials")) return /aws_access_key_id/i.test(b);
  if (path === "/config.json") return /\{[\s\S]*\}/.test(b) && !/<html/i.test(b);
  if (path === "/server-status") return /Apache Server Status/i.test(b);
  return false;
}

async function checkExposedFiles(base: URL): Promise<Finding[]> {
  const results = await Promise.all(EXPOSED_PATHS.map(async (e) => {
    const f = await safeFetch(new URL(e.path, base).toString(), { redirect: "manual" });
    if (f && f.status === 200 && looksLikeRealFile(e.path, f.body)) {
      return { ok: true, e };
    }
    return { ok: false, e };
  }));
  const hits = results.filter((r) => r.ok);
  if (hits.length === 0) {
    return [{
      id: "exposed-files", title: "No exposed sensitive files", status: "pass", severity: "none",
      chapter: 25, chapterTitle: "Deployment & Infrastructure",
      detail: "None of the commonly-leaked paths (.env, .git, credentials, debug endpoints) were reachable.",
    }];
  }
  return hits.map((h) => ({
    id: `exposed-${h.e.path}`,
    title: `Exposed: ${h.e.label}`,
    status: "fail" as const,
    severity: h.e.sev,
    chapter: h.e.sev === "critical" ? 5 : 25,
    chapterTitle: h.e.sev === "critical" ? "Secrets & Environment" : "Deployment & Infrastructure",
    detail: `\`${h.e.path}\` is publicly reachable and returns real content.`,
    fix: `Remove ${h.e.path} from the served root; rotate any secret it exposed immediately.`,
  }));
}

const SECRET_PATTERNS: { re: RegExp; label: string; sev: Finding["severity"] }[] = [
  { re: /AKIA[0-9A-Z]{16}/, label: "AWS access key ID", sev: "critical" },
  { re: /sk_live_[0-9a-zA-Z]{20,}/, label: "Stripe live secret key", sev: "critical" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, label: "private key", sev: "critical" },
  { re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, label: "JWT (possible service token)", sev: "high" },
  { re: /service_role/, label: "Supabase service_role reference", sev: "high" },
  { re: /AIza[0-9A-Za-z_-]{35}/, label: "Google API key", sev: "medium" },
  { re: /xox[baprs]-[0-9A-Za-z-]{10,}/, label: "Slack token", sev: "high" },
  { re: /ghp_[0-9A-Za-z]{36}/, label: "GitHub personal access token", sev: "critical" },
];

async function checkBundleSecrets(base: URL, homeBody: string): Promise<Finding[]> {
  // Collect a few first-party script URLs from the landing HTML.
  const srcs = [...homeBody.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => m[1])
    .filter((s) => !s.startsWith("http") || s.includes(base.hostname))
    .slice(0, 6);
  const bodies: { where: string; text: string }[] = [{ where: "the landing HTML", text: homeBody }];
  let sourceMapFound = false;
  for (const s of srcs) {
    let u: string;
    try { u = new URL(s, base).toString(); } catch { continue; }
    const f = await safeFetch(u);
    if (f && f.status === 200) {
      bodies.push({ where: s.split("/").pop() || s, text: f.body });
      if (/\/\/[#@]\s*sourceMappingURL=/.test(f.body)) sourceMapFound = true;
    }
  }
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const { where, text } of bodies) {
    for (const p of SECRET_PATTERNS) {
      const m = text.match(p.re);
      if (m && !seen.has(p.label)) {
        seen.add(p.label);
        findings.push({
          id: `secret-${p.label}`, title: `Secret in client code: ${p.label}`,
          status: "fail", severity: p.sev, chapter: 5, chapterTitle: "Secrets & Environment",
          detail: `A ${p.label} pattern was found in ${where}. Anything in client JS is public.`,
          fix: "Move the secret server-side; never prefix secrets with NEXT_PUBLIC_/VITE_. Rotate it now.",
        });
      }
    }
  }
  // NEXT_PUBLIC_ scan (informational — these are meant to be public but often misused)
  const npMatches = new Set(
    [...bodies.flatMap((b) => [...b.text.matchAll(/NEXT_PUBLIC_[A-Z0-9_]+/g)].map((m) => m[0]))]
  );
  const suspicious = [...npMatches].filter((k) => /SECRET|SERVICE|PRIVATE|TOKEN|KEY_ID|PASSWORD/.test(k));
  if (suspicious.length) {
    findings.push({
      id: "next-public", title: "Suspicious NEXT_PUBLIC_ variables", status: "warn", severity: "high",
      chapter: 5, chapterTitle: "Secrets & Environment",
      detail: `Client-exposed vars that sound secret: ${suspicious.slice(0, 5).join(", ")}. NEXT_PUBLIC_ ships to every visitor.`,
      fix: "If any of these hold a real secret, rename without the public prefix and rotate.",
    });
  }
  if (sourceMapFound) {
    findings.push({
      id: "sourcemaps", title: "Public source maps", status: "warn", severity: "low",
      chapter: 17, chapterTitle: "Client Data Protection",
      detail: "A `sourceMappingURL` was referenced in production JS, exposing original source.",
      fix: "Disable production browser source maps unless the source is meant to be public.",
    });
  }
  if (findings.length === 0) {
    findings.push({
      id: "bundle-secrets", title: "No obvious secrets in client code", status: "pass", severity: "none",
      chapter: 5, chapterTitle: "Secrets & Environment",
      detail: "Scanned the landing HTML and first-party scripts; no high-signal secret patterns matched.",
    });
  }
  return findings;
}

async function checkSecurityTxt(base: URL): Promise<Finding> {
  for (const p of ["/.well-known/security.txt", "/security.txt"]) {
    const f = await safeFetch(new URL(p, base).toString(), { redirect: "manual" });
    if (f && f.status === 200 && /contact:/i.test(f.body)) {
      return { id: "security-txt", title: "security.txt present", status: "pass", severity: "none",
        chapter: 25, chapterTitle: "Deployment & Infrastructure",
        detail: "A vulnerability-disclosure contact is published at security.txt." };
    }
  }
  return { id: "security-txt", title: "security.txt", status: "info", severity: "none",
    chapter: 25, chapterTitle: "Deployment & Infrastructure",
    detail: "No security.txt found — optional, but it gives researchers a way to report issues.",
    fix: "Publish /.well-known/security.txt with a Contact and Expires field." };
}

function checkDisclosure(h: Headers): Finding {
  const leaks: string[] = [];
  const xp = has(h, "x-powered-by");
  const srv = has(h, "server");
  if (xp) leaks.push(`X-Powered-By: ${xp}`);
  if (srv && /\d/.test(srv)) leaks.push(`Server: ${srv}`);
  if (leaks.length === 0) {
    return { id: "disclosure", title: "Version disclosure", status: "pass", severity: "none",
      chapter: 25, chapterTitle: "Deployment & Infrastructure",
      detail: "No framework/version banners leaked in response headers." };
  }
  return { id: "disclosure", title: "Version disclosure", status: "warn", severity: "low",
    chapter: 25, chapterTitle: "Deployment & Infrastructure",
    detail: `Response headers reveal stack details: ${leaks.join("; ")}.`,
    fix: "Strip X-Powered-By and version numbers from the Server header." };
}

async function checkDmarc(host: string): Promise<Finding> {
  // Registrable-ish domain: last two labels (good enough for a surface check).
  const parts = host.split(".");
  const domain = parts.length > 2 ? parts.slice(-2).join(".") : host;
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=_dmarc.${domain}&type=TXT`,
      { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(6000) },
    );
    const j = (await r.json()) as { Answer?: { data: string }[] };
    const txt = (j.Answer || []).map((a) => a.data).join(" ");
    if (/v=DMARC1/i.test(txt)) {
      const policy = txt.match(/p=(\w+)/i)?.[1]?.toLowerCase();
      if (policy === "none") {
        return { id: "dmarc", title: "DMARC policy", status: "warn", severity: "low",
          chapter: 23, chapterTitle: "Email, SMS & Notifications",
          detail: "DMARC exists but is set to `p=none` (monitor only) — it doesn't stop spoofing yet.",
          fix: "Move DMARC from p=none → quarantine → reject once reports look clean." };
      }
      return { id: "dmarc", title: "DMARC policy", status: "pass", severity: "none",
        chapter: 23, chapterTitle: "Email, SMS & Notifications",
        detail: `DMARC enforced (\`p=${policy}\`), protecting the domain from email spoofing.` };
    }
    return { id: "dmarc", title: "DMARC policy", status: "warn", severity: "medium",
      chapter: 23, chapterTitle: "Email, SMS & Notifications",
      detail: `No DMARC record on ${domain} — anyone can spoof email from this domain.`,
      fix: "Publish a _dmarc TXT record; start at p=none with reporting, then enforce." };
  } catch {
    return { id: "dmarc", title: "DMARC policy", status: "info", severity: "none",
      chapter: 23, chapterTitle: "Email, SMS & Notifications", detail: "Could not check DMARC." };
  }
}

const BLIND_SPOTS = [
  { chapter: 2, chapterTitle: "Authorization & RBAC", note: "Whether every request is authorized (IDOR/BOLA) needs authenticated testing on accounts you own." },
  { chapter: 4, chapterTitle: "Database & RLS", note: "Row-Level Security lives in your database — invisible from outside." },
  { chapter: 6, chapterTitle: "Hashing & Tokens", note: "Password hashing and JWT signing happen server-side; can't be observed." },
  { chapter: 8, chapterTitle: "Webhooks", note: "Webhook signature verification is internal to your handlers." },
  { chapter: 19, chapterTitle: "Business Logic", note: "Coupon/trial/workflow abuse requires interacting with the app as a user." },
  { chapter: 21, chapterTitle: "Agents, MCP & RAG", note: "Agent and RAG authorization can't be seen from the public surface." },
];

// ---- orchestration -------------------------------------------------------

const WEIGHT: Record<Finding["severity"], number> = { critical: 40, high: 20, medium: 10, low: 3, none: 0 };

export async function runScan(input: string): Promise<ScanResult> {
  let target: URL;
  try {
    target = await assertSafeTarget(input);
  } catch (e) {
    throw e instanceof UnsafeUrlError ? e : new UnsafeUrlError("Could not process that URL.");
  }

  const home = await safeFetch(target.toString());
  if (!home) {
    throw new UnsafeUrlError("Couldn't reach that site (it may be down, blocking bots, or too slow).");
  }
  const finalUrl = home.res.url || target.toString();
  const h = home.headers;

  // HTTP-version probe (best effort) for redirect check
  let httpProbe: Fetched | null | "n/a" = "n/a";
  if (target.protocol === "https:") {
    httpProbe = await safeFetch(`http://${target.host}${target.pathname}`);
  }

  const findings: Finding[] = [];
  findings.push(checkHttps(finalUrl, httpProbe));
  findings.push(checkHeader(h, "strict-transport-security", "hsts", "HSTS", 10, "Headers, CSP & CORS", "medium",
    "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload."));
  findings.push(checkHeader(h, "content-security-policy", "csp", "Content-Security-Policy", 10, "Headers, CSP & CORS", "high",
    "Add a Content-Security-Policy; prefer a nonce-based policy over unsafe-inline.",
    (v) => /unsafe-inline/.test(v)
      ? { id: "csp", title: "Content-Security-Policy", status: "warn", severity: "medium", chapter: 10,
          chapterTitle: "Headers, CSP & CORS", detail: "CSP is present but allows `unsafe-inline`, which weakens XSS protection.",
          fix: "Move to a nonce-based CSP with strict-dynamic; drop unsafe-inline." }
      : null));
  findings.push(checkHeader(h, "x-frame-options", "xfo", "Clickjacking protection", 10, "Headers, CSP & CORS", "medium",
    "Set X-Frame-Options: DENY or a CSP frame-ancestors 'none' directive.",
    (v) => {
      const csp = has(h, "content-security-policy") || "";
      if (/frame-ancestors/.test(csp) || /deny|sameorigin/i.test(v)) return null;
      return { id: "xfo", title: "Clickjacking protection", status: "warn", severity: "low", chapter: 10,
        chapterTitle: "Headers, CSP & CORS", detail: `X-Frame-Options is \`${v}\` — verify framing is restricted.`, };
    }));
  findings.push(checkHeader(h, "x-content-type-options", "xcto", "X-Content-Type-Options", 10, "Headers, CSP & CORS", "low",
    "Add X-Content-Type-Options: nosniff."));
  findings.push(checkHeader(h, "referrer-policy", "referrer", "Referrer-Policy", 10, "Headers, CSP & CORS", "low",
    "Add Referrer-Policy: strict-origin-when-cross-origin."));
  findings.push(checkCookies(h));
  findings.push(await checkCors(target));
  findings.push(...(await checkExposedFiles(target)));
  findings.push(...(await checkBundleSecrets(target, home.body)));
  findings.push(checkDisclosure(h));
  findings.push(await checkSecurityTxt(target));
  findings.push(await checkDmarc(target.hostname));

  // score
  let penalty = 0;
  for (const f of findings) if (f.status === "fail" || f.status === "warn") penalty += WEIGHT[f.severity] * (f.status === "warn" ? 0.5 : 1);
  const score = Math.max(0, Math.round(100 - penalty));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  const summary = {
    pass: findings.filter((f) => f.status === "pass").length,
    fail: findings.filter((f) => f.status === "fail").length,
    warn: findings.filter((f) => f.status === "warn").length,
    info: findings.filter((f) => f.status === "info").length,
  };

  const order: Record<Finding["status"], number> = { fail: 0, warn: 1, info: 2, pass: 3, blind: 4 };
  const sev: Record<Finding["severity"], number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
  findings.sort((a, b) => order[a.status] - order[b.status] || sev[a.severity] - sev[b.severity]);

  return {
    url: input, finalUrl, scannedAt: new Date().toISOString(),
    grade, score, summary, findings, blindSpots: BLIND_SPOTS,
  };
}
