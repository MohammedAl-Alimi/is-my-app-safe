"use client";

import { useState, Fragment } from "react";
import type { ScanResult, Finding } from "@/lib/types";
import { chapterLink, PLAYBOOK_URL } from "@/lib/types";

const ICONS: Record<Finding["status"], string> = {
  fail: "✕", warn: "!", pass: "✓", info: "i", blind: "◌",
};
const GRADE_COLOR: Record<string, string> = {
  A: "#4ade80", B: "#a3e635", C: "#fbbf24", D: "#fb923c", F: "#f87171",
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  async function scan(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await r.json();
      if (!r.ok) setError(data.error || "Scan failed.");
      else setResult(data);
    } catch {
      setError("Network error — please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="wrap">
      <div className="hero">
        <div className="badge"><span className="dot" /> passive surface check · no login · nothing stored</div>
        <h1>
          Is my app <span className="grad">safe?</span>
        </h1>
        <p className="sub">
          Enter a URL. We run a read-only security check from the outside — headers, exposed files,
          leaked secrets, CORS, TLS, email spoofing — and map every result to the{" "}
          <a href={PLAYBOOK_URL} style={{ color: "var(--accent2)" }}>Agent Security Playbook</a>.
        </p>

        <form onSubmit={scan}>
          <input
            type="text"
            placeholder="example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            autoComplete="off" autoCapitalize="off" spellCheck={false}
            aria-label="Website URL to scan"
          />
          <button className="scan" type="submit" disabled={loading}>
            {loading ? <span className="spinner" /> : "Scan"}
          </button>
        </form>
        <p className="note">
          Passive only: we fetch public pages like a browser does. No attacks, no scanning of things behind a login.
        </p>
        {error && <p className="err">{error}</p>}
      </div>

      {result && <Results r={result} />}

      <footer>
        Built on the{" "}
        <a href={PLAYBOOK_URL}>Agent Security Playbook</a>. A surface check is not a full audit —{" "}
        see the blind spots below.
      </footer>
    </main>
  );
}

function Results({ r }: { r: ScanResult }) {
  const host = (() => {
    try { return new URL(r.finalUrl).host; } catch { return r.url; }
  })();
  const grade = r.grade;
  const color = GRADE_COLOR[grade] || "#93a1bd";
  const verdict =
    grade === "A" ? "Strong surface posture" :
    grade === "B" ? "Good, a few gaps" :
    grade === "C" ? "Some real issues to fix" :
    grade === "D" ? "Multiple weaknesses" : "Serious exposure";

  return (
    <div className="result">
      <div className="scorecard">
        <div className="gradeCircle" style={{ color }}>{grade}</div>
        <div className="gradeMeta">
          <div className="host">{host}</div>
          <div className="line">{verdict} · {r.score}/100</div>
          <div className="pills">
            <span className="pill fail">{r.summary.fail} failed</span>
            <span className="pill warn">{r.summary.warn} warnings</span>
            <span className="pill pass">{r.summary.pass} passed</span>
          </div>
        </div>
      </div>

      <div className="section-h">What we checked</div>
      {r.findings.map((f) => (
        <div key={f.id} className={`finding ${f.status}`}>
          <div className="f-head">
            <span className="f-icon" style={{ color: `var(--${f.status === "info" ? "info" : f.status})` }}>
              {ICONS[f.status]}
            </span>
            <span className="f-title">{f.title}</span>
            {f.severity !== "none" && (f.status === "fail" || f.status === "warn") && (
              <span className={`sev ${f.severity}`}>{f.severity}</span>
            )}
          </div>
          <div className="f-detail">{renderCode(f.detail)}</div>
          {f.fix && (f.status === "fail" || f.status === "warn") && (
            <div className="f-fix"><b>Fix:</b> {renderCode(f.fix)}</div>
          )}
          <a className="chapter-link" href={chapterLink(f.chapter)} target="_blank" rel="noopener noreferrer">
            → Playbook ch{f.chapter}: {f.chapterTitle}
          </a>
        </div>
      ))}

      <div className="section-h">Blind spots — we can&apos;t see these from outside</div>
      <p className="blind-intro">
        A URL scan can only observe the public surface. The most catastrophic vibe-coding failures live
        server-side, where only your code (or an authenticated test) can reach them:
      </p>
      {r.blindSpots.map((b) => (
        <div key={b.chapter} className="finding blind">
          <div className="f-head">
            <span className="f-icon" style={{ color: "var(--faint)" }}>◌</span>
            <span className="f-title">{b.chapterTitle}</span>
          </div>
          <div className="f-detail">{b.note}</div>
          <a className="chapter-link" href={chapterLink(b.chapter)} target="_blank" rel="noopener noreferrer">
            → Playbook ch{b.chapter}
          </a>
        </div>
      ))}

      <div className="cta">
        <h3>Want the checks a scanner can&apos;t do?</h3>
        <p>
          Point your AI coding agent at the playbook and have it audit your actual code — RLS, authz,
          hashing, webhooks, business logic.
        </p>
        <a className="btn" href={PLAYBOOK_URL} target="_blank" rel="noopener noreferrer">
          Open the Agent Security Playbook →
        </a>
      </div>
    </div>
  );
}

// Render backtick-delimited spans as <code> React nodes. No HTML sink: finding
// text can include values echoed from the scanned site (headers, CORS origins),
// so we never build an HTML string (Agent Security Playbook ch18). React escapes
// every text node, so third-party content can't inject markup.
function renderCode(s: string): React.ReactNode {
  return s.split(/(`[^`]+`)/g).map((part, i) =>
    part.startsWith("`") && part.endsWith("`") ? (
      <code key={i}>{part.slice(1, -1)}</code>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  );
}
