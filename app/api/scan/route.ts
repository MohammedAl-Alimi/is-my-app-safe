import { NextResponse } from "next/server";
import { z } from "zod";
import { runScan } from "@/lib/checks";
import { UnsafeUrlError } from "@/lib/url-guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const Body = z.object({ url: z.string().min(3).max(2048) });

// Best-effort in-memory limiter. NOTE: per-instance only — see ch07 of the
// playbook. For real scale, swap in @upstash/ratelimit. Honest stopgap for v1.
const HITS = new Map<string, number[]>();
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 8;

function limited(ip: string): boolean {
  const now = Date.now();
  const arr = (HITS.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  arr.push(now);
  HITS.set(ip, arr);
  if (HITS.size > 5000) HITS.clear(); // crude memory cap
  return arr.length > MAX_PER_WINDOW;
}

export async function POST(req: Request) {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    req.headers.get("x-real-ip") ||
    "unknown";

  if (limited(ip)) {
    return NextResponse.json(
      { error: "Too many scans from your connection. Wait a minute and try again." },
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }

  let json: unknown;
  try {
    json = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const parsed = Body.safeParse(json);
  if (!parsed.success) {
    return NextResponse.json({ error: "Please provide a URL to scan." }, { status: 400 });
  }

  try {
    const result = await runScan(parsed.data.url);
    return NextResponse.json(result, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    if (e instanceof UnsafeUrlError) {
      return NextResponse.json({ error: e.message }, { status: 400 });
    }
    return NextResponse.json(
      { error: "The scan failed unexpectedly. Try a different URL." },
      { status: 500 },
    );
  }
}
