import { lookup } from "node:dns/promises";
import net from "node:net";

// SSRF guard for the scanner itself (Agent Security Playbook ch13).
// This tool fetches user-supplied URLs server-side, so it MUST refuse to reach
// private, loopback, link-local, or cloud-metadata addresses — otherwise the
// scanner becomes an SSRF proxy into our own infrastructure.

export class UnsafeUrlError extends Error {}

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
]);

// Returns true for any address we must never connect to.
function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10) return true; // 10.0.0.0/8
    if (p[0] === 127) return true; // loopback
    if (p[0] === 0) return true; // 0.0.0.0/8
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true; // 172.16/12
    if (p[0] === 192 && p[1] === 168) return true; // 192.168/16
    if (p[0] === 169 && p[1] === 254) return true; // link-local + AWS/GCP metadata 169.254.169.254
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT 100.64/10
    if (p[0] >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const a = ip.toLowerCase();
    if (a === "::1" || a === "::") return true; // loopback / unspecified
    if (a.startsWith("fe80")) return true; // link-local
    if (a.startsWith("fc") || a.startsWith("fd")) return true; // unique local
    // IPv4-mapped (::ffff:169.254.169.254 etc.)
    const m = a.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
    if (m) return isPrivateIp(m[1]);
    return false;
  }
  return true; // unknown format → refuse
}

/**
 * Validate and normalize a target URL, then resolve DNS and confirm every
 * resolved address is public. Returns the normalized https/http URL to fetch.
 * Throws UnsafeUrlError on anything unsafe.
 */
export async function assertSafeTarget(raw: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw.includes("://") ? raw : `https://${raw}`);
  } catch {
    throw new UnsafeUrlError("That doesn't look like a valid URL.");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new UnsafeUrlError("Only http and https URLs can be scanned.");
  }
  if (url.username || url.password) {
    throw new UnsafeUrlError("URLs with embedded credentials aren't allowed.");
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".localhost")) {
    throw new UnsafeUrlError("Internal hostnames can't be scanned.");
  }
  // A bare IP literal is checked directly; a hostname is resolved below.
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new UnsafeUrlError("Private/internal addresses can't be scanned.");
    return url;
  }
  if (!host.includes(".")) {
    throw new UnsafeUrlError("Enter a full domain, e.g. example.com.");
  }

  let addrs;
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new UnsafeUrlError("That domain doesn't resolve.");
  }
  if (addrs.length === 0) throw new UnsafeUrlError("That domain doesn't resolve.");
  for (const a of addrs) {
    if (isPrivateIp(a.address)) {
      throw new UnsafeUrlError("That domain resolves to a private address and can't be scanned.");
    }
  }
  return url;
}
