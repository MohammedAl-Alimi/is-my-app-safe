export type Status = "pass" | "fail" | "warn" | "info" | "blind";
export type Severity = "critical" | "high" | "medium" | "low" | "none";

export interface Finding {
  id: string;
  title: string;
  status: Status;
  severity: Severity;
  chapter: number; // Agent Security Playbook chapter number
  chapterTitle: string;
  detail: string; // what the scan observed
  fix?: string; // what to do about it
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  scannedAt: string;
  grade: string; // A–F
  score: number; // 0–100
  summary: { pass: number; fail: number; warn: number; info: number };
  findings: Finding[];
  blindSpots: { chapter: number; chapterTitle: string; note: string }[];
}

export const PLAYBOOK_URL =
  "https://github.com/MohammedAl-Alimi/agent-security-playbook";

export function chapterLink(n: number): string {
  const files: Record<number, string> = {
    1: "01-authentication",
    2: "02-authorization",
    3: "03-input-validation",
    4: "04-database-rls",
    5: "05-secrets-and-env",
    6: "06-hashing-and-tokens",
    8: "08-webhooks",
    9: "09-logging-and-errors",
    10: "10-headers-csp-cors",
    13: "13-ssrf-and-llm",
    17: "17-client-data-protection",
    19: "19-business-logic",
    21: "21-agent-mcp-rag",
    23: "23-email-sms-notifications",
    25: "25-deployment-infrastructure",
  };
  const f = files[n];
  return f ? `${PLAYBOOK_URL}/blob/main/rules/${f}.md` : PLAYBOOK_URL;
}
