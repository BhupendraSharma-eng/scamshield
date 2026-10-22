import type { Channel, VerdictLabel } from "./types";

export const VERDICT_META: Record<VerdictLabel, { label: string; tone: "scam" | "warn" | "safe"; blurb: string }> = {
  SCAM: { label: "Scam", tone: "scam", blurb: "This is very likely a scam." },
  SUSPICIOUS: { label: "Suspicious", tone: "warn", blurb: "Some warning signs — verify before acting." },
  SAFE: { label: "Looks safe", tone: "safe", blurb: "No scam signs found." },
};

export const CHANNEL_LABEL: Record<Channel, string> = { sms: "SMS", email: "Email", url: "Link" };

export const CATEGORY_LABEL: Record<string, string> = {
  kyc_freeze: "Fake KYC / account block",
  upi_trap: "UPI trap",
  otp_theft: "OTP / PIN theft",
  fake_job: "Fake job offer",
  lottery_prize: "Prize / lottery bait",
  impersonation: "Impersonation",
  invoice_fraud: "Invoice / payment fraud",
  delivery: "Fake delivery",
  credential_phish: "Login phishing",
  other_scam: "Other scam",
};

export const TRIGGER_LABEL: Record<string, string> = {
  urgency: "Urgency",
  fear: "Fear",
  authority: "Authority",
  greed: "Greed",
  curiosity: "Curiosity",
};

export const DECIDED_BY_LABEL: Record<string, string> = {
  tier1: "AI decision model",
  local: "On-device models",
  rules: "Security rules",
  rule_floor: "Hard security rule",
  url: "Dangerous link",
  allowlist: "Official domain",
  model_cap: "URL model alert unconfirmed",
  brand_tld_cap: "Brand name on unofficial domain",
  llm: "AI analyst review",
};

export const SEVERITY_LABEL = ["Harmless", "Annoying", "Personal data at risk", "Money at risk"];

export const pct = (x: number | null | undefined, digits = 0) =>
  x == null ? "—" : `${(x * 100).toFixed(digits)}%`;

export const ms = (x: number | null | undefined) =>
  x == null ? "—" : x >= 1000 ? `${(x / 1000).toFixed(1)} s` : `${Math.round(x)} ms`;

export function timeAgo(iso: string): string {
  // SQLite datetime('now') is UTC without a zone marker
  const t = new Date(iso.includes("T") || iso.endsWith("Z") ? iso : `${iso.replace(" ", "T")}Z`).getTime();
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(" ");
