// Mirrors the backend Verdict JSON (backend/app/engine/pipeline.py).

export type Channel = "sms" | "email" | "url";
export type VerdictLabel = "SCAM" | "SUSPICIOUS" | "SAFE";
export type LlmStatus = "skipped" | "pending" | "done" | "error" | "unavailable";

export interface Evidence {
  id: string;
  source: "rule" | "model" | "tier1" | "llm";
  weight: number;
  floor: number | null;
  reason: string;
  detail: Record<string, unknown>;
}

export interface UrlRow {
  url: string;
  domain: string | null;
  risk: number;
  model: number | null;
  flags: string[];
}

export interface Tier1 {
  server_processing_ms?: number | null;
  request_overhead_ms?: number | null;
  provider: string;
  model: string;
  p_scam: number;
  category: string;
  category_conf: number;
  trigger: string;
  trigger_conf: number;
  severity: number;
  asks_secret: number;
  impersonation: number;
  payment_change: number | null;
  latency_ms: number;
}

export interface LlmAudit {
  verdict: "SCAM" | "SAFE" | "UNSURE";
  confidence: number;
  indicators: { quote: string; why: string }[];
  summary: string;
  user_advice: string;
  latency_ms: number;
  model: string;
}

export interface Verdict {
  scan_id: string;
  channel: Channel;
  verdict: VerdictLabel;
  risk: number;
  confidence: number;
  category: string | null;
  trigger: string | null;
  severity: number | null;
  decided_by: string;
  reasons: string[];
  action: string;
  analyst_summary?: string;
  urls: UrlRow[];
  evidence: Evidence[];
  scores: {
    p_jev: number | null;
    p_local: number | null;
    rules: number;
    url: number | null;
    models: Record<string, number>;
  };
  tier1: Tier1 | null;
  llm: { status: LlmStatus; audit: LlmAudit | null; error?: string };
  mode: "online" | "offline";
  latency_ms: Record<string, number>;
  input: { sender: string | null; subject: string | null; text: string; urls: string[] };
  cached: boolean;
}

export interface ScanRow {
  id: string;
  created_at: string;
  channel: Channel;
  preview: string;
  verdict: VerdictLabel;
  risk: number;
  category: string | null;
  decided_by: string;
  mode: string;
  total_ms: number;
  llm_status: LlmStatus;
}

export interface Stats {
  total: number;
  avg_latency_ms: number;
  by_verdict: Record<string, number>;
  by_channel: Record<string, number>;
  by_category: Record<string, number>;
  by_decided_by: Record<string, number>;
}

export interface Health {
  status: "ok" | "degraded";
  models: Record<string, string>;
  tier1: { provider: string; status: string; model: string };
  llm: { available: boolean; provider: string; model: string };
  thresholds: { scam: number; suspicious: number };
}
