import type { Channel, Health, ScanRow, Stats, Verdict, VerdictLabel } from "./types";

const API_KEY = "scamshield.apiBase";
const BUILD_DEFAULT: string = import.meta.env.VITE_API_BASE ?? "";

/** Backend origin: user override (Server settings) → build default → same origin. */
export function getApiBase(): string {
  try {
    const v = localStorage.getItem(API_KEY);
    if (v !== null) return v;
  } catch {
    /* storage unavailable */
  }
  return BUILD_DEFAULT;
}

export function setApiBase(url: string | null) {
  try {
    if (url === null) localStorage.removeItem(API_KEY);
    else localStorage.setItem(API_KEY, url.replace(/\/+$/, ""));
  } catch {
    /* storage unavailable: the setting lasts for this page only */
  }
}

export const defaultApiBase = () => BUILD_DEFAULT;

/** Skips ngrok's free-plan browser interstitial (otherwise fetch gets HTML instead of JSON). */
export const TUNNEL_HEADERS = { "ngrok-skip-browser-warning": "1" };

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${getApiBase()}${path}`, {
      ...init,
      headers: { ...TUNNEL_HEADERS, ...(init?.headers as Record<string, string> | undefined) },
    });
  } catch {
    const where = getApiBase() || window.location.origin;
    throw new ApiError(0, `Can't reach the ScamShield server at ${where}. Start the backend or change it in Server settings.`);
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail)) msg = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  analyzeSms: (content: string, sender?: string, deep = false) =>
    request<Verdict>(`/api/analyze/sms${deep ? "?deep=true" : ""}`, json({ content, sender: sender || null })),

  analyzeEmail: (input: { raw?: string; sender?: string; subject?: string; body?: string }, deep = false) =>
    request<Verdict>(`/api/analyze/email${deep ? "?deep=true" : ""}`, json(input)),

  analyzeEmailFile: (file: File, deep = false) => {
    const form = new FormData();
    form.append("file", file);
    return request<Verdict>(`/api/analyze/email/upload${deep ? "?deep=true" : ""}`, { method: "POST", body: form });
  },

  analyzeUrl: (url: string, deep = false) =>
    request<Verdict>(`/api/analyze/url${deep ? "?deep=true" : ""}`, json({ url })),

  getScan: (id: string) => request<Verdict>(`/api/scans/${id}`),

  deepAudit: (id: string) => request<Verdict>(`/api/scans/${id}/deep-audit`, { method: "POST" }),

  listScans: (params: { limit?: number; channel?: Channel; verdict?: VerdictLabel } = {}) => {
    const q = new URLSearchParams();
    if (params.limit) q.set("limit", String(params.limit));
    if (params.channel) q.set("channel", params.channel);
    if (params.verdict) q.set("verdict", params.verdict);
    return request<ScanRow[]>(`/api/scans?${q}`);
  },

  stats: () => request<Stats>("/api/stats"),
  health: () => request<Health>("/api/health"),
};
