import { ApiError, getApiBase, TUNNEL_HEADERS } from "./api";
import type { VerdictLabel } from "./types";

export interface CallUpdate {
  session_id: string;
  seq: number;
  text: string;
  transcript: string;
  verdict: VerdictLabel;
  risk: number;
  reasons: string[];
  category: string | null;
  trigger: string | null;
  flags: string[];
  deepfake: {
    p_fake: number | null;
    chunk_p_fake: number | null;
    label: "likely_ai" | "uncertain" | "likely_human" | null;
    chunks: number;
  };
  alert: boolean;
  action: string;
  latency_ms: { stt: number; decision: number; deepfake: number; total: number };
}

async function callRequest<T>(path: string, init: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${getApiBase()}${path}`, {
      ...init,
      headers: { ...TUNNEL_HEADERS, ...(init.headers as Record<string, string> | undefined) },
    });
  } catch {
    const where = getApiBase() || window.location.origin;
    throw new ApiError(0, `Can't reach the ScamShield server at ${where}. Start the backend or check Server settings.`);
  }
  if (!response.ok) {
    let message = `Call analysis failed (${response.status})`;
    try {
      const body = await response.json() as { detail?: string | { msg?: string }[] };
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail)) message = body.detail.map((item) => item.msg ?? "Invalid request").join("; ");
    } catch {
      // Keep the status-based message for non-JSON errors.
    }
    throw new ApiError(response.status, message);
  }
  return response.json() as Promise<T>;
}

const jsonPost = (body?: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export const callApi = {
  createSession: (number?: string) =>
    callRequest<{ session_id: string }>("/api/call/session", jsonPost(number?.trim() ? { number: number.trim() } : {})),

  sendChunk: (sessionId: string, file: Blob, seq: number) => {
    const form = new FormData();
    form.append("file", file, `call-${seq}.wav`);
    form.append("seq", String(seq));
    return callRequest<CallUpdate>(`/api/call/session/${encodeURIComponent(sessionId)}/chunk`, { method: "POST", body: form });
  },

  endSession: (sessionId: string) =>
    callRequest<CallUpdate>(`/api/call/session/${encodeURIComponent(sessionId)}/end`, { method: "POST" }),

  analyzeFile: (file: File) => {
    const form = new FormData();
    form.append("file", file, file.name);
    return callRequest<{ updates: CallUpdate[] }>("/api/call/analyze-file", { method: "POST", body: form });
  },
};
