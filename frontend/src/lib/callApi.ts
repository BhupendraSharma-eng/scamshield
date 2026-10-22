import { ApiError, getApiBase, TUNNEL_HEADERS } from "./api";
import type { VerdictLabel } from "./types";

export interface PreparedTranscript { text: string; latency_ms: number }
export interface CallSession {
  session_id: string;
  capabilities?: { prepared_transcription?: boolean };
}

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

export async function callRequest<T>(path: string, init: RequestInit, timeoutMs = 30_000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${getApiBase()}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { ...TUNNEL_HEADERS, ...(init.headers as Record<string, string> | undefined) },
    });
    if (!response.ok) {
      let message = `Call analysis failed (${response.status})`;
      try {
        const body = await response.json() as { detail?: string | { msg?: string }[] };
        if (typeof body.detail === "string") message = body.detail;
        else if (Array.isArray(body.detail)) message = body.detail.map(item => item.msg ?? "Invalid request").join("; ");
      } catch { /* Keep the status-based message for non-JSON error responses. */ }
      if (response.status === 405 && !path.endsWith("/transcribe")) {
        message = "This server does not support the live-call endpoint. Check Server settings or update and restart the backend.";
      }
      throw new ApiError(response.status, message);
    }
    return await response.json() as T;
  } catch (error) {
    if (controller.signal.aborted) {
      throw new ApiError(0, "Call analysis timed out. Check your connection and try again.");
    }
    if (error instanceof ApiError) throw error;
    const where = getApiBase() || window.location.origin;
    throw new ApiError(0, `Can't reach the ScamShield server at ${where}. Start the backend or check Server settings.`);
  } finally {
    clearTimeout(timer);
  }
}

const jsonPost = (body?: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export const callApi = {
  createSession: (number?: string) =>
    callRequest<CallSession>("/api/call/session", jsonPost(number?.trim() ? { number: number.trim() } : {})),

  transcribeChunk: (sessionId: string, file: Blob) => {
    const form = new FormData();
    form.append("file", file, "chunk.wav");
    return callRequest<PreparedTranscript>(`/api/call/session/${encodeURIComponent(sessionId)}/transcribe`, { method: "POST", body: form });
  },

  sendChunk: (sessionId: string, file: Blob, seq: number, prepared?: PreparedTranscript) => {
    const form = new FormData();
    form.append("file", file, `call-${seq}.wav`);
    form.append("seq", String(seq));
    if (prepared) {
      form.append("transcription_prepared", "true");
      form.append("transcribed_text", prepared.text);
      form.append("transcription_ms", String(prepared.latency_ms));
    }
    return callRequest<CallUpdate>(`/api/call/session/${encodeURIComponent(sessionId)}/chunk`, { method: "POST", body: form });
  },

  endSession: (sessionId: string) =>
    callRequest<CallUpdate>(`/api/call/session/${encodeURIComponent(sessionId)}/end`, { method: "POST" }),

  analyzeFile: (file: File) => {
    const form = new FormData();
    form.append("file", file, file.name);
    return callRequest<{ updates: CallUpdate[] }>("/api/call/analyze-file", { method: "POST", body: form }, 180_000);
  },
};


/** Keep live calls working when the hosted UI is ahead of the running API. */
export function createLiveCallTransport(session: CallSession) {
  let canPrepare = session.capabilities?.prepared_transcription === true;
  return {
    async prepare(file: Blob): Promise<PreparedTranscript | undefined> {
      if (!canPrepare) return undefined;
      try {
        return await callApi.transcribeChunk(session.session_id, file);
      } catch (error) {
        if (error instanceof ApiError && (error.status === 404 || error.status === 405)) {
          // A stale proxy/server can advertise a feature without routing it.
          // Retry this same audio through /chunk; subsequent chunks skip preparation.
          canPrepare = false;
          return undefined;
        }
        throw error;
      }
    },
    send(file: Blob, seq: number, prepared?: PreparedTranscript) {
      return callApi.sendChunk(session.session_id, file, seq, prepared);
    },
  };
}
