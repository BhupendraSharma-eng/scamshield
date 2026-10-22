import { Bot, Clock, Cpu, Link2, ListChecks, Quote, ScrollText, ShieldQuestion, Sparkles } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { api } from "../lib/api";
import {
  CATEGORY_LABEL, cx, DECIDED_BY_LABEL, ms, pct, SEVERITY_LABEL, TRIGGER_LABEL, VERDICT_META,
} from "../lib/format";
import { usePolling } from "../lib/hooks";
import type { Verdict } from "../lib/types";
import { Card, ErrorNote, RichText, SectionTitle, Spinner, toneOf, VerdictBadge } from "./ui";

const SCAM_T = 0.7;
const SUSP_T = 0.35;

/** Single-value meter: the hero number carries the value; the bar shows where it sits vs thresholds. */
function RiskMeter({ risk, verdict }: { risk: number; verdict: Verdict["verdict"] }) {
  const t = toneOf(verdict);
  return (
    <div>
      <div className="relative h-2.5 w-full rounded-full bg-surface-2" role="meter" aria-valuemin={0} aria-valuemax={100}
        aria-valuenow={Math.round(risk * 100)} aria-label="Scam risk">
        <div className={cx("h-full rounded-full transition-[width] duration-500", t.dot)} style={{ width: `${Math.max(2, risk * 100)}%` }} />
        {[SUSP_T, SCAM_T].map((x) => (
          <span key={x} className="absolute -top-1 h-4.5 w-0.5 rounded bg-ink-3/60" style={{ left: `${x * 100}%` }} aria-hidden />
        ))}
      </div>
      <div className="relative mt-1.5 h-4 text-[11px] text-ink-3">
        <span className="absolute left-0">Safe</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${(SUSP_T + SCAM_T) * 50}%` }}>Suspicious</span>
        <span className="absolute right-0">Scam</span>
      </div>
    </div>
  );
}

/** Highlights the exact phrases the rules/LLM flagged inside the original message. */
function HighlightedText({ text, phrases }: { text: string; phrases: string[] }) {
  const parts = useMemo(() => {
    const ps = [...new Set(phrases.filter((p) => p && p.length >= 3 && text.toLowerCase().includes(p.toLowerCase())))];
    if (!ps.length) return [{ s: text, hit: false }];
    const re = new RegExp(`(${ps.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
    return text.split(re).map((s, i) => ({ s, hit: i % 2 === 1 }));
  }, [text, phrases]);
  return (
    <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-ink">
      {parts.map((p, i) =>
        p.hit ? <mark key={i} className="rounded bg-warn-soft px-0.5 text-ink underline decoration-warn decoration-2 underline-offset-2">{p.s}</mark> : <span key={i}>{p.s}</span>,
      )}
    </p>
  );
}

function ScoreRow({ icon, label, sub, value, latency }: { icon: ReactNode; label: string; sub?: string; value: number | null; latency?: number }) {
  return (
    <div className="grid grid-cols-[auto_1fr_auto] items-center gap-x-3 gap-y-1">
      <span className="text-ink-3">{icon}</span>
      <div className="min-w-0">
        <div className="flex items-baseline justify-between gap-2">
          <span className="truncate text-sm font-medium text-ink">{label}</span>
          <span className="tabular text-sm text-ink">{value == null ? "off" : pct(value)}</span>
        </div>
        {sub && <div className="truncate text-xs text-ink-3">{sub}</div>}
      </div>
      <span className="tabular w-14 text-right text-xs text-ink-3">{latency != null ? ms(latency) : ""}</span>
      <span />
      <div className="col-span-2 h-1.5 rounded-full bg-surface-2">
        {value != null && <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(1.5, value * 100)}%` }} />}
      </div>
    </div>
  );
}

function AnalystPanel({ v, onUpdate }: { v: Verdict; onUpdate: (v: Verdict) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const status = v.llm.status;

  // Background audit: poll the scan until the LLM result lands
  usePolling(async () => {
    const next = await api.getScan(v.scan_id);
    if (next.llm.status !== "pending") {
      onUpdate(next);
      return true;
    }
    return false;
  }, 1500, status === "pending");

  const runAudit = async () => {
    setBusy(true);
    setError(null);
    try {
      onUpdate(await api.deepAudit(v.scan_id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const audit = v.llm.audit;
  return (
    <Card>
      <SectionTitle aside={audit && <span className="text-xs text-ink-3">{audit.model} · {ms(audit.latency_ms)}</span>}>
        <span className="inline-flex items-center gap-2"><Sparkles className="size-4" aria-hidden /> AI analyst review</span>
      </SectionTitle>
      {status === "pending" || busy ? (
        <div className="flex items-center gap-2 text-sm text-ink-2"><Spinner /> Analyst is reviewing this message…</div>
      ) : audit ? (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">Analyst verdict:</span>
            {audit.verdict === "UNSURE" ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-surface-2 px-2 py-0.5 text-xs font-semibold text-ink-2 ring-1 ring-line">
                <ShieldQuestion className="size-3.5" aria-hidden /> Unsure
              </span>
            ) : (
              <VerdictBadge verdict={audit.verdict} />
            )}
            <span className="tabular text-ink-3">confidence {pct(audit.confidence)}</span>
          </div>
          <p className="text-sm leading-relaxed text-ink">{audit.summary}</p>
          {audit.indicators.length > 0 && (
            <ul className="space-y-2">
              {audit.indicators.map((i, n) => (
                <li key={n} className="rounded-xl bg-surface-2 p-3 text-sm">
                  <div className="flex gap-2 font-medium text-ink"><Quote className="mt-0.5 size-3.5 shrink-0 text-ink-3" aria-hidden />“{i.quote}”</div>
                  <div className="mt-1 pl-5.5 text-ink-2">{i.why}</div>
                </li>
              ))}
            </ul>
          )}
          {audit.user_advice && <p className="text-sm text-ink-2"><span className="font-medium text-ink">Advice: </span>{audit.user_advice}</p>}
        </div>
      ) : (
        <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-ink-2">
            {status === "error" ? "The analyst review failed." : status === "unavailable" ? "The AI analyst isn't configured on the server." : "Get a detailed second opinion from the AI analyst (takes a few seconds)."}
          </p>
          {status !== "unavailable" && (
            <button type="button" onClick={runAudit}
              className="inline-flex min-h-10 items-center gap-2 rounded-xl bg-surface-2 px-4 text-sm font-medium text-ink ring-1 ring-line hover:bg-accent-soft">
              <Bot className="size-4" aria-hidden /> {status === "error" ? "Try again" : "Ask AI analyst"}
            </button>
          )}
        </div>
      )}
      {error && <div className="mt-3"><ErrorNote message={error} /></div>}
    </Card>
  );
}

/** Render with key={scan_id} so a new scan resets local state (LLM updates). */
export default function VerdictView({ verdict: initial }: { verdict: Verdict }) {
  const [v, setV] = useState(initial);

  const meta = VERDICT_META[v.verdict];
  const t = toneOf(v.verdict);
  const lat = v.latency_ms;
  const flagged = useMemo(() => {
    const out: string[] = [];
    for (const e of v.evidence) {
      const m = e.detail?.matches;
      if (Array.isArray(m)) out.push(...(m as string[]));
    }
    for (const i of v.llm.audit?.indicators ?? []) out.push(i.quote);
    return out;
  }, [v]);
  const message = [v.input.subject, v.input.text].filter(Boolean).join("\n\n") || v.input.urls.join("\n");

  return (
    <div className="animate-rise space-y-4">
      {/* Hero */}
      <Card className={cx("ring-2", t.ring)}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-2">
            <VerdictBadge verdict={v.verdict} size="lg" />
            <p className="text-lg font-semibold text-ink">{meta.blurb}</p>
            <div className="flex flex-wrap gap-2 text-xs">
              {v.category && <span className="rounded-full bg-surface-2 px-2.5 py-1 text-ink-2">{CATEGORY_LABEL[v.category] ?? v.category}</span>}
              {v.trigger && <span className="rounded-full bg-surface-2 px-2.5 py-1 text-ink-2">Pressure: {TRIGGER_LABEL[v.trigger] ?? v.trigger}</span>}
              {v.severity != null && v.verdict !== "SAFE" && (
                <span className="rounded-full bg-surface-2 px-2.5 py-1 text-ink-2">Harm: {SEVERITY_LABEL[Math.min(3, Math.round(v.severity))]}</span>
              )}
            </div>
          </div>
          <div className="sm:text-right">
            <div className="text-4xl font-bold tracking-tight text-ink">{pct(v.risk)}</div>
            <div className="text-xs text-ink-3">scam risk · decided by {DECIDED_BY_LABEL[v.decided_by] ?? v.decided_by}</div>
          </div>
        </div>
        <div className="mt-4"><RiskMeter risk={v.risk} verdict={v.verdict} /></div>
        <div className={cx("mt-4 rounded-xl p-3 text-sm font-medium", t.bg, t.text)}>{v.action}</div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <SectionTitle><span className="inline-flex items-center gap-2"><ListChecks className="size-4" aria-hidden /> Why</span></SectionTitle>
          <ol className="space-y-2.5">
            {v.reasons.map((r, i) => (
              <li key={i} className="flex gap-3 text-sm leading-relaxed text-ink">
                <span className={cx("mt-0.5 grid size-5 shrink-0 place-items-center rounded-full text-[11px] font-bold", t.bg, t.text)}>{i + 1}</span>
                <span className="min-w-0"><RichText text={r} /></span>
              </li>
            ))}
          </ol>
        </Card>

        <Card>
          <SectionTitle><span className="inline-flex items-center gap-2"><ScrollText className="size-4" aria-hidden /> Message</span></SectionTitle>
          {v.input.sender && <p className="mb-2 truncate text-xs text-ink-3">From: {v.input.sender}</p>}
          <div className="max-h-64 overflow-y-auto rounded-xl bg-surface-2 p-3">
            <HighlightedText text={message} phrases={flagged} />
          </div>
        </Card>
      </div>

      {v.urls.length > 0 && (
        <Card>
          <SectionTitle><span className="inline-flex items-center gap-2"><Link2 className="size-4" aria-hidden /> Links ({v.urls.length})</span></SectionTitle>
          <ul className="divide-y divide-line">
            {v.urls.map((u) => {
              const uv = u.risk >= SCAM_T ? "SCAM" : u.risk >= SUSP_T ? "SUSPICIOUS" : "SAFE";
              return (
                <li key={u.url} className="flex flex-col gap-1.5 py-2.5 sm:flex-row sm:items-center sm:gap-3">
                  <span className="self-start sm:self-auto"><VerdictBadge verdict={uv} /></span>
                  <code className="min-w-0 flex-1 break-all text-xs text-ink">{u.url}</code>
                  <div className="flex flex-wrap gap-1">
                    {u.flags.slice(0, 4).map((f) => (
                      <span key={f} className="rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-ink-2">{f.replaceAll("_", " ")}</span>
                    ))}
                  </div>
                  <span className="tabular text-xs text-ink-3 sm:w-12 sm:text-right">{pct(u.risk)}</span>
                </li>
              );
            })}
          </ul>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <SectionTitle aside={<span className="inline-flex items-center gap-1 text-xs text-ink-3"><Clock className="size-3.5" aria-hidden />{ms(lat.total)}{v.cached ? " · cached" : ""}</span>}>
            <span className="inline-flex items-center gap-2"><Cpu className="size-4" aria-hidden /> How we decided</span>
          </SectionTitle>
          <div className="space-y-3.5">
            <ScoreRow icon={<ListChecks className="size-4" />} label="Security rules" sub="links, sender, scam phrases" value={v.scores.rules} latency={lat.tier0a} />
            <ScoreRow icon={<Cpu className="size-4" />} label="On-device AI models" sub={Object.entries(v.scores.models).map(([k, x]) => `${k} ${pct(x)}`).join(" · ") || "—"} value={v.scores.p_local} latency={lat.tier0b} />
            <ScoreRow icon={<Sparkles className="size-4" />} label="AI decision model"
              sub={v.tier1 ? `${v.tier1.provider} · ${v.tier1.model}` : "offline — skipped"} value={v.scores.p_jev} latency={lat.tier1} />
          </div>
          <p className="mt-4 text-xs text-ink-3">
            Mode: {v.mode === "online" ? "online (all tiers)" : "offline (on-device only)"} · Combined in log-odds, then hard security rules applied.
          </p>
        </Card>
        <AnalystPanel v={v} onUpdate={setV} />
      </div>
    </div>
  );
}
