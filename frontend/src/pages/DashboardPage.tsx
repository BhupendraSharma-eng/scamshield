import { BarChart3, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Card, EmptyState, ErrorNote, SectionTitle, Spinner, VerdictBadge } from "../components/ui";
import { api } from "../lib/api";
import { CATEGORY_LABEL, DECIDED_BY_LABEL, ms } from "../lib/format";
import type { Health, Stats, VerdictLabel } from "../lib/types";

interface BarDatum {
  key: string;
  label: string;
  value: number;
  color: string;
}

function TableToggle({ table, onChange }: { table: boolean; onChange: (table: boolean) => void }) {
  return (
    <button
      type="button"
      aria-pressed={table}
      onClick={() => onChange(!table)}
      className="min-h-10 rounded-lg px-3 text-xs font-medium text-ink-2 hover:bg-surface-2 hover:text-ink"
    >
      {table ? "Chart" : "Table"}
    </button>
  );
}

function DataTable({ rows, total, percent = false }: { rows: BarDatum[]; total?: number; percent?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-ink-3">
          <tr><th className="pb-2 font-medium">Name</th><th className="pb-2 text-right font-medium">Count</th>{percent && <th className="pb-2 text-right font-medium">Percent</th>}</tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} className="border-t border-line">
              <th scope="row" className="py-2 text-left font-normal text-ink">{row.label}</th>
              <td className="tabular py-2 text-right text-ink">{row.value}</td>
              {percent && <td className="tabular py-2 text-right text-ink-2">{total ? `${Math.round(row.value / total * 100)}%` : "0%"}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HorizontalBars({ rows }: { rows: BarDatum[] }) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <div className="space-y-3">
      {rows.map((row) => (
        <div key={row.key}>
          <div className="mb-1 flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 truncate text-ink" title={row.label}>{row.label}</span>
            <span className="tabular shrink-0 text-ink">{row.value}</span>
          </div>
          <div className="h-2 overflow-hidden rounded bg-surface-2">
            <div className={`h-full rounded-r ${row.color}`} style={{ width: `${row.value / max * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function BarsCard({ title, rows }: { title: string; rows: BarDatum[] }) {
  const [table, setTable] = useState(false);
  return (
    <Card>
      <SectionTitle aside={<TableToggle table={table} onChange={setTable} />}>{title}</SectionTitle>
      {table ? <DataTable rows={rows} /> : <HorizontalBars rows={rows} />}
    </Card>
  );
}

const VERDICT_COLOR: Record<VerdictLabel, string> = {
  SCAM: "bg-scam",
  SUSPICIOUS: "bg-warn",
  SAFE: "bg-safe",
};

function VerdictsCard({ stats }: { stats: Stats }) {
  const [table, setTable] = useState(false);
  const verdicts: VerdictLabel[] = ["SCAM", "SUSPICIOUS", "SAFE"];
  const rows = verdicts.map((verdict) => ({
    key: verdict,
    label: verdict === "SCAM" ? "Scam" : verdict === "SUSPICIOUS" ? "Suspicious" : "Safe",
    value: stats.by_verdict[verdict] ?? 0,
    color: VERDICT_COLOR[verdict],
  }));
  const visible = rows.filter((row) => row.value > 0);

  return (
    <Card>
      <SectionTitle aside={<TableToggle table={table} onChange={setTable} />}>Verdicts</SectionTitle>
      {table ? <DataTable rows={rows} total={stats.total} percent /> : (
        <>
          <div className="flex h-5 w-full gap-0.5 bg-surface" aria-label="Verdict distribution">
            {visible.map((row, index) => {
              const percent = row.value / stats.total * 100;
              return (
                <div
                  key={row.key}
                  tabIndex={0}
                  aria-label={`${row.label}: ${row.value}, ${Math.round(percent)} percent`}
                  className={`${row.color} ${index === 0 ? "rounded-l" : ""} ${index === visible.length - 1 ? "rounded-r" : ""} focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent`}
                  style={{ width: `${percent}%` }}
                  title={`${row.label}: ${row.value} (${Math.round(percent)}%)`}
                />
              );
            })}
          </div>
          <div className="mt-4 grid gap-2.5">
            {verdicts.map((verdict) => {
              const count = stats.by_verdict[verdict] ?? 0;
              return (
                <div key={verdict} className="flex min-w-0 items-center justify-between gap-2">
                  <span className="shrink-0"><VerdictBadge verdict={verdict} /></span>
                  <span className="tabular whitespace-nowrap text-sm text-ink">{count} <span className="text-ink-3">· {Math.round(count / stats.total * 100)}%</span></span>
                </div>
              );
            })}
          </div>
        </>
      )}
    </Card>
  );
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <Card className="min-w-0">
      <p className="text-sm text-ink-2">{label}</p>
      <p className="mt-2 truncate text-2xl font-semibold leading-none text-ink sm:text-3xl">{value}</p>
    </Card>
  );
}

function StatusLine({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className="inline-flex min-w-0 items-start gap-2 text-sm text-ink">
      <span className={`mt-1.5 size-2 shrink-0 rounded-full ${ok ? "bg-safe" : "bg-scam"}`} aria-hidden />
      <span className="min-w-0 break-words">{children}</span>
    </span>
  );
}

function SystemCard({ health }: { health: Health }) {
  return (
    <Card>
      <SectionTitle>System</SectionTitle>
      <dl className="space-y-4">
        <div>
          <dt className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-3">Decision model</dt>
          <dd><StatusLine ok={health.tier1.status.startsWith("ready")}>{health.tier1.provider} · {health.tier1.model} · {health.tier1.status}</StatusLine></dd>
        </div>
        <div>
          <dt className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-3">LLM analyst</dt>
          <dd><StatusLine ok={health.llm.available}>{health.llm.provider} · {health.llm.model} · {health.llm.available ? "available" : "unavailable"}</StatusLine></dd>
        </div>
        <div>
          <dt className="mb-2 text-xs font-medium uppercase tracking-wide text-ink-3">Local models</dt>
          <dd className="grid gap-2">
            {Object.entries(health.models).map(([name, status]) => (
              <StatusLine key={name} ok={status.toLowerCase().startsWith("ok")}><span className="font-medium">{name}</span> · {status}</StatusLine>
            ))}
          </dd>
        </div>
      </dl>
    </Card>
  );
}

function categoryRows(values: Record<string, number>): BarDatum[] {
  const sorted = Object.entries(values)
    .filter(([key]) => key && key.toLowerCase() !== "none" && key.toLowerCase() !== "null")
    .sort((a, b) => b[1] - a[1]);
  const folded = sorted.length > 8
    ? [...sorted.slice(0, 7), ["__other", sorted.slice(7).reduce((sum, [, value]) => sum + value, 0)] as [string, number]]
    : sorted;
  return folded.map(([key, value]) => ({
    key,
    label: key === "__other" ? "Other" : (CATEGORY_LABEL[key] ?? key.replaceAll("_", " ")),
    value,
    color: "bg-accent",
  }));
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const requestNumber = useRef(0);

  const load = useCallback(async (showActivity = false) => {
    const request = ++requestNumber.current;
    if (showActivity) setRefreshing(true);
    try {
      const [nextStats, nextHealth] = await Promise.all([api.stats(), api.health()]);
      if (request !== requestNumber.current) return;
      setStats(nextStats);
      setHealth(nextHealth);
      setError(null);
    } catch (reason) {
      if (request !== requestNumber.current) return;
      setError(reason instanceof Error ? reason.message : "Could not load dashboard data.");
    } finally {
      if (request === requestNumber.current) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load(true);
    const refreshIfVisible = () => {
      if (document.visibilityState === "visible") void load(false);
    };
    const timer = window.setInterval(refreshIfVisible, 10_000);
    document.addEventListener("visibilitychange", refreshIfVisible);
    return () => {
      requestNumber.current += 1;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshIfVisible);
    };
  }, [load]);

  const channels: BarDatum[] = stats ? [
    { key: "sms", label: "SMS", value: stats.by_channel.sms ?? 0, color: "bg-ch-sms" },
    { key: "email", label: "Email", value: stats.by_channel.email ?? 0, color: "bg-ch-email" },
    { key: "url", label: "Link", value: stats.by_channel.url ?? 0, color: "bg-ch-url" },
  ] : [];
  const decidedBy: BarDatum[] = stats ? Object.entries(stats.by_decided_by)
    .sort((a, b) => b[1] - a[1])
    .map(([key, value]) => ({ key, label: DECIDED_BY_LABEL[key] ?? key.replaceAll("_", " "), value, color: "bg-ink-3" })) : [];

  return (
    <div className="min-w-0">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">Dashboard</h1>
          <p className="mt-1 text-sm text-ink-2">Scan activity and system status</p>
        </div>
        <button
          type="button"
          onClick={() => void load(true)}
          disabled={refreshing}
          className="flex min-h-10 shrink-0 items-center gap-2 rounded-xl border border-line bg-surface px-3 text-sm font-medium text-ink-2 transition hover:bg-surface-2 hover:text-ink disabled:opacity-60"
        >
          {refreshing ? <Spinner /> : <RefreshCw className="size-4" aria-hidden />}
          <span className="hidden sm:inline">Refresh</span>
          <span className="sr-only sm:hidden">Refresh</span>
        </button>
      </div>

      {error && <div className="mb-4"><ErrorNote message={error} /></div>}

      {(!stats || !health) && !error ? (
        <div className="flex justify-center py-16 text-ink-3"><Spinner className="size-6" /></div>
      ) : !stats || !health ? null : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatTile label="Total scans" value={stats.total} />
            <StatTile label="Scams caught" value={stats.by_verdict.SCAM ?? 0} />
            <StatTile label="Suspicious" value={stats.by_verdict.SUSPICIOUS ?? 0} />
            <StatTile label="Avg latency" value={ms(stats.avg_latency_ms)} />
          </div>

          {stats.total === 0 ? (
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <EmptyState icon={<BarChart3 className="size-9" aria-hidden />} title="No scan data yet">
                  Check a message on the Check tab to start building your dashboard.
                </EmptyState>
              </Card>
              <SystemCard health={health} />
            </div>
          ) : (
            <div className="grid items-start gap-4 lg:grid-cols-2">
              <VerdictsCard stats={stats} />
              <BarsCard title="By channel" rows={channels} />
              <BarsCard title="Scam types" rows={categoryRows(stats.by_category)} />
              <BarsCard title="Who decided" rows={decidedBy} />
              <SystemCard health={health} />
            </div>
          )}
        </>
      )}
    </div>
  );
}
