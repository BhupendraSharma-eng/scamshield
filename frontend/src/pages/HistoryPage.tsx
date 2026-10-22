import { History, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ChannelTag, EmptyState, ErrorNote, Segmented, Spinner, VerdictBadge } from "../components/ui";
import { api } from "../lib/api";
import { CATEGORY_LABEL, cx, ms, pct, timeAgo } from "../lib/format";
import type { Channel, ScanRow, VerdictLabel } from "../lib/types";

type ChannelFilter = "all" | Channel;
type VerdictFilter = "all" | VerdictLabel;

const CHANNELS: { value: ChannelFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "sms", label: "SMS" },
  { value: "email", label: "Email" },
  { value: "url", label: "Link" },
];

const VERDICTS: { value: VerdictFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "SCAM", label: "Scam" },
  { value: "SUSPICIOUS", label: "Suspicious" },
  { value: "SAFE", label: "Safe" },
];

const GRID = "md:grid md:grid-cols-[7.5rem_5rem_minmax(10rem,1fr)_8rem_4.5rem_5.5rem_4.5rem] md:items-center md:gap-3";

function categoryLabel(category: string | null) {
  if (!category) return "—";
  return CATEGORY_LABEL[category] ?? category.replaceAll("_", " ");
}

function ScanItem({ scan }: { scan: ScanRow }) {
  return (
    <Link
      to={`/scan/${scan.id}`}
      className={cx(
        "block min-h-11 rounded-xl border border-line bg-surface p-4 transition hover:border-accent/40 hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent md:rounded-none md:border-x-0 md:border-b-0 md:bg-transparent md:px-3 md:py-3",
        GRID,
      )}
    >
      <div className="flex min-w-0 items-center justify-between gap-3 md:block">
        <VerdictBadge verdict={scan.verdict} />
        <span className="md:hidden"><ChannelTag channel={scan.channel} /></span>
      </div>
      <div className="hidden md:block"><ChannelTag channel={scan.channel} /></div>
      <p className="mt-3 min-w-0 truncate text-sm font-medium text-ink md:mt-0 md:line-clamp-2 md:whitespace-normal" title={scan.preview}>
        {scan.preview || "No preview available"}
      </p>
      <p className="mt-1 truncate text-xs text-ink-2 md:mt-0 md:text-sm" title={categoryLabel(scan.category)}>
        {categoryLabel(scan.category)}
      </p>
      <div className="mt-3 grid grid-cols-3 gap-3 border-t border-line pt-3 text-xs md:contents">
        <div>
          <span className="text-ink-3 md:hidden">Risk</span>
          <p className="tabular font-medium text-ink">{pct(scan.risk)}</p>
        </div>
        <div>
          <span className="text-ink-3 md:hidden">Time</span>
          <p className="whitespace-nowrap text-ink-2">{timeAgo(scan.created_at)}</p>
        </div>
        <div className="text-right md:text-left">
          <span className="text-ink-3 md:hidden">Latency</span>
          <p className="tabular whitespace-nowrap text-ink-2">{ms(scan.total_ms)}</p>
        </div>
      </div>
    </Link>
  );
}

export default function HistoryPage() {
  const [channel, setChannel] = useState<ChannelFilter>("all");
  const [verdict, setVerdict] = useState<VerdictFilter>("all");
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const requestNumber = useRef(0);

  const load = useCallback(async (showActivity = false) => {
    const request = ++requestNumber.current;
    if (showActivity) setRefreshing(true);
    try {
      const rows = await api.listScans({
        limit: 100,
        channel: channel === "all" ? undefined : channel,
        verdict: verdict === "all" ? undefined : verdict,
      });
      if (request !== requestNumber.current) return;
      setScans(rows);
      setError(null);
    } catch (reason) {
      if (request !== requestNumber.current) return;
      setError(reason instanceof Error ? reason.message : "Could not load scan history.");
    } finally {
      if (request === requestNumber.current) setRefreshing(false);
    }
  }, [channel, verdict]);

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

  return (
    <div className="min-w-0">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">Scan history</h1>
          <p className="mt-1 text-sm text-ink-2">Your 100 most recent checks</p>
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

      <div className="mb-4 flex min-w-0 flex-col gap-2 sm:flex-row sm:items-center">
        <div className="min-w-0 flex-1"><Segmented value={channel} onChange={setChannel} options={CHANNELS} label="Filter by channel" /></div>
        <div className="min-w-0 flex-[1.2]"><Segmented value={verdict} onChange={setVerdict} options={VERDICTS} label="Filter by verdict" /></div>
      </div>

      {error && <div className="mb-4"><ErrorNote message={error} /></div>}

      {scans === null && !error ? (
        <div className="flex justify-center py-16 text-ink-3"><Spinner className="size-6" /></div>
      ) : scans === null ? null : scans.length === 0 ? (
        <div className="rounded-2xl border border-line bg-surface">
          <EmptyState icon={<History className="size-9" aria-hidden />} title="No scans yet">
            No scans yet — check a message on the Check tab.
          </EmptyState>
        </div>
      ) : (
        <div className="space-y-2 md:space-y-0 md:overflow-hidden md:rounded-2xl md:border md:border-line md:bg-surface">
          <div className={cx("hidden bg-surface-2 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-ink-3", GRID)} aria-hidden>
            <span>Verdict</span><span>Channel</span><span>Message</span><span>Category</span><span>Risk</span><span>Time</span><span>Latency</span>
          </div>
          {scans.map((scan) => <ScanItem key={scan.id} scan={scan} />)}
        </div>
      )}
    </div>
  );
}
