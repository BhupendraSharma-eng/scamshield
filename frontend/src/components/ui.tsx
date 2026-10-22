import { AlertTriangle, ShieldAlert, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { cx, VERDICT_META } from "../lib/format";
import type { Channel, VerdictLabel } from "../lib/types";

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={cx("rounded-2xl border border-line bg-surface p-4 sm:p-5", className)}>{children}</section>;
}

export function SectionTitle({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between gap-2">
      <h2 className="text-sm font-semibold text-ink-2">{children}</h2>
      {aside}
    </div>
  );
}

const TONE = {
  scam: { text: "text-scam-ink", bg: "bg-scam-soft", ring: "ring-scam/30", dot: "bg-scam", Icon: ShieldAlert },
  warn: { text: "text-warn-ink", bg: "bg-warn-soft", ring: "ring-warn/40", dot: "bg-warn", Icon: AlertTriangle },
  safe: { text: "text-safe-ink", bg: "bg-safe-soft", ring: "ring-safe/30", dot: "bg-safe", Icon: ShieldCheck },
} as const;

export const toneOf = (v: VerdictLabel) => TONE[VERDICT_META[v].tone];

/** Verdict pill: status colour always paired with icon + text label. */
export function VerdictBadge({ verdict, size = "sm" }: { verdict: VerdictLabel; size?: "sm" | "lg" }) {
  const t = toneOf(verdict);
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full font-semibold ring-1",
        t.bg, t.text, t.ring,
        size === "lg" ? "px-3 py-1.5 text-base" : "px-2 py-0.5 text-xs",
      )}
    >
      <t.Icon className={size === "lg" ? "size-5" : "size-3.5"} aria-hidden />
      {VERDICT_META[verdict].label}
    </span>
  );
}

const CH_DOT: Record<Channel, string> = { sms: "bg-ch-sms", email: "bg-ch-email", url: "bg-ch-url" };

export function ChannelTag({ channel }: { channel: Channel }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-ink-2">
      <span className={cx("size-2 rounded-full", CH_DOT[channel])} aria-hidden />
      {channel === "url" ? "Link" : channel.toUpperCase()}
    </span>
  );
}

export function Segmented<T extends string>({
  value, onChange, options, label,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string; icon?: ReactNode }[];
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="grid auto-cols-fr grid-flow-col gap-1 rounded-xl bg-surface-2 p-1">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          type="button"
          aria-selected={value === o.value}
          onClick={() => onChange(o.value)}
          className={cx(
            "flex min-h-10 items-center justify-center gap-2 rounded-lg px-3 text-sm font-medium transition",
            value === o.value ? "bg-surface text-ink shadow-sm ring-1 ring-line" : "text-ink-2 hover:text-ink",
          )}
        >
          {o.icon}
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cx("inline-block size-4 animate-spin rounded-full border-2 border-current border-t-transparent", className)}
      aria-hidden
    />
  );
}

export function EmptyState({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="text-ink-3">{icon}</div>
      <p className="font-medium text-ink">{title}</p>
      {children && <div className="max-w-sm text-sm text-ink-2">{children}</div>}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-xl border border-scam/30 bg-scam-soft p-3 text-sm text-scam-ink">
      <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

/** Renders the backend's light markup in reason sentences: `code` and **bold**. */
export function RichText({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return (
    <>
      {parts.map((p, i) =>
        p.startsWith("`") && p.endsWith("`") ? (
          <code key={i} className="[overflow-wrap:anywhere] rounded bg-surface-2 px-1 py-0.5 text-[0.9em]">{p.slice(1, -1)}</code>
        ) : p.startsWith("**") && p.endsWith("**") ? (
          <strong key={i} className="font-semibold">{p.slice(2, -2)}</strong>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}
