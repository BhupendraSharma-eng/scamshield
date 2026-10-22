import { Server, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { defaultApiBase, getApiBase, setApiBase } from "../lib/api";
import { cx } from "../lib/format";
import { Spinner } from "./ui";

type TestState = { kind: "idle" } | { kind: "busy" } | { kind: "ok"; detail: string } | { kind: "fail"; detail: string };

/** Lets the hosted UI (e.g. GitHub Pages) point at any ScamShield backend: localhost, LAN IP or a tunnel. */
export default function ServerSettings({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [url, setUrl] = useState(getApiBase());
  const [test, setTest] = useState<TestState>({ kind: "idle" });

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      setUrl(getApiBase());
      setTest({ kind: "idle" });
      d.showModal();
    } else if (!open && d.open) d.close();
  }, [open]);

  const clean = (u: string) => u.trim().replace(/\/+$/, "");

  const runTest = async () => {
    setTest({ kind: "busy" });
    try {
      const r = await fetch(`${clean(url)}/api/health`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const h = await r.json();
      setTest({ kind: "ok", detail: `Connected · decision model ${h.tier1?.model ?? "?"} (${h.tier1?.status ?? "?"})` });
    } catch (e) {
      setTest({ kind: "fail", detail: `Couldn't connect (${(e as Error).message}). Check the URL, that the backend is running, and allow local-network access if the browser asks.` });
    }
  };

  const save = (value: string | null) => {
    setApiBase(value === null ? null : clean(value));
    window.location.reload();
  };

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      className="m-auto w-[min(32rem,calc(100vw-2rem))] rounded-2xl border border-line bg-surface p-0 text-ink shadow-xl backdrop:bg-black/40"
    >
      <div className="space-y-4 p-5">
        <div className="flex items-center justify-between">
          <h2 className="inline-flex items-center gap-2 font-semibold"><Server className="size-4" aria-hidden /> Server settings</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg p-1.5 text-ink-2 hover:bg-surface-2"><X className="size-4" /></button>
        </div>
        <p className="text-sm text-ink-2">
          The ScamShield backend (models + AI) runs separately from this page. Enter its address — e.g.
          {" "}<code className="rounded bg-surface-2 px-1">http://localhost:8000</code>, a LAN IP, or an HTTPS tunnel URL. Leave empty to use this site's own origin.
        </p>
        <div className="space-y-1.5">
          <label htmlFor="api-base" className="text-sm font-medium text-ink-2">Backend URL</label>
          <input
            id="api-base"
            className="w-full rounded-xl border border-line bg-surface px-3 py-2.5 text-[16px] outline-none focus:border-accent focus:ring-2 focus:ring-accent/25 sm:text-sm"
            inputMode="url" autoCapitalize="off" autoCorrect="off" spellCheck={false}
            placeholder={window.location.origin}
            value={url}
            onChange={(e) => { setUrl(e.target.value); setTest({ kind: "idle" }); }}
          />
          {defaultApiBase() && <p className="text-xs text-ink-3">Default for this build: {defaultApiBase()}</p>}
        </div>
        {test.kind !== "idle" && (
          <p role="status" className={cx("rounded-xl p-3 text-sm",
            test.kind === "ok" && "bg-safe-soft text-safe-ink",
            test.kind === "fail" && "bg-scam-soft text-scam-ink",
            test.kind === "busy" && "bg-surface-2 text-ink-2")}>
            {test.kind === "busy" ? <span className="inline-flex items-center gap-2"><Spinner /> Testing…</span> : test.detail}
          </p>
        )}
        <div className="flex flex-wrap justify-end gap-2">
          <button type="button" onClick={() => save(null)} className="min-h-10 rounded-xl px-3 text-sm font-medium text-ink-2 hover:bg-surface-2">Reset</button>
          <button type="button" onClick={runTest} className="min-h-10 rounded-xl px-4 text-sm font-medium ring-1 ring-line hover:bg-surface-2">Test</button>
          <button type="button" onClick={() => save(url)} className="min-h-10 rounded-xl bg-accent px-4 text-sm font-semibold text-accent-ink hover:brightness-110">Save</button>
        </div>
      </div>
    </dialog>
  );
}
