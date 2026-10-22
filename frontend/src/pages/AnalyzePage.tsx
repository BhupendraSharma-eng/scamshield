import { FileUp, Globe, Mail, MessageSquareText, ScanSearch, X } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import VerdictView from "../components/VerdictView";
import { ErrorNote, Segmented, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { cx } from "../lib/format";
import { EMAIL_SAMPLES, SMS_SAMPLES, URL_SAMPLES, type Sample } from "../lib/samples";
import type { Channel, Verdict } from "../lib/types";

const field =
  "w-full rounded-xl border border-line bg-surface px-3 py-2.5 text-[16px] text-ink placeholder:text-ink-3 outline-none transition focus:border-accent focus:ring-2 focus:ring-accent/25 sm:text-sm";

function SampleChips({ samples, onPick }: { samples: Sample[]; onPick: (s: Sample) => void }) {
  return (
    <div className="relative -mx-1 flex gap-2 overflow-x-auto px-1 pb-1 [scrollbar-width:none]">
      {samples.map((s) => (
        <button key={s.label} type="button" onClick={() => onPick(s)}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 hover:border-accent hover:text-ink">
          <span className={cx("size-1.5 rounded-full", s.scam ? "bg-scam" : "bg-safe")} aria-hidden />
          {s.label}
          <span className="sr-only">{s.scam ? "(scam example)" : "(genuine example)"}</span>
        </button>
      ))}
    </div>
  );
}

export default function AnalyzePage() {
  const [channel, setChannel] = useState<Channel>("sms");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [emailMode, setEmailMode] = useState<"paste" | "upload">("paste");
  const [file, setFile] = useState<File | null>(null);
  const [deep, setDeep] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Verdict | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);

  const canSubmit =
    !busy &&
    (channel === "url" ? url.trim().length > 3 : channel === "email" && emailMode === "upload" ? !!file : text.trim().length > 0);

  const pick = (s: Sample) => {
    setError(null);
    if (channel === "url") setUrl(s.text);
    else {
      setText(s.text);
      setSender(s.sender ?? "");
      setSubject(s.subject ?? "");
      if (channel === "email") setEmailMode("paste");
    }
  };

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      let v: Verdict;
      if (channel === "sms") v = await api.analyzeSms(text, sender, deep);
      else if (channel === "url") v = await api.analyzeUrl(url.trim(), deep);
      else if (emailMode === "upload" && file) v = await api.analyzeEmailFile(file, deep);
      else v = await api.analyzeEmail({ sender: sender || undefined, subject: subject || undefined, body: text }, deep);
      setResult(v);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Is this a scam?</h1>
        <p className="mt-1 text-sm text-ink-2">Paste an SMS, an email or a link. We check it with security rules, on-device AI and an AI decision model — in under a second.</p>
      </div>

      <form onSubmit={submit} onKeyDown={onKey} className="space-y-4 rounded-2xl border border-line bg-surface p-4 sm:p-5">
        <Segmented<Channel>
          label="What do you want to check?"
          value={channel}
          onChange={(c) => { setChannel(c); setError(null); }}
          options={[
            { value: "sms", label: "SMS", icon: <MessageSquareText className="size-4" aria-hidden /> },
            { value: "email", label: "Email", icon: <Mail className="size-4" aria-hidden /> },
            { value: "url", label: "Link", icon: <Globe className="size-4" aria-hidden /> },
          ]}
        />

        {channel === "url" ? (
          <div className="space-y-2">
            <label htmlFor="url" className="text-sm font-medium text-ink-2">Link</label>
            <input id="url" className={field} inputMode="url" autoCapitalize="off" autoCorrect="off" spellCheck={false}
              placeholder="https://example.com/login" value={url} onChange={(e) => setUrl(e.target.value)} />
          </div>
        ) : (
          <>
            {channel === "email" && (
              <div className="flex gap-2 text-sm">
                {(["paste", "upload"] as const).map((m) => (
                  <button key={m} type="button" onClick={() => setEmailMode(m)}
                    className={cx("rounded-lg px-3 py-1.5 font-medium", emailMode === m ? "bg-accent-soft text-ink" : "text-ink-2 hover:text-ink")}>
                    {m === "paste" ? "Paste text" : "Upload .eml"}
                  </button>
                ))}
              </div>
            )}

            {channel === "email" && emailMode === "upload" ? (
              <label htmlFor="eml"
                className="flex min-h-32 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-line bg-surface-2 p-4 text-center text-sm text-ink-2 hover:border-accent">
                {file ? (
                  <span className="inline-flex items-center gap-2 font-medium text-ink">
                    <FileUp className="size-4" aria-hidden /> {file.name}
                    <button type="button" aria-label="Remove file" onClick={(e) => { e.preventDefault(); setFile(null); }} className="rounded p-1 hover:bg-surface"><X className="size-4" /></button>
                  </span>
                ) : (
                  <>
                    <FileUp className="size-6 text-ink-3" aria-hidden />
                    <span><span className="font-medium text-ink">Choose an .eml file</span> — full headers enable SPF/DKIM and spoofing checks</span>
                  </>
                )}
                <input id="eml" type="file" accept=".eml,message/rfc822" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </label>
            ) : (
              <>
                <div className={cx("grid gap-3", channel === "email" && "sm:grid-cols-2")}>
                  <div className="space-y-1.5">
                    <label htmlFor="sender" className="text-sm font-medium text-ink-2">Sender <span className="font-normal text-ink-3">(optional)</span></label>
                    <input id="sender" className={field} placeholder={channel === "sms" ? "e.g. VM-SBIINB or +91…" : "Name <email@domain>"}
                      value={sender} onChange={(e) => setSender(e.target.value)} />
                  </div>
                  {channel === "email" && (
                    <div className="space-y-1.5">
                      <label htmlFor="subject" className="text-sm font-medium text-ink-2">Subject <span className="font-normal text-ink-3">(optional)</span></label>
                      <input id="subject" className={field} value={subject} onChange={(e) => setSubject(e.target.value)} />
                    </div>
                  )}
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="text" className="text-sm font-medium text-ink-2">{channel === "sms" ? "Message" : "Email body"}</label>
                  <textarea id="text" rows={channel === "sms" ? 4 : 7} className={cx(field, "resize-y")}
                    placeholder={channel === "sms" ? "Paste the SMS or WhatsApp message here…" : "Paste the email text (or HTML) here…"}
                    value={text} onChange={(e) => setText(e.target.value)} />
                </div>
              </>
            )}
          </>
        )}

        <div className="space-y-1.5">
          <p className="text-xs font-medium text-ink-3">Try an example</p>
          <SampleChips samples={channel === "sms" ? SMS_SAMPLES : channel === "email" ? EMAIL_SAMPLES : URL_SAMPLES} onPick={pick} />
        </div>

        <div className="flex flex-col-reverse gap-3 sm:flex-row sm:items-center sm:justify-between">
          <label className="inline-flex items-center gap-2 text-sm text-ink-2">
            <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} className="size-4 accent-[var(--accent)]" />
            Also get an AI analyst review <span className="text-ink-3">(+3–5 s)</span>
          </label>
          <button type="submit" disabled={!canSubmit}
            className="inline-flex min-h-12 items-center justify-center gap-2 rounded-xl bg-accent px-6 font-semibold text-accent-ink shadow-sm transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50">
            {busy ? <Spinner /> : <ScanSearch className="size-5" aria-hidden />}
            {busy ? "Checking…" : "Check now"}
          </button>
        </div>
        {error && <ErrorNote message={error} />}
      </form>

      <div ref={resultRef} className="scroll-mt-20">
        {result && <VerdictView key={result.scan_id} verdict={result} />}
      </div>
    </div>
  );
}
