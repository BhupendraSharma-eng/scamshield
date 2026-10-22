import {
  AudioLines, Bot, Clock3, FileAudio, HelpCircle, Mic, PhoneCall, PhoneOff,
  Play, Radio, ShieldAlert, Upload, User, Volume2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { callApi, type CallUpdate } from "../lib/callApi";
import { CATEGORY_LABEL, cx, ms, pct, TRIGGER_LABEL } from "../lib/format";
import { startMicCapture, type MicCapture } from "../lib/audio";
import { Card, ErrorNote, RichText, SectionTitle, Segmented, Spinner, toneOf, VerdictBadge } from "../components/ui";

type Mode = "live" | "demo";
type Activity = "idle" | "starting" | "listening" | "stopping" | "analyzing" | "playing";
type QueuedChunk = { file: Blob; seq: number };

const BUILT_IN_CLIPS = [
  { path: "demo/scam_call_ai.mp3", label: "Play scam call (AI voice)" },
  { path: "demo/genuine_call.mp3", label: "Play genuine call" },
] as const;

const formatTimer = (seconds: number) =>
  `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;

function playAlertSound() {
  try {
    const context = new AudioContext();
    const gain = context.createGain();
    gain.gain.setValueAtTime(0.0001, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.18, context.currentTime + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + 0.42);
    const oscillator = context.createOscillator();
    oscillator.type = "square";
    oscillator.frequency.setValueAtTime(740, context.currentTime);
    oscillator.frequency.setValueAtTime(520, context.currentTime + 0.2);
    oscillator.connect(gain);
    gain.connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.42);
    oscillator.addEventListener("ended", () => void context.close(), { once: true });
  } catch {
    // The visual warning remains primary when browser audio is unavailable.
  }
}

function HighlightedText({ text, phrases }: { text: string; phrases: string[] }) {
  const parts = useMemo(() => {
    const relevant = [...new Set(phrases.filter((phrase) => phrase.length >= 3 && text.toLowerCase().includes(phrase.toLowerCase())))]
      .sort((a, b) => b.length - a.length);
    if (!relevant.length) return [{ text, hit: false }];
    const escaped = relevant.map((phrase) => phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    const expression = new RegExp(`(${escaped.join("|")})`, "gi");
    return text.split(expression).map((part, index) => ({ text: part, hit: index % 2 === 1 }));
  }, [phrases, text]);

  return (
    <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-ink">
      {parts.map((part, index) => part.hit ? (
        <mark key={index} className="rounded bg-warn-soft px-0.5 text-ink underline decoration-warn decoration-2 underline-offset-2">
          {part.text}
        </mark>
      ) : <span key={index}>{part.text}</span>)}
    </p>
  );
}

function RiskTimeline({ updates }: { updates: CallUpdate[] }) {
  const values = updates.map((update) => Math.max(0, Math.min(1, update.risk)));
  const points = values.map((value, index) => {
    const x = values.length <= 1 ? 0 : index * 300 / (values.length - 1);
    return `${x},${76 - value * 68}`;
  });
  if (points.length === 1) points.push(`300,${76 - values[0] * 68}`);
  const verdict = updates.at(-1)?.verdict ?? "SAFE";
  const stroke = verdict === "SCAM" ? "var(--scam)" : verdict === "SUSPICIOUS" ? "var(--warn)" : "var(--safe)";

  return (
    <div>
      <svg viewBox="0 0 300 80" className="h-24 w-full overflow-visible" role="img" aria-label={`Scam risk timeline, now ${pct(values.at(-1))}`}>
        <line x1="0" x2="300" y1="52.2" y2="52.2" stroke="var(--grid)" strokeDasharray="4 4" />
        <line x1="0" x2="300" y1="28.4" y2="28.4" stroke="var(--grid)" strokeDasharray="4 4" />
        <polyline points={points.join(" ")} fill="none" stroke={stroke} strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
        {points.map((point, index) => {
          const [cxValue, cyValue] = point.split(",");
          return <circle key={index} cx={cxValue} cy={cyValue} r={index === points.length - 1 ? 4 : 2.5} fill={stroke} />;
        })}
      </svg>
      <div className="-mt-1 flex justify-between text-[11px] text-ink-3">
        <span>0%</span><span>35% suspicious</span><span>70% scam</span><span>100%</span>
      </div>
    </div>
  );
}

function VoiceCard({ update }: { update: CallUpdate }) {
  const probability = update.deepfake.p_fake;
  const label = update.deepfake.label;
  const meta: { title: string; Icon: typeof Bot; color: string } = label === "likely_ai"
    ? { title: "Likely AI-generated voice", Icon: Bot, color: "bg-scam" }
    : label === "likely_human"
      ? { title: "Likely human", Icon: User, color: "bg-safe" }
      : { title: probability == null ? "Listening for enough voice audio" : "Uncertain", Icon: HelpCircle, color: "bg-warn" };

  return (
    <Card>
      <SectionTitle aside={<span className="text-xs text-ink-3">{update.deepfake.chunks} voice chunks</span>}>
        <span className="inline-flex items-center gap-2"><AudioLines className="size-4" aria-hidden /> AI-voice likelihood</span>
      </SectionTitle>
      <div className="flex items-end justify-between gap-4">
        <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-ink">
          <meta.Icon className="size-5 shrink-0" aria-hidden />
          <span>{meta.title}</span>
        </div>
        <span className="tabular shrink-0 text-2xl font-bold text-ink">{pct(probability)}</span>
      </div>
      <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-surface-2" role="meter" aria-label="AI voice likelihood"
        aria-valuemin={0} aria-valuemax={100} aria-valuenow={probability == null ? undefined : Math.round(probability * 100)}>
        {probability != null && <div className={cx("h-full rounded-full transition-[width] duration-500", meta.color)} style={{ width: `${Math.max(2, probability * 100)}%` }} />}
      </div>
      <p className="mt-3 text-xs leading-relaxed text-ink-3">
        Supporting signal only — audio over speakerphone is noisy. Always weigh the words and requested action more heavily.
      </p>
    </Card>
  );
}

function HowItWorks() {
  const steps: { icon: ReactNode; title: string; detail: string }[] = [
    { icon: <Volume2 className="size-5" />, title: "Use speakerphone", detail: "Keep the call beside this device." },
    { icon: <Mic className="size-5" />, title: "Listen live", detail: "Audio is checked in short 4-second windows." },
    { icon: <ShieldAlert className="size-5" />, title: "Get warned", detail: "Scam scripts and cloned-voice signals update live." },
  ];
  return (
    <Card>
      <SectionTitle>How it works</SectionTitle>
      <div className="grid gap-3 sm:grid-cols-3">
        {steps.map((step, index) => (
          <div key={step.title} className="flex gap-3 rounded-xl bg-surface-2 p-3 sm:block">
            <div className="grid size-9 shrink-0 place-items-center rounded-full bg-accent-soft text-accent" aria-hidden>{step.icon}</div>
            <div className="min-w-0 sm:mt-3">
              <p className="text-sm font-semibold text-ink">{index + 1}. {step.title}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-ink-2">{step.detail}</p>
            </div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs text-ink-3">Audio is sent to your configured ScamShield server for analysis.</p>
    </Card>
  );
}

export default function CallShieldPage() {
  const [mode, setMode] = useState<Mode>("live");
  const [activity, setActivity] = useState<Activity>("idle");
  const [callerNumber, setCallerNumber] = useState("");
  const [updates, setUpdates] = useState<CallUpdate[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [level, setLevel] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [alertUpdate, setAlertUpdate] = useState<CallUpdate | null>(null);
  const [demoUrl, setDemoUrl] = useState<string | null>(null);
  const [builtIns, setBuiltIns] = useState<Record<string, boolean>>({});

  const captureRef = useRef<MicCapture | null>(null);
  const sessionRef = useRef<string | null>(null);
  const seqRef = useRef(0);
  const inFlightRef = useRef(false);
  const pendingRef = useRef<QueuedChunk | null>(null);
  const drainWaitersRef = useRef<(() => void)[]>([]);
  const scamSeenRef = useRef(false);
  const stoppingRef = useRef(false);
  const startedAtRef = useRef(0);
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const demoUpdatesRef = useRef<CallUpdate[]>([]);
  const revealedRef = useRef(0);

  const current = updates.at(-1);
  const flags = useMemo(() => [...new Set(updates.flatMap((update) => update.flags))], [updates]);

  const applyUpdate = useCallback((update: CallUpdate) => {
    setUpdates((previous) => [...previous, update]);
    const firstScam = update.verdict === "SCAM" && !scamSeenRef.current;
    if (update.verdict === "SCAM") scamSeenRef.current = true;
    if (update.alert || firstScam) {
      setAlertUpdate(update);
      navigator.vibrate?.([300, 150, 300]);
      playAlertSound();
    }
  }, []);

  const settleQueue = () => {
    if (inFlightRef.current || pendingRef.current) return;
    drainWaitersRef.current.splice(0).forEach((resolve) => resolve());
  };

  const sendQueued = useCallback(async (initial: QueuedChunk) => {
    if (inFlightRef.current) {
      pendingRef.current = initial;
      return;
    }
    inFlightRef.current = true;
    let next: QueuedChunk | null = initial;
    while (next) {
      const sessionId = sessionRef.current;
      if (!sessionId) break;
      try {
        applyUpdate(await callApi.sendChunk(sessionId, next.file, next.seq));
      } catch (reason) {
        setError((reason as Error).message);
      }
      next = pendingRef.current;
      pendingRef.current = null;
    }
    inFlightRef.current = false;
    settleQueue();
  }, [applyUpdate]);

  const enqueueChunk = useCallback((file: Blob) => {
    const chunk = { file, seq: seqRef.current++ };
    if (inFlightRef.current) pendingRef.current = chunk;
    else void sendQueued(chunk);
  }, [sendQueued]);

  const waitForQueue = () => {
    if (!inFlightRef.current && !pendingRef.current) return Promise.resolve();
    return new Promise<void>((resolve) => drainWaitersRef.current.push(resolve));
  };

  const resetAnalysis = () => {
    setUpdates([]);
    setAlertUpdate(null);
    setError(null);
    setElapsed(0);
    setLevel(0);
    scamSeenRef.current = false;
    seqRef.current = 0;
    pendingRef.current = null;
    demoUpdatesRef.current = [];
    revealedRef.current = 0;
  };

  const startLive = async () => {
    resetAnalysis();
    setActivity("starting");
    try {
      const capture = await startMicCapture({ onChunk: enqueueChunk, onLevel: setLevel });
      captureRef.current = capture;
      const session = await callApi.createSession(callerNumber);
      sessionRef.current = session.session_id;
      startedAtRef.current = Date.now();
      setActivity("listening");
    } catch (reason) {
      await captureRef.current?.stop();
      captureRef.current = null;
      const caught = reason as Error;
      const permissionDenied = caught.name === "NotAllowedError" || caught.name === "SecurityError";
      setError(permissionDenied
        ? "Microphone access was blocked. Allow microphone access for this site in your browser settings, then try again."
        : caught.message || "Could not start live call protection.");
      setActivity("idle");
    }
  };

  const stopLive = useCallback(async () => {
    if (stoppingRef.current) return;
    stoppingRef.current = true;
    setActivity("stopping");
    try {
      await captureRef.current?.stop();
      captureRef.current = null;
      await waitForQueue();
      if (sessionRef.current) applyUpdate(await callApi.endSession(sessionRef.current));
    } catch (reason) {
      setError((reason as Error).message);
    } finally {
      sessionRef.current = null;
      setLevel(0);
      setActivity("idle");
      stoppingRef.current = false;
    }
  }, [applyUpdate]);

  useEffect(() => {
    if (activity !== "listening") return;
    const updateTimer = () => setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000));
    updateTimer();
    const timer = window.setInterval(updateTimer, 1000);
    return () => window.clearInterval(timer);
  }, [activity]);

  useEffect(() => {
    transcriptRef.current?.scrollTo({ top: transcriptRef.current.scrollHeight, behavior: "smooth" });
  }, [updates.length]);

  useEffect(() => {
    let active = true;
    const base = import.meta.env.BASE_URL.endsWith("/") ? import.meta.env.BASE_URL : `${import.meta.env.BASE_URL}/`;
    void Promise.all(BUILT_IN_CLIPS.map(async (clip) => {
      try {
        const response = await fetch(`${base}${clip.path}`, { method: "HEAD" });
        const contentType = response.headers.get("content-type") ?? "";
        return [clip.path, response.ok && !contentType.includes("text/html")] as const;
      } catch {
        return [clip.path, false] as const;
      }
    })).then((entries) => active && setBuiltIns(Object.fromEntries(entries)));
    return () => { active = false; };
  }, []);

  useEffect(() => () => {
    void captureRef.current?.stop();
    if (sessionRef.current) void callApi.endSession(sessionRef.current).catch(() => undefined);
    if (demoUrl) URL.revokeObjectURL(demoUrl);
  }, [demoUrl]);

  const startDemo = async (file: File) => {
    resetAnalysis();
    audioRef.current?.pause();
    if (demoUrl) URL.revokeObjectURL(demoUrl);
    setDemoUrl(null);
    setActivity("analyzing");
    try {
      const result = await callApi.analyzeFile(file);
      if (!result.updates.length) throw new Error("The clip did not contain any analyzable audio.");
      demoUpdatesRef.current = result.updates;
      setDemoUrl(URL.createObjectURL(file));
      setActivity("playing");
      window.setTimeout(() => {
        void audioRef.current?.play().catch(() => undefined);
      }, 0);
    } catch (reason) {
      setError((reason as Error).message);
      setActivity("idle");
    }
  };

  const loadBuiltIn = async (path: string) => {
    setError(null);
    try {
      const base = import.meta.env.BASE_URL.endsWith("/") ? import.meta.env.BASE_URL : `${import.meta.env.BASE_URL}/`;
      const response = await fetch(`${base}${path}`);
      if (!response.ok) throw new Error("That demo clip is not available.");
      const blob = await response.blob();
      await startDemo(new File([blob], path.split("/").at(-1) ?? "demo.mp3", { type: blob.type || "audio/mpeg" }));
    } catch (reason) {
      setError((reason as Error).message);
      setActivity("idle");
    }
  };

  const revealDemoUpdates = () => {
    const audio = audioRef.current;
    if (!audio) return;
    const count = Math.min(demoUpdatesRef.current.length, Math.floor(audio.currentTime / 4) + 1);
    while (revealedRef.current < count) {
      applyUpdate(demoUpdatesRef.current[revealedRef.current]);
      revealedRef.current += 1;
    }
  };

  const changeMode = async (next: Mode) => {
    if (next === mode) return;
    if (activity === "listening" || activity === "stopping") await stopLive();
    audioRef.current?.pause();
    setActivity("idle");
    setMode(next);
    resetAnalysis();
  };

  const handleHungUp = async () => {
    setAlertUpdate(null);
    if (mode === "live" && (activity === "listening" || activity === "stopping")) await stopLive();
    else {
      audioRef.current?.pause();
      setActivity("idle");
    }
  };

  const isLiveActive = activity === "starting" || activity === "listening" || activity === "stopping";
  const modeLocked = activity === "starting" || activity === "stopping" || activity === "analyzing";
  const amplifiedLevel = Math.min(1, level * 8);

  return (
    <div className="animate-rise space-y-4 overflow-x-hidden">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <PhoneCall className="size-6 text-accent" aria-hidden />
            <h1 className="text-2xl font-bold tracking-tight text-ink">Call Shield</h1>
          </div>
          <p className="mt-1 max-w-2xl text-sm leading-relaxed text-ink-2">
            Put the call on speaker. We listen for scam scripts and AI-cloned voices — live.
          </p>
        </div>
        <label className="block sm:w-56">
          <span className="mb-1 block text-xs font-medium text-ink-2">Caller number <span className="font-normal text-ink-3">(optional)</span></span>
          <input type="tel" inputMode="tel" autoComplete="tel" value={callerNumber} onChange={(event) => setCallerNumber(event.target.value)}
            disabled={isLiveActive} placeholder="+91 98…" aria-label="Caller number"
            className="min-h-10 w-full rounded-xl border border-line bg-surface px-3 text-sm text-ink outline-none placeholder:text-ink-3 focus:border-accent disabled:opacity-60" />
        </label>
      </div>

      <Card className="space-y-4">
        <div className={cx(modeLocked && "pointer-events-none opacity-60")} aria-disabled={modeLocked || undefined}>
          <Segmented value={mode} onChange={(value) => void changeMode(value)} label="Call Shield mode" options={[
            { value: "live", label: "Live (microphone)", icon: <Mic className="size-4" aria-hidden /> },
            { value: "demo", label: "Demo clip (upload)", icon: <FileAudio className="size-4" aria-hidden /> },
          ]} />
        </div>

        {mode === "live" ? (
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
            <button type="button" onClick={() => activity === "listening" ? void stopLive() : void startLive()}
              disabled={activity === "starting" || activity === "stopping"}
              className={cx(
                "inline-flex min-h-14 w-full items-center justify-center gap-2 rounded-2xl px-6 text-base font-bold text-accent-ink shadow-sm transition active:scale-[0.99] disabled:cursor-wait disabled:opacity-70 sm:w-auto sm:min-w-52",
                activity === "listening" || activity === "stopping" ? "bg-scam" : "bg-accent",
              )}>
              {activity === "starting" || activity === "stopping" ? <Spinner /> : activity === "listening" ? <PhoneOff className="size-5" /> : <Mic className="size-5" />}
              {activity === "starting" ? "Starting shield…" : activity === "stopping" ? "Finishing analysis…" : activity === "listening" ? "Stop protection" : "Start live protection"}
            </button>

            {activity === "listening" && (
              <div className="min-w-0 flex-1 rounded-xl bg-surface-2 p-3" aria-live="polite">
                <div className="flex items-center justify-between gap-3">
                  <span className="inline-flex items-center gap-2 text-sm font-semibold text-scam-ink">
                    <span className="relative flex size-3" aria-hidden>
                      <span className="absolute inline-flex size-full animate-ping rounded-full bg-scam opacity-60 motion-reduce:animate-none" />
                      <span className="relative inline-flex size-3 rounded-full bg-scam" />
                    </span>
                    Listening
                  </span>
                  <span className="tabular inline-flex items-center gap-1.5 text-sm font-medium text-ink">
                    <Clock3 className="size-4 text-ink-3" aria-hidden />{formatTimer(elapsed)}
                  </span>
                </div>
                <div className="mt-2 flex h-7 items-center gap-1" aria-label={`Microphone input level ${Math.round(level * 100)} percent`}>
                  {Array.from({ length: 18 }, (_, index) => {
                    const threshold = index / 18;
                    const active = amplifiedLevel >= threshold;
                    const height = 28 + ((index * 37) % 72);
                    return <span key={index} className={cx("min-w-0 flex-1 rounded-full transition-colors", active ? "bg-accent" : "bg-line")}
                      style={{ height: `${height}%` }} aria-hidden />;
                  })}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <label className={cx("inline-flex min-h-12 cursor-pointer items-center gap-2 rounded-xl bg-accent px-4 text-sm font-semibold text-accent-ink", activity === "analyzing" && "pointer-events-none opacity-70")}>
                {activity === "analyzing" ? <Spinner /> : <Upload className="size-4" aria-hidden />}
                {activity === "analyzing" ? "Analyzing clip…" : "Choose an audio clip"}
                <input type="file" accept="audio/*,.wav,.mp3,.m4a,.webm" className="sr-only" disabled={activity === "analyzing"}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) void startDemo(file);
                    event.currentTarget.value = "";
                  }} />
              </label>
              {BUILT_IN_CLIPS.filter((clip) => builtIns[clip.path]).map((clip) => (
                <button key={clip.path} type="button" onClick={() => void loadBuiltIn(clip.path)} disabled={activity === "analyzing"}
                  className="inline-flex min-h-12 items-center gap-2 rounded-xl bg-surface-2 px-4 text-sm font-medium text-ink ring-1 ring-line hover:bg-accent-soft disabled:opacity-60">
                  <Play className="size-4" aria-hidden />{clip.label}
                </button>
              ))}
            </div>
            <p className="text-xs text-ink-3">WAV, MP3, M4A, or WebM · up to 2 minutes. Analysis is revealed in sync with playback.</p>
            {demoUrl && (
              <audio ref={audioRef} src={demoUrl} controls className="h-12 w-full" onPlay={revealDemoUpdates}
                onTimeUpdate={revealDemoUpdates} onSeeked={revealDemoUpdates}
                onEnded={() => { revealDemoUpdates(); setActivity("idle"); }}>
                Your browser does not support audio playback.
              </audio>
            )}
          </div>
        )}

        {current && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line pt-3 text-xs text-ink-3">
            <span>Chunk {current.seq}</span>
            <span>speech {ms(current.latency_ms.stt)}</span>
            <span>decision {ms(current.latency_ms.decision)}</span>
            <span>voice {ms(current.latency_ms.deepfake)}</span>
            <span className="font-medium text-ink-2">total {ms(current.latency_ms.total)}</span>
          </div>
        )}
      </Card>

      {error && <ErrorNote message={error} />}

      {current ? (
        <div className="grid items-start gap-4 lg:grid-cols-2">
          <div className="space-y-4">
            <Card className={cx("ring-2", toneOf(current.verdict).ring)}>
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <VerdictBadge verdict={current.verdict} size="lg" />
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {current.category && <span className="rounded-full bg-surface-2 px-2.5 py-1 text-xs text-ink-2">{CATEGORY_LABEL[current.category] ?? current.category}</span>}
                    {current.trigger && <span className="rounded-full bg-surface-2 px-2.5 py-1 text-xs text-ink-2">Pressure: {TRIGGER_LABEL[current.trigger] ?? current.trigger}</span>}
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <div className="tabular text-4xl font-bold tracking-tight text-ink">{pct(current.risk)}</div>
                  <div className="text-xs text-ink-3">scam risk</div>
                </div>
              </div>
              <div className="mt-4"><RiskTimeline updates={updates} /></div>
              {current.reasons.length > 0 && (
                <ol className="mt-4 space-y-2 border-t border-line pt-4">
                  {current.reasons.slice(0, 3).map((reason, index) => (
                    <li key={`${index}-${reason}`} className="flex gap-2 text-sm leading-relaxed text-ink">
                      <span className={cx("mt-0.5 grid size-5 shrink-0 place-items-center rounded-full text-[11px] font-bold", toneOf(current.verdict).bg, toneOf(current.verdict).text)}>{index + 1}</span>
                      <span className="min-w-0"><RichText text={reason} /></span>
                    </li>
                  ))}
                </ol>
              )}
              <div className={cx("mt-4 rounded-xl p-3 text-sm font-semibold", toneOf(current.verdict).bg, toneOf(current.verdict).text)}>{current.action}</div>
            </Card>
            <VoiceCard update={current} />
          </div>

          <Card className="lg:sticky lg:top-8">
            <SectionTitle aside={activity === "listening" || activity === "playing" ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-scam-ink"><Radio className="size-3.5" aria-hidden /> Live</span>
            ) : undefined}>
              <span className="inline-flex items-center gap-2"><Volume2 className="size-4" aria-hidden /> Running transcript</span>
            </SectionTitle>
            <div ref={transcriptRef} className="max-h-[32rem] min-h-72 space-y-3 overflow-y-auto rounded-xl bg-surface-2 p-3" aria-live="polite" aria-label="Call transcript">
              {updates.some((update) => update.text.trim()) ? updates.map((update, index) => update.text.trim() && (
                <div key={`${update.seq}-${index}`} className="rounded-xl bg-surface p-3 ring-1 ring-line">
                  <div className="mb-1.5 flex items-center justify-between text-[11px] text-ink-3">
                    <span>{formatTimer(Math.max(0, index * 4))}</span>
                    {update.flags.length > 0 && <span className="font-medium text-warn-ink">{update.flags.length} red flag{update.flags.length === 1 ? "" : "s"}</span>}
                  </div>
                  <HighlightedText text={update.text} phrases={flags} />
                </div>
              )) : current.transcript.trim() ? (
                <div className="rounded-xl bg-surface p-3 ring-1 ring-line">
                  <HighlightedText text={current.transcript} phrases={flags} />
                </div>
              ) : (
                <div className="grid min-h-64 place-items-center px-6 text-center">
                  <div>
                    <AudioLines className="mx-auto size-8 text-ink-3" aria-hidden />
                    <p className="mt-2 text-sm font-medium text-ink">Waiting for speech…</p>
                    <p className="mt-1 text-xs text-ink-3">The transcript appears here in 4-second sections.</p>
                  </div>
                </div>
              )}
            </div>
          </Card>
        </div>
      ) : activity === "listening" || activity === "starting" || activity === "analyzing" ? (
        <Card>
          <div className="flex min-h-36 flex-col items-center justify-center gap-3 text-center">
            <Spinner className="size-6 text-accent" />
            <div>
              <p className="font-medium text-ink">{activity === "analyzing" ? "Preparing the live playback…" : "Shield is listening…"}</p>
              <p className="mt-1 text-sm text-ink-2">{activity === "analyzing" ? "The clip is being split into 4-second windows." : "Your first risk update will appear after the first audio window."}</p>
            </div>
          </div>
        </Card>
      ) : <HowItWorks />}

      {alertUpdate && (
        <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-scam p-4 text-accent-ink" role="alertdialog" aria-modal="true" aria-labelledby="scam-alert-title">
          <div className="w-full max-w-2xl py-8 text-center">
            <div className="mx-auto grid size-20 place-items-center rounded-full bg-surface/15 ring-4 ring-surface/30">
              <PhoneOff className="size-10" aria-hidden />
            </div>
            <h2 id="scam-alert-title" className="mt-6 text-3xl font-black tracking-tight sm:text-5xl">🛑 HANG UP — this call is a scam</h2>
            <div className="tabular mt-3 text-xl font-bold">Risk: {pct(alertUpdate.risk)}</div>
            {alertUpdate.reasons.length > 0 && (
              <ul className="mx-auto mt-6 max-w-xl space-y-2 text-left text-base sm:text-lg">
                {alertUpdate.reasons.slice(0, 2).map((reason, index) => (
                  <li key={index} className="flex gap-3 rounded-xl bg-surface/15 p-3">
                    <ShieldAlert className="mt-0.5 size-5 shrink-0" aria-hidden />
                    <span><RichText text={reason} /></span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mx-auto mt-5 max-w-xl text-lg font-semibold">{alertUpdate.action}</p>
            <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
              <button type="button" onClick={() => void handleHungUp()}
                className="min-h-14 rounded-2xl bg-surface px-7 text-base font-bold text-scam-ink shadow-sm focus:outline-none focus:ring-4 focus:ring-surface/40">
                I hung up
              </button>
              <button type="button" onClick={() => setAlertUpdate(null)}
                className="min-h-14 rounded-2xl bg-surface/15 px-7 text-base font-semibold text-accent-ink ring-2 ring-surface/50 hover:bg-surface/25">
                Keep listening
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
