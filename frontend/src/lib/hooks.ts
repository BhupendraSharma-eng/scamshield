import { useCallback, useEffect, useRef, useState } from "react";

type ThemePref = "system" | "light" | "dark";
const THEME_KEY = "scamshield.theme";

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

/** Resolves OS preference + manual override into <html data-theme>. */
export function useTheme() {
  const [pref, setPref] = useState<ThemePref>(readPref);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const on = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  const resolved = pref === "system" ? (systemDark ? "dark" : "light") : pref;
  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  const toggle = useCallback(() => {
    const next: ThemePref = resolved === "dark" ? "light" : "dark";
    setPref(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* storage unavailable: theme still applies for this session */
    }
  }, [resolved]);

  return { theme: resolved, toggle };
}

/** Re-runs `fn` every `intervalMs` while `active`; stops on unmount. */
export function usePolling(fn: () => Promise<boolean>, intervalMs: number, active: boolean) {
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    if (!active) return;
    let stopped = false;
    let timer: number;
    const tick = async () => {
      let done = false;
      try {
        done = await fnRef.current();
      } catch {
        done = false;
      }
      if (!stopped && !done) timer = window.setTimeout(tick, intervalMs);
    };
    timer = window.setTimeout(tick, intervalMs);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [intervalMs, active]);
}
