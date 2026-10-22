import { History, LayoutDashboard, Moon, PhoneCall, ScanSearch, Shield, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../lib/api";
import { cx } from "../lib/format";
import { useTheme } from "../lib/hooks";
import type { Health } from "../lib/types";
import ServerSettings from "./ServerSettings";

const NAV = [
  { to: "/", label: "Check", icon: ScanSearch, end: true },
  { to: "/history", label: "History", icon: History, end: false },
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, end: false },
  { to: "/call", label: "Call Shield", icon: PhoneCall, end: false },
];

function StatusDot({ onClick }: { onClick: () => void }) {
  const [health, setHealth] = useState<Health | null>(null);
  const [down, setDown] = useState(false);
  useEffect(() => {
    let alive = true;
    const load = () =>
      api.health().then(
        (h) => alive && (setHealth(h), setDown(false)),
        () => alive && setDown(true),
      );
    load();
    const t = window.setInterval(load, 30_000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  const online = health?.tier1.status.startsWith("ready");
  const label = down ? "Server offline" : !health ? "Connecting…" : online ? "AI online" : "Offline mode";
  const dot = down ? "bg-scam" : !health ? "bg-ink-3" : online ? "bg-safe" : "bg-warn";
  return (
    <button type="button" onClick={onClick}
      className="inline-flex min-h-8 items-center gap-1.5 rounded-lg px-1.5 text-xs text-ink-2 hover:bg-surface-2 hover:text-ink"
      aria-label={`${label}. Server settings`}
      title={health ? `Decision model: ${health.tier1.model}` : undefined}>
      <span className={cx("size-2 rounded-full", dot)} aria-hidden />
      {label}
    </button>
  );
}

export default function Layout() {
  const { theme, toggle } = useTheme();
  const ThemeIcon = theme === "dark" ? Sun : Moon;
  const [settings, setSettings] = useState(false);
  const openSettings = () => setSettings(true);

  return (
    <div className="min-h-dvh md:grid md:grid-cols-[15rem_minmax(0,1fr)]">
      {/* Desktop sidebar */}
      <aside className="sticky top-0 hidden h-dvh flex-col border-r border-line bg-surface p-4 md:flex">
        <div className="mb-8 flex items-center gap-2 px-2">
          <Shield className="size-6 text-accent" aria-hidden />
          <span className="text-lg font-bold tracking-tight">ScamShield</span>
        </div>
        <nav className="flex flex-col gap-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition",
                  isActive ? "bg-accent-soft text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
                )
              }
            >
              <Icon className="size-5" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto flex items-center justify-between px-2">
          <StatusDot onClick={openSettings} />
          <button
            type="button"
            onClick={toggle}
            className="rounded-lg p-2 text-ink-2 hover:bg-surface-2 hover:text-ink"
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          >
            <ThemeIcon className="size-4" />
          </button>
        </div>
      </aside>

      <div className="flex min-h-dvh min-w-0 flex-col">
        {/* Mobile top bar */}
        <header className="sticky top-0 z-20 flex items-center justify-between border-b border-line bg-surface/90 px-4 py-3 backdrop-blur md:hidden">
          <div className="flex items-center gap-2">
            <Shield className="size-5 text-accent" aria-hidden />
            <span className="font-bold tracking-tight">ScamShield</span>
          </div>
          <div className="flex items-center gap-2">
            <StatusDot onClick={openSettings} />
            <button
              type="button"
              onClick={toggle}
              className="rounded-lg p-2 text-ink-2"
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              <ThemeIcon className="size-4" />
            </button>
          </div>
        </header>

        <main className="mx-auto w-full min-w-0 max-w-5xl flex-1 px-4 pt-4 pb-28 sm:px-6 md:pt-8 md:pb-10">
          <Outlet />
        </main>

        {/* Mobile bottom tabs */}
        <nav className="safe-bottom fixed inset-x-0 bottom-0 z-20 grid grid-cols-4 border-t border-line bg-surface/95 pt-1.5 backdrop-blur md:hidden">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx("flex flex-col items-center gap-0.5 py-1 text-[11px] font-medium", isActive ? "text-accent" : "text-ink-3")
              }
            >
              <Icon className="size-6" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
      </div>
      <ServerSettings open={settings} onClose={() => setSettings(false)} />
    </div>
  );
}
