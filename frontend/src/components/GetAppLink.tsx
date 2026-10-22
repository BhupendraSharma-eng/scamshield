import { Download, Smartphone } from "lucide-react";
import { cx } from "../lib/format";

export const ANDROID_APK_URL = "https://github.com/BhupendraSharma-eng/scamshield/releases/download/android-v1.0.0/ScamShield.apk";

export default function GetAppLink({ className }: { className?: string }) {
  return (
    <a href={ANDROID_APK_URL}
      aria-label="Download ScamShield for Android (APK)"
      className={cx("flex min-h-12 items-center gap-3 rounded-xl bg-accent px-3 py-3 text-white shadow-sm transition hover:brightness-110 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent", className)}>
      <Smartphone className="size-5 shrink-0" aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-semibold">Get app</span>
        <span className="block text-[11px] text-white/80">Android APK · Android 8+</span>
      </span>
      <Download className="size-4 shrink-0" aria-hidden />
    </a>
  );
}
