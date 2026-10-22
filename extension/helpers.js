(function (root) {
  "use strict";

  const DEFAULT_API_BASE = "https://dandruff-sneer-almanac.ngrok-free.dev";
  const DASHBOARD_URL = "https://bhupendrasharma-eng.github.io/scamshield/dashboard";
  const ANALYSIS_BASE = "https://bhupendrasharma-eng.github.io/scamshield/scan/";

  const ALLOWLIST = Object.freeze([
    "google.com", "youtube.com", "youtu.be", "github.com", "wikipedia.org",
    "amazon.com", "amazon.in", "flipkart.com", "onlinesbi.sbi", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "yesbank.in",
    "bankofbaroda.in", "pnbindia.in", "canarabank.com", "unionbankofindia.co.in",
    "mail.google.com", "gmail.com", "web.whatsapp.com", "whatsapp.com",
    "microsoft.com", "live.com", "office.com", "apple.com", "icloud.com",
    "linkedin.com", "x.com", "twitter.com", "instagram.com", "facebook.com",
    "meta.com", "netflix.com", "hotstar.com", "primevideo.com", "spotify.com",
    "irctc.co.in", "incometax.gov.in", "uidai.gov.in", "india.gov.in",
    "digilocker.gov.in", "epfindia.gov.in", "gst.gov.in", "rbi.org.in",
    "npci.org.in", "paytm.com", "phonepe.com", "googlepay.com", "razorpay.com",
    "paypal.com", "stripe.com", "adobe.com", "mozilla.org", "stackoverflow.com",
    "reddit.com", "quora.com", "medium.com", "zoom.us", "slack.com",
    "dropbox.com", "cloudflare.com", "openai.com", "chatgpt.com", "bing.com",
    "yahoo.com", "nytimes.com", "bbc.com", "cnn.com"
  ]);

  function normalizeBaseUrl(value) {
    const candidate = String(value || DEFAULT_API_BASE).trim();
    try {
      const url = new URL(candidate);
      if (url.protocol !== "http:" && url.protocol !== "https:") return DEFAULT_API_BASE;
      return url.origin + url.pathname.replace(/\/+$/, "");
    } catch (_) {
      return DEFAULT_API_BASE;
    }
  }

  function parseHttpUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === "http:" || url.protocol === "https:" ? url : null;
    } catch (_) {
      return null;
    }
  }

  function hostMatches(hostname, domain) {
    const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
    const allowed = String(domain || "").toLowerCase();
    return host === allowed || host.endsWith("." + allowed);
  }

  function registeredDomain(hostname) {
    const parts = String(hostname || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const twoLevelSuffixes = new Set([
      "co.in", "com.au", "com.br", "com.cn", "com.sg", "com.tr", "co.jp", "co.uk",
      "gov.in", "org.in", "net.in", "ac.in", "org.uk", "net.au", "org.au"
    ]);
    const suffix = parts.slice(-2).join(".");
    return parts.slice(twoLevelSuffixes.has(suffix) ? -3 : -2).join(".");
  }

  function isAllowlisted(input) {
    const url = typeof input === "string" ? parseHttpUrl(input) : input;
    if (!url) return false;
    return ALLOWLIST.some((domain) => hostMatches(url.hostname, domain));
  }

  function isLocalHost(hostname) {
    const host = String(hostname || "").toLowerCase();
    return host === "localhost" || host === "::1" || host === "[::1]" ||
      host === "0.0.0.0" || /^127(?:\.\d{1,3}){3}$/.test(host) ||
      /^10(?:\.\d{1,3}){3}$/.test(host) ||
      /^192\.168(?:\.\d{1,3}){2}$/.test(host) ||
      /^172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}$/.test(host) ||
      host.endsWith(".local");
  }

  function shouldSkipUrl(value, apiBase) {
    const url = parseHttpUrl(value);
    if (!url || isLocalHost(url.hostname) || isAllowlisted(url)) return true;
    const apiUrl = parseHttpUrl(normalizeBaseUrl(apiBase));
    return Boolean(apiUrl && hostMatches(url.hostname, apiUrl.hostname));
  }

  function cacheKey(value) {
    const url = parseHttpUrl(value);
    if (!url) return "";
    let path = url.pathname || "/";
    path = path.replace(/\/{2,}/g, "/");
    return `${url.hostname.toLowerCase()}${url.port ? ":" + url.port : ""}${path}`;
  }

  function stripReasonMarkup(value) {
    return String(value || "")
      .replace(/`([^`]*)`/g, "$1")
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/__([^_]+)__/g, "$1")
      .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
      .replace(/<[^>]*>/g, "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function cleanVerdict(raw) {
    if (!raw || !["SCAM", "SUSPICIOUS", "SAFE"].includes(raw.verdict)) {
      throw new Error("Invalid verdict response");
    }
    return {
      ...raw,
      risk: Math.max(0, Math.min(1, Number(raw.risk) || 0)),
      category: raw.category ? stripReasonMarkup(raw.category) : "Unknown",
      reasons: Array.isArray(raw.reasons) ? raw.reasons.map(stripReasonMarkup).filter(Boolean) : [],
      action: stripReasonMarkup(raw.action || "Use caution and verify independently.")
    };
  }

  function minimalVerdict(verdict) {
    return {
      scan_id: verdict.scan_id || "",
      verdict: verdict.verdict,
      risk: verdict.risk,
      category: verdict.category || "Unknown",
      reasons: (verdict.reasons || []).slice(0, 5),
      action: verdict.action || ""
    };
  }

  function riskPercent(risk) {
    return `${Math.round(Math.max(0, Math.min(1, Number(risk) || 0)) * 100)}%`;
  }

  const api = {
    DEFAULT_API_BASE, DASHBOARD_URL, ANALYSIS_BASE, ALLOWLIST, normalizeBaseUrl,
    parseHttpUrl, hostMatches, registeredDomain, isAllowlisted, isLocalHost, shouldSkipUrl,
    cacheKey, stripReasonMarkup, cleanVerdict, minimalVerdict, riskPercent
  };

  root.ScamShieldHelpers = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
