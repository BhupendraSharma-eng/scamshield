"use strict";

importScripts("helpers.js");

const H = ScamShieldHelpers;
const CACHE_TTL_MS = 30 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 15000;
const inFlightUrls = new Map();
const navigationTokens = new Map();

chrome.runtime.onInstalled.addListener(async () => {
  const sync = await chrome.storage.sync.get(["protectionEnabled", "apiBase"]);
  const updates = {};
  if (typeof sync.protectionEnabled !== "boolean") updates.protectionEnabled = true;
  if (!sync.apiBase) updates.apiBase = H.DEFAULT_API_BASE;
  if (Object.keys(updates).length) await chrome.storage.sync.set(updates);
  const local = await chrome.storage.local.get(["pagesChecked", "threatsBlocked"]);
  await chrome.storage.local.set({
    pagesChecked: Number(local.pagesChecked) || 0,
    threatsBlocked: Number(local.threatsBlocked) || 0
  });
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  void guardNavigation(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  navigationTokens.delete(tabId);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync" || !changes.protectionEnabled) return;
  void chrome.tabs.query({}).then((tabs) => Promise.all(tabs.map(async (tab) => {
    if (tab.id == null) return;
    if (changes.protectionEnabled.newValue === false) await setBadge(tab.id, "off");
    else if (tab.active && tab.url) await guardNavigation(tab.id, tab.url);
  }))).catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void handleMessage(message, sender).then(sendResponse).catch(() => sendResponse({ ok: false, offline: true }));
  return true;
});

async function settings() {
  const values = await chrome.storage.sync.get(["protectionEnabled", "apiBase"]);
  return {
    enabled: values.protectionEnabled !== false,
    apiBase: H.normalizeBaseUrl(values.apiBase)
  };
}

async function guardNavigation(tabId, url) {
  const cfg = await settings();
  if (!cfg.enabled) {
    await setBadge(tabId, "off");
    return;
  }

  const parsed = H.parseHttpUrl(url);
  if (!parsed) return;
  const token = `${Date.now()}:${Math.random()}`;
  navigationTokens.set(tabId, token);

  if (await isSessionAllowed(url)) {
    await setTabVerdict(tabId, url, { verdict: "SAFE", risk: 0, reasons: [], category: "Session exception", action: "" }, true);
    await setBadge(tabId, "SAFE");
    return;
  }

  if (H.shouldSkipUrl(url, cfg.apiBase)) {
    await setTabVerdict(tabId, url, { verdict: "SAFE", risk: 0, reasons: [], category: "Trusted site", action: "" }, true);
    await setBadge(tabId, "SAFE");
    return;
  }

  const result = await analyzeUrl(url, { count: true });
  if (navigationTokens.get(tabId) !== token) return;
  if (!result.ok) {
    await setBadge(tabId, "offline");
    return;
  }

  const verdict = result.verdict;
  await setTabVerdict(tabId, url, verdict, false);
  await setBadge(tabId, verdict.verdict);

  if (verdict.verdict === "SCAM") {
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    if (!tab || !sameDestination(tab.url, url)) return;
    await incrementStat("threatsBlocked");
    const scan = encodeURIComponent(JSON.stringify(H.minimalVerdict(verdict)));
    const warning = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&scan=${scan}`);
    await chrome.tabs.update(tabId, { url: warning }).catch(() => {});
  } else if (verdict.verdict === "SUSPICIOUS") {
    await chrome.tabs.sendMessage(tabId, { type: "SHOW_PAGE_WARNING", verdict }).catch(() => {});
  }
}

function sameDestination(current, checked) {
  if (!current) return false;
  try {
    const a = new URL(current);
    const b = new URL(checked);
    return a.hostname === b.hostname && a.pathname === b.pathname;
  } catch (_) {
    return false;
  }
}

async function analyzeUrl(url, options = {}) {
  const cfg = await settings();
  if (!cfg.enabled) return { ok: false, disabled: true };
  if (await isSessionAllowed(url) || H.shouldSkipUrl(url, cfg.apiBase)) {
    return { ok: true, skipped: true, verdict: { verdict: "SAFE", risk: 0, category: "Trusted site", reasons: [], action: "" } };
  }
  const key = H.cacheKey(url);
  const cached = await getCachedVerdict(key);
  if (cached) return { ok: true, cached: true, verdict: cached };
  if (inFlightUrls.has(key)) return inFlightUrls.get(key);

  const request = (async () => {
    if (options.count) await incrementStat("pagesChecked");
    try {
      const raw = await apiRequest("/api/analyze/url", { url });
      const verdict = H.cleanVerdict(raw);
      await putCachedVerdict(key, verdict);
      return { ok: true, cached: false, verdict };
    } catch (_) {
      return { ok: false, offline: true };
    } finally {
      inFlightUrls.delete(key);
    }
  })();
  inFlightUrls.set(key, request);
  return request;
}

async function apiRequest(path, body) {
  const cfg = await settings();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(cfg.apiBase + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "ngrok-skip-browser-warning": "1",
        ...(body === undefined ? {} : { "Content-Type": "application/json" })
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      cache: "no-store"
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) throw new Error("Backend returned a non-JSON response");
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function handleMessage(message, sender) {
  if (!message || typeof message.type !== "string") return { ok: false };
  switch (message.type) {
    case "CHECK_URL":
      return analyzeUrl(message.url);
    case "ANALYZE_EMAIL": {
      const cfg = await settings();
      if (!cfg.enabled) return { ok: false, disabled: true };
      try {
        return { ok: true, verdict: H.cleanVerdict(await apiRequest("/api/analyze/email", message.payload)) };
      } catch (_) {
        return { ok: false, offline: true };
      }
    }
    case "ANALYZE_SMS": {
      const cfg = await settings();
      if (!cfg.enabled) return { ok: false, disabled: true };
      try {
        return { ok: true, verdict: H.cleanVerdict(await apiRequest("/api/analyze/sms", message.payload)) };
      } catch (_) {
        return { ok: false, offline: true };
      }
    }
    case "GET_TAB_VERDICT":
      return getTabVerdict(message.tabId ?? sender.tab?.id);
    case "WHITELIST_URL":
      await allowForSession(message.url);
      return { ok: true };
    case "RECORD_BLOCK":
      await incrementStat("threatsBlocked");
      return { ok: true };
    case "GET_SETTINGS": {
      const cfg = await settings();
      return { ok: true, ...cfg };
    }
    case "TEST_BACKEND":
      try {
        return { ok: true, health: await apiRequest("/api/health") };
      } catch (_) {
        return { ok: false, offline: true };
      }
    default:
      return { ok: false };
  }
}

async function getCachedVerdict(key) {
  if (!key) return null;
  const { verdictCache = {} } = await chrome.storage.session.get("verdictCache");
  const item = verdictCache[key];
  if (!item || item.expiresAt <= Date.now()) {
    if (item) {
      delete verdictCache[key];
      await chrome.storage.session.set({ verdictCache });
    }
    return null;
  }
  return item.verdict;
}

async function putCachedVerdict(key, verdict) {
  if (!key) return;
  const { verdictCache = {} } = await chrome.storage.session.get("verdictCache");
  verdictCache[key] = { verdict, expiresAt: Date.now() + CACHE_TTL_MS };
  const keys = Object.keys(verdictCache);
  if (keys.length > 500) {
    keys.sort((a, b) => verdictCache[a].expiresAt - verdictCache[b].expiresAt)
      .slice(0, keys.length - 400).forEach((oldKey) => delete verdictCache[oldKey]);
  }
  await chrome.storage.session.set({ verdictCache });
}

async function allowForSession(url) {
  const key = H.cacheKey(url);
  if (!key) return;
  const { sessionAllow = {} } = await chrome.storage.session.get("sessionAllow");
  sessionAllow[key] = true;
  await chrome.storage.session.set({ sessionAllow });
}

async function isSessionAllowed(url) {
  const key = H.cacheKey(url);
  if (!key) return false;
  const { sessionAllow = {} } = await chrome.storage.session.get("sessionAllow");
  return sessionAllow[key] === true;
}

async function setTabVerdict(tabId, url, verdict, allowlisted) {
  if (tabId == null) return;
  const { tabVerdicts = {} } = await chrome.storage.session.get("tabVerdicts");
  tabVerdicts[String(tabId)] = { url, verdict, allowlisted, checkedAt: Date.now() };
  await chrome.storage.session.set({ tabVerdicts });
}

async function getTabVerdict(tabId) {
  if (tabId == null) return { ok: false };
  const { tabVerdicts = {} } = await chrome.storage.session.get("tabVerdicts");
  return { ok: true, data: tabVerdicts[String(tabId)] || null };
}

async function incrementStat(name) {
  const values = await chrome.storage.local.get(name);
  await chrome.storage.local.set({ [name]: (Number(values[name]) || 0) + 1 });
}

async function setBadge(tabId, status) {
  const styles = {
    SCAM: { text: "!", color: "#D03B3B", title: "ScamShield: scam blocked" },
    SUSPICIOUS: { text: "?", color: "#FAB219", title: "ScamShield: suspicious page" },
    SAFE: { text: "✓", color: "#0CA30C", title: "ScamShield: safe" },
    offline: { text: "–", color: "#667085", title: "ScamShield: backend offline" },
    off: { text: "", color: "#667085", title: "ScamShield: protection off" }
  };
  const style = styles[status] || styles.off;
  await Promise.all([
    chrome.action.setBadgeText({ tabId, text: style.text }).catch(() => {}),
    chrome.action.setBadgeBackgroundColor({ tabId, color: style.color }).catch(() => {}),
    chrome.action.setTitle({ tabId, title: style.title }).catch(() => {})
  ]);
}
