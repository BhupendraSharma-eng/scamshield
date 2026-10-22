(function () {
  "use strict";

  const H = ScamShieldHelpers;
  const checked = new Map();
  let enabled = true;
  let hoverTimer = null;
  let pendingAnchor = null;
  let requestInFlight = false;
  let queuedHover = null;
  let host = null;
  let shadow = null;
  let tooltip = null;

  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }).then((response) => {
    enabled = response?.enabled !== false;
  }).catch(() => {});

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.protectionEnabled) {
      enabled = changes.protectionEnabled.newValue !== false;
      if (!enabled) removeUi();
    }
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "SHOW_PAGE_WARNING" && enabled && message.verdict) {
      showPageBanner(message.verdict);
    }
  });

  document.addEventListener("mouseover", (event) => {
    if (!enabled) return;
    const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
    const url = externalHttpUrl(anchor);
    if (!url) {
      hideTooltip();
      return;
    }
    clearTimeout(hoverTimer);
    pendingAnchor = anchor;
    const known = checked.get(H.cacheKey(url.href));
    if (known) {
      renderTooltip(anchor, known);
      return;
    }
    hoverTimer = setTimeout(() => void checkHoveredLink(anchor, url.href), 300);
  }, true);

  document.addEventListener("mouseout", (event) => {
    const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
    if (!anchor) return;
    if (event.relatedTarget instanceof Node && anchor.contains(event.relatedTarget)) return;
    clearTimeout(hoverTimer);
    pendingAnchor = null;
    hideTooltip();
  }, true);

  document.addEventListener("click", (event) => {
    if (!enabled || event.defaultPrevented || event.button !== 0) return;
    const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
    const url = externalHttpUrl(anchor);
    if (!url) return;
    const result = checked.get(H.cacheKey(url.href));
    if (result?.verdict === "SCAM") {
      event.preventDefault();
      event.stopImmediatePropagation();
      chrome.runtime.sendMessage({ type: "RECORD_BLOCK" }).catch(() => {});
      showConfirm(url.href, result);
    }
  }, true);

  async function checkHoveredLink(anchor, url) {
    if (requestInFlight) {
      queuedHover = { anchor, url };
      return;
    }
    if (anchor !== pendingAnchor || !anchor.isConnected) return;
    requestInFlight = true;
    try {
      const response = await chrome.runtime.sendMessage({ type: "CHECK_URL", url });
      if (!response?.ok || !response.verdict) return;
      checked.set(H.cacheKey(url), response.verdict);
      if (anchor === pendingAnchor && anchor.isConnected) renderTooltip(anchor, response.verdict);
    } catch (_) {
      // Fail open when the background worker or backend is unavailable.
    } finally {
      requestInFlight = false;
      const queued = queuedHover;
      queuedHover = null;
      if (queued && queued.anchor === pendingAnchor && queued.anchor.isConnected) {
        void checkHoveredLink(queued.anchor, queued.url);
      }
    }
  }

  function externalHttpUrl(anchor) {
    if (!anchor) return null;
    let url;
    try { url = new URL(anchor.href, location.href); } catch (_) { return null; }
    if (!H.parseHttpUrl(url.href) || H.registeredDomain(url.hostname) === H.registeredDomain(location.hostname)) return null;
    return url;
  }

  function ensureShadow() {
    if (shadow) return shadow;
    host = document.createElement("div");
    host.id = "scamshield-ui-host";
    host.style.cssText = "all:initial!important;position:fixed!important;z-index:2147483647!important;top:0!important;left:0!important;width:0!important;height:0!important;";
    (document.documentElement || document).appendChild(host);
    shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box} .tip{position:fixed;max-width:360px;padding:10px 12px;border-radius:10px;color:#fff;font:600 13px/1.35 system-ui,-apple-system,sans-serif;box-shadow:0 8px 28px #0005;pointer-events:none}
      .tip.scam{background:#D03B3B}.tip.suspicious{background:#FAB219;color:#241a00}.page{position:fixed;top:12px;left:50%;transform:translateX(-50%);width:min(720px,calc(100vw - 24px));padding:14px 16px;border:1px solid #d68b00;background:#fff5d6;color:#2b2000;border-radius:12px;box-shadow:0 10px 36px #0005;font:14px/1.45 system-ui,-apple-system,sans-serif;pointer-events:auto}
      .page strong{font-size:15px}.page a{color:#765000;font-weight:700}.close{float:right;border:0;background:transparent;color:inherit;font-size:20px;cursor:pointer}
      .backdrop{position:fixed;inset:0;background:#101828cc;display:grid;place-items:center;width:100vw;height:100vh;pointer-events:auto;font:14px/1.45 system-ui,-apple-system,sans-serif}.dialog{width:min(470px,calc(100vw - 32px));background:#fff;color:#182230;padding:26px;border-radius:16px;box-shadow:0 24px 70px #0008}.mark{width:48px;height:48px;border-radius:50%;display:grid;place-items:center;background:#fee4e2;color:#D03B3B;font-size:25px;font-weight:900}.dialog h2{margin:14px 0 8px;font-size:22px}.dialog p{margin:0 0 20px;color:#475467}.buttons{display:flex;gap:10px;justify-content:flex-end}.buttons button{border:0;border-radius:10px;padding:10px 15px;font:700 14px system-ui;cursor:pointer}.cancel{background:#2A78D6;color:#fff}.open{background:#f2f4f7;color:#344054}
    `;
    shadow.appendChild(style);
    return shadow;
  }

  function renderTooltip(anchor, verdict) {
    if (verdict.verdict === "SAFE") return hideTooltip();
    ensureShadow();
    if (tooltip) tooltip.remove();
    tooltip = document.createElement("div");
    const label = verdict.verdict === "SCAM" ? "Scam link" : "Suspicious link";
    tooltip.className = `tip ${verdict.verdict.toLowerCase()}`;
    tooltip.textContent = `⚠ ${label} · ${H.riskPercent(verdict.risk)}${verdict.reasons?.[0] ? " — " + verdict.reasons[0] : ""}`;
    shadow.appendChild(tooltip);
    const rect = anchor.getBoundingClientRect();
    const width = Math.min(360, Math.max(220, tooltip.offsetWidth));
    const left = Math.max(8, Math.min(innerWidth - width - 8, rect.left));
    const top = rect.bottom + 9 + tooltip.offsetHeight < innerHeight ? rect.bottom + 9 : Math.max(8, rect.top - tooltip.offsetHeight - 9);
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
  }

  function hideTooltip() {
    if (tooltip) tooltip.remove();
    tooltip = null;
  }

  function showPageBanner(verdict) {
    ensureShadow();
    if (shadow.querySelector(".page")) return;
    const banner = document.createElement("div");
    banner.className = "page";
    const close = document.createElement("button");
    close.className = "close";
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss warning");
    close.textContent = "×";
    close.addEventListener("click", () => banner.remove());
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `⚠ Suspicious page · ${H.riskPercent(verdict.risk)}`;
    const reason = document.createElement("span");
    reason.textContent = verdict.reasons?.[0] ? ` — ${verdict.reasons[0]} ` : " ";
    const link = document.createElement("a");
    link.href = verdict.scan_id ? H.ANALYSIS_BASE + encodeURIComponent(verdict.scan_id) : H.DASHBOARD_URL;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "Details";
    text.append(title, reason, link);
    banner.append(close, text);
    shadow.appendChild(banner);
  }

  function showConfirm(url, verdict) {
    ensureShadow();
    shadow.querySelector(".backdrop")?.remove();
    const backdrop = document.createElement("div");
    backdrop.className = "backdrop";
    const dialog = document.createElement("div");
    dialog.className = "dialog";
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    const mark = document.createElement("div");
    mark.className = "mark";
    mark.textContent = "!";
    const heading = document.createElement("h2");
    heading.textContent = "This link is a scam";
    const copy = document.createElement("p");
    copy.textContent = `${H.riskPercent(verdict.risk)} risk${verdict.reasons?.[0] ? " — " + verdict.reasons[0] : ". Opening it may put your information or money at risk."}`;
    const buttons = document.createElement("div");
    buttons.className = "buttons";
    const back = document.createElement("button");
    back.className = "cancel";
    back.textContent = "Go back";
    back.addEventListener("click", () => backdrop.remove());
    const open = document.createElement("button");
    open.className = "open";
    open.textContent = "Open anyway";
    open.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "WHITELIST_URL", url }).catch(() => {});
      location.href = url;
    });
    buttons.append(back, open);
    dialog.append(mark, heading, copy, buttons);
    backdrop.appendChild(dialog);
    shadow.appendChild(backdrop);
    back.focus();
  }

  function removeUi() {
    clearTimeout(hoverTimer);
    host?.remove();
    host = shadow = tooltip = null;
  }
})();
