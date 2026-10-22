(function () {
  "use strict";

  const H = ScamShieldHelpers;
  const seen = new Set();
  const queue = [];
  let working = false;
  let enabled = true;
  let scheduled = false;

  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }).then((response) => {
    enabled = response?.enabled !== false;
    if (enabled) scheduleScan();
  }).catch(() => {});

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.protectionEnabled) enabled = changes.protectionEnabled.newValue !== false;
  });

  new MutationObserver(scheduleScan).observe(document.documentElement, { childList: true, subtree: true });
  scheduleScan();

  function scheduleScan() {
    if (!enabled || scheduled) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      collectMessages();
    }, 350);
  }

  function collectMessages() {
    for (const bubble of document.querySelectorAll("div.message-in")) {
      if (bubble.dataset.scamshieldSeen === "1") continue;
      bubble.dataset.scamshieldSeen = "1";
      const textNodes = bubble.querySelectorAll("span.selectable-text");
      const text = Array.from(textNodes).map((node) => node.innerText || node.textContent || "").join(" ").trim();
      if (text.length < 15) continue;
      const meta = bubble.querySelector("[data-pre-plain-text]")?.getAttribute("data-pre-plain-text") || "";
      const sender = parseSender(meta);
      const dedupeKey = text;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      if (seen.size > 1000) seen.delete(seen.values().next().value);
      queue.push({ bubble, text, sender });
    }
    void drainQueue();
  }

  async function drainQueue() {
    if (working || !enabled) return;
    working = true;
    while (queue.length && enabled) {
      const item = queue.shift();
      try {
        const response = await chrome.runtime.sendMessage({
          type: "ANALYZE_SMS",
          payload: { content: item.text, ...(item.sender ? { sender: item.sender } : {}) }
        });
        if (response?.ok && response.verdict && response.verdict.verdict !== "SAFE" && item.bubble.isConnected) {
          appendPill(item.bubble, response.verdict);
        }
      } catch (_) {
        // Selector or network failures should never affect WhatsApp.
      }
    }
    working = false;
  }

  function parseSender(meta) {
    const match = meta.match(/\]\s*([^:]+):/);
    return match ? match[1].trim() : undefined;
  }

  function appendPill(bubble, verdict) {
    if (bubble.querySelector(".scamshield-wa-pill")) return;
    const isScam = verdict.verdict === "SCAM";
    const pill = document.createElement("a");
    pill.className = "scamshield-wa-pill";
    pill.href = verdict.scan_id ? H.ANALYSIS_BASE + encodeURIComponent(verdict.scan_id) : H.DASHBOARD_URL;
    pill.target = "_blank";
    pill.rel = "noopener noreferrer";
    pill.textContent = `⚠ ${isScam ? "Scam" : "Suspicious"} · ${H.riskPercent(verdict.risk)} · ${H.categoryLabel(verdict.category)}${verdict.reasons?.[0] ? " — " + verdict.reasons[0] : ""}`;
    pill.style.cssText = `display:block;max-width:360px;margin:5px 7px 4px;padding:5px 9px;border-radius:9px;background:${isScam ? "#D03B3B" : "#FAB219"};color:${isScam ? "#fff" : "#241a00"};font:600 12px/1.35 system-ui,-apple-system,sans-serif;text-decoration:none;box-shadow:0 2px 8px #0003;`;
    bubble.appendChild(pill);
  }
})();
