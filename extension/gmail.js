(function () {
  "use strict";

  const H = ScamShieldHelpers;
  const verdicts = new Map();
  const pending = new Set();
  let enabled = true;
  let scheduled = false;

  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }).then((response) => {
    enabled = response?.enabled !== false;
    if (enabled) scheduleScan();
  }).catch(() => {});

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.protectionEnabled) enabled = changes.protectionEnabled.newValue !== false;
  });

  const observer = new MutationObserver(scheduleScan);
  observer.observe(document.documentElement, { childList: true, subtree: true });
  scheduleScan();

  function scheduleScan() {
    if (!enabled || scheduled) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      void scanOpenMessage();
    }, 450);
  }

  async function scanOpenMessage() {
    const bodies = Array.from(document.querySelectorAll("div.a3s")).filter(isVisible);
    const body = bodies.at(-1);
    const subjectEl = document.querySelector("h2.hP");
    const senderEl = document.querySelector("span.gD[email]");
    if (!body || !subjectEl || !senderEl || body.dataset.scamshieldAttached === "1") return;

    const subject = subjectEl.textContent?.trim() || "";
    const sender = senderEl.getAttribute("email") || senderEl.textContent?.trim() || "";
    const bodyText = body.innerText?.trim() || "";
    if (!bodyText) return;
    const key = `${subject}\n${sender}\n${bodyText.slice(0, 200)}`;
    body.dataset.scamshieldAttached = "1";

    if (verdicts.has(key)) {
      injectBanner(body, verdicts.get(key));
      return;
    }
    if (pending.has(key)) return;
    pending.add(key);
    try {
      const response = await chrome.runtime.sendMessage({
        type: "ANALYZE_EMAIL",
        payload: { sender, subject, body: bodyText }
      });
      if (!response?.ok || !response.verdict || !body.isConnected) return;
      verdicts.set(key, response.verdict);
      injectBanner(body, response.verdict);
    } catch (_) {
      // Gmail must remain unaffected if protection is offline.
    } finally {
      pending.delete(key);
    }
  }

  function isVisible(element) {
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  }

  function injectBanner(body, verdict) {
    if (!body.parentNode || body.previousElementSibling?.classList.contains("scamshield-email-banner")) return;
    const colors = {
      SCAM: ["#D03B3B", "#fff", "⛔"],
      SUSPICIOUS: ["#FAB219", "#241a00", "⚠"],
      SAFE: ["#0CA30C", "#fff", "✓"]
    };
    const [background, color, icon] = colors[verdict.verdict] || colors.SUSPICIOUS;
    const banner = document.createElement("div");
    banner.className = "scamshield-email-banner";
    banner.style.cssText = `all:initial;display:block;margin:0 0 14px;padding:14px 16px;border-radius:12px;background:${background};color:${color};font:14px/1.45 system-ui,-apple-system,sans-serif;box-shadow:0 4px 18px #0002;`;
    const heading = document.createElement("div");
    heading.style.cssText = "font-weight:800;font-size:15px;margin-bottom:6px";
    heading.textContent = `${icon} ScamShield: ${titleCase(verdict.verdict)} · ${H.riskPercent(verdict.risk)} · ${H.categoryLabel(verdict.category)}`;
    const list = document.createElement("ul");
    list.style.cssText = "margin:5px 0 7px;padding-left:20px";
    (verdict.reasons || []).slice(0, 3).forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      list.appendChild(item);
    });
    const action = document.createElement("div");
    action.textContent = verdict.action || "Verify this message independently before acting.";
    const link = document.createElement("a");
    link.href = verdict.scan_id ? H.ANALYSIS_BASE + encodeURIComponent(verdict.scan_id) : H.DASHBOARD_URL;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "Full analysis ↗";
    link.style.cssText = `display:inline-block;margin-top:8px;color:${color};font-weight:800;text-decoration:underline`;
    banner.append(heading, list, action, link);
    body.parentNode.insertBefore(banner, body);
  }

  function titleCase(value) {
    return String(value || "").toLowerCase().replace(/^./, (c) => c.toUpperCase());
  }
})();
