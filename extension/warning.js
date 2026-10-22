(function () {
  "use strict";

  const H = ScamShieldHelpers;
  const params = new URLSearchParams(location.search);
  const target = params.get("url") || "";
  let verdict = null;
  try { verdict = JSON.parse(params.get("scan") || "null"); } catch (_) { verdict = null; }

  if (verdict) {
    document.getElementById("risk").textContent = H.riskPercent(verdict.risk);
    document.getElementById("category").textContent = verdict.category || "Scam";
    document.getElementById("action").textContent = H.stripReasonMarkup(verdict.action) || "Close this page and verify the website independently.";
    const list = document.getElementById("reasons");
    const reasons = Array.isArray(verdict.reasons) && verdict.reasons.length ? verdict.reasons : ["The destination showed strong phishing or scam indicators."];
    reasons.forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = H.stripReasonMarkup(reason);
      list.appendChild(item);
    });
    const details = document.getElementById("details");
    details.href = verdict.scan_id ? H.ANALYSIS_BASE + encodeURIComponent(verdict.scan_id) : H.DASHBOARD_URL;
  }
  document.getElementById("destination").textContent = target;

  document.getElementById("back").addEventListener("click", async () => {
    if (history.length > 1) history.back();
    else {
      const tab = await chrome.tabs.getCurrent().catch(() => null);
      if (tab?.id != null) chrome.tabs.remove(tab.id).catch(() => {});
    }
  });

  document.getElementById("proceed").addEventListener("click", async () => {
    if (!target) return;
    await chrome.runtime.sendMessage({ type: "WHITELIST_URL", url: target }).catch(() => {});
    location.replace(target);
  });
})();
