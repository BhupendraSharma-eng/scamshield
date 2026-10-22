(function () {
  "use strict";

  const H = ScamShieldHelpers;
  const protection = document.getElementById("protection");
  const apiBase = document.getElementById("api-base");
  const testButton = document.getElementById("test-api");
  const apiStatus = document.getElementById("api-status");

  void initialize();

  protection.addEventListener("change", async () => {
    await chrome.storage.sync.set({ protectionEnabled: protection.checked });
    if (!protection.checked) renderCurrentStatus(null, "off");
    else await refreshCurrentTab();
  });

  apiBase.addEventListener("change", saveApiBase);
  apiBase.addEventListener("blur", saveApiBase);

  testButton.addEventListener("click", async () => {
    await saveApiBase();
    testButton.disabled = true;
    apiStatus.className = "feedback";
    apiStatus.textContent = "Testing connection…";
    try {
      const response = await chrome.runtime.sendMessage({ type: "TEST_BACKEND" });
      if (!response?.ok) throw new Error("offline");
      const health = response.health;
      const modelSummary = summarizeModels(health);
      apiStatus.className = `feedback ${health.status === "ok" ? "good" : "warn"}`;
      apiStatus.textContent = `${health.status === "ok" ? "● Connected" : "◐ Degraded"} · ${modelSummary}`;
    } catch (_) {
      apiStatus.className = "feedback bad";
      apiStatus.textContent = "● Offline — browsing will continue without warnings";
    } finally {
      testButton.disabled = false;
    }
  });

  document.getElementById("check-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("check-url");
    const output = document.getElementById("check-result");
    let url;
    try { url = new URL(input.value).href; } catch (_) {
      output.className = "feedback bad";
      output.textContent = "Enter a complete http:// or https:// URL.";
      return;
    }
    output.className = "feedback";
    output.textContent = "Checking…";
    const response = await chrome.runtime.sendMessage({ type: "CHECK_URL", url }).catch(() => null);
    if (!response?.ok) {
      output.className = "feedback bad";
      output.textContent = response?.disabled ? "Protection is turned off." : "Backend offline. No verdict available.";
      return;
    }
    const verdict = response.verdict;
    output.className = `feedback ${verdict.verdict === "SAFE" ? "good" : verdict.verdict === "SCAM" ? "bad" : "warn"}`;
    output.textContent = `${verdict.verdict === "SAFE" ? "✓" : "⚠"} ${titleCase(verdict.verdict)} · ${H.riskPercent(verdict.risk)}${verdict.reasons?.[0] ? " — " + verdict.reasons[0] : ""}`;
  });

  async function initialize() {
    const [sync, local] = await Promise.all([
      chrome.storage.sync.get(["protectionEnabled", "apiBase"]),
      chrome.storage.local.get(["pagesChecked", "threatsBlocked"])
    ]);
    protection.checked = sync.protectionEnabled !== false;
    apiBase.value = H.normalizeBaseUrl(sync.apiBase);
    document.getElementById("pages-checked").textContent = Number(local.pagesChecked) || 0;
    document.getElementById("threats-blocked").textContent = Number(local.threatsBlocked) || 0;
    if (protection.checked) await refreshCurrentTab();
    else renderCurrentStatus(null, "off");
  }

  async function refreshCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id == null) return renderCurrentStatus(null, "none");
    const response = await chrome.runtime.sendMessage({ type: "GET_TAB_VERDICT", tabId: tab.id }).catch(() => null);
    renderCurrentStatus(response?.data || null, response ? "none" : "offline");
  }

  function renderCurrentStatus(data, fallback) {
    const card = document.getElementById("status-card");
    const icon = document.getElementById("status-icon");
    const label = document.getElementById("status-label");
    const risk = document.getElementById("status-risk");
    const category = document.getElementById("status-category");
    const reasons = document.getElementById("status-reasons");
    reasons.replaceChildren();
    risk.textContent = "";

    if (!data?.verdict) {
      card.className = `status-card ${fallback === "offline" ? "offline" : "neutral"}`;
      icon.textContent = fallback === "off" ? "○" : fallback === "offline" ? "–" : "…";
      label.textContent = fallback === "off" ? "Protection is off" : fallback === "offline" ? "Backend offline" : "No page verdict yet";
      category.textContent = fallback === "off" ? "Turn protection on to scan pages automatically." : "Reload this page to run a proactive check.";
      return;
    }

    const verdict = data.verdict;
    const style = verdict.verdict.toLowerCase();
    card.className = `status-card ${style}`;
    icon.textContent = verdict.verdict === "SAFE" ? "✓" : verdict.verdict === "SCAM" ? "!" : "?";
    label.textContent = verdict.verdict === "SAFE" ? "This page looks safe" : verdict.verdict === "SCAM" ? "Scam page blocked" : "Suspicious page";
    risk.textContent = H.riskPercent(verdict.risk);
    category.textContent = verdict.category || (data.allowlisted ? "Trusted site" : "AI analysis complete");
    (verdict.reasons || []).slice(0, 3).forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      reasons.appendChild(item);
    });
  }

  async function saveApiBase() {
    const normalized = H.normalizeBaseUrl(apiBase.value);
    apiBase.value = normalized;
    await chrome.storage.sync.set({ apiBase: normalized });
  }

  function summarizeModels(health) {
    const entries = Object.entries(health?.models || {});
    const ready = entries.filter(([, status]) => String(status).toLowerCase().includes("ready") || String(status).toLowerCase() === "ok").length;
    const local = entries.length ? `${ready}/${entries.length} local models` : "model status unavailable";
    const tier1 = health?.tier1?.status ? `Tier 1 ${health.tier1.status}` : "Tier 1 unknown";
    return `${local}, ${tier1}`;
  }

  function titleCase(value) {
    return String(value || "").toLowerCase().replace(/^./, (c) => c.toUpperCase());
  }
})();
