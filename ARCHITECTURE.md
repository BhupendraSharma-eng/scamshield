# ScamShield — Final Architecture (CodeX Statement 5)

> **Update (12:xx):** Chrome extension is now **deferred to Phase 2** along with the Android SMS app
> and Call Shield. Primary focus is the backend — see [BACKEND_ARCHITECTURE.md](BACKEND_ARCHITECTURE.md),
> which supersedes §2–§6 and §9 below.

Assumptions: build window 12:00–18:00, lunch 14:30–15:00 → ~5.5 working hours, team of 3–4.
Rule: **a working end-to-end demo exists by 14:30.** Everything after lunch is additive.

## 1. Scope (locked)

**Phase 1 — this hackathon: URL, Email, SMS.**

| Priority | Feature | Brief requirement it covers |
|---|---|---|
| P0 (before lunch) | Analyze SMS / email / URL → verdict + plain-language reasons | Core objective + explainability |
| P0 | Tier 0 heuristics + local ML model (works offline) | "ML or rule-based model" |
| P0 | Jev Tier 1 decision (category, trigger, severity) | Real-time AI |
| P1 | Email forensics: `.eml` upload, header checks (SPF/DKIM/DMARC, Reply-To mismatch, display-name spoof), link + attachment scan | Email phishing depth |
| P1 | Chrome extension (MV3) URL checker | Advanced: browser extension |
| P1 | Reporting dashboard (scan history, categories, metrics) | Advanced: dashboard |
| P2 | Gmail-page integration in extension (scan the open email) | Real-time email flagging |
| P3 | Deep Audit button (generative LLM, on demand) | Nice-to-have, cut first |

Cut list if behind: P3 → P2 → extension content-script (keep popup) → attachment checks.

**Phase 2 — deferred (after hackathon), see §9:** Android SMS app, Call Shield (live call + deepfake voice).
Phase 1 API is designed so both plug in without backend changes.

## 2. System diagram

```text
 ┌────────────────┐  ┌──────────────────────┐   ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
 │ Web app        │  │ Chrome ext (MV3)     │     Phase 2 (deferred)
 │ React+Vite     │  │ popup: current URL   │   │ Android SMS app     │
 │ SMS/Email/URL  │  │ badge on tab change  │     Call Shield
 │ .eml upload    │  │ (P2) Gmail scan btn  │   └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
 │ Dashboard      │  └──────────┬───────────┘             │
 └───────┬────────┘             │                         │
         └──────── REST ────────┴─────────── same API ────┘
                          ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ FastAPI backend (single service, :8000)                       │
 │                                                               │
 │  Parsers: sms (text), email (.eml / pasted raw / plain body), │
 │           url (normalize, extract all links from any input)   │
 │                │                                              │
 │  Tier 0  (<10 ms, offline)                                    │
 │   • url_features.py: punycode, IP host, entropy, risky TLD,   │
 │     brand lookalike (edit distance), @ / // tricks, shortener,│
 │     excessive subdomains, http (no TLS), suspicious path words│
 │   • email_headers.py: SPF/DKIM/DMARC from Authentication-     │
 │     Results, From vs Reply-To / Return-Path domain mismatch,  │
 │     display-name brand spoof, link text ≠ href, risky attach. │
 │   • text_rules.py: OTP/PIN ask, KYC/UPI/lottery/job keywords  │
 │   • local models (TF-IDF + LogisticRegression, calibrated):   │
 │       sms_model.pkl, email_model.pkl, url_model.pkl (char n-g)│
 │                │                                              │
 │                ▼  (asyncio.gather, run in parallel)           │
 │  Tier 1  Jev (jev-1.13.0, ~150 ms) — SMS/email always,        │
 │          URL-only checks only if Tier 0 risk ≥ 0.2            │
 │                │                                              │
 │                ▼                                              │
 │  Fusion + Template Explainer (<1 ms) → Verdict JSON           │
 │                │                                              │
 │  Tier 2  Deep Audit (LLM) — only on button click (P3)         │
 │                                                               │
 │  SQLite: scans table → dashboard stats                        │
 └───────────────────────────────────────────────────────────────┘
```

## 3. Decision logic (fusion)

- `jev = is_scam.noul`, `local = channel model probability`, `rules = Tier 0 rule score (0–1)`
- `risk = max(jev, 0.6*local + 0.4*rules)`; then take max with any embedded URL's risk.
- Hard overrides:
  - asks for OTP/PIN **and** contains link → risk ≥ 0.9
  - punycode / IP-host / brand lookalike URL → risk ≥ 0.8
  - email: SPF+DKIM fail **and** From display-name is a known brand → risk ≥ 0.85
  - email: link text shows one domain, href goes to another → risk ≥ 0.75
- Verdict (thresholds from TypeSafe guardrails cookbook):
  - `risk ≥ 0.70` → **SCAM** (red)
  - `0.35 ≤ risk < 0.70` → **SUSPICIOUS** (amber) + "Deep Audit" button
  - `< 0.35` → **SAFE** (green)
- Jev offline/error → Tier 0 only, `"mode": "offline"` (demo-safe).

## 4. Jev request (one call, all questions in parallel)

`state = {"channel", "sender", "subject"?, "untrusted_message", "url_flags": [...], "header_flags": [...]}`
Questions: `is_scam` (noul), `category` (choice, "none" first), `trigger` (choice, "none" first),
`severity` (score, 4 concrete levels), `asks_secret` (noul), `has_impersonation` (noul),
email only: `requests_payment_change` (noul — invoice/BEC fraud).
Never send raw URLs/headers for Jev to reason about — send Tier 0's flags as text.
Email body: strip HTML, cap at ~4k chars to keep state focused.

## 5. Explanation templates

Reasons are assembled from facts, never generated:
- category → "This looks like a **fake KYC / account-freeze** scam."
- trigger → "It uses **urgency** ('within 24 hours') to rush you."
- asks_secret → "It asks for your **OTP** — banks never ask for this."
- url flags → "The link `sbi-kyc-update.xyz` imitates **SBI** but is not SBI's domain."
- header flags → "The sender claims to be **HDFC Bank** but the email failed **SPF and DKIM** checks."
- header flags → "Replies would go to `refund@gmail.com`, not the sender's company."
- link mismatch → "The button says `paypal.com` but actually opens `paypa1-secure.top`."
- local model top tokens → "Suspicious phrases: 'account blocked', 'verify now'."
- Action line by category ("Do not click. Report at cybercrime.gov.in / call 1930.")

## 6. API contract (freeze at 12:20)

| Method | Path | Body → Response |
|---|---|---|
| POST | `/api/analyze/sms` | `{sender?, content}` → `Verdict` |
| POST | `/api/analyze/email` | `{raw?}` (full .eml text) or `{from?, subject?, body}` → `Verdict` |
| POST | `/api/analyze/email/upload` | multipart `.eml` file → `Verdict` |
| POST | `/api/check-url` | `{url}` → `Verdict` |
| POST | `/api/deep-audit` | `{scan_id}` → `{summary, indicators[]}` (P3) |
| GET | `/api/scans?limit=50&channel=` | → `Verdict[]` |
| GET | `/api/stats` | → `{total, by_verdict, by_category, by_channel, avg_latency_ms}` |

```json
Verdict = {
  "scan_id": "uuid", "channel": "sms|email|url",
  "verdict": "SCAM|SUSPICIOUS|SAFE", "risk": 0.91,
  "category": "kyc_freeze", "trigger": "urgency", "severity": 2.7,
  "reasons": ["...plain-language bullets..."], "action": "Do not click ...",
  "urls": [{"url": "...", "risk": 0.88, "flags": ["lookalike:sbi"]}],
  "signals": {"tier0": {"rules": 0.8, "local": 0.86, "header_flags": ["spf_fail"]},
              "jev": {"is_scam": 0.97, "category_conf": 0.9}},
  "mode": "online|offline", "latency_ms": {"tier0": 4, "jev": 162, "total": 170}
}
```

## 7. Data & models

- SMS: UCI SMS Spam Collection + hand-written Indian scam SMS (KYC, UPI collect, job, courier, electricity bill) incl. Hinglish.
- Email: a public phishing email corpus (e.g. Kaggle phishing-email dataset) + Enron/ham samples.
- URL: a public phishing URL dataset (PhishTank/Kaggle malicious URLs) → char n-gram model + heuristics.
- Train each with `CalibratedClassifierCV`; save precision/recall/F1 + confusion matrix to `metrics.json` → shown on dashboard.

## 8. Repo layout

```text
backend/   main.py, parsers/{sms,email,url}.py,
           tier0/{url_features,email_headers,text_rules,local_models}.py,
           jev_client.py, fusion.py, explain.py, db.py, train_local.py, data/, models/
frontend/  React+Vite+Tailwind: pages Analyze (SMS | Email | URL tabs), Dashboard
extension/ manifest.json, popup.html/js, background.js, (P2) gmail_content.js
demo/      sample_sms.json, sample_emails/*.eml, sample_urls.txt
```

## 9. Team & timeline

| Time | A — Backend + Jev | B — Tier 0 + ML | C — Frontend | D — Extension + Data |
|---|---|---|---|---|
| 12:00–12:20 | All: freeze contract, repo, TypeSafe API key, download datasets |||
| 12:20–13:30 | FastAPI skeleton, parsers, jev_client, fusion | url_features, text_rules | Analyze page (3 tabs) on mock JSON | MV3 popup → /api/check-url; demo SMS set |
| 13:30–14:30 | explain.py, SQLite, /scans /stats | train sms + url models, metrics | wire to real API, verdict card | demo .eml files (phish + legit), sample URLs |
| **14:30** | **Checkpoint: SMS + URL → verdict + reasons in UI** |||
| 15:00–16:15 | email parser + /analyze/email(+upload) | email_headers.py, email model | .eml upload, URL breakdown table, Dashboard | badge on tab change; Gmail scan button (P2) |
| 16:15–17:15 | deep-audit (P3), offline fallback test | threshold tuning on demo set | polish, latency display, metrics panel | end-to-end tests on all samples |
| 17:15–18:00 | **Feature freeze. Rehearse demo ×2, record backup video, slides** |||

## 10. Demo script (3 min)

1. SMS: KYC-freeze scam → SCAM in ~170 ms with reasons; legit bank OTP alert → SAFE.
2. Email: upload spoofed "HDFC" `.eml` → SPF/DKIM fail, Reply-To mismatch, hidden link → SCAM.
3. URL: extension on a lookalike domain → red badge + reasons.
4. Dashboard: counts by channel/category, model precision/recall.
5. Pull Wi-Fi → still works in offline mode (Tier 0).
6. Closing slide: Phase 2 roadmap (Android SMS app, Call Shield) reusing the same API.

## 11. Phase 2 — deferred

- **Android SMS app** (Kotlin): `BroadcastReceiver` for `SMS_RECEIVED` (or notification listener) → `POST /api/analyze/sms` → warning notification + overlay; offline fallback with on-device TF-Lite version of the SMS model.
- **Call Shield**: call audio → STT (Deepgram streaming) → rolling transcript segments → Jev → live risk meter; parallel audio anti-spoofing model for deepfake voice. Jev is text-only, so STT is mandatory.
- Both reuse `Verdict`, fusion, explainer and dashboard unchanged.
