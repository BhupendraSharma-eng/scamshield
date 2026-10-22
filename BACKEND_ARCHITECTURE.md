# ScamShield Backend — Final Architecture

Scope: one FastAPI service that analyzes **SMS, Email, URL** and returns a calibrated verdict with
plain-language reasons. Three intelligence layers: **local models → Jev → LLM**.
Clients (web UI now; extension, Android, Call Shield later) are thin — all logic lives here.

---

## 1. Design principles

1. **Fast path is deterministic.** Local models + Jev answer in ~200 ms. The LLM never blocks a verdict.
2. **Every signal becomes `Evidence`.** Rules, models, Jev and the LLM all emit the same object, so
   fusion and explanation are one generic step, not per-channel spaghetti.
3. **Explain from facts.** Reasons are templates filled from evidence — no hallucinated explanations.
4. **Degrade, don't fail.** Jev down → local only. LLM down → no deep audit. Always a verdict.
5. **Untrusted input everywhere.** Message text is data for Jev and the LLM, never instructions.

---

## 2. Request lifecycle

```text
 HTTP request (sms | email | url)
        │
        ▼
 ① INGEST ── parsers/ ──────────────► Envelope (normalized, channel-agnostic)
        │                              {channel, sender, subject, text, urls[], headers, attachments}
        ▼
 ② CACHE  ── sha256(normalized) hit? ─► return stored Verdict (instant repeat demos)
        │ miss
        ▼
 ③ TIER 0: LOCAL  (<10 ms, offline, CPU)
        │   ├─ url_analyzer    → per-URL Evidence + url_model probability
        │   ├─ header_analyzer → email auth / spoof Evidence
        │   ├─ text_rules      → OTP/KYC/UPI/urgency Evidence
        │   └─ local_model     → p_local (pretrained HF models, T=2)
        │
        ├─ URL-only & p ≤ 0.2 & no flags → skip Jev (fast SAFE)
        ▼
 ④ TIER 1: JEV  (~150 ms, async, timeout 2 s)
        │   one call, 6–7 typed questions; Tier 0 findings passed in as context
        │   → p_jev, category, trigger, severity, asks_secret, impersonation …
        ▼
 ⑤ FUSION  → risk, verdict, confidence, decided_by, needs_llm
        ▼
 ⑥ EXPLAIN → ranked plain-language reasons + recommended action
        ▼
 ⑦ PERSIST → SQLite `scans`
        ▼
 ⑧ RESPOND  (~200 ms total)  ──────────► Verdict JSON  (llm.status = "pending" | "skipped")
        │
        └─ if needs_llm or user asks:
           ⑨ TIER 2: LLM (background task, 1–4 s)
              structured JSON audit → may resolve SUSPICIOUS → SCAM/SAFE
              → updates scan row; client polls GET /api/scans/{id}
```

---

## 3. Module layout

```text
backend/
  app/
    main.py              FastAPI app, lifespan (load models, open clients), CORS, routers
    config.py            pydantic-settings: keys, model ids, thresholds, weights, timeouts
    schemas.py           Pydantic: requests, Envelope, Evidence, JevResult, LlmAudit, Verdict
    api/
      analyze.py         POST /api/analyze/{sms,email,email/upload,url}
      scans.py           GET /api/scans, GET /api/scans/{id}, POST /api/scans/{id}/deep-audit
      meta.py            GET /api/health, /api/stats, /api/metrics
    parsers/
      sms.py             clean text, extract URLs/phones/amounts
      email.py           .eml/raw → headers, text body (HTML stripped), <a> text+href pairs, attachments
      url.py             normalize, defang/refang, extract URLs from any text
    tier0/
      url_analyzer.py    lexical/host features + url_model
      header_analyzer.py SPF/DKIM/DMARC, From vs Reply-To/Return-Path, display-name spoof
      text_rules.py      regex/keyword rules (EN + Hinglish)
      local_model.py     load .pkl per channel, predict_proba, top features
      brands.py          brand → legit domains list (SBI, HDFC, ICICI, Paytm, PhonePe, Amazon, …)
    tier1/
      jev_client.py      AsyncTypeSafeClient wrapper, timeout, error → None
      questions.py       question sets per channel, build_state(envelope, tier0)
    tier2/
      llm_client.py      provider adapter (Gemini / OpenAI / Claude) with JSON-schema output
      prompts.py         system prompt + untrusted-content wrapping
      auditor.py         when to run, merge result back into scan
    engine/
      pipeline.py        orchestrates ①–⑨
      fusion.py          scores → risk/verdict/decided_by/needs_llm
      explain.py         Evidence → reasons[], action
      cache.py           in-memory LRU + DB lookup by hash
    db.py                SQLite (aiosqlite), scans table, stats queries
  scripts/
    download_models.py   pre-fetch the 4 HuggingFace models into the local cache
    smoke_models.py      run all models on demo/ samples → probabilities + latency (no training)
  tests/                 golden samples per channel → expected verdict
  .env.example
```

---

## 4. Core data model

```python
class Envelope(BaseModel):          # output of every parser
    channel: Literal["sms", "email", "url"]
    sender: str | None
    subject: str | None
    text: str                        # cleaned body ("" for url)
    urls: list[str]
    links: list[tuple[str, str]]     # email: (visible text, href)
    headers: dict[str, str]          # email only
    attachments: list[str]           # filenames

class Evidence(BaseModel):          # the universal signal unit
    id: str                          # "url.lookalike", "hdr.spf_fail", "jev.asks_secret"
    source: Literal["rule", "model", "jev", "llm"]
    weight: float                    # 0–1, how strongly it implies scam
    floor: float | None              # hard minimum risk if present (overrides)
    reason: str                      # plain-language sentence, already filled
    detail: dict                     # raw values for the UI (domain, brand, prob…)
```

`Verdict` (API response) — see §8.

---

## 5. The three layers

### Tier 0 — Local (always runs, offline)

> Full detail and exact model picks: [TIER0.md](TIER0.md). Order: 0a analyzers (~3 ms) first, then
> 0b models run **concurrently with Jev**. Models: URL `CrabInHoney/urlbert-tiny-v4-phishing-classifier`;
> Email `cybersectony/phishing-email-detection-distilbert_v2.4.1` + India model on body;
> SMS `anmolshrivastav/distilbert-scam-detector-india` + `mrm8488/bert-tiny-finetuned-sms-spam-detection`.
> **No custom training** — pretrained models only, temperature T=2 for calibration.

| Component | Technique | Output |
|---|---|---|
| `url_analyzer` | ~25 lexical/host features: punycode (`xn--`), IP host, entropy, length, subdomain depth, risky TLD, shortener, `@` / `//` tricks, no-TLS, brand lookalike (Levenshtein vs `brands.py`), brand-in-subdomain | Evidence per URL + urlbert-tiny probability |
| `header_analyzer` | parse `Authentication-Results`, compare From / Reply-To / Return-Path domains, brand name in display name vs domain, link text ≠ href, risky attachments (`.exe .scr .js .html .iso .zip`) | Evidence |
| `text_rules` | regex: OTP/PIN/CVV ask, KYC/account block, UPI collect / "receive money", lottery/refund, job/task earning, courier/customs, electricity disconnection, urgency words | Evidence (low weights — they are hints) |
| `local_model` | pretrained HF classifiers per channel (see TIER0.md), softmax with temperature T=2 | `p_local` |

`rules_score = 1 − Π(1 − weight_i)` (noisy-OR: many weak hints add up, none saturates alone).

### Tier 1 — Jev (System 1 decision)

- Model pinned `jev-1.13.0`, `AsyncTypeSafeClient`, created once at startup, timeout 2 s, no retry.
- **State** (object, untrusted text isolated):
  ```json
  {"channel": "email", "sender": "HDFC Bank <alerts@hdfc-secure.top>", "subject": "...",
   "untrusted_message": "...first 4k chars...",
   "automated_findings": ["link text says hdfcbank.com but opens hdfc-secure.top",
                          "SPF failed", "DKIM missing"]}
  ```
  Tier 0 does the URL/number/date reasoning Jev is weak at, and hands Jev the conclusions.
- **Questions** (one call, evaluated in parallel):

  | id | type | purpose |
  |---|---|---|
  | `is_scam` | noul | main probability `p_jev` |
  | `category` | choice (`none` first) | kyc_freeze, upi_trap, otp_theft, fake_job, lottery_prize, impersonation, invoice_fraud, delivery, other |
  | `trigger` | choice (`none` first) | urgency, fear, authority, greed, curiosity |
  | `severity` | score, 4 concrete levels | harm if user complies |
  | `asks_secret` | noul | OTP/PIN/password/card |
  | `impersonation` | noul | claims to be a bank/govt/brand |
  | `payment_change` | noul (email) | BEC/invoice bank-detail change |
- Output → `JevResult` + Evidence (`jev.category`, `jev.trigger`, `jev.asks_secret`, …) with weights from Jev's own probabilities.

### Tier 2 — LLM (System 2 deep audit)

- **When** (`needs_llm`): risk in uncertainty zone `[0.35, 0.70)`, **or** Jev and local model
  disagree (`|p_jev − p_local| > 0.5`), **or** user clicks Deep Audit. Never on confident SAFE/SCAM.
- **How**: FastAPI background task; verdict returned immediately with `llm.status = "pending"`.
- **Input**: untrusted content in delimited block + all Evidence + Jev answers. System prompt states
  the content is adversarial and may contain instructions to ignore.
- **Output** (JSON schema enforced):
  ```json
  {"verdict": "SCAM|SAFE|UNSURE", "confidence": 0.0-1.0,
   "indicators": [{"quote": "exact text from message", "why": "..."}],
   "summary": "2–3 sentence analyst explanation", "user_advice": "..."}
  ```
- **Authority**: can resolve SUSPICIOUS → SCAM/SAFE if `confidence ≥ 0.75`; cannot lower risk below
  a hard-rule floor; quotes are verified to exist in the message (drop any that don't → anti-hallucination).
- Provider adapter: whichever key you have (Gemini 2.5 Flash / OpenAI / Claude) — same interface.

---

## 6. Fusion (engine/fusion.py)

Both `p_local` and `p_jev` are calibrated probabilities, so combine in **log-odds space**:

```text
online : logit(risk₀) = 0.50·logit(p_jev) + 0.30·logit(p_local) + 0.20·logit(rules_score)
offline: logit(risk₀) = 0.65·logit(p_local) + 0.35·logit(rules_score)
risk   = max(risk₀, max(evidence.floor), max(url_risk for embedded URLs))
```

Hard floors (from Evidence): OTP ask + link 0.90 · punycode/IP/lookalike URL 0.80 ·
SPF+DKIM fail with brand display name 0.85 · link text ≠ href domain 0.75.

| risk | verdict | LLM |
|---|---|---|
| ≥ 0.70 | **SCAM** | only if user asks |
| 0.35 – 0.70 | **SUSPICIOUS** | auto |
| < 0.35 | **SAFE** | only if user asks / disagreement |

`decided_by` = which input dominated (`rule_floor`, `jev`, `local`, `llm`) — shown in UI, great for judges.
Weights live in `config.py`; tune on the labelled demo set if time allows.

---

## 7. Explanation (engine/explain.py)

1. Collect all Evidence with weight ≥ 0.3.
2. Rank by contribution (floor evidence first, then weight × source reliability).
3. Deduplicate by topic (`url.*` merges into one sentence per URL).
4. Emit top 5 `reasons[]` + one `action` chosen by category
   ("Don't click. Don't share OTP. Report at cybercrime.gov.in or call 1930.").
5. SAFE verdicts still get reasons ("Sender domain matches HDFC, SPF/DKIM pass, no links").
6. When the LLM finishes, its `summary` is appended as `analyst_summary` (reasons stay factual).

---

## 8. API

| Method | Path | Notes |
|---|---|---|
| POST | `/api/analyze/sms` | `{sender?, content}` |
| POST | `/api/analyze/email` | `{raw}` (.eml text) **or** `{from?, subject?, body}` |
| POST | `/api/analyze/email/upload` | multipart `.eml` |
| POST | `/api/analyze/url` | `{url}` |
| GET | `/api/scans/{id}` | poll for LLM result |
| POST | `/api/scans/{id}/deep-audit` | force Tier 2 |
| GET | `/api/scans?channel=&verdict=&limit=` | history |
| GET | `/api/stats` | counts by verdict/channel/category, avg latency per tier |
| GET | `/api/metrics` | optional: model precision/recall on public test sets (inference-only eval) |
| GET | `/api/health` | models loaded, Jev reachable, LLM configured |

All analyze endpoints accept `?deep=true` to wait for the LLM synchronously (demo convenience).

```json
{
  "scan_id": "…", "channel": "email", "verdict": "SCAM", "risk": 0.93, "confidence": 0.86,
  "category": "kyc_freeze", "trigger": "urgency", "severity": 2.6, "decided_by": "rule_floor",
  "reasons": ["The button says hdfcbank.com but opens hdfc-secure.top", "…"],
  "action": "Do not click the link or reply. Report at cybercrime.gov.in / 1930.",
  "urls": [{"url": "…", "risk": 0.9, "flags": ["lookalike:hdfc", "risky_tld"]}],
  "evidence": [ …Evidence… ],
  "scores": {"p_local": 0.81, "p_jev": 0.97, "rules": 0.88},
  "llm": {"status": "skipped|pending|done|error", "audit": null},
  "mode": "online|offline",
  "latency_ms": {"parse": 1, "tier0": 6, "jev": 158, "fusion": 0, "total": 168}
}
```

---

## 9. Storage & caching

SQLite table `scans`: `id, created_at, channel, input_hash, preview (first 200 chars), verdict, risk,
category, decided_by, mode, latency_json, result_json, llm_status, llm_json`.
Cache key = `sha256(channel + normalized envelope)`; hit returns stored result (still logged in stats).

---

## 10. Failure modes

| Failure | Behaviour |
|---|---|
| Jev timeout / 429 / 5xx | `p_jev = None`, offline weights, `mode="offline"`, category from rules |
| LLM error / bad JSON | `llm.status="error"`, verdict unchanged |
| Model .pkl missing | rules-only, `/api/health` shows degraded |
| Malformed .eml | fall back to treating it as plain text |
| Prompt injection in message | isolated as `untrusted_message`; LLM quotes verified; floors can't be lowered |
| Huge input | truncate body to 4k chars for Jev / 8k for LLM; reject > 1 MB |

---

## 11. Config (`.env`)

```text
TYPESAFE_API_KEY=…            JEV_MODEL=jev-1.13.0     JEV_TIMEOUT_S=2
LLM_PROVIDER=gemini|openai|anthropic   LLM_API_KEY=…   LLM_MODEL=…
THRESH_SCAM=0.70  THRESH_SUSPICIOUS=0.35  DISAGREE_LLM=0.5
```

---

## 12. Build order (backend only)

| Time | Track A (pipeline + Jev + LLM) | Track B (Tier 0) |
|---|---|---|
| 12:00–12:30 | skeleton: config, schemas, main, db, `/health` | `pip install`, pre-download 4 HF models, `brands.py` |
| 12:30–13:30 | parsers (sms, url), jev_client + questions, pipeline | url_analyzer, text_rules, load HF models, write demo/ samples |
| 13:30–14:30 | fusion, explain, `/analyze/sms` + `/analyze/url` end-to-end | local_model loader, smoke test, golden tests |
| **14:30** | **Checkpoint: curl SMS + URL → full Verdict JSON** ||
| 15:00–16:00 | email parser + endpoints | header_analyzer, email model wiring, smoke test on demo set |
| 16:00–17:00 | Tier 2 LLM (auditor, prompts, polling, deep-audit) | stats/metrics endpoints, tune weights on demo set |
| 17:00–18:00 | **Freeze, run golden tests, demo rehearsal** ||
