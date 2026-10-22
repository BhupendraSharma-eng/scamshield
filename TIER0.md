# Tier 0 — Local Intelligence Layer (detailed design)

Tier 0 runs entirely on our machine: no network, no API keys, no per-request cost.
It has two halves with different jobs:

| Half | What | Latency | Why it exists |
|---|---|---|---|
| **0a — Deterministic analyzers** | hand-written feature extractors + rules | < 5 ms | Exact facts Jev/LLMs are bad at: domains, punycode, edit distance, SPF/DKIM, link mismatch. Feeds Jev as `automated_findings`. Produces hard floors. |
| **0b — Local ML models** | pretrained HuggingFace transformers only (**no custom training**) | 5–60 ms | A learned probability per channel that works offline and gives Jev a second opinion to agree/disagree with. |

Execution order inside the pipeline:

```text
Envelope ──► 0a analyzers (≈3 ms) ──┬──► 0b models (in thread pool) ──┐
                                    │                                 ├──► fusion
                                    └──► Jev (needs 0a findings) ─────┘
```

0a must finish first because its findings go into Jev's state. 0b and Jev then run **concurrently**, so
0b's cost is hidden behind Jev's ~150 ms — we can afford a DistilBERT for email at no wall-clock cost.

---

## 1. Model selection (from a HuggingFace Hub scan, Oct 2026)

### Chosen

| Channel | Model | Size | Labels | Reported metrics | Role |
|---|---|---|---|---|---|
| **URL** | [`CrabInHoney/urlbert-tiny-v4-phishing-classifier`](https://huggingface.co/CrabInHoney/urlbert-tiny-v4-phishing-classifier) | 3.7M params, 15 MB | `LABEL_0`=good, `LABEL_1`=phish | Acc 0.991, P 0.994, R 0.986 (on `ealvaradob/phishing-dataset` urls) | Primary URL model. URL-specific tokenizer, max 64 tokens, ~2–5 ms CPU. Apache-2.0. |
| **Email** | [`cybersectony/phishing-email-detection-distilbert_v2.4.1`](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1) | 67M params, 268 MB | 0 legitimate_email, 1 phishing_url, 2 legitimate_url, 3 phishing_url_alt | Acc 99.6 % (own test split) | Primary email model. Most-downloaded phishing model on the Hub (~296k). `p_phish = P1 + P3`. Max 512 tokens, ~30–60 ms CPU. Apache-2.0. ONNX copy exists (`onnx-community/...-ONNX`). |
| **SMS** | [`anmolshrivastav/distilbert-scam-detector-india`](https://huggingface.co/anmolshrivastav/distilbert-scam-detector-india) | 67M params; **INT8 ONNX 67 MB** (`onnx/model.onnx`) | 0 ham, 1 spam | Acc 0.997, F1 0.996 (own split) | Primary SMS model. Fine-tuned on Indian SMS (`scam-hum-india`) + synthetic Aadhaar/KYC, UPI/bank, lottery, fake-job, OTP-theft examples. Apache-2.0. Use the quantized ONNX: ~5–15 ms CPU. Low downloads/new (Sep 2026) → validate on our demo set. |
| **SMS (2nd)** | [`mrm8488/bert-tiny-finetuned-sms-spam-detection`](https://huggingface.co/mrm8488/bert-tiny-finetuned-sms-spam-detection) | 4.4M params, 17 MB | 0 ham, 1 spam | Val acc 0.98 (UCI sms_spam) | Secondary vote for generic/global spam. ~1–3 ms. Weighted low. |
| **Email (2nd)** | same India model as SMS, run on email body | already loaded | — | — | Catches India-flavoured email scams (KYC/UPI/job) the global email model misses. Zero extra memory. |

> "Suspicious phrases" in explanations now come from the exact text spans matched by 0a regex rules
> (`match.group(0)`), not from model coefficients.

### Considered and rejected

| Model | Why not |
|---|---|
| `ealvaradob/bert-finetuned-phishing` | Covers URL+email+SMS in one, but BERT-large: 336M params, 1.3 GB, ~300–800 ms on CPU. Too slow/heavy. |
| `CrabInHoney/urlbert-tiny-v5` | Multi-head custom format, not a standard `ForSequenceClassification` — integration risk. |
| `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier` | 4-class (benign/phishing/malware/defacement); good optional add-on, but phishing F1 (0.973) lower than the binary phishing model. Stretch only. |
| `r3ddkahili/final-complete-malicious-url-model`, `kmack/malicious-url-detection` | 438 MB / 268 MB full BERT for URLs — overkill vs 15 MB urlbert. |
| `mariagrandury/roberta-base-...-sms-spam`, `dima806/phishing-email-detection` | 0.5–1 GB, same training data as smaller picks, no gain. |
| `VynoDePal/sentra-sms-fraud-detector` | Multilingual DistilBERT (541 MB) tuned for West-African mobile-money SMS; India model is a closer fit. Backup if India model disappoints. |
| `tanaos/tanaos-spam-detection-v1` | 541 MB, trained only on synthetic data, generic "spam" incl. ads → would flag legit promos. |
| Our own TF-IDF/LR models | Dropped to save ~1 h (data curation + training + eval code). Revisit only if pretrained models fail on Indian demo set. |
| Llama/Qwen phishing GGUFs | Generative, slow; that's what Tier 2 is for. |

### Important caveats (say this to judges — it shows maturity)

- All Hub metrics are **in-distribution** (tested on their own data). Only the India SMS model saw
  Indian scam patterns, and none handle Hinglish well. That's why 0a rules (with Hinglish regexes) and
  Jev sit alongside the models.
- Transformer softmax outputs are **overconfident** (0.999 everywhere). We calibrate them (§4) before fusion.
- `cybersectony` labels mix emails and URLs; we only feed it email bodies and only read P1+P3.

---

## 2. Tier 0a — Deterministic analyzers

Each check emits `Evidence(id, weight, floor, reason, detail)`. `weight` = how strongly it suggests scam
(0–1); `floor` = minimum final risk if present. Starting values below; tune on the demo set.

### 2.1 URL analyzer (`tier0/url_analyzer.py`)

Parse with `urllib.parse` + `tldextract` (registered domain, subdomain, suffix) + `idna`.

| id | Check | weight | floor | Reason template |
|---|---|---|---|---|
| `url.punycode` | host contains `xn--` or non-ASCII chars | 0.8 | 0.80 | "The address uses look-alike foreign characters (`{decoded}`) to imitate a real site." |
| `url.ip_host` | host is an IPv4/IPv6 literal | 0.7 | 0.80 | "The link points to a raw IP address instead of a company website." |
| `url.lookalike` | registered domain within edit distance ≤ 2 of a brand domain (or digit/letter swaps `0↔o 1↔l rn↔m`), but not equal | 0.85 | 0.80 | "`{domain}` imitates **{brand}** but is not {brand}'s real domain ({legit})." |
| `url.brand_in_sub` | brand name in subdomain/path while registered domain isn't the brand's (`sbi.co.in.verify-kyc.xyz`) | 0.75 | 0.75 | "The link puts '{brand}' in front of an unrelated site (`{domain}`)." |
| `url.at_symbol` | `@` in authority part | 0.6 | 0.70 | "The link hides its real destination after an '@' sign." |
| `url.risky_tld` | suffix in {xyz, top, tk, ml, ga, cf, gq, click, buzz, rest, cam, icu, sbs, cfd, live, shop, online, site} | 0.35 | – | "The site uses a `.{tld}` domain, common in scams." |
| `url.shortener` | domain in {bit.ly, tinyurl.com, t.co, cutt.ly, is.gd, rb.gy, shorturl.at, goo.gl, ow.ly, tiny.cc} | 0.3 | – | "The link is shortened, hiding where it really goes." |
| `url.free_host` | domain in {sites.google.com, forms.gle, docs.google.com/forms, *.web.app, *.firebaseapp.com, *.netlify.app, *.vercel.app, *.github.io, *.blogspot.com, *.weebly.com, *.wixsite.com, *.ngrok*.app, *.trycloudflare.com} | 0.35 | – | "The page is hosted on a free website builder, often used for fake login pages." |
| `url.no_tls` | scheme `http://` | 0.2 | – | "The link is not secure (no HTTPS)." |
| `url.many_subdomains` | ≥ 4 subdomain labels | 0.3 | – | "The address has an unusually long chain of sub-domains." |
| `url.long` | length > 100 | 0.15 | – | — (supporting only, not shown) |
| `url.entropy` | Shannon entropy of host > 4.0 or digits ratio > 0.3 | 0.3 | – | "The address looks randomly generated." |
| `url.sensitive_words` | path/host contains login, verify, update, kyc, secure, account, wallet, refund, otp, bank, pay, reward, claim | 0.25 | – | "The link uses words like '{word}' to look official." |
| `url.apk` | path ends `.apk` / `.exe` / `.scr` | 0.8 | 0.85 | "The link downloads an app/program file — a common way to install malware." |
| `url.allowlisted` | registered domain exactly in brand legit list or top-sites allowlist | **−0.5** | – | "The link goes to the official `{domain}` site." (pushes SAFE) |

Brand registry `tier0/brands.py` (~40 entries): SBI, HDFC, ICICI, Axis, Kotak, PNB, BoB, Paytm, PhonePe,
Google Pay, BHIM/NPCI, Amazon, Flipkart, Myntra, Meesho, IRCTC, India Post, BlueDart, Delhivery, DHL,
FedEx, Income Tax (incometax.gov.in), UIDAI/Aadhaar, EPFO, Jio, Airtel, Vi, BSNL, electricity boards,
Netflix, Microsoft, Apple, Google, PayPal, WhatsApp, Instagram, Facebook, LinkedIn → legit domains + aliases.
Plus a top-1k allowlist (Tranco list, downloaded once) to stop false alarms on normal sites.

### 2.2 Email header analyzer (`tier0/header_analyzer.py`)

Parse with stdlib `email` (`policy.default`), HTML body with `BeautifulSoup`.

| id | Check | weight | floor | Reason template |
|---|---|---|---|---|
| `hdr.spf_fail` | `Authentication-Results` has `spf=fail\|softfail` | 0.5 | – | "The sending server isn't authorized to send for `{domain}` (SPF failed)." |
| `hdr.dkim_fail` | `dkim=fail\|none` | 0.4 | – | "The email's digital signature is missing or invalid (DKIM)." |
| `hdr.dmarc_fail` | `dmarc=fail` | 0.6 | – | "The email failed the sender domain's anti-spoofing policy (DMARC)." |
| `hdr.brand_spoof` | display name contains a brand but From domain isn't that brand's | 0.8 | 0.80 | "It's signed '{brand}' but comes from `{domain}`." |
| `hdr.brand_spoof_auth` | `brand_spoof` **and** SPF/DKIM fail | 0.9 | 0.85 | (merged with above) |
| `hdr.replyto_mismatch` | Reply-To registered domain ≠ From registered domain | 0.5 | – | "Your reply would go to `{replyto}`, not the sender's company." |
| `hdr.returnpath_mismatch` | Return-Path domain ≠ From domain | 0.25 | – | (supporting) |
| `hdr.freemail_brand` | brand display name + gmail/yahoo/outlook/proton sender | 0.75 | 0.75 | "A '{brand}' email sent from a free `{provider}` account." |
| `link.text_mismatch` | `<a>` visible text is a URL/domain different from href's domain | 0.8 | 0.75 | "The link says `{shown}` but actually opens `{real}`." |
| `att.risky` | attachment ext in {exe, scr, js, vbs, bat, iso, img, html, htm, lnk, apk, docm, xlsm} | 0.7 | 0.75 | "It has a risky attachment (`{name}`) that can run code or show a fake login page." |
| `att.double_ext` | `invoice.pdf.exe` pattern | 0.85 | 0.85 | "The attachment hides its real type (`{name}`)." |
| `hdr.auth_pass` | SPF, DKIM, DMARC all pass and From domain allowlisted | **−0.4** | – | "Sender `{domain}` passed all authenticity checks." |

Pasted bodies without headers: skip header checks, `detail.headers_available=false` (UI says "upload .eml for full checks").

### 2.3 Text rules (`tier0/text_rules.py`) — SMS + email body

Compiled case-insensitive regexes, English + common Hinglish/Hindi-in-Latin forms. These are **hints**
(low weight) except the secret-request combo.

| id | Pattern examples | weight | floor |
|---|---|---|---|
| `txt.asks_otp` | `share|send|tell|batao|bhejo .{0,20} (otp|pin|cvv|password|mpin)` | 0.6 | – |
| `txt.otp_plus_link` | `asks_otp` and message contains URL or phone number | 0.9 | 0.90 |
| `txt.kyc` | `kyc (update|expired|pending|suspend)`, `pan (link|update)`, `aadhaar (link|update)` | 0.45 | – |
| `txt.account_block` | `account (will be )?(blocked|suspended|freeze|closed)`, `khata band` | 0.45 | – |
| `txt.upi_collect` | `(receive|collect|refund) .{0,20} (enter|scan|upi pin)`, "scan QR to receive" | 0.7 | 0.75 |
| `txt.lottery` | `(won|winner|lottery|lucky draw|prize|cashback of rs)` | 0.45 | – |
| `txt.job_task` | `(part.?time|work from home|daily (earn|income)|like (videos|youtube)|task) .{0,30} (rs|₹|\d{3,})` | 0.5 | – |
| `txt.electricity` | `electricity .{0,30} (disconnect|cut) .{0,30} (tonight|today|9:30)` | 0.65 | 0.70 |
| `txt.courier` | `(parcel|courier|package) .{0,30} (held|customs|address incomplete|re-?delivery fee)` | 0.45 | – |
| `txt.digital_arrest` | `(cbi|police|customs|narcotics|ed|trai) .{0,40} (arrest|case|warrant|video call)` | 0.7 | 0.75 |
| `txt.urgency` | `(within|in) \d+ (hours|hrs|minutes)`, `immediately`, `last chance`, `turant`, `abhi` | 0.25 | – |
| `txt.money_amount` | `(rs\.?|₹|inr) ?\d[\d,]*` | 0.1 | – |
| `txt.phone_call_to_action` | `call (now|immediately|on) \+?\d{10,}` | 0.3 | – |
| `txt.apk` | `download .{0,20} (apk|app) .{0,30} (link|http)` | 0.6 | 0.70 |

Rule score (noisy-OR, negative weights subtract):
`rules = clip( 1 − Π(1 − wᵢ⁺)  − Σ|wⱼ⁻|·0.5 , 0, 1 )`

---

## 3. Tier 0b — No training: validate instead (`scripts/smoke_models.py`)

We only run inference. The one thing we still do is a **15-minute sanity check** (no training):

1. Write ~30 test messages in `demo/` before 13:30: 10 Indian scam SMS, 10 legit Indian SMS
   (bank OTP alerts, UPI receipts, delivery updates), 5 phishing + 5 legit emails, 15 phishing + 15 legit URLs.
   These double as the demo script and as golden tests.
2. Run every model on them, print probabilities + latency.
3. If a model is clearly wrong on legit messages (false alarms), lower its weight in `config.py`.
   If the India SMS model is unusable, swap to `VynoDePal/sentra-sms-fraud-detector` (same interface).

Optional (only if ahead of schedule): run the models on public test sets
(`ucirvine/sms_spam`, `zefang-liu/phishing-email-dataset`, `ealvaradob/phishing-dataset` urls) →
`models/metrics.json` → `/api/metrics`. This is inference only, ~10 min of code.

---

## 4. Calibration of HuggingFace models (no fitting)

Transformer softmax ≈ 0.999 for almost everything → would dominate fusion. Fix with fixed
**temperature scaling**: `p = softmax(logits / T)` with `T = 2.0` for every model (set in `config.py`).
This softens 0.999 → ~0.97 and 0.9 → ~0.75 without any training. Tune `T` by eye on the demo set if needed.

---

## 5. Combining inside Tier 0 → `p_local`

Per channel, average in log-odds space (same math as main fusion):

| Channel | Formula |
|---|---|
| URL | `logit(p_local) = 0.7·logit(urlbert) + 0.3·logit(rules_url)` |
| SMS | `logit(p_local) = 0.7·logit(india_sms) + 0.3·logit(bert_tiny)` |
| Email | `logit(p_local) = 0.65·logit(cybersectony) + 0.35·logit(india_sms on body)`; then each embedded URL scored as URL channel, `p_local = max(p_local, 0.8·max_url_risk)` |

All probabilities clipped to [0.01, 0.99] before logit. `rules` and floors are passed separately to the main fusion (BACKEND_ARCHITECTURE.md §6).

---

## 6. Runtime & engineering details

- **Loading**: all models loaded once in FastAPI `lifespan`; `torch.set_num_threads(4)`; `model.eval()`;
  `torch.inference_mode()`. Warm-up inference at startup (first call is slow).
- **India SMS model via ONNX**: `optimum.onnxruntime.ORTModelForSequenceClassification.from_pretrained(..., subfolder="onnx")`
  (INT8, 67 MB). If `optimum` gives trouble, load the regular safetensors with `transformers` — same labels.
- **Threading**: `await asyncio.to_thread(run_models, envelope)` so the event loop keeps serving while Jev is in flight.
- **Input prep**: URL model gets `host + path` without scheme (matches its training style), truncated to 64 tokens.
  Email model gets `subject + "\n" + body_text` truncated to 512 tokens. SMS models get raw text.
- **Pre-download** (do this now, while Wi-Fi is good):
  ```bash
  huggingface-cli download CrabInHoney/urlbert-tiny-v4-phishing-classifier
  huggingface-cli download cybersectony/phishing-email-detection-distilbert_v2.4.1
  huggingface-cli download anmolshrivastav/distilbert-scam-detector-india
  huggingface-cli download mrm8488/bert-tiny-finetuned-sms-spam-detection
  ```
  Cached in `~/.cache/huggingface`; set `HF_HUB_OFFLINE=1` at runtime. Total ≈ 370 MB.
- **Dependencies**: `torch` (CPU), `transformers`, `optimum[onnxruntime]`, `tldextract`, `rapidfuzz`,
  `idna`, `beautifulsoup4`. No scikit-learn / datasets / pandas needed.
- **Fallback**: if any model fails to load, its weight is redistributed; `/api/health` reports `degraded`.

### Expected latency (CPU, laptop; estimates — measure at startup and expose in `/api/health`)

| Step | ms |
|---|---|
| 0a analyzers (all) | 1–5 |
| urlbert-tiny per URL | 2–5 |
| bert-tiny SMS | 1–3 |
| India DistilBERT INT8 ONNX (SMS) | 5–15 |
| cybersectony DistilBERT email (512 tok) | 30–60 |
| **Tier 0 total** | **SMS ≈ 20, URL ≈ 10, Email ≈ 80** — all hidden behind Jev's ~150 ms |

---

## 7. Known blind spots (and who covers them)

| Blind spot | Covered by |
|---|---|
| Brand-new scam domain with clean-looking name (`kyc-support-centre.in`) | Jev (meaning), sensitive-word + new-TLD rules, LLM |
| Legit message with scary words ("your account is blocked due to 3 wrong PIN attempts" from real bank) | allowlisted sender/URL negative evidence, Jev, LLM on disagreement |
| Hinglish / Hindi text | Hinglish regexes, Jev (lower accuracy), LLM |
| Compromised legit domain hosting phishing | not solvable offline — Jev/LLM on content; Phase 2: Google Safe Browsing lookup |
| Image-only emails | out of scope (Phase 2: OCR) |
