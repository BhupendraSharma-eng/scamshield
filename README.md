# ScamShield — AI phishing & scam detection (SMS · Email · URL)

CodeX (E-Cell League 2026) · Smart Cybersecurity · Statement 5.

ScamShield flags phishing and scam messages in real time and explains **why** in plain language.

## How it works

Three tiers, fused in log-odds space ([BACKEND_ARCHITECTURE.md](BACKEND_ARCHITECTURE.md)):

| Tier | What | Latency |
|---|---|---|
| 0 — Local | URL / email-header / text rules + pretrained HuggingFace models ([TIER0.md](TIER0.md)) | < 30 ms, works offline |
| 1 — Decision model | OpenAI Decisions API (`gpt-6-luna`) typed answers: scam?, category, pressure tactic, severity | ~150–400 ms |
| 2 — AI analyst | On-demand LLM audit with verified quotes, for uncertain cases | 3–5 s, async |

Results on the bundled Kaggle sets: 100% of 400 scam SMS/emails and 100 fraud URLs detected; no
"legitimate" URL marked SCAM. See `backend/scripts/eval_*.py`.

## Run locally

```bash
# backend (Python 3.12)
cd backend
uv venv --python 3.12 .venv && VIRTUAL_ENV=.venv uv pip install -r requirements.txt
python3 scripts/download_models.py          # ~615 MB of HuggingFace models → backend/models/
cp .env.example .env                        # add OPENAI_API_KEY (optional: runs offline without it)

# frontend
cd ../frontend && bun install && bun run build

# one server for API + UI
cd ../backend && .venv/bin/uvicorn app.main:app --port 8000   # open http://localhost:8000
```

## Hosted UI (GitHub Pages)

The frontend is deployed to GitHub Pages by `.github/workflows/pages.yml`. The models and AI run in
the backend, so the hosted UI talks to a backend you run, exposed with ngrok:

```bash
ngrok http 8000 --url https://dandruff-sneer-almanac.ngrok-free.dev
```

That static ngrok domain is the hosted UI's default backend.
Tap the status indicator (top bar) → **Server settings** to point it at another backend
(LAN IP or an HTTPS tunnel). Chrome may ask to allow local-network access the first time.

## Tests

```bash
cd backend && PYTHONPATH=. .venv/bin/python -m pytest tests -q
```


## Demo rehearsal (about 3 minutes)

1. Open the dashboard and confirm the server indicator is online. In **Scan**, try an
   SMS asking the recipient to share an OTP and open a verification link. Show the verdict,
   the quoted warning signs, and the recommended action. Use **Deep Audit** to explain an
   uncertain result; it requires a configured AI provider.
2. Scan `http://sbi-kyc-update.xyz/login` to show a phishing URL warning. Then scan
   `https://rntu.ac.in/` and `https://bssserp.com/login/mis` to demonstrate that an academic
   domain or login path alone does not justify a SCAM verdict. SUSPICIOUS means further
   checking is needed; SAFE is a risk estimate, not a guarantee about page content.
3. In Chrome for Testing with the unpacked extension loaded, hover over a phishing link on
   a local test page. Show the tooltip, then click the link to show the confirmation dialog.
   A direct visit to a known phishing URL should show the block page. Relaunch Chrome after
   editing the extension so the content scripts use the current files.
4. Open **Call Shield** and select **Play scam call (AI voice)**. Let the clip play until
   the full-screen alert appears, then show the transcript, risk timeline, and voice score.
   Voice scores are model estimates. A recorded demo does not validate live microphone
   performance; rehearse that separately with a human speaker and microphone permission.
5. Finish with scan history and explain the fallback: local rules and downloaded models
   continue working when the decision provider is unavailable. An unavailable backend is
   different: browser and phone clients need the API server to analyze new content.

Before presenting, keep the backend and tunnel running, check the hosted UI's server setting,
and confirm the Android permissions on the demonstration phone. Dataset evaluation measures
SCAM **or SUSPICIOUS** as detection and is a check on the bundled samples, not a guarantee
of performance on new messages.


Offline dataset check on 22 October 2026: all 400 scam SMS/emails and all 100 fraud URLs
were detected as SCAM. Of 100 labelled legitimate URLs, 66 were SAFE, 34 were SUSPICIOUS,
and none were SCAM. The remaining caution flags are false alarms on that labelled set.


## Portal and live-audio latency fix

The exact HTTPS BSSS MIS login URL is verified against the college's official app privacy
policy. Its reassuring signal applies only to that host/path without redirect queries,
credentials or nonstandard ports. URL cache policy is now `url-v3`; extension cache
entries from older policies are discarded on the next check.

Live audio captures three-second WAV chunks. Two `/transcribe` preparations run concurrently,
then `/chunk` receives the prepared text and audio for analysis in capture order. Every queued
chunk is retained. The original `/chunk` endpoint still supports audio-only callers. A shared
HTTP client reuses transcription connections. The live decision stage has a configurable
`CALL_DECISION_TIMEOUT_S` budget (default 1.25 seconds); timeout uses local rules and models.
Speech-provider latency itself remains external and is not guaranteed by this budget.

After applying: rebuild the frontend, restart the backend, relaunch the unpacked extension,
and reload existing test pages. Deploy the rebuilt frontend and backend together because
pipelined live capture uses the new preparation endpoint. Rehearse a human microphone call
and confirm all spoken phrases are retained, then test the recorded scam demo.


### Decisions request latency

The AI decision time is measured around the complete HTTP request, including connection
setup, network travel and provider processing. A persistent connection can now remain idle
for 120 seconds rather than HTTPX's default five seconds. Input JSON is compacted without
removing fields or questions. OpenAI's optional `openai-processing-ms` and `x-request-id`
headers are retained for diagnosis; missing server timing stays unknown. The UI timing
hover explains the total/server split. Other request time is an estimate, not a pure
network measurement or a model inference measurement.

Run `cd backend && .venv/bin/python scripts/benchmark_decisions.py --runs 5` against the
configured account to compare the first connection, subsequent requests, and one versus
all URL questions. The single-question variant is diagnostic and does not change the
production question set. No subsecond API result has been established by local mocked tests.
