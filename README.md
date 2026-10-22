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
the backend, so the hosted UI talks to a backend you run: by default `http://localhost:8000`.
Tap the status indicator (top bar) → **Server settings** to point it at another backend
(LAN IP or an HTTPS tunnel). Chrome may ask to allow local-network access the first time.

## Tests

```bash
cd backend && PYTHONPATH=. .venv/bin/python -m pytest tests -q
```
