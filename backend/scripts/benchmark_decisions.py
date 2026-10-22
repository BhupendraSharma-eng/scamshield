"""Measure Decisions transport cold/warm time and one-vs-full question payloads.

Run from backend: .venv/bin/python scripts/benchmark_decisions.py --runs 5
Uses the configured API key at runtime, never prints credentials or message content.
The one-question profile is diagnostic only; production retains all questions.
"""
import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import settings
from app.schemas import Envelope
from app.tier1.decision_client import DecisionClient
from app.tier1.questions import build_questions, build_state
import httpx


async def main(runs):
    if not settings.openai_api_key:
        raise SystemExit('OPENAI_API_KEY is not configured; no requests made.')
    state = build_state(Envelope(channel='url', urls=['https://example.com/login']), [])
    for name, questions in [('full', build_questions('url')), ('single', build_questions('url')[:1])]:
        client = DecisionClient()
        client.provider = 'openai'
        client._http = httpx.AsyncClient(
            base_url=settings.openai_base_url,
            headers={'Authorization': f'Bearer {settings.openai_api_key}'},
            timeout=settings.decision_timeout_s,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=120),
        )
        warm = []
        try:
            for index in range(runs + 1):
                start = time.perf_counter()
                _, _, info = await client._call_openai(state, questions)
                elapsed = (time.perf_counter() - start) * 1000
                if index:
                    warm.append(elapsed)
                print(json.dumps({'profile': name, 'phase': 'warm' if index else 'first_connection',
                                  'questions': len(questions), 'total_ms': round(elapsed, 1), **info}))
        finally:
            await client.close()
        ordered = sorted(warm)
        print(json.dumps({'profile': name, 'warm_p50_ms': round(statistics.median(warm), 1),
                          'warm_max_ms': round(ordered[-1], 1), 'samples': len(warm)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, choices=range(1, 31), default=5, metavar='1..30')
    try:
        asyncio.run(main(parser.parse_args().runs))
    except Exception as exc:
        # Do not dump arbitrary HTTP responses or configuration on error.
        raise SystemExit(f'Benchmark failed ({type(exc).__name__}); check connectivity and API configuration.')
