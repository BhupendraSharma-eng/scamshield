"""Run every demo sample through the full API (in-process) and print verdicts, risk, reasons, latency.

Usage (from backend/): .venv/bin/python scripts/eval_samples.py [--no-jev] [--verbose]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if "--no-jev" in sys.argv:
    import os
    os.environ["DECISION_ENABLED"] = "false"
    os.environ["OPENAI_API_KEY"] = ""
    os.environ["OPENROUTER_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402

settings.db_path = Path(__file__).resolve().parents[1] / "eval.db"
settings.db_path.unlink(missing_ok=True)

from app.main import app  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VERBOSE = "--verbose" in sys.argv


def main() -> None:
    samples = json.loads((ROOT / "demo" / "samples.json").read_text())
    rows = []
    with TestClient(app) as client:
        print("health:", json.dumps(client.get("/api/health").json(), indent=1))
        jobs = (
            [("sms", s, {"content": s["text"]}) for s in samples["sms"]]
            + [("email", s, {"subject": s["subject"], "body": s["text"]}) for s in samples["email"]]
            + [("url", s, {"url": s["text"]}) for s in samples["url"]]
        )
        for channel, s, body in jobs:
            r = client.post(f"/api/analyze/{channel}", json=body).json()
            if "verdict" not in r:
                print("ERROR", channel, r)
                continue
            ok = (r["verdict"] != "SAFE") == bool(s["label"])
            rows.append((channel, ok, r["verdict"] == "SUSPICIOUS"))
            sc = r["scores"]
            print(f"{'✓' if ok else '✗'} {channel:5} {r['verdict']:10} risk={r['risk']:.2f} by={r['decided_by']:10} "
                  f"t1={sc['p_jev'] if sc['p_jev'] is None else round(sc['p_jev'], 2)} "
                  f"local={sc['p_local'] if sc['p_local'] is None else round(sc['p_local'], 2)} rules={sc['rules']:.2f} "
                  f"{r['latency_ms']['total']:6.0f}ms  {(s.get('subject') or s['text'])[:55]}")
            if VERBOSE or not ok:
                for reason in r["reasons"]:
                    print(f"        - {reason}")
        print("\nstats:", json.dumps(client.get("/api/stats").json()))

    for ch in ("sms", "email", "url"):
        sub = [r for r in rows if r[0] == ch]
        print(f"{ch:5}: {sum(r[1] for r in sub)}/{len(sub)} correct (SAFE vs not-SAFE), {sum(r[2] for r in sub)} SUSPICIOUS")


if __name__ == "__main__":
    main()
