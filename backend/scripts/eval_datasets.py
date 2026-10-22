"""Detection on the provided datasets via the in-process API.

SMS/email sets: every row is a scam (recall only). URL set: labelled Fraud/Legitimate (recall + false alarms;
for the "Legitimate" rows, "detected" means a false alarm).

Usage (from backend/): .venv/bin/python scripts/eval_datasets.py [--no-jev] [--limit N] [--show-misses]
Reports detection rate (SCAM or SUSPICIOUS) per category, verdict mix, decided_by mix and latency.
"""

import csv
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

args = sys.argv[1:]
if "--no-jev" in args:
    import os
    os.environ["DECISION_ENABLED"] = "false"
    os.environ["OPENAI_API_KEY"] = ""
    os.environ["OPENROUTER_API_KEY"] = ""
LIMIT = int(args[args.index("--limit") + 1]) if "--limit" in args else None
SHOW_MISSES = "--show-misses" in args

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402

settings.db_path = Path(__file__).resolve().parents[1] / "eval.db"
settings.db_path.unlink(missing_ok=True)

from app.main import app  # noqa: E402

DATA = Path(__file__).resolve().parents[2] / "demo" / "datasets"


def load() -> list[tuple[str, str, dict, str]]:
    jobs = []
    for r in csv.DictReader(open(DATA / "SMSDataSet.csv", encoding="utf-8")):
        jobs.append(("sms", r["Category"], {"content": r["Message"], "sender": r["Sender"]}, r["Message"]))
    for r in csv.DictReader(open(DATA / "email_DataSet.csv", encoding="utf-8")):
        jobs.append(("email", r["Category"], {
            "sender": f'{r["Sender_Name"]} <{r["Sender_Email"]}>', "subject": r["Subject"], "body": r["Body"],
        }, r["Subject"]))
    for r in csv.DictReader(open(DATA / "UrlDataSet.csv", encoding="utf-8")):
        jobs.append(("url", r["Label"], {"url": r["URL"]}, r["URL"]))
    return jobs[:LIMIT] if LIMIT else jobs


def main() -> None:
    by_cat: dict[tuple[str, str], Counter] = defaultdict(Counter)
    decided: Counter = Counter()
    lat: dict[str, list[float]] = defaultdict(list)
    misses = []
    with TestClient(app) as client:
        for channel, cat, body, preview in load():
            r = client.post(f"/api/analyze/{channel}", json=body).json()
            by_cat[(channel, cat)][r["verdict"]] += 1
            decided[r["decided_by"]] += 1
            if not r.get("cached"):
                lat[channel].append(r["latency_ms"]["total"])
            wrong = (r["verdict"] != "SAFE") if cat == "Legitimate" else (r["verdict"] == "SAFE")
            if wrong:
                misses.append((channel, cat, round(r["risk"], 2), r["scores"], preview))

    print(f"\n{'channel':6} {'category':20} {'n':>4} {'SCAM':>5} {'SUSP':>5} {'SAFE':>5} {'detected':>9}")
    tot = Counter()
    for (ch, cat), c in sorted(by_cat.items()):
        n = sum(c.values())
        tot.update(c)
        print(f"{ch:6} {cat:20} {n:>4} {c['SCAM']:>5} {c['SUSPICIOUS']:>5} {c['SAFE']:>5} {(n - c['SAFE']) / n:>8.1%}")
    n = sum(tot.values())
    print(f"{'ALL':27} {n:>4} {tot['SCAM']:>5} {tot['SUSPICIOUS']:>5} {tot['SAFE']:>5} {(n - tot['SAFE']) / n:>8.1%}")
    print("decided_by:", dict(decided))
    for ch, xs in lat.items():
        print(f"latency {ch}: p50={statistics.median(xs):.0f}ms max={max(xs):.0f}ms (uncached n={len(xs)})")
    if SHOW_MISSES:
        print("\nERRORS (missed scams / false alarms on Legitimate):")
        for m in misses[:40]:
            print(" ", m)


if __name__ == "__main__":
    main()
