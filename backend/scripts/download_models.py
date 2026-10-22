"""Download the Tier 0 HuggingFace models into backend/models/<org>__<name> (stdlib only).

Usage: python3 scripts/download_models.py
Skips files that already exist with the right size, so it is safe to re-run on flaky Wi-Fi.
"""

import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MODELS = [
    "mrm8488/bert-tiny-finetuned-sms-spam-detection",
    "CrabInHoney/urlbert-tiny-v4-phishing-classifier",
    "anmolshrivastav/distilbert-scam-detector-india",
    "cybersectony/phishing-email-detection-distilbert_v2.4.1",
]
MODELS_DIR = Path(__file__).resolve().parents[1] / "models"


def wanted_files(repo_id: str) -> list[tuple[str, int]]:
    with urllib.request.urlopen(f"https://huggingface.co/api/models/{repo_id}?blobs=true") as r:
        siblings = json.load(r)["siblings"]
    names = {s["rfilename"] for s in siblings}
    keep = []
    for s in siblings:
        f = s["rfilename"]
        if f.endswith((".json", ".txt")) or f in ("model.safetensors", "onnx/model.onnx"):
            keep.append((f, s.get("size") or 0))
        elif f == "pytorch_model.bin" and "model.safetensors" not in names:
            keep.append((f, s.get("size") or 0))
    return keep


def fetch(repo_id: str, rfilename: str, size: int) -> str:
    dest = MODELS_DIR / repo_id.replace("/", "__") / rfilename
    if dest.exists() and (size == 0 or dest.stat().st_size == size):
        return f"skip {rfilename}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    url = f"https://huggingface.co/{repo_id}/resolve/main/{rfilename}"
    with urllib.request.urlopen(url) as r, open(tmp, "wb") as out:
        while chunk := r.read(1 << 20):
            out.write(chunk)
    tmp.rename(dest)
    return f"ok   {rfilename} ({dest.stat().st_size / 1e6:.1f} MB)"


def main() -> int:
    jobs = [(m, f, s) for m in MODELS for f, s in wanted_files(m)]
    total = sum(s for _, _, s in jobs) / 1e6
    print(f"{len(jobs)} files, {total:.0f} MB")
    failed = 0
    with ThreadPoolExecutor(max_workers=4) as pool:
        for (m, f, _), fut in zip(jobs, [pool.submit(fetch, *j) for j in jobs]):
            try:
                print(f"{m}: {fut.result()}", flush=True)
            except Exception as exc:
                failed += 1
                print(f"{m}: FAIL {f}: {exc!r}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
