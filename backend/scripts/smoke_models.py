"""Sanity + latency check for the Tier 0 HuggingFace models on demo/samples.json.

Usage: .venv/bin/python scripts/smoke_models.py [path/to/samples.json]
No training — inference only. Prints per-sample probabilities, accuracy at 0.5 and latency.
"""

import json
import os
import statistics
import sys
import time
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

torch.set_num_threads(4)
TEMPERATURE = 2.0

URL_MODEL = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
EMAIL_MODEL = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
INDIA_MODEL = "anmolshrivastav/distilbert-scam-detector-india"
SMS_TINY_MODEL = "mrm8488/bert-tiny-finetuned-sms-spam-detection"


MODELS_DIR = Path(__file__).resolve().parents[1] / "models"


def resolve(repo_id: str) -> str:
    """Prefer the copy in backend/models/<org>__<name>; else fall back to the HF cache."""
    local = MODELS_DIR / repo_id.replace("/", "__")
    return str(local) if (local / "config.json").exists() else repo_id


class HFClassifier:
    """Wraps a sequence classifier; `positive` lists the label indices that mean scam/phish."""

    def __init__(self, repo_id: str, positive: list[int], max_length: int, onnx: bool = False):
        name = resolve(repo_id)
        self.name = name
        self.positive = positive
        self.max_length = max_length
        self.backend = "torch"
        if onnx:
            try:
                from optimum.onnxruntime import ORTModelForSequenceClassification

                self.tokenizer = AutoTokenizer.from_pretrained(name, subfolder="onnx")
                self.model = ORTModelForSequenceClassification.from_pretrained(
                    name, subfolder="onnx", file_name="model.onnx"
                )
                self.backend = "onnx-int8"
            except Exception as exc:  # fall back to torch weights
                print(f"  [warn] ONNX load failed for {name}: {exc!r}; using torch")
                onnx = False
        if not onnx:
            self.tokenizer = AutoTokenizer.from_pretrained(name)
            self.model = AutoModelForSequenceClassification.from_pretrained(name).eval()
        self.predict("warm up")

    def predict(self, text: str) -> tuple[float, float, float]:
        """Returns (p_raw, p_calibrated, latency_ms)."""
        t0 = time.perf_counter()
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=self.max_length)
        with torch.inference_mode():
            logits = self.model(**inputs).logits[0].float()
        raw = torch.softmax(logits, -1)[self.positive].sum().item()
        cal = torch.softmax(logits / TEMPERATURE, -1)[self.positive].sum().item()
        return raw, cal, (time.perf_counter() - t0) * 1000


def strip_scheme(url: str) -> str:
    return url.split("://", 1)[-1]


def run(samples_path: Path) -> None:
    samples = json.loads(samples_path.read_text())

    print("Loading models…")
    t0 = time.perf_counter()
    models = {
        "urlbert": HFClassifier(URL_MODEL, [1], 64),
        "cybersectony": HFClassifier(EMAIL_MODEL, [1, 3], 512),
        "india": HFClassifier(INDIA_MODEL, [1], 256, onnx=True),
        "bert_tiny": HFClassifier(SMS_TINY_MODEL, [1], 256),
    }
    print(f"Loaded in {time.perf_counter() - t0:.1f}s; india backend = {models['india'].backend}\n")

    plan = {
        "sms": [("india", lambda s: s["text"]), ("bert_tiny", lambda s: s["text"])],
        "email": [
            ("cybersectony", lambda s: f"{s['subject']}\n{s['text']}"),
            ("india", lambda s: f"{s['subject']}\n{s['text']}"),
        ],
        "url": [("urlbert", lambda s: strip_scheme(s["text"])), ("cybersectony", lambda s: s["text"])],
    }

    summary = []
    for channel, runs in plan.items():
        print(f"=== {channel.upper()} ({len(samples[channel])} samples)  cols: raw / T={TEMPERATURE}")
        header = f"{'lbl':>3}  " + "  ".join(f"{m:>18}" for m, _ in runs) + "  text"
        print(header)
        stats = {m: {"correct": 0, "lat": [], "fp": 0, "fn": 0} for m, _ in runs}
        for s in samples[channel]:
            cells = []
            for m, prep in runs:
                raw, cal, ms = models[m].predict(prep(s))
                pred = int(raw >= 0.5)
                st = stats[m]
                st["correct"] += pred == s["label"]
                st["fp"] += pred == 1 and s["label"] == 0
                st["fn"] += pred == 0 and s["label"] == 1
                st["lat"].append(ms)
                mark = " " if pred == s["label"] else "✗"
                cells.append(f"{raw:6.3f}/{cal:5.3f} {mark}{ms:4.0f}ms")
            preview = (s.get("subject") or s["text"])[:60].replace("\n", " ")
            print(f"{s['label']:>3}  " + "  ".join(f"{c:>18}" for c in cells) + f"  {preview}")
        for m, st in stats.items():
            n = len(samples[channel])
            summary.append(
                (channel, m, st["correct"], n, st["fp"], st["fn"],
                 statistics.median(st["lat"]), max(st["lat"]))
            )
        print()

    print("=== SUMMARY (threshold 0.5 on raw prob)")
    print(f"{'channel':<7} {'model':<13} {'acc':>9} {'FP':>3} {'FN':>3} {'p50 ms':>7} {'max ms':>7}")
    for ch, m, c, n, fp, fn, p50, mx in summary:
        print(f"{ch:<7} {m:<13} {c:>3}/{n:<3} {c / n:4.0%} {fp:>3} {fn:>3} {p50:7.1f} {mx:7.1f}")


if __name__ == "__main__":
    default = Path(__file__).resolve().parents[2] / "demo" / "samples.json"
    run(Path(sys.argv[1]) if len(sys.argv) > 1 else default)
