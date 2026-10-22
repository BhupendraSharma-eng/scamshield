"""Tier 0b: pretrained HuggingFace classifiers (no training). Loaded once at startup.

See TIER0.md §1 for model choices and §5 for how scores are combined per channel.
"""

import logging
import math
import os
import time
from pathlib import Path

from pydantic import BaseModel

from app.config import settings
from app.schemas import Envelope

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

log = logging.getLogger(__name__)

URL_MODEL = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
EMAIL_MODEL = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
INDIA_MODEL = "anmolshrivastav/distilbert-scam-detector-india"
SMS_TINY_MODEL = "mrm8488/bert-tiny-finetuned-sms-spam-detection"

# (repo id, label indices meaning scam/phish, max tokens, try ONNX)
SPECS = {
    "urlbert": (URL_MODEL, [1], 64, False),
    "cybersectony": (EMAIL_MODEL, [1, 3], 512, False),
    "india": (INDIA_MODEL, [1], 256, True),
    "bert_tiny": (SMS_TINY_MODEL, [1], 256, False),
}

# Per-channel blend in log-odds space: (model, weight)
BLEND = {
    "sms": [("india", 0.7), ("bert_tiny", 0.3)],
    "email": [("cybersectony", 0.65), ("india", 0.35)],
}


def _resolve(repo_id: str) -> str:
    local = Path(settings.models_dir) / repo_id.replace("/", "__")
    return str(local) if (local / "config.json").exists() else repo_id


def _logit(p: float) -> float:
    p = min(max(p, 0.01), 0.99)
    return math.log(p / (1 - p))


class _Classifier:
    def __init__(self, repo_id: str, positive: list[int], max_length: int, onnx: bool):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self.positive = positive
        self.max_length = max_length
        self.backend = "torch"
        path = _resolve(repo_id)
        if onnx:
            try:
                from optimum.onnxruntime import ORTModelForSequenceClassification

                self.tokenizer = AutoTokenizer.from_pretrained(path, subfolder="onnx")
                self.model = ORTModelForSequenceClassification.from_pretrained(
                    path, subfolder="onnx", file_name="model.onnx"
                )
                self.backend = "onnx-int8"
            except Exception as exc:
                log.warning("ONNX load failed for %s (%r); using torch", repo_id, exc)
                onnx = False
        if not onnx:
            self.tokenizer = AutoTokenizer.from_pretrained(path)
            self.model = AutoModelForSequenceClassification.from_pretrained(path).eval()
        self.predict("warm up")

    def predict(self, text: str) -> float:
        """Calibrated P(scam) with temperature scaling."""
        torch = self._torch
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=self.max_length)
        with torch.inference_mode():
            logits = self.model(**inputs).logits[0].float()
        return torch.softmax(logits / settings.temperature, -1)[self.positive].sum().item()


class LocalScores(BaseModel):
    p_local: float | None
    per_model: dict[str, float]
    url_scores: dict[str, float]      # url -> urlbert probability
    latency_ms: float


class LocalModels:
    def __init__(self) -> None:
        self.models: dict[str, _Classifier] = {}
        self.status: dict[str, str] = {}

    def load(self) -> None:
        import torch

        torch.set_num_threads(settings.torch_threads)
        for key, (repo, positive, max_len, onnx) in SPECS.items():
            t0 = time.perf_counter()
            try:
                self.models[key] = _Classifier(repo, positive, max_len, onnx)
                self.status[key] = f"ok ({self.models[key].backend}, {time.perf_counter() - t0:.1f}s)"
            except Exception as exc:
                log.warning("Model %s failed to load: %r", key, exc)
                self.status[key] = f"error: {exc.__class__.__name__}"

    def score_url(self, url: str) -> float | None:
        m = self.models.get("urlbert")
        return m.predict(url.split("://", 1)[-1]) if m else None

    def score(self, env: Envelope) -> LocalScores:
        """Blocking — call via asyncio.to_thread."""
        t0 = time.perf_counter()
        per_model: dict[str, float] = {}
        url_scores: dict[str, float] = {}

        for url in env.urls[:10]:
            p = self.score_url(url)
            if p is not None:
                url_scores[url] = p

        p_local: float | None
        if env.channel == "url":
            p_local = max(url_scores.values()) if url_scores else None
            if p_local is not None:
                per_model["urlbert"] = p_local
        else:
            text = f"{env.subject}\n{env.text}" if env.subject else env.text
            parts = []
            for key, w in BLEND[env.channel]:
                m = self.models.get(key)
                if m is None or not text.strip():
                    continue
                per_model[key] = m.predict(text)
                parts.append((w, per_model[key]))
            if parts:
                total = sum(w for w, _ in parts)
                z = sum(w * _logit(p) for w, p in parts) / total
                p_local = 1 / (1 + math.exp(-z))
            else:
                p_local = None

        return LocalScores(
            p_local=p_local,
            per_model={k: round(v, 4) for k, v in per_model.items()},
            url_scores={k: round(v, 4) for k, v in url_scores.items()},
            latency_ms=(time.perf_counter() - t0) * 1000,
        )


local_models = LocalModels()
