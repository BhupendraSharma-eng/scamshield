"""Local voice-clone detector (mo-thecreator/Deepfake-audio-detection).

Loaded once, lazily and under a lock. Scoring never raises: missing weights, short audio,
and silence all return None so a live call keeps going.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

import numpy as np

from app.config import settings

log = logging.getLogger(__name__)

_MODEL_DIRNAME = "mo-thecreator__Deepfake-audio-detection"
_TARGET_SR = 16_000
_MIN_SAMPLES = _TARGET_SR  # skip under 1 second
_MIN_RMS = 0.005
_MAX_SAMPLES = _TARGET_SR * 30


def resample_linear(samples: np.ndarray, sr: int, target: int = _TARGET_SR) -> np.ndarray:
    """Resample a mono waveform with linear interpolation."""

    audio = np.ascontiguousarray(samples, dtype=np.float32)
    if sr == target or audio.size == 0:
        return audio
    count = int(round(audio.size * target / sr))
    if count <= 0:
        return np.zeros(0, dtype=np.float32)
    old = np.linspace(0.0, 1.0, num=audio.size, endpoint=False)
    new = np.linspace(0.0, 1.0, num=count, endpoint=False)
    return np.interp(new, old, audio).astype(np.float32, copy=False)


def _mono_float32(samples: np.ndarray) -> np.ndarray:
    audio = np.asarray(samples)
    if audio.ndim == 2:
        axis = 1 if audio.shape[1] <= audio.shape[0] else 0
        audio = audio.mean(axis=axis)
    elif audio.ndim > 2:
        audio = np.reshape(audio, -1)
    if np.issubdtype(audio.dtype, np.integer):
        scale = np.float32(1 << (np.iinfo(audio.dtype).bits - 1))
        audio = audio.astype(np.float32) / scale
    else:
        audio = audio.astype(np.float32, copy=False)
    return np.nan_to_num(audio, nan=0.0, posinf=0.0, neginf=0.0)


def _prepare(samples: np.ndarray, sr: int) -> np.ndarray | None:
    if sr <= 0:
        return None
    audio = resample_linear(_mono_float32(samples), sr, _TARGET_SR)
    if audio.size < _MIN_SAMPLES:
        return None
    rms = float(np.sqrt(np.mean(np.square(audio, dtype=np.float64))))
    if not np.isfinite(rms) or rms < _MIN_RMS:
        return None
    if audio.size > _MAX_SAMPLES:
        audio = audio[:_MAX_SAMPLES]
    return np.ascontiguousarray(audio, dtype=np.float32)


def _fake_index(config: object) -> int:
    labels = getattr(config, "id2label", None) or {0: "fake", 1: "real"}
    for key, label in labels.items():
        if str(label).strip().lower() == "fake":
            return int(key)
    return 0


class VoiceDeepfake:
    def __init__(self) -> None:
        self.status = "not_loaded"
        self._lock = threading.Lock()
        self._attempted = False
        self._extractor = None
        self._model = None
        self._fake_index = 0

    def load(self) -> None:
        """Load the local wav2vec2 classifier. Safe to call more than once. Never raises."""

        with self._lock:
            if self._attempted:
                return
            self._attempted = True
            path = Path(settings.models_dir) / _MODEL_DIRNAME
            try:
                if not (path / "config.json").is_file():
                    raise FileNotFoundError(path.name)
                os.environ.setdefault("HF_HUB_OFFLINE", "1")
                os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
                import torch
                from transformers import AutoFeatureExtractor, AutoModelForAudioClassification

                torch.set_num_threads(settings.torch_threads)
                extractor = AutoFeatureExtractor.from_pretrained(path, local_files_only=True)
                model = AutoModelForAudioClassification.from_pretrained(path, local_files_only=True)
                model.eval()
                self._fake_index = _fake_index(model.config)
                self._extractor = extractor
                self._model = model
                self.status = "ok"
                log.info("voice deepfake loaded (%s)", path.name)
            except Exception as exc:
                self._extractor = None
                self._model = None
                self.status = f"error: {exc.__class__.__name__}"
                log.warning("voice deepfake unavailable (%s): %s", path.name, self.status)

    def p_fake(self, samples: np.ndarray, sr: int) -> float | None:
        audio = _prepare(samples, sr)
        if audio is None:
            return None
        self.load()
        if self._model is None or self._extractor is None:
            return None
        try:
            with self._lock:
                return self._score(audio)
        except Exception as exc:
            log.warning("voice deepfake score failed: %s", exc.__class__.__name__)
            return None

    def _score(self, audio: np.ndarray) -> float:
        import torch

        inputs = self._extractor(audio, sampling_rate=_TARGET_SR, return_tensors="pt")
        with torch.inference_mode():
            logits = self._model(**inputs).logits
        probs = torch.softmax(logits.float(), dim=-1)[0]
        return float(probs[self._fake_index].item())


voice_detector = VoiceDeepfake()


def load() -> None:
    voice_detector.load()


def p_fake(samples: np.ndarray, sr: int) -> float | None:
    return voice_detector.p_fake(samples, sr)
