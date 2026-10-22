"""Live-call API: session chunks, a final hang-up, and whole-file analysis.

Each chunk is transcribed and scored for a cloned voice at the same time. Once the running
transcript is long enough, the existing SMS pipeline scores the words. A strong deepfake
score can raise that risk; it never runs the decision by itself.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import shutil
import subprocess
import time
import uuid
import wave
from typing import Any

import numpy as np
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.config import settings
from app.engine.explain import ACTIONS
from app.engine.pipeline import analyze
from app.schemas import Envelope
from app.tier0 import voice_deepfake
from app.tier0.url_analyzer import extract_urls
from app.tier2 import stt

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

SESSION_TTL_S = 30 * 60
MAX_AUDIO_BYTES = 15 * 1024 * 1024
WINDOW_SECONDS = 4.0
_MIN_TRANSCRIPT = 20
_DEEPFAKE_RAISE = 0.8
_DEEPFAKE_RISK_MIN = 0.35
_DEEPFAKE_RISK_FLOOR = 0.75
VOICE_CLONE_REASON = "The caller's voice shows signs of being AI-generated (voice clone)."
LISTENING_ACTION = "Listening\u2026"
_QUOTE_RE = re.compile(r'"([^"]+)"')
_AUDIO_KINDS = {"wav", "mp3", "m4a", "webm"}
_DECODE_ERROR = (
    "Cannot decode this audio. PCM WAV works with the built-in decoder; "
    "other formats need ffmpeg on PATH."
)

# session_id -> {number, chunks: [{seq, text, p_fake}], transcript, alerted, created, last}
sessions: dict[str, dict[str, Any]] = {}


class SessionRequest(BaseModel):
    number: str | None = Field(default=None, max_length=64)


class DeepfakeInfo(BaseModel):
    p_fake: float | None = None
    chunk_p_fake: float | None = None
    label: str | None = None
    chunks: int = 0


class LatencyMs(BaseModel):
    stt: float
    decision: float
    deepfake: float
    total: float


class CallUpdate(BaseModel):
    session_id: str
    seq: int
    text: str
    transcript: str
    verdict: str
    risk: float
    reasons: list[str]
    category: str | None = None
    trigger: str | None = None
    flags: list[str]
    deepfake: DeepfakeInfo
    alert: bool
    action: str
    latency_ms: LatencyMs


class AudioDecodeError(Exception):
    pass


def voice_label(p_fake: float | None) -> str | None:
    if p_fake is None:
        return None
    if p_fake >= 0.7:
        return "likely_ai"
    if p_fake >= 0.4:
        return "uncertain"
    return "likely_human"


def recent_p_fake(values: list[float | None]) -> tuple[float | None, int]:
    """Mean of the last four real scores, plus how many real scores exist."""

    scored = [value for value in values if value is not None]
    if not scored:
        return None, 0
    window = scored[-4:]
    return sum(window) / len(window), len(scored)


def split_windows(samples: np.ndarray, sr: int, seconds: float = WINDOW_SECONDS) -> list[np.ndarray]:
    width = max(1, int(round(sr * seconds)))
    return [samples[start:start + width] for start in range(0, int(samples.size), width)]


def _verdict_for(risk: float) -> str:
    if risk >= settings.thresh_scam:
        return "SCAM"
    if risk >= settings.thresh_suspicious:
        return "SUSPICIOUS"
    return "SAFE"


def _action_for(verdict: str, category: str | None) -> str:
    table = ACTIONS[verdict]
    return table.get(category or "", table["_default"])


def apply_voice_fusion(
    risk: float,
    verdict: str,
    reasons: list[str],
    category: str | None,
    action: str,
    p_fake: float | None,
) -> tuple[float, str, list[str], str | None, str]:
    """Raise a borderline transcript when the recent voice score is strongly synthetic."""

    reasons = list(reasons)
    if p_fake is None or p_fake < _DEEPFAKE_RAISE or risk < _DEEPFAKE_RISK_MIN:
        return risk, verdict, reasons, category, action
    risk = round(max(risk, _DEEPFAKE_RISK_FLOOR), 4)
    if VOICE_CLONE_REASON not in reasons:
        reasons.append(VOICE_CLONE_REASON)
    new_verdict = _verdict_for(risk)
    if new_verdict != verdict:
        verdict = new_verdict
        if verdict == "SAFE":
            category = None
        elif not category:
            category = "other_scam"
        action = _action_for(verdict, category)
    return risk, verdict, reasons, category, action


def _flags(evidence: list[dict[str, Any]], reasons: list[str]) -> list[str]:
    found: list[str] = []
    for item in evidence:
        for match in (item.get("detail") or {}).get("matches") or []:
            text = str(match).strip()
            if text and text not in found:
                found.append(text)
    for reason in reasons:
        for quote in _QUOTE_RE.findall(reason):
            quote = quote.strip()
            if quote and quote not in found:
                found.append(quote)
    return found


def _purge() -> None:
    cutoff = time.monotonic() - SESSION_TTL_S
    for sid in [key for key, item in sessions.items() if item.get("created", 0) < cutoff]:
        sessions.pop(sid, None)


def _create_session(number: str) -> str:
    _purge()
    session_id = uuid.uuid4().hex
    sessions[session_id] = {
        "number": number,
        "chunks": [],
        "transcript": "",
        "alerted": False,
        "created": time.monotonic(),
        "last": None,
        "lock": None,
    }
    return session_id


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


def _load_wave(data: bytes) -> tuple[np.ndarray, int] | None:
    try:
        with wave.open(io.BytesIO(data), "rb") as handle:
            if handle.getsampwidth() != 2 or handle.getcomptype() != "NONE":
                return None
            channels = handle.getnchannels() or 1
            sr = handle.getframerate()
            frames = handle.readframes(handle.getnframes())
        if sr <= 0 or not frames or channels < 1:
            return None
        samples = np.frombuffer(frames, dtype="<i2").astype(np.float32) / np.float32(32768.0)
        if channels > 1:
            usable = (samples.size // channels) * channels
            if usable == 0:
                return None
            samples = samples[:usable].reshape(-1, channels).mean(axis=1)
        return np.ascontiguousarray(samples, dtype=np.float32), int(sr)
    except Exception:
        return None


def _load_soundfile(data: bytes) -> tuple[np.ndarray, int] | None:
    try:
        import soundfile as sf
    except ImportError:
        return None
    try:
        audio, sr = sf.read(io.BytesIO(data), dtype="float32")
        audio = np.asarray(audio, dtype=np.float32)
        if audio.ndim == 2:
            audio = audio.mean(axis=1)
        if int(sr) <= 0 or audio.size == 0:
            return None
        return np.ascontiguousarray(audio, dtype=np.float32), int(sr)
    except Exception:
        return None


def _load_ffmpeg(data: bytes) -> np.ndarray | None:
    if shutil.which("ffmpeg") is None:
        return None
    try:
        proc = subprocess.run(
            ["ffmpeg", "-i", "-", "-f", "wav", "-ac", "1", "-ar", "16000", "-"],
            input=data,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    loaded = _load_wave(proc.stdout)
    if loaded is None:
        return None
    samples, sr = loaded
    return voice_deepfake.resample_linear(samples, sr)


def decode_to_16k(data: bytes, kind: str) -> np.ndarray:
    if kind == "wav":
        for loader in (_load_soundfile, _load_wave):
            loaded = loader(data)
            if loaded is not None:
                samples, sr = loaded
                audio = voice_deepfake.resample_linear(samples, sr)
                if audio.size:
                    return audio
    audio = _load_ffmpeg(data)
    if audio is None or audio.size == 0:
        raise AudioDecodeError(_DECODE_ERROR)
    return audio


def _encode_wav(samples: np.ndarray, sr: int) -> bytes:
    clipped = np.clip(np.asarray(samples, dtype=np.float32), -1.0, 1.0)
    pcm = (clipped * 32767.0).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sr)
        handle.writeframes(pcm.tobytes())
    return buf.getvalue()


def _audio_kind(filename: str | None, data: bytes) -> str | None:
    name = (filename or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in _AUDIO_KINDS:
        return ext
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    return None


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read(MAX_AUDIO_BYTES + 1)
    if len(data) > MAX_AUDIO_BYTES:
        raise HTTPException(413, "Audio file is larger than 15 MB.")
    if not data:
        raise HTTPException(415, "Audio file is empty.")
    return data


def _listening(
    session_id: str,
    seq: int,
    text: str,
    transcript: str,
    deepfake: DeepfakeInfo,
    latency: LatencyMs,
) -> CallUpdate:
    return CallUpdate(
        session_id=session_id,
        seq=seq,
        text=text,
        transcript=transcript,
        verdict="SAFE",
        risk=0,
        reasons=[],
        category=None,
        trigger=None,
        flags=[],
        deepfake=deepfake,
        alert=False,
        action=LISTENING_ACTION,
        latency_ms=latency,
    )


async def _timed_stt(wav_bytes: bytes, filename: str) -> tuple[str, float]:
    started = time.perf_counter()
    text = await stt.transcribe(wav_bytes, filename)
    return text, _ms(started)


def _timed_p_fake(samples: np.ndarray, sr: int) -> tuple[float | None, float]:
    started = time.perf_counter()
    try:
        score = voice_deepfake.p_fake(samples, sr)
    except Exception as exc:
        log.warning("voice score failed: %s", exc.__class__.__name__)
        score = None
    if score is not None:
        score = float(score)
    return score, _ms(started)


async def _handle_chunk(session_id: str, data: bytes, seq: int | None, filename: str,
                        transcribed_text: str | None = None, transcription_ms: float = 0) -> CallUpdate:
    session = sessions.get(session_id)
    if session is None:
        raise HTTPException(404, "Call session not found.")
    lock = session.get("lock")
    if lock is None:
        lock = asyncio.Lock()
        session["lock"] = lock
    async with lock:
        return await _score_chunk(session_id, session, data, seq, filename, transcribed_text, transcription_ms)


async def _score_chunk(
    session_id: str,
    session: dict[str, Any],
    data: bytes,
    seq: int | None,
    filename: str,
    transcribed_text: str | None = None,
    transcription_ms: float = 0,
) -> CallUpdate:
    started = time.perf_counter()
    loaded = _load_wave(data)
    if loaded is None:
        raise HTTPException(415, "Chunk must be a PCM16 WAV file.")
    samples, sr = loaded
    if seq is None:
        seq = len(session["chunks"]) + 1

    async def transcript_result():
        if transcribed_text is not None:
            return transcribed_text, transcription_ms
        return await _timed_stt(data, filename)

    (text, stt_ms), (chunk_p, fake_ms) = await asyncio.gather(
        transcript_result(),
        asyncio.to_thread(_timed_p_fake, samples, sr),
    )
    piece = text.strip()
    if piece:
        previous = session["transcript"]
        session["transcript"] = f"{previous} {piece}".strip() if previous else piece
    session["chunks"].append({"seq": seq, "text": piece, "p_fake": chunk_p})
    p_session, scored = recent_p_fake([item["p_fake"] for item in session["chunks"]])
    if p_session is not None:
        p_session = float(p_session)
    deepfake = DeepfakeInfo(
        p_fake=p_session,
        chunk_p_fake=chunk_p,
        label=voice_label(p_session),
        chunks=scored,
    )
    transcript = session["transcript"]
    if len(transcript) < _MIN_TRANSCRIPT:
        update = _listening(
            session_id,
            seq,
            piece,
            transcript,
            deepfake,
            LatencyMs(stt=stt_ms, decision=0, deepfake=fake_ms, total=_ms(started) + (transcription_ms if transcribed_text is not None else 0)),
        )
        session["last"] = update
        return update

    decision_started = time.perf_counter()
    result = await analyze(
        Envelope(
            channel="sms",
            sender=session["number"] or None,
            text=transcript[-1500:],
            urls=extract_urls(transcript[-1500:]),
        ),
        use_cache=False,
        decision_timeout_s=settings.call_decision_timeout_s,
    )
    decision_ms = _ms(decision_started)
    reasons = [str(item) for item in result.get("reasons") or [] if item]
    risk, verdict, reasons, category, action = apply_voice_fusion(
        float(result["risk"]),
        str(result["verdict"]),
        reasons,
        result.get("category"),
        str(result.get("action") or ""),
        p_session,
    )
    alert = verdict == "SCAM" and not session["alerted"]
    if alert:
        session["alerted"] = True
    update = CallUpdate(
        session_id=session_id,
        seq=seq,
        text=piece,
        transcript=transcript,
        verdict=verdict,
        risk=round(float(risk), 4),
        reasons=reasons,
        category=category,
        trigger=result.get("trigger"),
        flags=_flags(list(result.get("evidence") or []), reasons),
        deepfake=deepfake,
        alert=alert,
        action=action,
        latency_ms=LatencyMs(stt=stt_ms, decision=decision_ms, deepfake=fake_ms, total=_ms(started) + (transcription_ms if transcribed_text is not None else 0)),
    )
    session["last"] = update
    return update


@router.post("/call/session")
async def create_session(req: SessionRequest | None = None) -> dict[str, str]:
    number = req.number.strip() if req and req.number else ""
    return {"session_id": _create_session(number)}


@router.post("/call/session/{session_id}/transcribe")
async def transcribe_chunk(session_id: str, file: UploadFile = File(...)) -> dict[str, Any]:
    """Prepare speech concurrently; the client submits prepared chunks in capture order."""
    _purge()
    if session_id not in sessions:
        raise HTTPException(404, "Call session not found.")
    data = await _read_upload(file)
    if _load_wave(data) is None:
        raise HTTPException(415, "Chunk must be a PCM16 WAV file.")
    text, elapsed = await _timed_stt(data, file.filename or "chunk.wav")
    return {"text": text, "latency_ms": elapsed}


@router.post("/call/session/{session_id}/chunk")
async def post_chunk(
    session_id: str,
    file: UploadFile = File(...),
    seq: int | None = Form(default=None),
    transcribed_text: str | None = Form(default=None, max_length=12000),
    transcription_ms: float = Form(default=0, ge=0, le=120000),
    transcription_prepared: bool = Form(default=False),
) -> CallUpdate:
    _purge()
    if session_id not in sessions:
        raise HTTPException(404, "Call session not found.")
    data = await _read_upload(file)
    return await _handle_chunk(session_id, data, seq, file.filename or "chunk.wav", (transcribed_text or "") if transcription_prepared else None, transcription_ms)


@router.post("/call/session/{session_id}/end")
async def end_session(session_id: str) -> CallUpdate:
    _purge()
    session = sessions.pop(session_id, None)
    if session is None:
        raise HTTPException(404, "Call session not found.")
    last: CallUpdate | None = session.get("last")
    if last is None:
        return _listening(
            session_id,
            0,
            "",
            session.get("transcript") or "",
            DeepfakeInfo(),
            LatencyMs(stt=0, decision=0, deepfake=0, total=0),
        )
    # Ending the call is not a new detection, so it must not raise the alarm again.
    return last.model_copy(update={"alert": False})


@router.post("/call/analyze-file")
async def analyze_file(file: UploadFile = File(...)) -> dict[str, list[CallUpdate]]:
    data = await _read_upload(file)
    kind = _audio_kind(file.filename, data)
    if kind is None:
        raise HTTPException(415, "Upload a wav, mp3, m4a, or webm file.")
    try:
        samples = await asyncio.to_thread(decode_to_16k, data, kind)
    except AudioDecodeError as exc:
        raise HTTPException(415, str(exc)) from None
    windows = split_windows(samples, 16_000)
    if not windows:
        raise HTTPException(415, "Audio file is empty.")
    session_id = _create_session("")
    updates: list[CallUpdate] = []
    try:
        for index, window in enumerate(windows, start=1):
            wav = _encode_wav(window, 16_000)
            updates.append(await _handle_chunk(session_id, wav, index, f"chunk-{index}.wav"))
    finally:
        sessions.pop(session_id, None)
    return {"updates": updates}
