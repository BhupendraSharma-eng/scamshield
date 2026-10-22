"""Live-call sessions, deepfake fusion, and file windows. OpenAI is never contacted."""

import asyncio
import io
import time
import wave
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.api import call_stream
from app.api.call_stream import (
    LISTENING_ACTION,
    VOICE_CLONE_REASON,
    apply_voice_fusion,
    recent_p_fake,
    split_windows,
    voice_label,
)
from app.config import settings
from app.engine.explain import ACTIONS
from app.tier0 import voice_deepfake
from app.tier0.local_model import LocalScores, local_models
from app.tier0.voice_deepfake import p_fake, voice_detector
from app.tier1.decision_client import decision_client
from app.tier2 import stt

HELLO = "Hello sir I am calling from SBI head office"
OTP = "your account will be blocked today, tell me the OTP you received"
UPDATE_KEYS = {
    "session_id", "seq", "text", "transcript", "verdict", "risk", "reasons",
    "category", "trigger", "flags", "deepfake", "alert", "action", "latency_ms",
}
DEEPFAKE_KEYS = {"p_fake", "chunk_p_fake", "label", "chunks"}
LATENCY_KEYS = {"stt", "decision", "deepfake", "total"}


def _wav(seconds: float, sr: int = 16000) -> bytes:
    count = int(round(seconds * sr))
    timeline = np.arange(count, dtype=np.float64) / sr
    tone = 0.2 * np.sin(2 * np.pi * 440 * timeline)
    noise = 0.05 * np.random.default_rng(0).standard_normal(count)
    samples = np.clip(tone + noise, -1.0, 1.0)
    pcm = (samples * 32767.0).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sr)
        handle.writeframes(pcm.tobytes())
    return buf.getvalue()


def _post_chunk(client: TestClient, session_id: str, seq: int, wav: bytes | None = None):
    return client.post(
        f"/api/call/session/{session_id}/chunk",
        files={"file": ("chunk.wav", wav if wav is not None else _wav(1.5), "audio/wav")},
        data={"seq": str(seq)},
    )


class _Response:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _Client:
    def __init__(self, *, timeout: float | None = None, **kwargs: object) -> None:
        self.timeout = timeout

    async def __aenter__(self) -> "_Client":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def post(self, url: str, headers: dict | None = None, data: dict | None = None, files: dict | None = None):
        raise NotImplementedError


def test_transcribe_posts_model_and_prompt_without_language(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Client(_Client):
        async def post(self, url: str, headers: dict | None = None, data: dict | None = None, files: dict | None = None):
            seen["url"] = url
            seen["data"] = dict(data or {})
            seen["timeout"] = self.timeout
            seen["file"] = files["file"][0] if files else None
            return _Response({"text": "  namaste  "})

    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    monkeypatch.setattr(settings, "openai_base_url", "https://example.test/v1/")
    monkeypatch.setattr(settings, "stt_model", "gpt-4o-mini-transcribe")
    monkeypatch.setattr(stt.httpx, "AsyncClient", Client)

    assert asyncio.run(stt.transcribe(b"RIFFwav", "call.wav")) == "namaste"
    assert seen["url"] == "https://example.test/v1/audio/transcriptions"
    assert seen["timeout"] == 20.0
    assert seen["data"] == {"model": "gpt-4o-mini-transcribe", "prompt": "Phone call in Indian English or Hindi."}
    assert "language" not in seen["data"]
    assert seen["file"] == "call.wav"


def test_transcribe_empty_on_silence_errors_and_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    constructed = {"n": 0}

    class Boom(_Client):
        def __init__(self, *, timeout: float | None = None, **kwargs: object) -> None:
            constructed["n"] += 1
            super().__init__(timeout=timeout, **kwargs)

        async def post(self, url: str, headers: dict | None = None, data: dict | None = None, files: dict | None = None):
            raise stt.httpx.ConnectError("offline")

    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    monkeypatch.setattr(settings, "openai_base_url", "https://example.test/v1")
    monkeypatch.setattr(stt.httpx, "AsyncClient", Boom)
    assert asyncio.run(stt.transcribe(b"RIFFwav")) == ""
    assert constructed["n"] == 1

    class Silent(Boom):
        async def post(self, url: str, headers: dict | None = None, data: dict | None = None, files: dict | None = None):
            return _Response({"text": "   "})

    monkeypatch.setattr(stt.httpx, "AsyncClient", Silent)
    assert asyncio.run(stt.transcribe(b"RIFFwav")) == ""

    monkeypatch.setattr(settings, "openai_api_key", None)
    assert asyncio.run(stt.transcribe(b"RIFFwav")) == ""
    assert asyncio.run(stt.transcribe(b"")) == ""
    assert constructed["n"] == 2


def test_p_fake_skips_short_and_quiet_audio() -> None:
    assert p_fake(np.zeros(15_999, dtype=np.float32), 16_000) is None
    assert p_fake(np.full(16_000, 1e-4, dtype=np.float32), 16_000) is None
    assert p_fake(np.zeros(4_000, dtype=np.float32), 8_000) is None


def test_voice_label_and_recent_scores() -> None:
    assert voice_label(None) is None
    assert voice_label(0.7) == "likely_ai"
    assert voice_label(0.699) == "uncertain"
    assert voice_label(0.4) == "uncertain"
    assert voice_label(0.399) == "likely_human"
    assert recent_p_fake([None, None]) == (None, 0)
    mean, count = recent_p_fake([0.1, None, 0.2, 0.3, 0.4, 0.5])
    assert mean == pytest.approx(0.35)
    assert count == 5


def test_voice_fusion_raises_borderline_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "thresh_scam", 0.70)
    monkeypatch.setattr(settings, "thresh_suspicious", 0.35)
    risk, verdict, reasons, category, action = apply_voice_fusion(
        0.36, "SUSPICIOUS", ["Account pressure."], "kyc_freeze", "Be careful.", 0.8,
    )
    assert risk == 0.75
    assert verdict == "SCAM"
    assert category == "kyc_freeze"
    assert reasons == ["Account pressure.", VOICE_CLONE_REASON]
    assert action == ACTIONS["SCAM"]["kyc_freeze"]

    held = apply_voice_fusion(0.36, "SUSPICIOUS", ["Account pressure."], "kyc_freeze", "Be careful.", 0.79)
    assert held[:3] == (0.36, "SUSPICIOUS", ["Account pressure."])
    quiet = apply_voice_fusion(0.34, "SAFE", [], None, LISTENING_ACTION, 0.99)
    assert quiet[0] == 0.34
    assert quiet[1] == "SAFE"
    assert VOICE_CLONE_REASON not in quiet[2]


def test_nine_seconds_splits_into_three_windows() -> None:
    parts = split_windows(np.zeros(9 * 16_000, dtype=np.float32), 16_000)
    assert [len(part) for part in parts] == [64_000, 64_000, 16_000]


def test_call_session_file_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "db_path", tmp_path / "call-stream.db")
    monkeypatch.setattr(settings, "decision_enabled", False)
    monkeypatch.setattr(settings, "openai_api_key", None)
    monkeypatch.setattr(settings, "openrouter_api_key", None)
    monkeypatch.setattr(settings, "thresh_scam", 0.70)
    monkeypatch.setattr(settings, "thresh_suspicious", 0.35)
    monkeypatch.setattr(decision_client, "_http", None)
    monkeypatch.setattr(decision_client, "_ts", None)
    monkeypatch.setattr(local_models, "load", lambda: None)
    monkeypatch.setattr(voice_detector, "load", lambda: None)

    # Low local score keeps the OTP script under the scam line until the voice score lifts it.
    def fake_score(env: object) -> LocalScores:
        return LocalScores(p_local=0.05, per_model={}, url_scores={}, latency_ms=0.0)

    monkeypatch.setattr(local_models, "score", fake_score)
    monkeypatch.setattr(voice_deepfake, "p_fake", lambda samples, sr: 0.9)

    pending = [HELLO, OTP]

    async def fake_transcribe(wav_bytes: bytes, filename: str = "chunk.wav") -> str:
        if pending:
            return pending.pop(0)
        return "ok"

    monkeypatch.setattr(stt, "transcribe", fake_transcribe)
    call_stream.sessions.clear()

    from app.main import app

    wav = _wav(1.5)
    with TestClient(app) as client:
        created = client.post("/api/call/session", json={"number": "9876543210"})
        assert created.status_code == 200
        session_id = created.json()["session_id"]
        assert isinstance(session_id, str) and session_id

        first = _post_chunk(client, session_id, 0, wav)
        second = _post_chunk(client, session_id, 1, wav)
        third = _post_chunk(client, session_id, 2, wav)
        assert first.status_code == second.status_code == third.status_code == 200
        bodies = [first.json(), second.json(), third.json()]
        for body, seq in zip(bodies, (0, 1, 2), strict=True):
            assert set(body) == UPDATE_KEYS
            assert set(body["deepfake"]) == DEEPFAKE_KEYS
            assert set(body["latency_ms"]) == LATENCY_KEYS
            assert body["session_id"] == session_id
            assert body["seq"] == seq
            assert all(value >= 0 for value in body["latency_ms"].values())

        assert bodies[0]["text"] == HELLO
        assert bodies[0]["transcript"] == HELLO
        assert len(HELLO) >= 20
        assert bodies[0]["verdict"] == "SAFE"
        assert bodies[0]["risk"] < 0.35
        assert bodies[0]["alert"] is False
        assert VOICE_CLONE_REASON not in bodies[0]["reasons"]
        assert bodies[0]["deepfake"]["label"] == "likely_ai"
        assert bodies[0]["deepfake"]["chunks"] == 1

        assert bodies[1]["text"] == OTP
        assert HELLO in bodies[1]["transcript"] and OTP in bodies[1]["transcript"]
        assert bodies[1]["verdict"] == "SCAM"
        assert bodies[1]["alert"] is True
        assert bodies[1]["risk"] == pytest.approx(0.75)
        assert VOICE_CLONE_REASON in bodies[1]["reasons"]
        assert bodies[1]["category"] == "otp_theft"
        assert bodies[1]["trigger"] is None
        assert bodies[1]["action"] == ACTIONS["SCAM"]["otp_theft"]
        assert bodies[1]["flags"]
        assert any("otp" in flag.lower() for flag in bodies[1]["flags"])
        assert bodies[1]["deepfake"]["p_fake"] == pytest.approx(0.9)
        assert bodies[1]["deepfake"]["chunk_p_fake"] == pytest.approx(0.9)
        assert bodies[1]["deepfake"]["label"] == "likely_ai"
        assert [body["alert"] for body in bodies] == [False, True, False]
        assert bodies[2]["verdict"] == "SCAM"

        ended = client.post(f"/api/call/session/{session_id}/end")
        assert ended.status_code == 200
        final = ended.json()
        assert set(final) == UPDATE_KEYS
        assert final["verdict"] == "SCAM"
        assert final["alert"] is False
        assert OTP in final["transcript"]
        missing = _post_chunk(client, session_id, 3, wav)
        assert missing.status_code == 404

        uploaded = client.post(
            "/api/call/analyze-file",
            files={"file": ("call.wav", _wav(9), "audio/wav")},
        )
        assert uploaded.status_code == 200
        updates = uploaded.json()["updates"]
        assert len(updates) == 3
        assert [item["seq"] for item in updates] == [1, 2, 3]
        assert len({item["session_id"] for item in updates}) == 1
        for item in updates:
            assert set(item) == UPDATE_KEYS
            assert item["action"] == LISTENING_ACTION
            assert item["verdict"] == "SAFE"
            assert item["risk"] == 0
            assert item["reasons"] == []
        assert updates[0]["session_id"] not in call_stream.sessions

        rejected = client.post(
            "/api/call/analyze-file",
            files={"file": ("note.txt", b"hello", "text/plain")},
        )
        assert rejected.status_code == 415

        garbage = client.post(
            "/api/call/analyze-file",
            files={"file": ("clip.mp3", b"not really an mp3", "audio/mpeg")},
        )
        assert garbage.status_code == 415
        assert "decode" in garbage.json()["detail"].lower() or "ffmpeg" in garbage.json()["detail"].lower()

        fresh = client.post("/api/call/session", json={}).json()["session_id"]
        bad_wav = client.post(
            f"/api/call/session/{fresh}/chunk",
            files={"file": ("chunk.wav", b"not-a-wav", "audio/wav")},
            data={"seq": "0"},
        )
        assert bad_wav.status_code == 415
        call_stream.sessions[fresh]["created"] = time.monotonic() - call_stream.SESSION_TTL_S - 5
        expired = _post_chunk(client, fresh, 1, wav)
        assert expired.status_code == 404

        monkeypatch.setattr(call_stream, "MAX_AUDIO_BYTES", 8)
        too_big = client.post(
            "/api/call/analyze-file",
            files={"file": ("a.wav", b"0123456789", "audio/wav")},
        )
        assert too_big.status_code == 413
