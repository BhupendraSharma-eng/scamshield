"""Live-call speech-to-text via the OpenAI audio transcriptions API.

Failures, silence, and a missing API key all return an empty string. Callers keep the session alive.
"""

import logging

import httpx

from app.config import settings

log = logging.getLogger(__name__)

_PROMPT = "Phone call in Indian English or Hindi."
_TIMEOUT_S = 20.0


async def transcribe(wav_bytes: bytes, filename: str = "chunk.wav") -> str:
    """Transcribe one WAV chunk. Language is left unset so Hindi and Indian English both pass through."""

    if not wav_bytes or not settings.openai_api_key:
        return ""
    url = settings.openai_base_url.rstrip("/") + "/audio/transcriptions"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {settings.openai_api_key}"},
                data={"model": settings.stt_model, "prompt": _PROMPT},
                files={"file": (filename or "chunk.wav", wav_bytes, "audio/wav")},
            )
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        log.warning("transcription failed: %s", exc.__class__.__name__)
        return ""
    text = payload.get("text") if isinstance(payload, dict) else ""
    return text.strip() if isinstance(text, str) else ""
