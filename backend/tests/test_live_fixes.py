"""Verified URL trust and pipelined call regressions, with no external API calls."""
import asyncio
import io
import wave

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.engine.fusion import fuse
from app.engine.pipeline import _url_risk
from app.tier0.url_analyzer import analyze_url


@pytest.mark.parametrize('url', ['https://bssserp.com/login/mis', 'https://bssserp.com:443/login/mis/'])
def test_verified_bsss_portal_is_safe_even_with_a_high_url_model(url):
    evidence = analyze_url(url).evidence
    assert any(e.id == 'url.verified_portal' for e in evidence)
    for decision in [None, 0.56, 0.99]:
        assert fuse(evidence, 0.99, decision, channel='url').verdict == 'SAFE'
    assert _url_risk(evidence, 0.99) <= settings.allowlisted_url_cap


@pytest.mark.parametrize('url', [
    'http://bssserp.com/login/mis', 'https://bssserp.com.evil.top/login/mis',
    'https://evil.bssserp.com/login/mis', 'https://bssserp.com/login/mis?redirect=https://evil.top',
    'https://bssserp.com/login/mis/download.apk', 'https://bssserp.com:8443/login/mis',
    'https://user@bssserp.com/login/mis',
])
def test_portal_trust_does_not_expand_to_other_urls(url):
    assert all(e.id != 'url.verified_portal' for e in analyze_url(url).evidence)


def test_live_decision_budget_cancels_slow_provider_and_uses_local_fallback(tmp_path, monkeypatch):
    from app.engine import pipeline
    from app.tier0.local_model import LocalScores
    from app.tier2.auditor import auditor
    from app.schemas import Envelope
    from app import db
    cancelled = []
    async def slow(*args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)
    monkeypatch.setattr(pipeline.decision_client, 'classify', slow)
    monkeypatch.setattr(pipeline.local_models, 'score', lambda env: LocalScores(p_local=.01, per_model={}, url_scores={}, latency_ms=0))
    monkeypatch.setattr(settings, 'openai_api_key', None)
    monkeypatch.setattr(settings, 'openrouter_api_key', None)
    monkeypatch.setattr(settings, 'db_path', tmp_path / 'budget.db')
    async def check():
        await db.init_db()
        result = await asyncio.wait_for(pipeline.analyze(Envelope(channel='sms', text='Hello, see you tomorrow.'), use_cache=False, decision_timeout_s=.01), 1)
        assert result['mode'] == 'offline'
        assert result['verdict'] == 'SAFE'
        assert cancelled == [True]
    asyncio.run(check())


def test_prepared_transcript_is_not_transcribed_twice(tmp_path, monkeypatch):
    from app.api import call_stream
    from app.tier2 import stt
    from app.tier0.local_model import local_models
    from app.tier0.voice_deepfake import voice_detector
    monkeypatch.setattr(settings, 'db_path', tmp_path / 'calls.db')
    monkeypatch.setattr(settings, 'decision_enabled', False)
    monkeypatch.setattr(settings, 'openai_api_key', None)
    monkeypatch.setattr(settings, 'openrouter_api_key', None)
    monkeypatch.setattr(local_models, 'load', lambda: None)
    monkeypatch.setattr(voice_detector, 'load', lambda: None)
    monkeypatch.setattr(call_stream.voice_deepfake, 'p_fake', lambda *a: None)
    calls = []
    async def transcribe(*args):
        calls.append(1)
        return 'hello'
    monkeypatch.setattr(stt, 'transcribe', transcribe)
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wav:
        wav.setnchannels(1); wav.setsampwidth(2); wav.setframerate(16000)
        wav.writeframes(b'\0\0' * 16000)
    upload = {'file': ('chunk.wav', buf.getvalue(), 'audio/wav')}
    from app.main import app
    with TestClient(app) as client:
        sid = client.post('/api/call/session', json={}).json()['session_id']
        prepared = client.post(f'/api/call/session/{sid}/transcribe', files=upload)
        assert prepared.status_code == 200
        result = client.post(f'/api/call/session/{sid}/chunk', files=upload, data={
            'seq': '0', 'transcription_prepared': 'true', 'transcribed_text': prepared.json()['text'],
            'transcription_ms': str(prepared.json()['latency_ms']),
        })
        assert result.status_code == 200
        assert result.json()['transcript'] == 'hello'
        # An empty prepared chunk is silence, not a request to transcribe again.
        result = client.post(f'/api/call/session/{sid}/chunk', files=upload, data={
            'seq': '1', 'transcription_prepared': 'true', 'transcribed_text': '',
        })
        assert result.status_code == 200
        assert calls == [1]
        assert client.post(f'/api/call/session/{sid}/end').status_code == 200
        assert client.post(f'/api/call/session/{sid}/transcribe', files=upload).status_code == 404


def test_stt_reuses_shared_connection_pool(monkeypatch):
    from app.tier2 import stt
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={'text': 'hello'})
    monkeypatch.setattr(settings, 'openai_api_key', 'test-key')
    async def check():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            monkeypatch.setattr(stt, '_client', client)
            assert await stt.transcribe(b'wav') == 'hello'
            assert await stt.transcribe(b'wav') == 'hello'
        assert len(requests) == 2
    asyncio.run(check())
