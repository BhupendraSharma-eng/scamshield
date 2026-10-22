"""Real HTTP route flow with valid WAV audio, mocked only at the external/model boundary."""
import io
import wave

from fastapi.testclient import TestClient
from app.config import settings
from app.api import call_stream
from app.tier0.local_model import LocalScores, local_models
from app.tier0.voice_deepfake import voice_detector
from app.tier1.decision_client import decision_client
from app.tier2 import stt


def test_live_call_prepared_and_legacy_audio_both_produce_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'db_path', tmp_path / 'flow.db')
    monkeypatch.setattr(settings, 'openai_api_key', None)
    monkeypatch.setattr(settings, 'openrouter_api_key', None)
    monkeypatch.setattr(settings, 'decision_enabled', False)
    monkeypatch.setattr(decision_client, '_http', None)
    monkeypatch.setattr(decision_client, '_ts', None)
    monkeypatch.setattr(local_models, 'load', lambda: None)
    monkeypatch.setattr(voice_detector, 'load', lambda: None)
    monkeypatch.setattr(local_models, 'score', lambda env: LocalScores(p_local=.95, per_model={}, url_scores={}, latency_ms=0))
    monkeypatch.setattr(call_stream.voice_deepfake, 'p_fake', lambda *args: None)
    transcript = 'HDFC Bank: share your OTP 829104 at https://hdfc-verify.top now.'
    stt_calls = []
    async def recognize(*args):
        stt_calls.append(1)
        return transcript
    monkeypatch.setattr(stt, 'transcribe', recognize)
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wav:
        wav.setnchannels(1); wav.setsampwidth(2); wav.setframerate(16000)
        wav.writeframes(b'\0\0' * 16000)
    upload = {'file': ('chunk.wav', buf.getvalue(), 'audio/wav')}
    from app.main import app
    with TestClient(app) as client:
        created = client.post('/api/call/session', json={})
        assert created.status_code == 200
        assert created.json()['capabilities']['prepared_transcription'] is True
        sid = created.json()['session_id']
        prepared = client.post(f'/api/call/session/{sid}/transcribe', files=upload)
        assert prepared.status_code == 200
        data = {'seq': '0', 'transcription_prepared': 'true', 'transcribed_text': prepared.json()['text']}
        first = client.post(f'/api/call/session/{sid}/chunk', files=upload, data=data)
        assert first.status_code == 200
        assert first.json()['transcript'] == transcript
        assert first.json()['verdict'] == 'SCAM' and first.json()['alert'] is True
        again = client.post(f'/api/call/session/{sid}/chunk', files=upload, data={**data, 'seq': '1'})
        assert again.status_code == 200 and again.json()['alert'] is False
        assert len(stt_calls) == 1  # prepared text is never transcribed a second time
        ended = client.post(f'/api/call/session/{sid}/end')
        assert ended.status_code == 200 and ended.json()['alert'] is False
        # The exact original wire protocol remains supported for older clients/servers.
        sid = client.post('/api/call/session', json={}).json()['session_id']
        legacy = client.post(f'/api/call/session/{sid}/chunk', files=upload, data={'seq': '0'})
        assert legacy.status_code == 200
        assert legacy.json()['verdict'] == 'SCAM' and legacy.json()['alert'] is True
        assert legacy.json()['text'] == transcript
        assert len(stt_calls) == 2
        assert client.post(f'/api/call/session/{sid}/end').status_code == 200
