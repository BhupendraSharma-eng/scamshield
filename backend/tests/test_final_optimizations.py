"""Parallel demo preparation, ordered scoring, and no repeated inference during silence."""
import asyncio
import io
import wave

import numpy as np
from fastapi import UploadFile
from app.api import call_stream as calls


def wav():
    out = io.BytesIO()
    with wave.open(out, 'wb') as handle:
        handle.setnchannels(1); handle.setsampwidth(2); handle.setframerate(16000)
        handle.writeframes(b'\0\0' * 16000)
    return out.getvalue()


def test_file_transcription_overlaps_but_scoring_is_ordered(monkeypatch):
    async def check():
        second_started = asyncio.Event()
        prepared, committed = [], []
        async def stt(data, filename):
            index = int(filename.split('-')[1].split('.')[0])
            prepared.append(index)
            if index == 1:
                await second_started.wait()
            if index == 2:
                second_started.set()
            return f'words {index}', 10.0
        async def score(sid, data, seq, filename, text=None, elapsed=0):
            committed.append((seq, text))
            return calls._listening(sid, seq, text, text, calls.DeepfakeInfo(), calls.LatencyMs(stt=elapsed, decision=0, deepfake=0, total=elapsed))
        monkeypatch.setattr(calls, '_timed_stt', stt)
        monkeypatch.setattr(calls, '_handle_chunk', score)
        monkeypatch.setattr(calls, 'decode_to_16k', lambda *args: np.zeros(9 * 16000, dtype=np.float32))
        result = await asyncio.wait_for(calls.analyze_file(UploadFile(filename='demo.wav', file=io.BytesIO(wav()))), 1)
        assert prepared == [1, 2, 3]
        assert committed == [(1, 'words 1'), (2, 'words 2'), (3, 'words 3')]
        assert len(result['updates']) == 3
        assert result['updates'][0].session_id not in calls.sessions
    asyncio.run(check())


def test_silent_chunk_reuses_last_verdict_without_repeating_model_or_alert(monkeypatch):
    async def check():
        sid = calls._create_session('')
        session = calls.sessions[sid]
        transcript = 'Please share your OTP with the caller now.'
        old = calls._listening(sid, 0, transcript, transcript, calls.DeepfakeInfo(), calls.LatencyMs(stt=1, decision=1, deepfake=1, total=2))
        old = old.model_copy(update={'verdict': 'SCAM', 'risk': .9, 'alert': True})
        session.update(transcript=transcript, last=old, alerted=True)
        def fake_voice(*args):
            return None, 0.0
        async def forbidden(*args, **kwargs):
            raise AssertionError('No decision or transcription request for an already-prepared silent chunk')
        monkeypatch.setattr(calls, '_timed_p_fake', fake_voice)
        monkeypatch.setattr(calls, 'analyze', forbidden)
        monkeypatch.setattr(calls, '_timed_stt', forbidden)
        try:
            result = await calls._handle_chunk(sid, wav(), 1, 'chunk.wav', '', 0)
            assert result.verdict == 'SCAM'
            assert result.risk == .9
            assert result.transcript == transcript
            assert result.text == '' and result.seq == 1
            assert result.alert is False
            assert result.latency_ms.decision == 0
        finally:
            calls.sessions.pop(sid, None)
    asyncio.run(check())
