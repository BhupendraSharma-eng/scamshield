import { afterEach, expect, test } from 'bun:test';
import { callRequest } from '../src/lib/callApi';
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test('a stalled fetch times out instead of wedging the audio queue', async () => {
  globalThis.fetch = ((_url: unknown, init: RequestInit) => new Promise((_resolve, reject) => {
    init.signal!.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
  })) as typeof fetch;
  await expect(callRequest('/test', {}, 5)).rejects.toThrow('timed out');
});

test('the timeout covers the response body, not just receipt of headers', async () => {
  globalThis.fetch = ((_url: unknown, init: RequestInit) => Promise.resolve({
    ok: true,
    json: () => new Promise((_resolve, reject) => {
      init.signal!.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }),
  })) as typeof fetch;
  await expect(callRequest('/test', {}, 5)).rejects.toThrow('timed out');
});

test('success clears the timer and server errors keep their explanation', async () => {
  let signal: AbortSignal | undefined;
  globalThis.fetch = ((_url: unknown, init: RequestInit) => {
    signal = init.signal!;
    return Promise.resolve(Response.json({ text: 'hello' }));
  }) as typeof fetch;
  expect(await callRequest('/test', {}, 5)).toEqual({ text: 'hello' });
  await new Promise(resolve => setTimeout(resolve, 10));
  expect(signal!.aborted).toBe(false);
  globalThis.fetch = (() => Promise.resolve(Response.json({ detail: 'Call session not found.' }, { status: 404 }))) as typeof fetch;
  await expect(callRequest('/test', {})).rejects.toThrow('Call session not found.');
});

test('an older backend uses the original chunk endpoint for the complete live flow', async () => {
  const { callApi, createLiveCallTransport } = await import('../src/lib/callApi');
  const paths: string[] = [];
  const audio = new Blob(['original-audio'], { type: 'audio/wav' });
  globalThis.fetch = (async (url: unknown, init: RequestInit) => {
    const path = String(url); paths.push(path);
    expect(init.method).toBe('POST');
    if (path.endsWith('/session')) return Response.json({ session_id: 'old' });
    if (path.endsWith('/chunk')) {
      const form = init.body as FormData;
      expect(form.get('transcription_prepared')).toBeNull();
      expect(await (form.get('file') as Blob).text()).toBe('original-audio');
      return Response.json({ text: 'Recognized speech', transcript: 'Recognized speech' });
    }
    if (path.endsWith('/end')) return Response.json({ alert: false });
    throw new Error(`Unexpected request ${path}`);
  }) as typeof fetch;
  const session = await callApi.createSession();
  const transport = createLiveCallTransport(session);
  const prepared = await transport.prepare(audio);
  expect(prepared).toBeUndefined();
  expect((await transport.send(audio, 0, prepared)).text).toBe('Recognized speech');
  await callApi.endSession(session.session_id);
  expect(paths).toEqual(['/api/call/session', '/api/call/session/old/chunk', '/api/call/session/old/end']);
});

for (const status of [404, 405]) {
  test(`preparation HTTP ${status} falls back without losing audio or repeating the unsupported request`, async () => {
    const { createLiveCallTransport } = await import('../src/lib/callApi');
    const paths: string[] = [];
    globalThis.fetch = (async (url: unknown, init: RequestInit) => {
      const path = String(url); paths.push(path);
      if (path.endsWith('/transcribe')) return Response.json({ detail: 'Method Not Allowed' }, { status });
      expect(path.endsWith('/chunk')).toBe(true);
      const form = init.body as FormData;
      expect(await (form.get('file') as Blob).text()).toBe('speech');
      expect(form.get('transcription_prepared')).toBeNull();
      return Response.json({ text: 'Recognized speech' });
    }) as typeof fetch;
    const transport = createLiveCallTransport({ session_id: 'mixed', capabilities: { prepared_transcription: true } });
    const audio = new Blob(['speech']);
    for (let seq = 0; seq < 2; seq++) {
      const prepared = await transport.prepare(audio);
      await transport.send(audio, seq, prepared);
    }
    expect(paths.filter(path => path.endsWith('/transcribe'))).toHaveLength(1);
    expect(paths.filter(path => path.endsWith('/chunk'))).toHaveLength(2);
  });
}

test('a current backend keeps pipelined transcription and forwards prepared speech', async () => {
  const { createLiveCallTransport } = await import('../src/lib/callApi');
  globalThis.fetch = (async (url: unknown, init: RequestInit) => {
    if (String(url).endsWith('/transcribe')) return Response.json({ text: 'hello there', latency_ms: 12 });
    const form = init.body as FormData;
    expect(form.get('transcription_prepared')).toBe('true');
    expect(form.get('transcribed_text')).toBe('hello there');
    expect(form.get('transcription_ms')).toBe('12');
    return Response.json({ text: 'hello there' });
  }) as typeof fetch;
  const transport = createLiveCallTransport({ session_id: 'new', capabilities: { prepared_transcription: true } });
  const audio = new Blob(['speech']);
  expect((await transport.send(audio, 0, await transport.prepare(audio))).text).toBe('hello there');
});

test('provider failures are reported instead of treated as missing endpoint support', async () => {
  const { createLiveCallTransport } = await import('../src/lib/callApi');
  globalThis.fetch = (() => Promise.resolve(Response.json({ detail: 'Provider unavailable' }, { status: 503 }))) as typeof fetch;
  const transport = createLiveCallTransport({ session_id: 'new', capabilities: { prepared_transcription: true } });
  await expect(transport.prepare(new Blob(['speech']))).rejects.toThrow('Provider unavailable');
});
