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
