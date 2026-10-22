import { expect, test } from 'bun:test';
import { OrderedAudioQueue } from '../src/lib/orderedAudioQueue';

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const tick = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

test('prepares concurrently, commits in order, and retains every queued chunk', async () => {
  const gates = Array.from({ length: 5 }, () => deferred<string>());
  const started: number[] = [], committed: number[] = [], errors: unknown[] = [];
  const queue = new OrderedAudioQueue<number, string>(async n => {
    started.push(n); return gates[n].promise;
  }, async (n, text) => { expect(text).toBe(String(n)); committed.push(n); }, error => errors.push(error));
  for (let i = 0; i < 5; i++) queue.push(i);
  expect(started).toEqual([0, 1]);
  gates[1].resolve('1'); await tick();
  expect(committed).toEqual([]);
  expect(started).toEqual([0, 1, 2]);
  gates[0].resolve('0'); await tick();
  expect(committed).toEqual([0, 1]);
  for (let i = 2; i < 5; i++) gates[i].resolve(String(i));
  await queue.drain();
  expect(committed).toEqual([0, 1, 2, 3, 4]);
  expect(errors).toEqual([]);
});

test('a failed chunk is reported and does not wedge drain or later chunks', async () => {
  const errors: unknown[] = [], committed: number[] = [];
  const queue = new OrderedAudioQueue<number, string>(async n => {
    if (n === 0) throw new Error('transcription failed');
    return String(n);
  }, async n => {
    if (n === 1) throw new Error('analysis failed');
    committed.push(n);
  }, error => errors.push(error));
  queue.push(0); queue.push(1); queue.push(2);
  await queue.drain();
  expect(errors).toHaveLength(2);
  expect(committed).toEqual([2]);
});
