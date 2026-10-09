import { expect, it } from 'vitest';
import { createOutputQueue } from '../src/watch/output-queue.js';

it('WATCH/output-priority priority lines may exceed the normal limit but never grow without bound', () => {
  // A writer that never completes: nothing leaves the queue.
  const queue = createOutputQueue(() => new Promise<number>(() => undefined), 1_000);
  const line = 'x'.repeat(99) + '\n';
  for (let n = 0; n < 10_000; n++) queue.push(line, true);
  // At most four times the limit is held (40 lines of 100 bytes); the rest are dropped and counted.
  expect(queue.dropped()).toBeGreaterThanOrEqual(10_000 - 41);
  for (let n = 0; n < 10; n++) queue.push(line);
  expect(queue.dropped()).toBeGreaterThanOrEqual(10_000 - 41 + 10);
});
