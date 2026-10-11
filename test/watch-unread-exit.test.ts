import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { createOutputQueue, fdWriter } from '../src/watch/output-queue.js';
import { childEnvironment } from './helpers/environment.js';

// Fresh audit (2026-10-08): with stdout an open pipe that is never read, `watch --until`
// never exited: write retries (Linux) or a pending blocking write (Windows) kept it alive.
it('WATCH/unread-exit watch exits with its status in bounded time while stdout is never read (real bin entry point)', async () => {
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/watch-unread-exit-child.mjs'), 'watch', '--json'],
  { env: childEnvironment(), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  // Never read stdout: the pipe fills and stays full.
  child.stdout!.pause();
  let err = '';
  child.stderr!.on('data', chunk => { err += String(chunk); });
  const started = performance.now();
  const outcome = await new Promise<{ code: number | null; signal: string | null; timedOut: boolean }>(done => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); done({ code: null, signal: null, timedOut: true }); }, 25_000);
    child.once('exit', (code, signal) => { clearTimeout(timer); done({ code, signal, timedOut: false }); });
  });
  const elapsed = performance.now() - started;
  expect(err).toMatch(/handler done dropped [1-9]\d*/);
  expect(outcome.timedOut, err).toBe(false);
  // Output could not be delivered, so the deadline terminated it: non-zero, never a hang.
  if (process.platform === 'win32') expect(outcome.code).toBe(1);
  else expect(outcome.code === 0 || outcome.signal === 'SIGKILL').toBe(true);
  // Drain 0.5 s + summary write 2 s + exit grace 3 s, plus process start-up.
  expect(elapsed).toBeLessThan(15_000);
}, 30_000);

it('WATCH/unread-exit with a reader that reads, watch exits on its own with its real status before the deadline', async () => {
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/watch-unread-exit-child.mjs'), 'watch', '--json'],
  { env: childEnvironment(), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let out = '';
  child.stdout!.on('data', chunk => { out += String(chunk); });
  let err = '';
  child.stderr!.on('data', chunk => { err += String(chunk); });
  const outcome = await new Promise<{ code: number | null; signal: string | null }>(done => {
    child.once('exit', (code, signal) => done({ code, signal }));
  });
  expect(outcome, err).toEqual({ code: 0, signal: null });
  // The summary arrives last; the burst beyond the 1 MiB output limit is dropped by design.
  expect(out.trimEnd().split(/\r?\n/).at(-1)).toMatch(/"command":"watch"/);
}, 30_000);

it('WATCH/unread-exit close drops and counts queued lines and stops a writer that keeps getting EAGAIN', async () => {
  let attempts = 0;
  let stopped = false;
  const eagain = (_fd: number, _chunk: Buffer, callback: (error: NodeJS.ErrnoException | null, written: number) => void) => {
    attempts += 1;
    setImmediate(() => callback(Object.assign(new Error('again'), { code: 'EAGAIN' }), 0));
  };
  const queue = createOutputQueue(fdWriter(1, eagain, () => new Promise(done => setImmediate(done)), () => stopped));
  for (let i = 0; i < 100; i++) queue.push(`line ${i}\n`);
  expect(await queue.drain(50)).toBe(false);
  stopped = true;
  queue.close();
  const before = attempts;
  // The write in flight ends (its writer gives up because the queue is stopped): a positive
  // signal, after which no attempt can be scheduled, instead of a fixed 50 ms window.
  expect(await queue.settle(10_000)).toBe(true);
  // At most the one write already in flight completes; nothing retries afterwards.
  expect(attempts - before).toBeLessThanOrEqual(1);
  expect(queue.dropped()).toBeGreaterThanOrEqual(99);
  queue.push('late\n');
  expect(queue.dropped()).toBeGreaterThanOrEqual(100);
});
