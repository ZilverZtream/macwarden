import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import type { WatchEvent } from '../src/output/index.js';
import { ALERT_KILL_MS, ALERT_TIMEOUT_MS, runAlertCommand } from '../src/watch/alert.js';
import { createOutputQueue, fdWriter } from '../src/watch/output-queue.js';
import { UsageStore, writeUsage, USAGE_LIMIT } from '../src/watch/usage.js';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
let dir: string;
beforeAll(() => { mkdirSync(tmpRoot, { recursive: true }); dir = mkdtempSync(join(tmpRoot, 'watch-hardening-')); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

const canary: WatchEvent = { event: 'canary', time: '2026-10-08T12:00:00.000Z', method: '/lnrpc.Lightning/GetInfo',
  rootKeyId: '4294967342', credential: 'id:0123456789abcdef', label: 'decoy', denied: true };

it('WATCH/output-eagain a full non-blocking pipe (EAGAIN) is backpressure: the write is retried, never treated as closed', async () => {
  const waits: number[] = [];
  let attempts = 0;
  const writer = fdWriter(1, (_fd, chunk, callback) => {
    attempts += 1;
    if (attempts <= 9) callback(Object.assign(new Error('EAGAIN'), { code: 'EAGAIN' }), 0);
    else callback(null, chunk.length);
  }, async ms => { waits.push(ms); });
  expect(await writer(Buffer.from('alert\n'))).toBe(6);
  expect(attempts).toBe(10);
  // Capped exponential backoff on timers, not a busy loop.
  expect(waits).toEqual([5, 10, 20, 40, 80, 160, 200, 200, 200]);
  const closed = fdWriter(1, (_fd, _chunk, callback) => callback(Object.assign(new Error('EPIPE'), { code: 'EPIPE' }), 0), async () => undefined);
  await expect(closed(Buffer.from('x'))).rejects.toMatchObject({ code: 'EPIPE' });
});

it('WATCH/output-eagain with a reader that pauses, a canary alert sent after a burst still arrives (real child, CLI loaded)', async () => {
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/watch-eagain-child.mjs')],
  { env: childEnvironment(), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const out: Buffer[] = [];
  let err = '';
  child.stderr!.on('data', chunk => { err += String(chunk); });
  // Do not read for a second: the pipe fills while the burst is written.
  child.stdout!.pause();
  child.stdout!.on('data', chunk => { out.push(chunk); });
  setTimeout(() => child.stdout!.resume(), 1_000);
  const code = await new Promise<number | null>(done => child.once('close', done));
  const text = Buffer.concat(out).toString('utf8');
  expect(code, err).toBe(0);
  expect(text).toContain('CANARY-ALERT-MARKER');
  expect(err).toMatch(/dropped \d+ drained true/);
}, 30_000);

it('WATCH/alert-kill an alert command that never exits is abandoned at ALERT_KILL_MS (signals sent, run settles)', async () => {
  vi.useFakeTimers();
  // The tree kill uses System32 under SystemRoot; pin it so the test is platform-independent.
  const savedRoot = process.env.SystemRoot;
  process.env.SystemRoot = 'C:\\Windows';
  try {
    const signals: string[] = [];
    const spawned: { command: string; args: string[] }[] = [];
    // A fake child that ignores every signal and never reports exit.
    const spawnFake = ((command: string, args: string[]) => {
      spawned.push({ command, args });
      return { pid: 4321, once: () => undefined,
        kill: (name: string) => { signals.push(name); return true; }, stdin: { on: () => undefined, end: () => undefined } };
    }) as never;
    const outcome = runAlertCommand('/bin/alert', canary, spawnFake, 'win32').then(() => 'resolved', error => (error as Error).message);
    const taskkill = { command: 'C:\\Windows\\System32\\taskkill.exe', args: ['/T', '/F', '/PID', '4321'] };
    await vi.advanceTimersByTimeAsync(ALERT_TIMEOUT_MS);
    // Windows has no catchable SIGTERM and no process groups: the whole tree is killed at the
    // timeout while the command still runs, so its children cannot be orphaned first.
    expect(signals).toEqual([]);
    expect(spawned.slice(1)).toEqual([taskkill]);
    await vi.advanceTimersByTimeAsync(ALERT_KILL_MS - ALERT_TIMEOUT_MS);
    expect(spawned.slice(1)).toEqual([taskkill, taskkill]);
    expect(await outcome).toBe('alert command timed out');
  } finally {
    vi.useRealTimers();
    if (savedRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = savedRoot;
  }
});

it('WATCH/usage-flush a full store serializes and writes quickly, and its size is bounded', async () => {
  const store = new UsageStore();
  const at = new Date('2026-10-08T12:00:00Z');
  for (let n = 0; n < USAGE_LIMIT + 5_000; n++)
    store.record(`02${'ab'.repeat(32)}`, `id:${n.toString(16).padStart(16, '0')}`, String(4294967296 + n), '/lnrpc.Lightning/GetInfo', at);
  expect(store.size).toBe(USAGE_LIMIT);
  expect(store.evictions).toBe(5_000);
  // Event-loop cost of one flush is dominated by serialization (synchronous); the write is async.
  const runs: number[] = [];
  let text = '';
  for (let i = 0; i < 5; i++) { const start = performance.now(); text = store.toText(); runs.push(performance.now() - start); }
  const best = Math.min(...runs);
  // Measured about 10 ms at 20,000 records; the bound is generous for loaded CI machines.
  expect(best).toBeLessThan(100);
  expect(Buffer.byteLength(text)).toBeLessThan(6 * 1024 * 1024);
  const path = join(dir, 'registry.json.usage.json');
  const bytes = await writeUsage(path, store, fs);
  expect(bytes).toBe(Buffer.byteLength(readFileSync(path, 'utf8')));
  process.stdout.write(`usage flush at ${USAGE_LIMIT} records: serialize ${best.toFixed(1)} ms, ${(bytes / 1024 / 1024).toFixed(2)} MiB\n`);
}, 60_000);

it('WATCH/output-priority-eagain a queue whose writer retries keeps priority lines and delivers them once writable', async () => {
  let writable = false;
  const delivered: string[] = [];
  const queue = createOutputQueue(fdWriter(1, (_fd, chunk, callback) => {
    if (!writable) callback(Object.assign(new Error('EAGAIN'), { code: 'EAGAIN' }), 0);
    else { delivered.push(chunk.toString('utf8')); callback(null, chunk.length); }
  }), 1_000);
  for (let n = 0; n < 100; n++) queue.push(`${'x'.repeat(99)}\n`);
  queue.push('ALERT\n', true);
  await new Promise(resolve => setTimeout(resolve, 100));
  writable = true;
  expect(await queue.drain(5_000)).toBe(true);
  expect(delivered.join('')).toContain('ALERT\n');
  // Ordinary lines beyond the 1,000-byte limit were dropped and counted, not the alert.
  expect(queue.dropped()).toBeGreaterThan(0);
});
