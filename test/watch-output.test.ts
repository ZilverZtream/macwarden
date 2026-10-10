import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createSecureServer } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { createOutputQueue } from '../src/watch/output-queue.js';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
let dir: string;

beforeAll(() => { mkdirSync(tmpRoot, { recursive: true }); dir = mkdtempSync(join(tmpRoot, 'watch-output-')); });
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

it('WATCH/output-queue keeps order across partial writes, drops ordinary lines over the limit, never priority lines', async () => {
  const written: Buffer[] = [];
  let release!: () => void;
  let gate = new Promise<void>(done => { release = done; });
  // A writer that is blocked until released, then writes at most 7 bytes per call.
  const queue = createOutputQueue(async chunk => { await gate; written.push(chunk.subarray(0, 7)); return Math.min(7, chunk.length); }, 20);
  queue.push('aaaaaaaaaa\n');
  queue.push('bbbbbbbbbb\n');           // 22 bytes queued would exceed 20: dropped
  queue.push('ALERT\n', true);           // priority: always kept
  queue.push('cc\n');                    // fits again
  expect(queue.dropped()).toBe(1);
  expect(await queue.drain(50)).toBe(false);
  release();
  gate = Promise.resolve();
  expect(await queue.drain(2_000)).toBe(true);
  expect(Buffer.concat(written).toString('utf8')).toBe('aaaaaaaaaa\nALERT\ncc\n');
});

it('WATCH/output-queue a write error (closed pipe) stops output quietly and counts what was lost', async () => {
  let calls = 0;
  const queue = createOutputQueue(async () => { calls += 1; throw Object.assign(new Error('EPIPE'), { code: 'EPIPE' }); });
  queue.push('one\n');
  expect(await queue.drain(1_000)).toBe(true);
  queue.push('two\n');
  queue.push('three\n', true);
  expect(calls).toBe(1);
  // The line whose write failed is lost too (1.2.1), with the two refused after the pipe closed.
  expect(queue.dropped()).toBe(3);
});

const varint = (value: number) => { const out: number[] = []; do { let b = value & 0x7f; value = Math.floor(value / 128); if (value) b |= 0x80; out.push(b); } while (value); return Buffer.from(out); };
const ld = (field: number, bytes: Buffer) => Buffer.concat([varint((field << 3) | 2), varint(bytes.length), bytes]);
const vi = (field: number, value: number) => Buffer.concat([varint(field << 3), varint(value)]);
const frame = (message: Buffer) => { const head = Buffer.alloc(5); head.writeUInt32BE(message.length, 1); return Buffer.concat([head, message]); };

it('WATCH/output-stall intercept feedback keeps flowing while nobody reads the watcher\'s stdout', async () => {
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, 'lnd.key'), crt = join(dir, 'lnd.crt');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-config', config,
    '-keyout', key, '-out', crt, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8', timeout: 20_000 });
  expect(made.status).toBe(0);
  const caller = readFileSync(join(repo, 'test/vectors/preset-read-only.macaroon'));
  const total = 2000;
  const sent = new Map<number, number>();
  let worst = 0;
  let answered = 0;
  let allAnswered!: () => void;
  const finished = new Promise<void>(done => { allAnswered = done; });
  const server = createSecureServer({ key: readFileSync(key), cert: readFileSync(crt) });
  server.on('sessionError', () => undefined);
  server.on('stream', stream => {
    // Killing the child at the end resets the connection.
    stream.on('error', () => undefined);
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' });
    let buffer = Buffer.alloc(0);
    let registered = false;
    stream.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 5 && buffer.length >= 5 + buffer.readUInt32BE(1)) {
        const length = buffer.readUInt32BE(1);
        const message = buffer.subarray(5, 5 + length);
        buffer = buffer.subarray(5 + length);
        if (!registered) {
          registered = true;
          stream.write(frame(vi(8, 1)));
          let next = 0;
          const tick = setInterval(() => {
            for (let k = 0; k < 20 && next < total; k++, next++) {
              const id = next + 2;
              sent.set(id, performance.now());
              stream.write(frame(Buffer.concat([vi(1, id), ld(2, caller), ld(5, ld(1, Buffer.from('/lnrpc.Lightning/GetInfo'))), vi(7, id)])));
            }
            if (next >= total) clearInterval(tick);
          }, 5);
          continue;
        }
        // RPCMiddlewareResponse{ ref_msg_id(1) = varint }: read it independently.
        let value = 0, shift = 0, at = 1;
        for (;;) { const byte = message[at++]; value += (byte & 0x7f) * 2 ** shift; if (!(byte & 0x80)) break; shift += 7; }
        worst = Math.max(worst, performance.now() - sent.get(value)!);
        if (++answered === total) allAnswered();
      }
    });
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const port = (server.address() as AddressInfo).port;
  const child = spawn(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import',
    pathToFileURL(resolve('test/helpers/cp038-loader.mjs')).href, resolve('test/helpers/watch-stall-child.mjs'),
    String(port), crt, join(repo, 'test/vectors/default-admin.macaroon')],
  { env: childEnvironment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  // child.stdout is deliberately never read: the pipe fills and stays full.
  let stderr = '';
  child.stderr!.on('data', chunk => { stderr += String(chunk); });
  try {
    await Promise.race([finished, new Promise((_, fail) => setTimeout(() => fail(new Error(`not all intercepts answered: ${answered}/${total}; ${stderr}`)), 60_000))]);
    child.send('report');
    for (let wait = 0; wait < 200 && !/dropped \d+/.test(stderr); wait++) await new Promise(done => setTimeout(done, 25));
    // The stall was real (lines were dropped), and LND never waited on it.
    expect(Number(/dropped (\d+)/.exec(stderr)?.[1])).toBeGreaterThan(0);
    expect(worst).toBeLessThan(250);
  } finally {
    child.kill('SIGKILL');
    server.close();
  }
}, 90_000);

// 1.2.1 (owner finding): the batch whose write failed is lost too, and counts as dropped.
it('WATCH/output-queue a write that fails counts the batch it was writing as dropped', async () => {
  const queue = createOutputQueue(async () => { throw Object.assign(new Error('broken pipe'), { code: 'EPIPE' }); });
  queue.push('one\n');
  queue.push('two\n');
  expect(await queue.drain(1_000)).toBe(true);
  expect(queue.dropped()).toBe(2);
  queue.push('three\n');
  expect(queue.dropped()).toBe(3);
});

// 1.2.1 (audit F11): a partially written batch is requeued line by line, so a later loss
// counts every line that was not completely written, not one buffer.
it('WATCH/output-queue a partial write keeps line boundaries, so a later failure counts every unwritten line', async () => {
  const results: (() => Promise<number>)[] = [];
  const calls: string[] = [];
  let releaseFirst!: () => void;
  const first = new Promise<void>(done => { releaseFirst = done; });
  results.push(async () => { await first; return 5; });                                  // 'zero\n' written whole
  results.push(async () => 1);                                                           // one byte of the batch
  results.push(async () => { throw Object.assign(new Error('broken pipe'), { code: 'EPIPE' }); });
  const queue = createOutputQueue(chunk => { calls.push(chunk.toString('utf8')); return results.shift()!(); });
  queue.push('zero\n');
  queue.push('one\n');
  queue.push('two\n');
  queue.push('three\n');
  releaseFirst();
  expect(await queue.drain(1_000)).toBe(true);
  // The three lines were written as one coalesced batch; the remainder was retried in order.
  expect(calls).toEqual(['zero\n', 'one\ntwo\nthree\n', 'ne\ntwo\nthree\n']);
  expect(queue.dropped()).toBe(3);
});

// 1.2.1 (audit F11): after close the remainder of a partial write is dropped and counted,
// never requeued, and settle and drain resolve as soon as that write completes.
it('WATCH/output-queue close during a write drops its unwritten remainder and settles at once', async () => {
  let blockFirst!: (written: number) => void;
  let calls = 0;
  const blocked = createOutputQueue(() => { calls += 1; return new Promise<number>(done => { blockFirst = done; }); });
  blocked.push('zero\n');                // in flight
  blocked.push('one\n');
  blocked.push('two\n');
  blockFirst(5);
  await new Promise(resolve => setImmediate(resolve));
  expect(calls).toBe(2);                 // 'one\ntwo\n' is now in flight as one batch
  blocked.push('three\n');               // queued behind it
  blocked.close();
  expect(blocked.dropped()).toBe(1);     // the queued line
  const started = Date.now();
  const settled = blocked.settle(5_000);
  const drained = blocked.drain(5_000);
  blockFirst(1);                         // one byte of the batch, then nothing more may be written
  expect(await settled).toBe(true);
  expect(await drained).toBe(true);
  expect(Date.now() - started).toBeLessThan(1_000);
  expect(calls).toBe(2);
  expect(blocked.dropped()).toBe(3);     // 'ne\n' and 'two\n' were never completely written
});
