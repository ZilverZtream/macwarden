import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createSecureServer, type Http2SecureServer, type ServerHttp2Session, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { registerMiddleware, type MiddlewareCall } from '../src/lnd/index.js';
import { openGrpcStream } from '../src/lnd/grpc.js';
import { Secret } from '../src/secret.js';

// A real local TLS HTTP/2 peer standing in for a hostile or broken LND. Message bytes are
// written by hand from lnrpc/lightning.proto (v0.21.4-beta), independently of the decoder.
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const own = readFileSync(join(resolve(), 'test/vectors/default-admin.macaroon'));
let dir: string;
let tls: { key: Buffer; ca: Buffer };

beforeAll(() => {
  mkdirSync(tmpRoot, { recursive: true });
  dir = mkdtempSync(join(tmpRoot, 'watch-peer-'));
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, 'peer.key'), crt = join(dir, 'peer.crt');
  const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-config', config,
    '-keyout', key, '-out', crt, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8', timeout: 20_000 });
  if (run.status !== 0) throw new Error('Local TLS certificate generation failed');
  tls = { key: readFileSync(key), ca: readFileSync(crt) };
});
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

const varint = (value: number) => { const out: number[] = []; do { let b = value & 0x7f; value = Math.floor(value / 128); if (value) b |= 0x80; out.push(b); } while (value); return Buffer.from(out); };
const ld = (field: number, bytes: Buffer) => Buffer.concat([varint((field << 3) | 2), varint(bytes.length), bytes]);
const vi = (field: number, value: number) => Buffer.concat([varint(field << 3), varint(value)]);
const frame = (message: Buffer) => { const head = Buffer.alloc(5); head.writeUInt32BE(message.length, 1); return Buffer.concat([head, message]); };
const regComplete = frame(Buffer.concat([vi(1, 1), vi(8, 1), vi(7, 1)]));
// RPCMiddlewareRequest{ request_id, raw_macaroon, custom_caveat_condition, request: RPCMessage{ method_full_uri }, msg_id }
const intercept = (fields: { macaroon?: Buffer; condition?: string; method: string; msgId: number }) => frame(Buffer.concat([
  vi(1, fields.msgId), ...(fields.macaroon ? [ld(2, fields.macaroon)] : []),
  ...(fields.condition !== undefined ? [ld(3, Buffer.from(fields.condition))] : []),
  ld(5, ld(1, Buffer.from(fields.method))), vi(7, fields.msgId)]));

async function peer(onStream: (stream: ServerHttp2Stream) => void) {
  let current: ServerHttp2Stream | undefined;
  const server: Http2SecureServer = createSecureServer({ key: tls.key, cert: tls.ca });
  const sessions = new Set<ServerHttp2Session>();
  server.on('session', session => { sessions.add(session); session.on('close', () => sessions.delete(session)); });
  server.on('stream', stream => {
    current = stream;
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' });
    onStream(stream);
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const port = (server.address() as AddressInfo).port;
  return { url: { host: '127.0.0.1', port }, close: () => new Promise<void>(done => { current?.close(); for (const session of sessions) session.destroy(); server.close(() => done()); }) };
}

it('WATCH/peer-registration a peer that never confirms registration ends the session (old: silent forever)', async () => {
  const p = await peer(() => undefined);
  const started = performance.now();
  const session = registerMiddleware({ ...p.url, tlsCert: tls.ca, macaroon: new Secret(own), registrationTimeoutMs: 300 },
    { name: 'macwarden-watch', readOnly: true }, () => '', () => undefined);
  const end = await Promise.race([session.ended, new Promise(done => setTimeout(() => done('still waiting'), 5_000))]);
  expect(end).toMatchObject({ registered: false, code: 4, message: 'LND did not complete the middleware registration' });
  expect(performance.now() - started).toBeLessThan(3_000);
  session.close();
  await p.close();
});

it('WATCH/peer-stall a message that stops arriving midway ends the session and frees its buffer', async () => {
  const p = await peer(stream => {
    stream.write(regComplete);
    // Announce 1 MiB, send 10 bytes, then nothing.
    const head = Buffer.alloc(5); head.writeUInt32BE(1024 * 1024, 1);
    stream.write(Buffer.concat([head, Buffer.alloc(10)]));
  });
  const end = await new Promise(done => {
    const stream = openGrpcStream({ ...p.url, ca: tls.ca, path: '/lnrpc.Lightning/RegisterRPCMiddleware', metadata: {}, stallTimeoutMs: 300 },
      () => undefined);
    void stream.ended.then(done);
    setTimeout(() => done('still waiting'), 5_000);
  });
  expect(end).toMatchObject({ message: 'stalled gRPC message', transport: true });
  await p.close();
});

it('WATCH/peer-fields oversized method, macaroon and condition fields are capped before they are copied or decoded', async () => {
  const calls: MiddlewareCall[] = [];
  const hugeMethod = `/${'a'.repeat(4 * 1024 * 1024)}/X`;
  const p = await peer(stream => {
    stream.write(regComplete);
    stream.write(intercept({ msgId: 2, method: hugeMethod, macaroon: Buffer.alloc(1024 * 1024, 1), condition: 'c'.repeat(1024) }));
    stream.write(intercept({ msgId: 3, method: '/lnrpc.Lightning/GetInfo', macaroon: own, condition: '3a1e61423be44eaf' }));
  });
  const started = performance.now();
  const session = registerMiddleware({ ...p.url, tlsCert: tls.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch', readOnly: true }, call => { calls.push({ ...call }); return ''; }, () => undefined);
  for (let i = 0; i < 500 && calls.length < 2; i++) await new Promise(r => setTimeout(r, 10));
  const elapsed = performance.now() - started;
  // Audit 1.4.0: of the 1 MiB macaroon only a 4 KiB prefix (its header) is passed on, never the whole field.
  expect(calls[0]).toMatchObject({ method: '/unknown/Unknown', macaroonBytes: 4 * 1024, oversizedMacaroon: true, customCaveatCondition: '' });
  expect(calls[0].macaroon).not.toBeNull();
  // Normal-sized fields pass through unchanged.
  expect(calls[1]).toMatchObject({ method: '/lnrpc.Lightning/GetInfo', customCaveatCondition: '3a1e61423be44eaf', macaroonBytes: own.length });
  expect(calls[1].macaroon).not.toBeNull();
  process.stdout.write(`peer-fields: 4 MiB method + 1 MiB macaroon handled in ${elapsed.toFixed(0)} ms\n`);
  session.close();
  await p.close();
}, 30_000);

it('WATCH/peer-backpressure a peer that stops reading feedback ends the session instead of growing memory', async () => {
  // The peer has opened the stream and stopped reading it: a positive signal, not a fixed wait.
  let paused!: () => void;
  const reading = new Promise<void>(done => { paused = done; });
  const p = await peer(stream => { stream.pause(); paused(); });
  const stream = openGrpcStream({ ...p.url, ca: tls.ca, path: '/lnrpc.Lightning/RegisterRPCMiddleware', metadata: {} }, () => undefined);
  await reading;
  let accepted = 0;
  for (let n = 0; n < 40; n++) if (stream.send(Buffer.alloc(1024 * 1024))) accepted += 1; else break;
  const end = await Promise.race([stream.ended, new Promise(done => setTimeout(() => done('still open'), 5_000))]);
  expect(end).toMatchObject({ message: 'LND is not reading middleware feedback', transport: true });
  // About 16 MiB are buffered before the session gives up, never 40 MiB.
  expect(accepted).toBeLessThanOrEqual(17);
  await p.close();
}, 30_000);

it('WATCH/peer-backpressure-flow feedback held by HTTP/2 flow control (a peer that stopped reading) is bounded at 16 MiB', async () => {
  // Small writes spread over many turns each leave our writable buffer at once and wait in
  // HTTP/2 flow control, where writableLength cannot see them: only counting what is not yet
  // flushed bounds them (old: the session stayed open while memory grew without limit).
  // The peer has opened the stream and stopped reading it: a positive signal, not a fixed wait.
  let paused!: () => void;
  const reading = new Promise<void>(done => { paused = done; });
  const p = await peer(stream => { stream.pause(); paused(); });
  const stream = openGrpcStream({ ...p.url, ca: tls.ca, path: '/lnrpc.Lightning/RegisterRPCMiddleware', metadata: {} }, () => undefined);
  await reading;
  let sent = 0;
  let open = true;
  const chunk = Buffer.alloc(64 * 1024);
  for (let turn = 0; turn < 1_024 && open; turn++) {
    if (stream.send(chunk)) sent += chunk.length; else open = false;
    await new Promise(resolve => setImmediate(resolve));
  }
  const end = await Promise.race([stream.ended, new Promise(done => setTimeout(() => done('still open'), 5_000))]);
  expect(end).toMatchObject({ message: 'LND is not reading middleware feedback', transport: true });
  process.stdout.write(`peer-backpressure-flow: session ended after ${(sent / 2 ** 20).toFixed(1)} MiB of unread feedback\n`);
  expect(sent).toBeLessThanOrEqual(17 * 1024 * 1024);
  await p.close();
}, 60_000);

it('WATCH/peer-announced a message announced at 190 MiB but never sent costs what arrived, not the announced length', async () => {
  const p = await peer(stream => {
    const head = Buffer.alloc(5); head.writeUInt32BE(190 * 1024 * 1024, 1);
    stream.write(Buffer.concat([head, Buffer.alloc(10)]));
  });
  global.gc?.();
  const before = process.memoryUsage().arrayBuffers;
  let peak = before;
  const sampler = setInterval(() => { peak = Math.max(peak, process.memoryUsage().arrayBuffers); }, 5);
  const stream = openGrpcStream({ ...p.url, ca: tls.ca, path: '/lnrpc.Lightning/RegisterRPCMiddleware', metadata: {}, stallTimeoutMs: 500 },
    () => undefined);
  const end = await Promise.race([stream.ended, new Promise(done => setTimeout(() => done('still waiting'), 5_000))]);
  clearInterval(sampler);
  expect(end).toMatchObject({ message: 'stalled gRPC message' });
  process.stdout.write(`peer-announced: array buffers grew by at most ${((peak - before) / 2 ** 20).toFixed(1)} MiB\n`);
  // Old: 190 MiB reserved the moment the header arrived.
  expect(peak - before).toBeLessThan(16 * 1024 * 1024);
  await p.close();
}, 30_000);

it('WATCH/peer-lazy-macaroon the caller macaroon is a Secret while the handler runs and gone afterwards', async () => {
  const seen: { during: boolean; call: MiddlewareCall }[] = [];
  const skipped: MiddlewareCall[] = [];
  const p = await peer(stream => {
    stream.write(regComplete);
    stream.write(intercept({ msgId: 2, method: '/lnrpc.Lightning/GetInfo', macaroon: own }));
    stream.write(intercept({ msgId: 3, method: '/lnrpc.Lightning/GetInfo', macaroon: own }));
  });
  let n = 0;
  const session = registerMiddleware({ ...p.url, tlsCert: tls.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch', readOnly: true }, call => {
      // The first handler reads the macaroon; the second never does (an observer shedding load).
      if (n++ === 0) seen.push({ during: call.macaroon instanceof Secret, call }); else skipped.push(call);
      return '';
    }, () => undefined);
  for (let i = 0; i < 500 && seen.length + skipped.length < 2; i++) await new Promise(r => setTimeout(r, 10));
  expect(seen[0].during).toBe(true);
  expect(seen[0].call.macaroon).toBeNull();
  expect(skipped[0].macaroonBytes).toBe(own.length);
  expect(skipped[0].macaroon).toBeNull();
  session.close();
  await p.close();
}, 30_000);

it('WATCH/peer-split messages split anywhere (across 64 KiB blocks, many per chunk, a byte at a time) arrive intact', async () => {
  const big = Buffer.alloc(200 * 1024 + 7);
  for (let i = 0; i < big.length; i++) big[i] = (i * 31) & 0xff;
  const small = [Buffer.from('a'), Buffer.alloc(0), Buffer.from('xyz')];
  const wire = Buffer.concat([...small.map(frame), frame(big), frame(Buffer.from('tail'))]);
  const p = await peer(stream => {
    void (async () => {
      // Odd-sized pieces, then the last 64 bytes one at a time.
      let at = 0;
      for (const size of [3, 1, 9_000, 65_536, 65_535]) {
        stream.write(wire.subarray(at, at + size)); at += size;
        await new Promise(resolve => setImmediate(resolve));
      }
      while (at < wire.length) {
        stream.write(wire.subarray(at, at + (wire.length - at > 64 ? 4_096 : 1))); at += wire.length - at > 64 ? 4_096 : 1;
        await new Promise(resolve => setImmediate(resolve));
      }
    })();
  });
  const received: Buffer[] = [];
  const stream = openGrpcStream({ ...p.url, ca: tls.ca, path: '/lnrpc.Lightning/RegisterRPCMiddleware', metadata: {} },
    message => { received.push(Buffer.from(message)); });
  for (let i = 0; i < 500 && received.length < 5; i++) await new Promise(r => setTimeout(r, 10));
  expect(received.map(item => item.toString('hex'))).toEqual([...small, big, Buffer.from('tail')].map(item => item.toString('hex')));
  stream.close();
  await p.close();
}, 30_000);

it('WATCH/peer-split-header a chunk that ends right after the header of a split message still assembles it intact', async () => {
  const body = Buffer.from('0123456789abcdef');
  const head = Buffer.alloc(5); head.writeUInt32BE(body.length, 1);
  const p = await peer(stream => {
    void (async () => {
      for (const piece of [head, body.subarray(0, 7), body.subarray(7)]) {
        stream.write(piece);
        await new Promise(resolve => setTimeout(resolve, 20));
      }
    })();
  });
  const received: Buffer[] = [];
  const stream = openGrpcStream({ ...p.url, ca: tls.ca, path: '/lnrpc.Lightning/RegisterRPCMiddleware', metadata: {} },
    message => { received.push(Buffer.from(message)); });
  for (let i = 0; i < 300 && received.length < 1; i++) await new Promise(r => setTimeout(r, 10));
  expect(received.map(item => item.toString())).toEqual([body.toString()]);
  stream.close();
  await p.close();
}, 30_000);
