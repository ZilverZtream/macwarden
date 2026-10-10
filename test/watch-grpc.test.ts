import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createSecureServer, type Http2SecureServer, type ServerHttp2Stream } from 'node:http2';
import { createServer as createTcpServer, Socket, type AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { macaroonId } from '../src/decode/index.js';
import { registerMiddleware, type MiddlewareCall } from '../src/lnd/index.js';
import { Secret } from '../src/secret.js';

// A real local TLS HTTP/2 peer that speaks LND's RegisterRPCMiddleware framing. Expected
// bytes are written by hand from lnrpc/lightning.proto (v0.21.4-beta), independently of
// src/lnd/middleware-proto.ts.
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const own = readFileSync(join(resolve(), 'test/vectors/default-admin.macaroon'));
const caller = readFileSync(join(resolve(), 'test/vectors/preset-read-only.macaroon'));
let dir: string;
let good: { key: Buffer; ca: Buffer };
let wrong: { key: Buffer; ca: Buffer };

function cert(name: string) {
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, `${name}.key`), crt = join(dir, `${name}.crt`);
  const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', crt, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
  { encoding: 'utf8', timeout: 20_000 });
  if (run.status !== 0) throw new Error('Local TLS certificate generation failed');
  return { key: readFileSync(key), ca: readFileSync(crt) };
}

beforeAll(() => {
  mkdirSync(tmpRoot, { recursive: true });
  dir = mkdtempSync(join(tmpRoot, 'watch-grpc-'));
  good = cert('good');
  wrong = cert('wrong');
});
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

const varint = (value: number) => { const out: number[] = []; do { let b = value & 0x7f; value = Math.floor(value / 128); if (value) b |= 0x80; out.push(b); } while (value); return Buffer.from(out); };
const ld = (field: number, bytes: Buffer) => Buffer.concat([varint((field << 3) | 2), varint(bytes.length), bytes]);
const vi = (field: number, value: number) => Buffer.concat([varint(field << 3), varint(value)]);
const frame = (message: Buffer) => { const head = Buffer.alloc(5); head.writeUInt32BE(message.length, 1); return Buffer.concat([head, message]); };
const unframe = (data: Buffer) => { const out: Buffer[] = []; let at = 0; while (at + 5 <= data.length) { const n = data.readUInt32BE(at + 1); out.push(data.subarray(at + 5, at + 5 + n)); at += 5 + n; } return out; };

type Peer = { url: { host: string; port: number }; received: () => Buffer[]; headers: () => Record<string, unknown> | undefined;
  stream: () => ServerHttp2Stream | undefined; close: () => Promise<void> };

async function peer(key = good.key, ca = good.ca, onStream?: (stream: ServerHttp2Stream) => void): Promise<Peer> {
  let data = Buffer.alloc(0);
  let headers: Record<string, unknown> | undefined;
  let current: ServerHttp2Stream | undefined;
  const server: Http2SecureServer = createSecureServer({ key, cert: ca });
  server.on('stream', (stream, h) => {
    headers = h as Record<string, unknown>;
    current = stream;
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
    stream.on('data', (chunk: Buffer) => { data = Buffer.concat([data, chunk]); });
    stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0' }));
    onStream?.(stream);
  });
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  const port = (server.address() as AddressInfo).port;
  return { url: { host: '127.0.0.1', port }, received: () => unframe(data), headers: () => headers, stream: () => current,
    close: () => new Promise(done => { server.close(() => done()); for (const s of [current]) s?.close(); }) };
}

const until = async (check: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!check()) { if (Date.now() > end) throw new Error('timeout'); await new Promise(r => setTimeout(r, 10)); }
};

it('WATCH/grpc-registration read-only registration bytes, macaroon metadata and accept feedback match the proto', async () => {
  const p = await peer();
  const calls: MiddlewareCall[] = [];
  let registered = false;
  const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch', readOnly: true }, call => { calls.push({ ...call }); return ''; }, () => { registered = true; });
  await until(() => p.received().length >= 1);
  // RPCMiddlewareResponse{ register(2): MiddlewareRegistration{ middleware_name(1), read_only_mode(3)=true } }
  expect(p.received()[0].toString('hex')).toBe(ld(2, Buffer.concat([ld(1, Buffer.from('macwarden-watch')), vi(3, 1)])).toString('hex'));
  expect(p.headers()?.[':path']).toBe('/lnrpc.Lightning/RegisterRPCMiddleware');
  expect(p.headers()?.macaroon).toBe(own.toString('hex'));
  expect(p.headers()?.['content-type']).toBe('application/grpc');
  // reg_complete(8)=true, then a unary request intercept with an unknown extra field (99).
  p.stream()!.write(frame(vi(8, 1)));
  await until(() => registered);
  p.stream()!.write(frame(Buffer.concat([vi(1, 5), ld(2, caller), ld(5, ld(1, Buffer.from('/lnrpc.Lightning/GetInfo'))),
    vi(7, 7), ld(99, Buffer.from('ignored'))])));
  await until(() => p.received().length >= 2);
  // RPCMiddlewareResponse{ ref_msg_id(1)=7, feedback(3): InterceptFeedback{} } accepts.
  expect(p.received()[1].toString('hex')).toBe(Buffer.concat([vi(1, 7), ld(3, Buffer.alloc(0))]).toString('hex'));
  expect(calls).toHaveLength(1);
  expect(calls[0]).toMatchObject({ kind: 'request', method: '/lnrpc.Lightning/GetInfo', requestId: 5n, isError: false });
  // The caller's macaroon arrives as a Secret; its identity is the identifier hash.
  const identifier = (() => { let at = 1; for (;;) { const type = caller[at], len = caller[at + 1]; if (type === 2) return caller.subarray(at + 2, at + 2 + len); at += 2 + len; } })();
  expect(macaroonId(calls[0].macaroon!).id).toBe(`id:${createHash('sha256').update(identifier).digest('hex').slice(0, 16)}`);
  session.close();
  expect((await session.ended).message).toBe('closed');
  await p.close();
});

it('WATCH/grpc-deny a caveat middleware registration names the caveat and a denial carries the error text', async () => {
  const p = await peer();
  const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch-guard', readOnly: false, caveatName: 'region-a1a2f213' }, () => 'permission denied', () => undefined);
  await until(() => p.received().length >= 1);
  expect(p.received()[0].toString('hex')).toBe(ld(2, Buffer.concat([ld(1, Buffer.from('macwarden-watch-guard')),
    ld(2, Buffer.from('region-a1a2f213'))])).toString('hex'));
  p.stream()!.write(frame(vi(8, 1)));
  p.stream()!.write(frame(Buffer.concat([vi(1, 9), ld(2, caller), ld(3, Buffer.from('3a1e61423be44eaf')),
    ld(4, ld(1, Buffer.from('/lnrpc.Lightning/SubscribeInvoices'))), vi(7, 300)])));
  await until(() => p.received().length >= 2);
  expect(p.received()[1].toString('hex')).toBe(Buffer.concat([vi(1, 300), ld(3, ld(1, Buffer.from('permission denied')))]).toString('hex'));
  session.close();
  await session.ended;
  await p.close();
});

it('WATCH/grpc-tls an untrusted server certificate ends the session before any registration is sent', async () => {
  const p = await peer(wrong.key, wrong.ca);
  const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch', readOnly: true }, () => '', () => undefined);
  const end = await session.ended;
  expect(end).toMatchObject({ registered: false, code: 4, message: 'LND transport failure' });
  expect(p.received()).toHaveLength(0);
  expect(p.headers()).toBeUndefined();
  await p.close();
});

it('WATCH/grpc-disabled LND without rpcmiddleware.enable is reported as disabled, not as a transport failure', async () => {
  const p = await peer();
  // Replace the success trailers with LND's error status for a disabled middleware.
  const server = p;
  const session = registerMiddleware({ ...server.url, tlsCert: good.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch', readOnly: true }, () => '', () => undefined);
  await until(() => p.stream() !== undefined);
  p.stream()!.removeAllListeners('wantTrailers');
  p.stream()!.on('wantTrailers', () => p.stream()!.sendTrailers({ 'grpc-status': '2', 'grpc-message': 'RPC%20middleware%20not%20enabled%20in%20config' }));
  p.stream()!.end();
  const end = await session.ended;
  expect(end).toMatchObject({ registered: false, code: 4, disabled: true, message: 'LND RPC middleware is disabled' });
  await p.close();
});

it('WATCH/grpc-limits an oversized length prefix and a compressed message end the stream as invalid', async () => {
  for (const head of [Buffer.from([0, 0x20, 0, 0, 0]), Buffer.from([1, 0, 0, 0, 1])]) {
    const p = await peer();
    const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
      { name: 'macwarden-watch', readOnly: true }, () => '', () => undefined);
    await until(() => p.received().length >= 1);
    p.stream()!.write(head);
    const end = await session.ended;
    expect(end).toMatchObject({ registered: false, code: 5, message: 'invalid LND middleware stream' });
    await p.close();
  }
});

it('WATCH/grpc-order an intercept before reg_complete or a malformed varint is refused, never accepted', async () => {
  for (const message of [Buffer.concat([vi(1, 1), ld(5, ld(1, Buffer.from('/lnrpc.Lightning/GetInfo'))), vi(7, 1)]), Buffer.from([0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01])]) {
    const p = await peer();
    const decided: unknown[] = [];
    const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
      { name: 'macwarden-watch', readOnly: true }, call => { decided.push(call); return ''; }, () => undefined);
    await until(() => p.received().length >= 1);
    p.stream()!.write(frame(message));
    const end = await session.ended;
    expect(end.code).toBe(5);
    expect(decided).toHaveLength(0);
    expect(p.received()).toHaveLength(1);
    await p.close();
  }
});

it('WATCH/grpc-unknown-intercept an intercept type this version does not know still gets feedback: accept for the observer, deny for the guard', async () => {
  for (const [readOnly, expected] of [[true, Buffer.alloc(0)], [false, ld(1, Buffer.from('permission denied'))]] as const) {
    const p = await peer();
    const decided: MiddlewareCall[] = [];
    const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
      readOnly ? { name: 'macwarden-watch', readOnly: true } : { name: 'macwarden-watch-guard', readOnly: false, caveatName: 'region-a1a2f213' },
      call => { decided.push(call); return ''; }, () => undefined);
    await until(() => p.received().length >= 1);
    p.stream()!.write(frame(vi(8, 1)));
    // msg_id(7)=41 with an intercept field (12) that LND 0.21.4 does not define.
    p.stream()!.write(frame(Buffer.concat([vi(1, 3), ld(12, Buffer.from('future')), vi(7, 41)])));
    await until(() => p.received().length >= 2);
    expect(p.received()[1].toString('hex')).toBe(Buffer.concat([vi(1, 41), ld(3, expected)]).toString('hex'));
    expect(decided).toEqual([]);
    session.close();
    await session.ended;
    await p.close();
  }
});

it('WATCH/grpc-fail-closed an exception while deciding denies for the guard and accepts for the observer', async () => {
  for (const [readOnly, expected] of [[true, Buffer.alloc(0)], [false, ld(1, Buffer.from('permission denied'))]] as const) {
    const p = await peer();
    const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
      readOnly ? { name: 'macwarden-watch', readOnly: true } : { name: 'macwarden-watch-guard', readOnly: false, caveatName: 'region-a1a2f213' },
      () => { throw new Error('decision failed'); }, () => undefined);
    await until(() => p.received().length >= 1);
    p.stream()!.write(frame(vi(8, 1)));
    p.stream()!.write(frame(Buffer.concat([vi(1, 5), ld(2, caller), ld(5, ld(1, Buffer.from('/lnrpc.Lightning/GetInfo'))), vi(7, 8)])));
    await until(() => p.received().length >= 2);
    expect(p.received()[1].toString('hex')).toBe(Buffer.concat([vi(1, 8), ld(3, expected)]).toString('hex'));
    session.close();
    await session.ended;
    await p.close();
  }
});

it('WATCH/grpc-liveness a peer that stops answering is detected by HTTP/2 PING and ends the session', async () => {
  const p = await peer();
  // A TCP relay that later swallows traffic both ways without closing: a crashed host or a dropped NAT entry.
  let blackhole = false;
  const sockets: Socket[] = [];
  const relay = createTcpServer(client => {
    const upstream = new Socket();
    sockets.push(client, upstream);
    upstream.connect(p.url.port, '127.0.0.1');
    client.on('data', chunk => { if (!blackhole) upstream.write(chunk); });
    upstream.on('data', chunk => { if (!blackhole) client.write(chunk); });
    client.on('error', () => undefined); upstream.on('error', () => undefined);
  });
  await new Promise<void>(done => relay.listen(0, '127.0.0.1', done));
  const port = (relay.address() as AddressInfo).port;
  let registered = false;
  const session = registerMiddleware({ host: '127.0.0.1', port, tlsCert: good.ca, macaroon: new Secret(own),
    pingIntervalMs: 200, pingTimeoutMs: 300 }, { name: 'macwarden-watch', readOnly: true }, () => '', () => { registered = true; });
  await until(() => p.received().length >= 1);
  p.stream()!.write(frame(vi(8, 1)));
  await until(() => registered);
  blackhole = true;
  const started = performance.now();
  const end = await session.ended;
  // Ended as a lost connection (so watch reconnects), within an interval plus the PING timeout.
  expect(end).toMatchObject({ registered: true, code: 4, stage: 'middleware-stream', message: 'LND transport failure' });
  expect(performance.now() - started).toBeLessThan(5_000);
  // The blackholed relay leaves the server session half-open; release everything without waiting on it.
  for (const socket of sockets) socket.destroy();
  relay.close();
  void p.close();
});

// Audit 1.2.1: a repeated registration confirmation from LND is not a new session.
it('WATCH/grpc-registration a repeated reg_complete confirms the registration once', async () => {
  const p = await peer();
  let confirmations = 0;
  const session = registerMiddleware({ ...p.url, tlsCert: good.ca, macaroon: new Secret(own) },
    { name: 'macwarden-watch', readOnly: true }, () => '', () => { confirmations += 1; });
  await until(() => p.received().length >= 1);
  p.stream()!.write(frame(vi(8, 1)));
  await until(() => confirmations >= 1);
  p.stream()!.write(frame(vi(8, 1)));
  p.stream()!.write(frame(vi(8, 1)));
  await new Promise(resolve => setTimeout(resolve, 200));
  expect(confirmations).toBe(1);
  session.close();
  await session.ended;
  await p.close();
});
