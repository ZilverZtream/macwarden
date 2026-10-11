import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { createLndAdapter } from '../src/lnd/index.js';
import { Secret } from '../src/secret.js';

// Audit 1.4.0 (LND section): a fake LND REST proxy, in the style of cp020-adapter, answering every
// request through one handler.
type Adapter = ReturnType<typeof createLndAdapter>;
async function serve<T>(handle: (request: IncomingMessage, response: ServerResponse) => void, work: (adapter: Adapter) => Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new Error('MACWARDEN_TEST_TMP is required');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'lnd-audit-adapter-'));
  const keyPath = join(dir, 'local.key'), certPath = join(dir, 'local.crt');
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256',
    '-nodes', '-days', '1', '-config', config, '-keyout', keyPath, '-out', certPath, '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { encoding: 'utf8', timeout: 20_000 });
  if (generated.status !== 0) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error('Local HTTPS certificate generation failed');
  }
  const ca = readFileSync(certPath);
  const server = createServer({ key: readFileSync(keyPath), cert: ca }, (request, response) => {
    request.resume();
    request.on('end', () => handle(request, response));
  });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    const port = (server.address() as AddressInfo).port;
    return await work(createLndAdapter({ restUrl: `https://127.0.0.1:${port}`, tlsCert: ca,
      macaroon: new Secret(readFileSync(resolve('test/vectors/default-readonly.macaroon'))) }));
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}

const reply = (status: number, body: unknown, newline = false) => (_request: IncomingMessage, response: ServerResponse) => {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body) + (newline ? '\n' : ''));
};

it('LND-audit TrackPaymentV2 authentication failure in a stream error body is exit 4, as on unary calls', async () => {
  for (const message of ['verification failed: signature mismatch after caveat verification', 'permission denied', 'macaroon has expired']) {
    // grpc-gateway v2 writes a server-streaming failure before the first message as HTTP 500 with {"error": {...}}.
    await serve((request, response) => {
      expect(request.url).toMatch(/^\/v2\/router\/track\//);
      reply(500, { error: { code: 2, message, details: [] } }, true)(request, response);
    }, async lnd => {
      await expect(lnd.trackPayment('ab'.repeat(32)), message).rejects.toMatchObject({ code: 4, message: 'LND authentication failure' });
    });
  }
  // A stream error that is not authentication stays an LND rejection (exit 5), and "not initiated" stays absent.
  await serve(reply(500, { error: { code: 2, message: 'some other failure' } }, true), async lnd => {
    await expect(lnd.trackPayment('ab'.repeat(32))).rejects.toMatchObject({ code: 5 });
  });
  await serve(reply(500, { error: { code: 5, message: 'payment isn\'t initiated' } }, true), async lnd => {
    expect(await lnd.trackPayment('ab'.repeat(32))).toBeNull();
  });
});

it('LND-audit payment and HTLC statuses named after Object.prototype members read as unknown', async () => {
  const payment = (status: string, htlcStatus: string) => ({
    payment_hash: 'cd'.repeat(32), status, creation_time_ns: '1700000000000000000', value_msat: '1000', fee_msat: '0',
    payment_index: '1', failure_reason: 'FAILURE_REASON_NONE',
    htlcs: [{ status: htlcStatus, route: { total_amt_msat: '1000', total_fees_msat: '0' } }],
  });
  const names = ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf'];
  await serve(reply(200, { payments: names.map(name => payment(name, name)), last_index_offset: '5' }), async lnd => {
    const page = await lnd.listPayments({ startSeconds: 0, endSeconds: 2_000_000_000, indexOffset: 0n, max: 10 });
    expect(page.payments).toHaveLength(names.length);
    for (const item of page.payments) {
      expect(item.status).toBe('unknown');
      // The HTLC counted neither as settled nor in flight.
      expect(item.succeededAttempts).toBe(0);
      expect(item.inFlightMsat).toBe(0n);
    }
    expect(JSON.parse(JSON.stringify(page.payments.map(item => ({ status: item.status }))))).toEqual(names.map(() => ({ status: 'unknown' })));
  });
  // The known names still map.
  await serve(reply(200, { payments: [payment('SUCCEEDED', 'SUCCEEDED')], last_index_offset: '1' }), async lnd => {
    const [item] = (await lnd.listPayments({ startSeconds: 0, endSeconds: 2_000_000_000, indexOffset: 0n, max: 10 })).payments;
    expect(item).toMatchObject({ status: 'succeeded', succeededAttempts: 1, succeededMsat: 1000n });
  });
});

it('LND-audit ListMacaroonIDs with a repeated root key ID is an invalid LND response (exit 5)', async () => {
  for (const ids of [['7', '7'], ['0', '9', '9'], ['7', 7]]) {
    await serve(reply(200, { root_key_ids: ids }), async lnd => {
      await expect(lnd.listMacaroonIds(), JSON.stringify(ids)).rejects.toMatchObject({ code: 5, message: 'invalid LND response' });
    });
  }
  await serve(reply(200, { root_key_ids: ['0', '7', '9'] }), async lnd => {
    expect(await lnd.listMacaroonIds()).toEqual([0n, 7n, 9n]);
  });
});
