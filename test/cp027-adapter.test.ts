import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { directory, maxId, register, vector } from './helpers/cp026-revoke-support.mjs';
import { safe } from './helpers/cp027-revoke-support.js';

type Adapter = { deleteMacaroonId(id: bigint): Promise<{ deleted: boolean }> };
async function server(work: (adapter: Adapter, seen: Array<{ method: string; path: string; body: string }>,
  connections: () => number) => Promise<void>, reply: { status: number; body: unknown }) {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'cp027-https-'));
  writeFileSync(join(dir, 'openssl.cnf'), '[req]\ndistinguished_name=dn\n[dn]\n');
  const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-days', '1', '-config', join(dir, 'openssl.cnf'), '-keyout', join(dir, 'local.key'),
    '-out', join(dir, 'local.crt'), '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
  { encoding: 'utf8', timeout: 20_000 });
  if (generated.status !== 0) throw new Error('Local HTTPS certificate generation failed');
  const credential = vector('default-admin').bytes; register(credential);
  const seen: Array<{ method: string; path: string; body: string }> = [];
  let connections = 0;
  const https = createServer({ key: readFileSync(join(dir, 'local.key')), cert: readFileSync(join(dir, 'local.crt')) },
    (request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', chunk => chunks.push(Buffer.from(chunk)));
      request.on('end', () => {
        expect(request.headers['grpc-metadata-macaroon'] === credential.toString('hex')).toBe(true);
        seen.push({ method: request.method!, path: request.url!, body: Buffer.concat(chunks).toString() });
        response.writeHead(reply.status, { 'content-type': 'application/json' }); response.end(JSON.stringify(reply.body));
      });
    });
  https.on('connection', () => { connections++; });
  try {
    await new Promise<void>((done, fail) => https.listen(0, '127.0.0.1', done).once('error', fail));

    const module = await import('../src/lnd/index.js');
    const adapter = module.createLndAdapter({ restUrl: `https://127.0.0.1:${(https.address() as AddressInfo).port}`,
      tlsCert: readFileSync(join(dir, 'local.crt')), macaroon: new Secret(credential) }) as Adapter;
    expect(typeof adapter.deleteMacaroonId).toBe('function');
    await work(adapter, seen, () => connections);
  } finally {
    https.closeAllConnections(); await new Promise<void>(done => https.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}
it('CP-027/adapter-zero root key zero is refused before any HTTP connection', async () => {
  await server(async (adapter, seen, connections) => {
    await expect(adapter.deleteMacaroonId(0n)).rejects.toBeDefined();
    expect(seen).toEqual([]); expect(connections()).toBe(0);
  }, { status: 200, body: { deleted: true } });
}, 20_000);
it.each([true, false])('CP-027/adapter-zero deleted %s uses exact uint64 DELETE endpoint and no request body', async deleted => {
  await server(async (adapter, seen) => {
    expect(await adapter.deleteMacaroonId(BigInt(maxId))).toEqual({ deleted });
    expect(seen).toEqual([{ method: 'DELETE', path: `/v1/macaroon/${maxId}`, body: '' }]);
  }, { status: 200, body: { deleted } });
}, 20_000);
it.each([401, 403, 500])('CP-027/adapter-zero HTTP %s fails once without retry and keeps echoed credential out of errors', async status => {
  await server(async (adapter, seen) => {
    let error: { code?: number; message?: string } = {};
    try { await adapter.deleteMacaroonId(27n); } catch (caught) { if (!(caught instanceof Error)) throw caught; error = caught; }
    expect(error).toBeDefined(); expect(error!.code).toBe(status === 500 ? 5 : 4);
    expect(seen).toEqual([{ method: 'DELETE', path: '/v1/macaroon/27', body: '' }]);
    safe(String(error!) + JSON.stringify(error) + error!.message, []);
  }, { status, body: { code: 2, message: vector('default-admin').bytes.toString('hex') } });
}, 20_000);
