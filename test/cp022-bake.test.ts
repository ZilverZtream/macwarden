import { revealSecret } from './helpers/secret-bytes.js';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';

type Adapter = {
  bakeMacaroon(perms: string[], rootKeyId: bigint): Promise<Secret>;
  getInfo(): Promise<unknown>;
  listMacaroonIds(): Promise<unknown>;
  listPermissions(): Promise<unknown>;
  checkMacaroon(mac: Secret, perms: string[]): Promise<unknown>;
};
type Seen = { method: string; path: string; body: string };
type Reply = { status?: number; body?: unknown };
const repo = resolve();
const tmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
process.env.MACWARDEN_TEST_TMP = tmp;
const own = () => readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
const vector = () => readFileSync(join(repo, 'test/vectors/root-max.macaroon'));

async function withServer(work: (fixture: { url: string; ca: Buffer; wrongCa: Buffer;
  seen: Seen[]; connections: () => number }) => Promise<void>,
reply: (request: Seen) => Reply = () => ({ body: { macaroon: vector().toString('hex') } })) {
  mkdirSync(tmp, { recursive: true });
  const dir = mkdtempSync(join(tmp, 'cp022-https-'));
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const certificate = (name: string) => {
    const key = join(dir, `${name}.key`), ca = join(dir, `${name}.crt`);
    const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
      '-days', '1', '-config', config, '-keyout', key, '-out', ca, '-subj', `/CN=${name}`,
      '-addext', `subjectAltName=${name === '127.0.0.1' ? 'IP' : 'DNS'}:${name}`], { encoding: 'utf8', timeout: 20_000 });
    if (run.status !== 0) throw new Error('Local HTTPS certificate generation failed');
    return { key: readFileSync(key), ca: readFileSync(ca) };
  };
  const good = certificate('127.0.0.1'), wrong = certificate('wrong.invalid');
  const seen: Seen[] = [];
  let connections = 0;
  const server: Server = createServer({ key: good.key, cert: good.ca }, (request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', chunk => chunks.push(Buffer.from(chunk)));
    request.on('end', () => {
      const record = { method: request.method || '', path: request.url || '',
        body: Buffer.concat(chunks).toString('utf8') };
      seen.push(record);
      const answer = reply(record);
      response.writeHead(answer.status || 200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(answer.body ?? {}));
    });
  });
  server.on('connection', () => { connections++; });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    await work({ url: `https://127.0.0.1:${(server.address() as AddressInfo).port}`,
      ca: good.ca, wrongCa: wrong.ca, seen, connections: () => connections });
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}

async function adapter(url: string, ca: Buffer): Promise<Adapter> {

  const module = await import('../src/lnd/index.js') as {
    createLndAdapter: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => Adapter;
  };
  return module.createLndAdapter({ restUrl: url, tlsCert: ca, macaroon: new Secret(own()) });
}
async function failure(call: () => Promise<unknown>) {
  try { await call(); } catch (error) { return error as Error & { code?: number; kind?: string }; }
  throw new Error('Expected adapter failure');
}
async function allocator() {

  return await import('../src/commands/bake/allocate.js') as {
    allocateRootKeyId: (lndIds: readonly bigint[], registryIds: readonly bigint[], draw: () => bigint) => bigint;
  };
}

it('CP-022/B1 root key zero is refused with exit 2 before a network connection', async () => {
  await withServer(async ({ url, ca, seen, connections }) => {
    const value = await adapter(url, ca);
    const error = await failure(() => value.bakeMacaroon(['info:read'], 0n));
    expect(error.code).toBe(2);
    expect(connections()).toBe(0);
    expect(seen).toHaveLength(0);
  });
});

it('CP-022/B2 bake sends exact decimal ID, split permissions and no external permission flag', async () => {
  await withServer(async ({ url, ca, seen }) => {
    await (await adapter(url, ca)).bakeMacaroon(
      ['info:read', 'invoices:write', 'uri:/lnrpc.Lightning/GetInfo'], 18446744073709551615n);
    expect(seen.map(item => `${item.method} ${item.path}`)).toEqual(['POST /v1/macaroon']);
    const body = JSON.parse(seen[0].body) as Record<string, unknown>;
    expect(body.root_key_id).toBe('18446744073709551615');
    expect(body.permissions).toEqual([
      { entity: 'info', action: 'read' }, { entity: 'invoices', action: 'write' },
      { entity: 'uri', action: '/lnrpc.Lightning/GetInfo' },
    ]);
    expect(body.allow_external_permissions).not.toBe(true);
    expect(Object.keys(body).sort()).toEqual(
      body.allow_external_permissions === undefined ? ['permissions', 'root_key_id'] :
        ['allow_external_permissions', 'permissions', 'root_key_id']);
  });
});

it('CP-022/B3 allocation rejects LND and revoked registry collisions before using the third draw', async () => {
  const { allocateRootKeyId } = await allocator();
  const draws = [4294967296n, 4294967297n, 4294967298n];
  let count = 0;
  expect(allocateRootKeyId([draws[0]], [draws[1]], () => draws[count++])).toBe(draws[2]);
  expect(count).toBe(3);
});

it('CP-022/B3 allocation redraws outside inclusive bounds and accepts both boundary IDs', async () => {
  const { allocateRootKeyId } = await allocator();
  const low = 4294967296n, high = 9223372036854775807n;
  const draws = [low - 1n, high + 1n, high];
  let count = 0;
  expect(allocateRootKeyId([], [], () => draws[count++])).toBe(high);
  expect(count).toBe(3);
  expect(allocateRootKeyId([], [], () => low)).toBe(low);
});

it('CP-022/B3 sixteen colliding or invalid draws exhaust with shared LND exit 5', async () => {
  const { allocateRootKeyId } = await allocator();
  const errors = await import('../src/errors.js') as Record<string, unknown>;
  let count = 0;
  let caught: unknown;
  try {
    allocateRootKeyId([4294967296n], [], () => { count++; return count % 2 ? 4294967296n : 4294967295n; });
  } catch (error) { caught = error; }
  expect(count).toBe(16);
  expect(caught).toBeInstanceOf(errors.LndError as new (...args: never[]) => Error);
  expect((caught as { code?: number }).code).toBe(5);
});

it('CP-022/B4 endpoint inventory permits approved bake and delete methods and excludes changepassword', async () => {
  await withServer(async ({ url, ca, seen }) => {
    const value = await adapter(url, ca);
    await value.getInfo();
    await value.listMacaroonIds();
    await value.listPermissions();
    await value.checkMacaroon(new Secret(own()), ['info:read']);
    await value.bakeMacaroon(['info:read'], 18446744073709551615n);
    expect(seen.map(item => `${item.method} ${item.path}`)).toEqual([
      'GET /v1/getinfo', 'GET /v1/macaroon/ids', 'GET /v1/macaroon/permissions',
      'POST /v1/macaroon/checkpermissions', 'POST /v1/macaroon',
    ]);
    const exposed = [...new Set([...Object.keys(value),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(value))])]
      .filter(name => name !== 'constructor').sort();
    expect(exposed).not.toContain('changePassword');
    expect(exposed).not.toContain('changepassword');
    expect(exposed.filter(name => /bake|change|password|delete/i.test(name)))
      .toEqual(['bakeMacaroon', 'deleteMacaroonId']);
  }, request => ({ body: request.path === '/v1/macaroon/ids' ? { root_key_ids: ['0'] } :
    request.path === '/v1/macaroon/permissions' ? { method_permissions: {} } :
      request.path === '/v1/macaroon/checkpermissions' ? { valid: true as const } :
        request.path === '/v1/macaroon' ? { macaroon: vector().toString('hex') } :
          { alias: 'a', version: '0.21.4-beta', identity_pubkey: '02' + 'ab'.repeat(32),
            chains: [{ chain: 'bitcoin', network: 'regtest' }] } }));
});

it('CP-022/B5 transport, TLS, HTTP auth and Unknown LND errors use safe exit classes', async () => {
  await withServer(async ({ url, ca, wrongCa, seen }) => {
    const value = await adapter(url, wrongCa);
    expect((await failure(() => value.bakeMacaroon(['info:read'], 4294967296n))).code).toBe(4);
    expect(seen).toHaveLength(0);
    const unavailable = await adapter(url.replace(/:\d+$/, ':1'), ca);
    expect((await failure(() => unavailable.bakeMacaroon(['info:read'], 4294967296n))).code).toBe(4);
  });
  for (const status of [401, 403, 500]) {
    await withServer(async ({ url, ca, seen }) => {
      const error = await failure(() => adapter(url, ca).then(value =>
        value.bakeMacaroon(['info:read'], 4294967296n)));
      expect(error.code).toBe(status === 500 ? 5 : 4);
      expect(seen).toHaveLength(1);
      const shown = `${String(error)}\n${JSON.stringify(error)}\n${error.message}`;
      expect(shown).not.toContain(seen[0].body);
      for (const encoding of ['hex', 'base64', 'base64url'] as const)
        expect(shown).not.toContain(own().toString(encoding));
    }, request => ({ status, body: { code: 'Unknown',
      message: `${request.body} ${own().toString('hex')}` } }));
  }
  for (const [message, kind] of [
    ["root key with id 4294967296 doesn't exist", 'root-key-missing'],
    ['permission refused', 'other'],
  ]) {
    await withServer(async ({ url, ca }) => {
      const error = await failure(() => adapter(url, ca).then(value =>
        value.bakeMacaroon(['info:read'], 4294967296n)));
      expect(error.code).toBe(kind === 'root-key-missing' ? 4 : 5);
      expect(error.kind).toBe(kind === 'root-key-missing' ? undefined : kind);
    }, () => ({ status: 500, body: { code: 'Unknown', message } }));
  }
});

it('CP-022/B6 bake response from a committed fixture remains Secret with its chosen storage ID', async () => {
  await withServer(async ({ url, ca }) => {
    const result = await (await adapter(url, ca)).bakeMacaroon(['info:read'], 18446744073709551615n);
    expect(result).toBeInstanceOf(Secret);
    expect(Buffer.from(revealSecret(result)).equals(vector())).toBe(true);
    const { decodeMacaroon } = await import('../src/decode/index.js');
    const printed = JSON.parse(readFileSync(join(repo, 'test/vectors/root-max.printmacaroon.json'), 'utf8')) as {
      root_key_id: string; permissions: string[] };
    const decoded = decodeMacaroon(result);
    expect(decoded.rootKeyId.toString()).toBe(printed.root_key_id);
    expect(decoded.permissions).toEqual(printed.permissions);
  });
});
