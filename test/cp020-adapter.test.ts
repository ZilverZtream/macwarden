import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';

type Check = { valid: true } | { valid: false; reason: string; message: string };
type Adapter = { checkMacaroon(mac: Secret, perms: string[]): Promise<Check> };
const credential = () => new Secret(readFileSync(resolve('test/vectors/default-readonly.macaroon')));

async function respond<T>(status: number, body: unknown, work: (adapter: Adapter) => Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new Error('MACWARDEN_TEST_TMP is required');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'cp020-adapter-'));
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
    expect(request.method).toBe('POST');
    expect(request.url).toBe('/v1/macaroon/checkpermissions');
    request.resume();
    request.on('end', () => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    });
  });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    const port = (server.address() as AddressInfo).port;
    const module = await import('../src/lnd/index.js') as {
      createLndAdapter: (options: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => Adapter;
    };
    return await work(module.createLndAdapter({ restUrl: `https://127.0.0.1:${port}`,
      tlsCert: ca, macaroon: credential() }));
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}

it('CP-020/B1 adapter classifies verified target signature mismatch without a gRPC code', async () => {
  await respond(400, { message: 'rpc error: desc = signature mismatch' }, async adapter => {
    expect(await adapter.checkMacaroon(credential(), ['info:read']))
      .toMatchObject({ valid: false as const, reason: 'signature-mismatch' });
  });
});

it('CP-020/B1 adapter keeps valid, missing-root and unknown outcomes distinct', async () => {
  await respond(200, { valid: true }, async adapter => {
    expect(await adapter.checkMacaroon(credential(), ['info:read'])).toEqual({ valid: true });
  });
  await respond(400, { message: "root key with id 9 doesn't exist" }, async adapter => {
    expect(await adapter.checkMacaroon(credential(), ['info:read']))
      .toMatchObject({ valid: false as const, reason: 'root-key-missing' });
  });
  await respond(400, { message: 'permission denied' }, async adapter => {
    expect(await adapter.checkMacaroon(credential(), ['info:read']))
      .toMatchObject({ valid: false as const, reason: 'other' as const });
  });
  await respond(500, { message: 'signature mismatch' }, async adapter => {
    await expect(adapter.checkMacaroon(credential(), ['info:read'])).rejects.toMatchObject({ code: 4 });
  });
});

it('CP-020/B1 adapter gives HTTP 401 and 403 OWN authentication precedence', async () => {
  for (const status of [401, 403]) {
    await respond(status, { message: 'signature mismatch' }, async adapter => {
      await expect(adapter.checkMacaroon(credential(), ['info:read']))
        .rejects.toMatchObject({ code: 4 });
    });
  }
});

// 1.2.1: text inside a quoted span is the caller's (a caveat LND quotes), never node evidence.
it('CP-020/B1 adapter never reads a missing root key or a signature mismatch out of quoted caveat text', async () => {
  for (const message of [
    `caveat "root key with id 9 doesn't exist" not satisfied: caveat not recognized`,
    'caveat "signature mismatch" not satisfied: caveat not recognized',
    `caveat "a \\" root key with id 9 doesn't exist" not satisfied: caveat not recognized`,
  ]) {
    await respond(400, { message }, async adapter => {
      expect(await adapter.checkMacaroon(credential(), ['info:read']), message)
        .toEqual({ valid: false as const, reason: 'other' as const, message: 'LND rejected macaroon' });
    });
  }
  // The reason LND gives after the quoted caveat is the node's own text and is still classified.
  await respond(400, { message: `caveat "root key with id 9 doesn't exist" not satisfied: signature mismatch` }, async adapter => {
    expect(await adapter.checkMacaroon(credential(), ['info:read'])).toMatchObject({ valid: false as const, reason: 'signature-mismatch' });
  });
});

// Audit 1.2.1: the classifier's wildcard regex was quadratic; a hostile 1 MiB error body stalled every call for 65 s.
it('CP-020/B1 adapter classifies a hostile 1 MiB error body in bounded time', async () => {
  const body = { message: 'macaroon'.repeat(130_000) };
  const started = performance.now();
  await respond(500, body, async adapter => {
    await expect(adapter.checkMacaroon(credential(), ['info:read'])).rejects.toMatchObject({ code: 5 });
  });
  expect(performance.now() - started).toBeLessThan(5_000);
}, 30_000);
