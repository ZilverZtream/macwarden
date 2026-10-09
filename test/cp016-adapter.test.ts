import { spawnSync } from 'node:child_process';
import { channel } from 'node:diagnostics_channel';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import { join, resolve } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, expect, it } from 'vitest';
import { Secret } from '../src/secret.js';

const diagnosticCodes = new Set([
  'ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ECONNABORTED', 'ETIMEDOUT',
  'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL',
  'EPROTO', 'ERR_SOCKET_CLOSED', 'ERR_STREAM_PREMATURE_CLOSE',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_TLS_INVALID_PROTOCOL_VERSION',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID',
  'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  'ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR', 'ERR_SSL_WRONG_VERSION_NUMBER',
  'ERR_SSL_EE_KEY_TOO_SMALL', 'ERR_SSL_CA_KEY_TOO_SMALL',
  'ERR_SSL_UNSUPPORTED_PROTOCOL', 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
  'ERR_SSL_NO_SHARED_CIPHER',
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET', 'UND_ERR_ABORTED', 'UND_ERR_DESTROYED', 'UND_ERR_CLOSED',
  'UND_ERR_RES_CONTENT_LENGTH_MISMATCH',
]);
const requestErrorChannel = channel('http.client.request.error');
const observeRequestError = (message: unknown) => {
  const { code, errno } = (message as {
    error?: { code?: unknown; errno?: unknown };
  }).error ?? {};
  const safe: { case: string; code?: string; errno?: number | string } = {
    case: `CP016/${/^CP-016\/(B(?:[1-8]|10)) /.exec(expect.getState().currentTestName ?? '')?.[1] ?? 'outside-case'}`,
  };
  if (typeof code === 'string' && diagnosticCodes.has(code)) safe.code = code;
  if (typeof errno === 'number' && Number.isInteger(errno) && Math.abs(errno) <= 4096) safe.errno = errno;
  else if (typeof errno === 'string' && diagnosticCodes.has(errno)) safe.errno = errno;
  if (safe.code !== undefined || safe.errno !== undefined) process.stderr.write(JSON.stringify(safe) + '\n');
};
requestErrorChannel.subscribe(observeRequestError);
afterAll(() => { requestErrorChannel.unsubscribe(observeRequestError); });

type Adapter = {
  getInfo(): Promise<{ pubkey: string; alias: string; network: string; version: string }>;
  listMacaroonIds(): Promise<bigint[]>;
  listPermissions(): Promise<Record<string, string[]>>;
  checkMacaroon(mac: Secret, perms: string[]): Promise<
    { valid: true } | { valid: false; reason: 'root-key-missing' | 'other'; message: string }>;
};
type Seen = { method: string; path: string; headers: Record<string, string | string[] | undefined>; body: string };
type Reply = { status?: number; body?: unknown; stall?: boolean };
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
process.env.MACWARDEN_TEST_TMP = tmpRoot;
const ownBytes = () => readFileSync(join(resolve(), 'test/sentinels/sentinel.macaroon'));
const credential = () => new Secret(ownBytes());

function cert(dir: string, name: string, hostname: string) {
  const config = join(dir, 'openssl.cnf');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const key = join(dir, `${name}.key`), publicCert = join(dir, `${name}.crt`);
  const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-days', '1', '-config', config, '-keyout', key, '-out', publicCert,
    '-subj', `/CN=${hostname}`, '-addext', `subjectAltName=${hostname === '127.0.0.1' ? 'IP' : 'DNS'}:${hostname}`],
  { encoding: 'utf8', timeout: 20_000 });
  if (run.status !== 0) throw new Error('Local HTTPS certificate generation failed');
  return { key: readFileSync(key), ca: readFileSync(publicCert) };
}

async function withServer<T>(work: (context: {
  url: string; ca: Buffer; wrongCa: Buffer; seen: Seen[]; connections: () => number;
}) => Promise<T>, answer: (request: Seen) => Reply = () => ({ body: {} }), presentWrongCert = false) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'cp016-https-'));
  const good = cert(dir, 'local', '127.0.0.1');
  const wrong = cert(dir, 'other', 'other.invalid');
  const seen: Seen[] = [];
  let connections = 0;
  const presented = presentWrongCert ? wrong : good;
  const server: Server = createServer({ key: presented.key, cert: presented.ca }, (request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', chunk => chunks.push(Buffer.from(chunk)));
    request.on('end', () => {
      const entry = { method: request.method || '', path: request.url || '',
        headers: request.headers, body: Buffer.concat(chunks).toString('utf8') };
      seen.push(entry);
      const reply = answer(entry);
      if (reply.stall) return;
      response.writeHead(reply.status || 200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(reply.body ?? {}));
    });
  });
  server.on('connection', () => { connections++; });
  try {
    await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
    const port = (server.address() as AddressInfo).port;
    return await work({ url: `https://127.0.0.1:${port}`,
      ca: good.ca, wrongCa: wrong.ca, seen, connections: () => connections });
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(dir, { recursive: true, force: true });
  }
}

async function adapter(url: string, ca: Buffer): Promise<Adapter> {

  const module = await import('../src/lnd/index.js') as {
    createLndAdapter?: (config: { restUrl: string; tlsCert: Buffer; macaroon: Secret }) => Adapter;
  };
  expect(typeof module.createLndAdapter).toBe('function');
  return module.createLndAdapter!({ restUrl: url, tlsCert: ca, macaroon: credential() });
}

async function failure(call: () => Promise<unknown>) {
  try { await call(); } catch (error) { return error as { code?: number; kind?: string; message?: string }; }
  throw new Error('Expected adapter failure');
}

it('CP-016/B1 getInfo maps the four documented fields from the configured peer', async () => {
  await withServer(async ({ url, ca, seen }) => {
    const result = await (await adapter(url, ca)).getInfo();
    expect(result).toEqual({ pubkey: '02' + 'ab'.repeat(32), alias: 'fixture-node', network: 'regtest',
      version: '0.21.4-beta' });
    expect(seen.map(({ method, path }) => [method, path])).toEqual([['GET', '/v1/getinfo']]);
  }, () => ({ body: { identity_pubkey: '02' + 'ab'.repeat(32), alias: 'fixture-node',
    chains: [{ chain: 'bitcoin', network: 'regtest' }], version: '0.21.4-beta' } }));
});

it('CP-016/B2 wrong CA and hostname each fail TLS verification in one attempt', async () => {
  await withServer(async ({ url, wrongCa, seen, connections }) => {
    const value = await adapter(url, wrongCa);
    const error = await failure(() => value.getInfo());
    expect(error.code).toBe(4);
    expect(connections()).toBe(1);
    expect(seen).toHaveLength(0);
  });
  await withServer(async ({ url, wrongCa, seen, connections }) => {
    const value = await adapter(url, wrongCa);
    const error = await failure(() => value.getInfo());
    expect(error.code).toBe(4);
    expect(connections()).toBe(1);
    expect(seen).toHaveLength(0);
  }, () => ({ body: {} }), true);
});

it('CP-016/B3 HTTP 401 and 403 are auth failures and 500 is an LND failure', async () => {
  for (const status of [401, 403, 500]) {
    await withServer(async ({ url, ca, seen }) => {
      const value = await adapter(url, ca);
      const error = await failure(() => value.getInfo());
      expect(error.code).toBe(status === 500 ? 5 : 4);
      expect(seen).toHaveLength(1);
    }, () => ({ status, body: { code: 2, message: 'request rejected' } }));
  }
});

it('CP-016/B4 stalled response and refused connection are transport failures without retry', async () => {
  await withServer(async ({ url, ca, seen }) => {
    const started = performance.now();
    const value = await adapter(url, ca);
    const error = await failure(() => value.getInfo());
    const elapsed = performance.now() - started;
    expect(error.code).toBe(4);
    expect(elapsed).toBeGreaterThanOrEqual(9_000);
    expect(elapsed).toBeLessThan(13_000);
    expect(seen).toHaveLength(1);
  }, () => ({ stall: true }));
  await withServer(async ({ url, ca, seen }) => {
    const unavailable = url.replace(/:\d+$/, ':1');
    const value = await adapter(unavailable, ca);
    const error = await failure(() => value.getInfo());
    expect(error.code).toBe(4);
    expect(seen).toHaveLength(0);
  });
}, 35_000);

it('CP-016/B5 decimal string and numeric root IDs retain bigint identity', async () => {
  for (const value of ['18446744073709551615', '15002', 15002]) {
    await withServer(async ({ url, ca }) => {
      const ids = await (await adapter(url, ca)).listMacaroonIds();
      expect(ids).toEqual([BigInt(value)]);
      expect(ids.map(String)).toEqual([String(value)]);
    }, () => ({ body: { root_key_ids: [value] } }));
  }
});

it('CP-016/B6 verification sends own permissions, URI entries and no default method fields', async () => {
  await withServer(async ({ url, ca, seen }) => {
    const value = await adapter(url, ca);
    const perms = ['info:read', 'uri:/lnrpc.Lightning/GetInfo'];
    expect(await value.checkMacaroon(credential(), perms)).toEqual({ valid: true });
    const request = JSON.parse(seen[0].body) as Record<string, unknown>;
    expect(seen.map(item => [item.method, item.path])).toEqual([['POST', '/v1/macaroon/checkpermissions']]);
    expect(request.permissions).toEqual([
      { entity: 'info', action: 'read' },
      { entity: 'uri', action: '/lnrpc.Lightning/GetInfo' },
    ]);
    expect(request.fullMethod).toBeUndefined();
    expect(request.check_default_perms_from_full_method).toBeUndefined();
    expect(request.macaroon === ownBytes().toString('base64')).toBe(true);
    await failure(() => value.checkMacaroon(credential(), []));
    expect(seen).toHaveLength(1);
  }, () => ({ body: { valid: true } }));
});

it('CP-016/B7 own macaroon is confined to its required request header', async () => {
  await withServer(async ({ url, ca, seen }) => {
    await (await adapter(url, ca)).getInfo();
    const request = seen[0];
    expect(request.headers['grpc-metadata-macaroon'] === ownBytes().toString('hex')).toBe(true);
    expect(request.method).toBe('GET');
    expect(request.body).toBe('');
    const otherFields = { ...request.headers };
    delete otherFields['grpc-metadata-macaroon'];
    const shown = JSON.stringify(otherFields) + request.path;
    expect(shown.includes(ownBytes().toString('hex'))).toBe(false);
    expect(shown.includes(ownBytes().toString('base64'))).toBe(false);
  }, () => ({ body: { identity_pubkey: '02' + 'ab'.repeat(32), alias: 'a', chains: [{ network: 'regtest' }], version: 'v' } }));
});

it('CP-016/B8 adapter exposes four read endpoints and the staged bake and delete methods', async () => {
  await withServer(async ({ url, ca, seen }) => {
    const value = await adapter(url, ca);
    await value.getInfo();
    await value.listMacaroonIds();
    await value.listPermissions();
    await value.checkMacaroon(credential(), ['info:read']);
    expect(seen.map(item => `${item.method} ${item.path}`)).toEqual([
      'GET /v1/getinfo', 'GET /v1/macaroon/ids', 'GET /v1/macaroon/permissions',
      'POST /v1/macaroon/checkpermissions',
    ]);
    const exposed = [...Object.keys(value), ...Object.getOwnPropertyNames(Object.getPrototypeOf(value))];
    expect(exposed.filter(key => /change|password|delete|bake/i.test(key)).sort()).toEqual(['bakeMacaroon', 'deleteMacaroonId']);
  }, request => ({ body: request.path === '/v1/macaroon/ids' ? { root_key_ids: ['0'] } :
    request.path === '/v1/macaroon/permissions' ? { method_permissions: {} } :
      request.path === '/v1/macaroon/checkpermissions' ? { valid: true } :
        { identity_pubkey: '02' + 'ab'.repeat(32), alias: 'a', chains: [{ network: 'regtest' }], version: 'v' } }));
});

it('CP-016/B10 echoed credential and control characters cannot escape adapter errors', async () => {
  await withServer(async ({ url, ca }) => {
    const value = await adapter(url, ca);
    const error = await failure(() => value.getInfo());
    const shown = `${String(error)}\n${JSON.stringify(error)}\n${error.message || ''}`;
    for (const encoding of ['utf8', 'latin1', 'hex', 'base64', 'base64url'] as const) {
      const marker = ownBytes().toString(encoding);
      if (marker.length >= 8) expect(shown.includes(marker)).toBe(false);
    }
    expect(Array.from(shown.replaceAll('\n', '')).some(char => {
      const code = char.codePointAt(0)!;
      return code < 32 || (code >= 127 && code <= 159);
    })).toBe(false);
  }, () => ({ status: 500, body: { code: 2,
    message: `${ownBytes().toString('hex')}\u001b[31m` } }));
});
