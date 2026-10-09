import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { run, LOCAL_EXPIRY_UNCONFIRMED, REJECTED_INCONCLUSIVE } from '../src/commands/verify.js';
import { addFirstPartyCaveat } from '../src/decode/index.js';
import { createLndAdapter } from '../src/lnd/index.js';
import type { VerifyResult } from '../src/output/index.js';
import { Secret } from '../src/secret.js';
import { revealSecret } from '../src/secret-capability.js';
import { ownId, pubkey, register, responseBytes, root, vector } from './helpers/cp038-online.js';
import { childEnvironment } from './helpers/environment.js';
import { expectSchemaValid } from './helpers/output-schema.js';

// MW110-02 (audit of 1.1.0): a rejection is conclusive only on node-side evidence. The local
// clock never turns a caller-dependent rejection (an IP lock) into an expiry. These tests drive
// the real verify command through the real REST adapter against a local HTTPS server that
// answers exactly as LND v0.21.4 does: CheckMacaroonPermissions returns gRPC InvalidArgument
// (HTTP 400 through the REST gateway) whose message is the bakery error of the first caveat
// that failed (macaroons/service.go CheckMacAuth; macaroon-bakery v2.0.1 checkers.go and
// checker.go; IP lock text from macaroons/constraints.go IPLockChecker).
const dir = mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'verify-node-'));
const registry = join(dir, 'registry.json');
writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }), { mode: 0o600 });
const own = register(responseBytes(ownId, vector('default-admin').permissions));
const targetId = 4294967700n;
const snapshot = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')).methods as Record<string, string[]>;

let answer: { status: number; body: unknown } = { status: 200, body: { valid: true } };
let port = 0;
let ca: Buffer;
const server = (() => {
  const config = join(dir, 'openssl.cnf'), cert = join(dir, 'local.crt'), key = join(dir, 'local.key');
  writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-config', config, '-keyout', key, '-out', cert, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
  { env: childEnvironment(), encoding: 'utf8', timeout: 20_000 });
  if (made.status !== 0) throw new Error('disposable HTTPS certificate generation failed');
  ca = readFileSync(cert);
  return createServer({ key: readFileSync(key), cert: ca }, (request, response) => {
    request.resume();
    request.on('end', () => {
      const path = request.url ?? '';
      let status = 200;
      let body: unknown;
      if (path === '/v1/getinfo') body = { identity_pubkey: pubkey, alias: 'fixture', version: '0.21.4-beta',
        chains: [{ chain: 'bitcoin', network: 'regtest' }] };
      else if (path === '/v1/macaroon/permissions') body = { method_permissions: Object.fromEntries(Object.entries(snapshot)
        .map(([method, permissions]) => [method, { permissions: permissions.map(pair => {
          const [entity, action] = pair.split(':'); return { entity, action }; }) }])) };
      else if (path === '/v1/macaroon/ids') body = { root_key_ids: ['0', String(ownId), String(targetId)] };
      else if (path === '/v1/macaroon/checkpermissions') ({ status, body } = answer);
      else { status = 404; body = { code: 5, message: 'Not Found', details: [] }; }
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    });
  });
})();
beforeAll(async () => {
  await new Promise<void>((done, fail) => server.listen(0, '127.0.0.1', done).once('error', fail));
  port = (server.address() as AddressInfo).port;
  writeFileSync(join(dir, 'tls.cert'), ca);
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>(done => server.close(() => done()));
  rmSync(dir, { recursive: true, force: true });
});

/** LND's REST error for CheckMacaroonPermissions: gRPC InvalidArgument (3) carrying err.Error(). */
const lndRejects = (message: string) => ({ status: 400, body: { code: 3, message, details: [] } });

async function verify(target: string, now: Date) {
  const result = await run([target, '--registry', registry, '--lnd-rest', `127.0.0.1:${port}`,
    '--tls-cert', join(dir, 'tls.cert'), '--macaroon', own], {
    createAdapter: createLndAdapter, fs: { ...fs }, env: {}, clock: () => now,
    stdin: Object.assign(Readable.from([]), { isTTY: true }) });
  expectSchemaValid(result);
  return { result, value: result.result as VerifyResult, exit: result.error?.code ?? result.exitCode ?? 0 };
}

function credential(...caveats: string[]): string {
  let mac = new Secret(responseBytes(targetId, ['info:read']));
  for (const caveat of caveats) mac = addFirstPartyCaveat(mac, caveat);
  return register(revealSecret(mac));
}

const expiry = '2026-10-04T12:00:00Z';
const correct = new Date('2026-10-04T00:00:00Z');
const dayAhead = new Date(correct.getTime() + 86_400_000);

it('VERIFY/MW110-02 an IP-locked rejection stays inconclusive (exit 1) with the local clock a day ahead of the expiry', async () => {
  const target = credential('ipaddr 203.0.113.9', `time-before ${expiry}`);
  // LND checks caveats in order and reports the first that fails: the IP lock, for this caller.
  answer = lndRejects('caveat "ipaddr 203.0.113.9" not satisfied: macaroon locked to different IP address');
  const baseline = await verify(target, correct);
  expect(baseline.exit).toBe(1);
  expect(baseline.value).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false, rootKeyListed: true });
  expect(baseline.value.guidance).not.toContain(LOCAL_EXPIRY_UNCONFIRMED);

  const skewed = await verify(target, dayAhead);
  expect(skewed.exit).toBe(1);
  expect(skewed.value).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false, rootKeyListed: true });
  // The local reading stays visible as presentation, never as the verdict.
  expect(skewed.value.caveats).toContainEqual({ type: 'time-before', value: expiry, expired: true });
  expect(skewed.value.guidance[0]).toBe(REJECTED_INCONCLUSIVE);
  expect(skewed.value.guidance).toContain(LOCAL_EXPIRY_UNCONFIRMED);
  expect(skewed.value.guidance.join('\n')).toContain(`macwarden revoke ${targetId} --unregistered`);
});

it('VERIFY/MW110-02 an expiry LND itself reports for a caveat the credential carries is conclusive (exit 0), whatever the local clock says', async () => {
  const target = credential(`time-before ${expiry}`);
  answer = lndRejects(`caveat "time-before ${expiry}" not satisfied: macaroon has expired`);
  for (const now of [correct, dayAhead]) {
    const { exit, value } = await verify(target, now);
    expect(exit, now.toISOString()).toBe(0);
    expect(value).toMatchObject({ status: 'rejected', rejection: 'expired', conclusive: true, rootKeyListed: true });
    expect(value.guidance[0]).toContain('a time-before caveat has passed');
    expect(value.guidance).not.toContain(LOCAL_EXPIRY_UNCONFIRMED);
  }
});

it('VERIFY/MW110-02 expiry text that does not name one of the credential\'s own time-before caveats is not node evidence', async () => {
  const target = credential('ipaddr 203.0.113.9', `time-before ${expiry}`);
  for (const message of [
    'caveat "time-before 2026-10-01T00:00:00Z" not satisfied: macaroon has expired',
    'caveat "lnd-custom x time-before 2026-10-04T12:00:00Z" not satisfied: macaroon has expired',
    `caveat "time-before ${expiry}" not satisfied: macaroon has expired; caveat "ipaddr 203.0.113.9" not satisfied`,
    `rpc error: caveat "time-before ${expiry}" not satisfied: macaroon has expired`,
    'macaroon has expired',
  ]) {
    answer = lndRejects(message);
    const { exit, value } = await verify(target, dayAhead);
    expect(exit, message).toBe(1);
    expect(value, message).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false });
  }
});

it('VERIFY/MW110-02 the REST adapter classifies only LND\'s exact expiry error and returns the caveat value it names', async () => {
  const adapter = createLndAdapter({ restUrl: `https://127.0.0.1:${port}`, tlsCert: ca, macaroon: new Secret(readFileSync(own)) });
  const mac = new Secret(vector('time-before').bytes);
  answer = lndRejects('caveat "time-before 2026-10-02T17:38:38.792272998Z" not satisfied: macaroon has expired');
  expect(await adapter.checkMacaroon(mac, ['info:read'])).toEqual({ valid: false, reason: 'expired',
    caveat: '2026-10-02T17:38:38.792272998Z', message: 'LND rejected macaroon' });
  answer = lndRejects('caveat "ipaddr 203.0.113.9" not satisfied: macaroon locked to different IP address');
  expect(await adapter.checkMacaroon(mac, ['info:read'])).toEqual({ valid: false, reason: 'other', message: 'LND rejected macaroon' });
});
