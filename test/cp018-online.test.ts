import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { captureMain } from './support/capture.js';

const names = ['MACWARDEN_LND_REST', 'MACWARDEN_TLS_CERT', 'MACWARDEN_MACAROON',
  'NODE_DEBUG', 'NODE_OPTIONS'] as const;
const original = Object.fromEntries(names.map(name => [name, process.env[name]]));
const vector = resolve('test/vectors/default-readonly.macaroon');
const noMacaroonRead = resolve('test/vectors/grade-uri-read-pair.macaroon');
const missing = resolve('test/cp018-no-such-file');
const endpoint = '127.0.0.1:1';

function registryArgs(args: string[]): string[] {
  const testTmp = process.env.MACWARDEN_TEST_TMP;
  if (!testTmp) throw new Error('MACWARDEN_TEST_TMP is required');
  let path: string;
  do { path = join(resolve(testTmp), `cp018-registry-${randomUUID()}.json`); }
  while (existsSync(path));
  return ['inventory', '--registry', path, ...args];
}

function captureInventory(args: string[]) {
  return captureMain(main, registryArgs(args));
}

afterEach(() => {
  for (const name of names) {
    const value = original[name];
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

function cleanEnv() {
  for (const name of names) delete process.env[name];
}

function envelope(stdout: string) {
  let parsed: unknown;
  try { parsed = JSON.parse(stdout); }
  catch { throw new Error('Expected one JSON envelope'); }
  const value = parsed as {
    schema: number; command: string | null; ok: boolean; warnings: Array<string | {code:string;message?:string}>;
    result: unknown; error: { code: number; step: string | null; message: string } | null;
  };
  expect(value).toHaveProperty('schema', 1);
  expect(value).toHaveProperty('command', 'inventory');
  expect(value.ok).toBe(value.error === null);
  return value;
}

it('CP-018/B1 online flags use matching environment fallbacks and reject missing or unknown arguments', async () => {
  cleanEnv();
  for (const args of [[], ['--unknown'], ['--lnd-rest']]) {
    const actual = await captureInventory(['--json', ...args]);
    expect(actual.code).toBe(2);
    expect(actual.stderr).toBe('');
    expect(envelope(actual.stdout).error).toMatchObject({ code: 2, step: null });
    expect(actual.stdout).not.toContain('--unknown');
  }

  process.env.MACWARDEN_LND_REST = endpoint;
  process.env.MACWARDEN_TLS_CERT = missing;
  process.env.MACWARDEN_MACAROON = vector;
  const fromEnv = await captureInventory(['--json']);
  expect(fromEnv.code).toBe(4);
  expect(envelope(fromEnv.stdout).error?.message).toMatch(/tls|cert/i);

  // RO-4: connection settings come from one source. A flag never combines with the
  // environment's other settings: the mixed invocation is refused before any request.
  process.env.MACWARDEN_LND_REST = 'invalid-port:abc';
  const mixedRest = await captureInventory(['--json', '--lnd-rest', endpoint]);
  expect(mixedRest.code).toBe(2);
  expect(envelope(mixedRest.stdout).error).toMatchObject({ code: 2, step: null });
  expect(envelope(mixedRest.stdout).error?.message).toMatch(/MACWARDEN_TLS_CERT, MACWARDEN_MACAROON/);
  expect(mixedRest.stdout).not.toContain(vector.replaceAll('\\', '\\\\'));

  const mixedCert = await captureInventory(['--json', '--tls-cert',
    resolve('test/fixture/wrong-tls.cert'), '--macaroon', noMacaroonRead]);
  expect(mixedCert.code).toBe(2);
  expect(envelope(mixedCert.stdout).error?.message).toMatch(/MACWARDEN_LND_REST/);

  // All three flags: the environment is ignored entirely, whatever it holds.
  process.env.MACWARDEN_MACAROON = missing;
  const allFlags = await captureInventory(['--json', '--lnd-rest', endpoint,
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', noMacaroonRead]);
  expect(allFlags.code).toBe(4);
  expect(envelope(allFlags.stdout).error?.message).toMatch(/macaroon:read|ListMacaroonIDs|permission/i);
});

it('CP-018/B2 own macaroon argument refuses credential text without echoing it', async () => {
  cleanEnv();
  const bytes = readFileSync(vector);
  const forms = [bytes.toString('hex'), bytes.toString('base64'),
    `lndconnect://localhost:10009?macaroon=${bytes.toString('base64url')}`];
  for (const credential of forms) {
    for (const asEnv of [false, true]) {
      for (const json of [false, true]) {
        if (asEnv) process.env.MACWARDEN_MACAROON = credential;
        const actual = await captureInventory([...(json ? ['--json'] : []),
          '--lnd-rest', endpoint, '--tls-cert', missing,
          ...(!asEnv ? ['--macaroon', credential] : [])]);
        expect(actual.code).toBe(2);
        if (json) {
          expect(actual.stderr).toBe('');
          expect(envelope(actual.stdout).error).toMatchObject({ code: 2, step: null });
        }
        expect((actual.stdout + actual.stderr).includes(credential)).toBe(false);
        delete process.env.MACWARDEN_MACAROON;
      }
    }
  }
});

it('CP-018/B3 ENV refuses network debug and report settings before OWN; fs debug proceeds', async () => {
  cleanEnv();
  const args = ['--json', '--lnd-rest', endpoint,
    '--tls-cert', missing, '--macaroon', vector];
  for (const debug of ['http', 'https', 'tls', 'net', 'fs,net']) {
    process.env.NODE_DEBUG = debug;
    const actual = await captureInventory(args);
    expect(actual.code, debug).toBe(2);
    expect(envelope(actual.stdout).error).toMatchObject({ code: 2, step: expect.any(String) });
  }
  delete process.env.NODE_DEBUG;
  process.env.NODE_OPTIONS = '--report-on-fatalerror';
  const report = await captureInventory(args);
  expect(report.code).toBe(2);
  expect(envelope(report.stdout).error).toMatchObject({ code: 2, step: expect.any(String) });
  delete process.env.NODE_OPTIONS;
  process.env.NODE_DEBUG = 'fs';
  const control = await captureInventory(args);
  expect(control.code).toBe(4);
  expect(envelope(control.stdout).error?.message).toMatch(/tls|cert/i);
});

it('CP-018/B4 OWN refuses unreadable TLS, undecodable macaroon and missing permissions', async () => {
  cleanEnv();
  const base = ['--json', '--lnd-rest', endpoint];
  const absentCert = await captureInventory([...base, '--tls-cert', missing, '--macaroon', vector]);
  expect(absentCert.code).toBe(4);
  expect(envelope(absentCert.stdout).error?.message).toMatch(/tls|cert/i);

  // A public fixture JSON is intentionally not a macaroon. The TLS path exists,
  // so OWN must reach the credential decode before any connection attempt.
  const cert = resolve('test/vectors/default-readonly.printmacaroon.json');
  const badMacaroon = await captureInventory([...base, '--tls-cert', cert, '--macaroon', cert]);
  expect(badMacaroon.code).toBe(4);
  expect(envelope(badMacaroon.stdout).error?.message).toMatch(/macaroon|credential|decode/i);

  const missingPermission = await captureInventory([...base, '--tls-cert', cert,
    '--macaroon', noMacaroonRead]);
  expect(missingPermission.code).toBe(4);
  expect(envelope(missingPermission.stdout).error?.message).toMatch(/macaroon:read|ListMacaroonIDs|permission/i);
});
