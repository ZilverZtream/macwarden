import { childEnvironment } from './helpers/environment.js';
import { afterEach, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repo = resolve();
type Vector = { name: string; file: string; purpose: string; source: 'lncli' | 'hand-made'; expectedGrade: string; fingerprint: string; canonicalLength: number; network: string; lndVersion: string };
type Manifest = { vectors: Vector[]; notBakeable: { row: string; reason: string }[] };
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as Manifest;
const vectorsDir = join(repo, 'test/vectors');
const tempRoots: string[] = [];
function temp(): string {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const path = mkdtempSync(join(base, 'cp004-unit-')); tempRoots.push(path); return path;
}
afterEach(() => {
  for (const path of tempRoots.splice(0)) {
    const base = resolve(process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp'));
    if (!resolve(path).startsWith(base + '\\') && !resolve(path).startsWith(base + '/')) throw new Error('Unsafe test temp path');
    rmSync(path, { recursive: true, force: true });
  }
});
function stored(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(vectorsDir, `${name}.printmacaroon.json`), 'utf8'));
}
function stubRun(network: string | null, version: string): { code: number | null; calls: string[]; unchanged: boolean } {
  const root = temp();
  mkdirSync(join(root, 'scripts'), { recursive: true });
  mkdirSync(join(root, 'test/fixture'), { recursive: true });
  mkdirSync(join(root, 'test/helpers'), { recursive: true });
  mkdirSync(join(root, 'src/grade'), { recursive: true });
  copyFileSync(join(repo, 'scripts/make-vectors.mjs'), join(root, 'scripts/make-vectors.mjs'));
  copyFileSync(join(repo, 'test/fixture/observe-empty.mjs'), join(root, 'test/fixture/observe-empty.mjs'));
  copyFileSync(join(repo, 'test/fixture/topology.mjs'), join(root, 'test/fixture/topology.mjs'));
  copyFileSync(join(repo, 'test/helpers/fixture-invalid.mjs'), join(root, 'test/helpers/fixture-invalid.mjs'));
  copyFileSync(join(repo, 'src/grade/lnd-permissions.json'), join(root, 'src/grade/lnd-permissions.json'));
  cpSync(vectorsDir, join(root, 'test/vectors'), { recursive: true });
  writeFileSync(join(root, 'package.json'), '{"type":"module"}');
  const log = join(root, 'calls.jsonl');
  const stub = join(root, 'lncli-stub.mjs');
  const chains = network === null ? [] : [{ network }];
  writeFileSync(stub, `import { appendFileSync } from 'node:fs';\nappendFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2)) + '\\n');\nif (process.argv[2] === 'getinfo') { process.stdout.write(JSON.stringify(${JSON.stringify({ chains, version })})); process.exit(0); }\nprocess.exit(1);\n`);
  const beforeSnapshot = readFileSync(join(root, 'src/grade/lnd-permissions.json'));
  const beforeManifest = readFileSync(join(root, 'test/vectors/manifest.json'));
  const beforeFiles = new Map(manifest.vectors.flatMap(v => [v.file, `${v.name}.printmacaroon.json`]).map(file => [file, readFileSync(join(root, 'test/vectors', file))]));
  const p = spawnSync(process.execPath, ['scripts/make-vectors.mjs'], { cwd: root, encoding: 'utf8', timeout: 30_000,
    env: childEnvironment({ MACWARDEN_LNCLI: `"${process.execPath}" "${stub}"`, MACWARDEN_TEST_TMP: root }) });
  const calls = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line) as string[]).map(args => args[0]) : [];
  const unchanged = beforeSnapshot.equals(readFileSync(join(root, 'src/grade/lnd-permissions.json')))
    && beforeManifest.equals(readFileSync(join(root, 'test/vectors/manifest.json')))
    && [...beforeFiles].every(([file, bytes]) => bytes.equals(readFileSync(join(root, 'test/vectors', file))));
  return { code: p.status, calls, unchanged };
}

  it('CP-004/B1 every vector has a file, print JSON, regtest and pinned version', () => {
    expect(manifest.vectors.length).toBeGreaterThan(0);
    for (const vector of manifest.vectors) {
      expect(existsSync(join(vectorsDir, vector.file))).toBe(true);
      expect(existsSync(join(vectorsDir, `${vector.name}.printmacaroon.json`))).toBe(true);
      const print = stored(vector.name);
      for (const key of ['version', 'location', 'root_key_id', 'permissions', 'caveats']) expect(print).toHaveProperty(key);
      expect(typeof print.root_key_id).toBe('string');
      expect(Array.isArray(print.permissions)).toBe(true);
      expect(print.caveats === null || Array.isArray(print.caveats)).toBe(true);
      expect(vector.network).toBe('regtest');
      expect(vector.lndVersion.startsWith('0.21.4-beta')).toBe(true);
    }
  });
  it('CP-004/B2 grade rows, presets, caveats and structural cases are represented', () => {
    const names = new Set(manifest.vectors.map(v => v.name));
    const unbakeable = new Map(manifest.notBakeable.map(v => [v.row, v.reason]));
    const rows = ['admin-set', 'spend-pair', 'signer-read', 'info-write', 'onchain-generate', 'peers-pair', 'uri-disconnect',
      'invoice-send', 'uri-read-pair', 'uri-add-invoice', 'unknown-uri', 'unknown-entity', 'remote-signer', 'admin-unknown',
      'unknown-action', 'malformed-info', 'malformed-info-empty', 'malformed-empty-read', 'malformed-case',
      'malformed-uri-empty', 'malformed-uri-read', 'empty', 'duplicate-info'];
    for (const row of rows) {
      const name = `grade-${row}`;
      expect(names.has(name) || unbakeable.has(name), name).toBe(true);
      if (names.has(name)) expect(manifest.vectors.find(v => v.name === name)?.source).toBe('lncli');
      else expect(unbakeable.get(name)?.length).toBeGreaterThan(0);
    }
    for (const name of ['default-admin', 'default-readonly', 'default-invoice', 'preset-read-only', 'preset-invoice-only',
      'preset-pay-only', 'time-before', 'ipaddr', 'root-max']) expect(manifest.vectors.find(v => v.name === name)?.source).toBe('lncli');
    for (const name of ['third-party', 'unknown-condition', 'iprange', 'lnd-custom', 'time-nanosecond', 'time-unparseable',
      'duplicate-ops', 'no-location', 'trailing-bytes']) expect(manifest.vectors.find(v => v.name === name)?.source).toBe('hand-made');
    expect(stored('root-max').root_key_id).toBe('18446744073709551615');
    expect(unbakeable.get('grade-empty')).toContain('LND REST BakeMacaroon: permission list cannot be empty');
  });
  it('CP-004/B3 default file permission counts and identifiers match LND', () => {
    const admin = stored('default-admin'), readonly = stored('default-readonly'), invoice = stored('default-invoice');
    expect((admin.permissions as unknown[]).length).toBe(19);
    expect((readonly.permissions as unknown[]).length).toBe(9);
    expect((readonly.permissions as string[]).every(p => p.endsWith(':read'))).toBe(true);
    expect((invoice.permissions as unknown[]).length).toBe(5);
    for (const value of [admin, readonly, invoice]) {
      expect(value.root_key_id).toBe('0'); expect(value.location).toBe('lnd');
    }
    expect(readonly.caveats).toBeNull();
  });
  it('CP-004/B4 ListPermissions snapshot has the specified method facts', () => {
    const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { lndVersion: string; methods: Record<string, string[]> };
    expect(snapshot.lndVersion).toBe('0.21.4-beta');
    expect(Object.keys(snapshot.methods)).toHaveLength(164);
    for (const actions of Object.values(snapshot.methods)) {
      expect(Array.isArray(actions)).toBe(true);
      for (const action of actions) { expect(action).toMatch(/^[a-z]+:[a-z]+$/); expect(action.startsWith('remotesigner:')).toBe(false); }
    }
    expect(snapshot.methods['/autopilotrpc.Autopilot/ModifyStatus']).toEqual(['onchain:write', 'offchain:write']);
    expect(snapshot.methods['/routerrpc.Router/SendPaymentV2']).toEqual(['offchain:write']);
    expect(snapshot.methods['/routerrpc.Router/TrackPaymentV2']).toEqual(['offchain:read']);
    expect(snapshot.methods['/lnrpc.Lightning/DecodePayReq']).toEqual(['offchain:read']);
    expect(snapshot.methods['/lnrpc.Lightning/ListInvoices']).toEqual(['invoices:read']);
  });
  it('CP-004/B5 manifest fingerprints cover canonical bytes', () => {
    for (const vector of manifest.vectors) {
      const bytes = readFileSync(join(vectorsDir, vector.file));
      const expected = `fp:${createHash('sha256').update(bytes.subarray(0, vector.canonicalLength)).digest('hex').slice(0, 16)}`;
      expect(vector.fingerprint).toBe(expected);
      expect(vector.canonicalLength === bytes.length).toBe(vector.name !== 'trailing-bytes');
    }
  });
  it('CP-004/B6 wrong networks stop before any write or second lncli call', () => {
    for (const network of ['mainnet', 'testnet', 'signet', null]) {
      const result = stubRun(network, '0.21.4-beta commit=v0.21.4-beta');
      expect(result.code).toBe(1); expect(result.calls).toEqual(['getinfo']); expect(result.unchanged).toBe(true);
    }
  });
  it('CP-004/B7 wrong LND version stops before writes and the pinned version proceeds', () => {
    const wrong = stubRun('regtest', '0.21.5-beta commit=v0.21.5-beta');
    expect(wrong.code).toBe(1); expect(wrong.calls).toEqual(['getinfo']); expect(wrong.unchanged).toBe(true);
    const correct = stubRun('regtest', '0.21.4-beta commit=v0.21.4-beta');
    expect(correct.calls[0]).toBe('getinfo'); expect(correct.calls).toContain('listpermissions');
  });
  it('CP-004/B8 compose pins the fixture images and regtest flags', () => {
    const compose = readFileSync(join(repo, 'test/fixture/docker-compose.yml'), 'utf8');
    const images = [...compose.matchAll(/^\s*image:\s*(\S+)\s*$/gm)].map(match => match[1]);
    expect(images).toEqual([
      'lightninglabs/bitcoin-core:31.1@sha256:86e15e4348869a86343aacbbd1aff38e96cffddd87b61644694b1e1358d737cd',
      'lightninglabs/lnd:v0.21.4-beta@sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d',
    ]);
    for (const flag of ['--bitcoin.regtest', '--noseedbackup', '--restlisten=0.0.0.0:8080', '--tlsextradomain=localhost']) expect(compose).toContain(flag);
    expect(compose).not.toMatch(/--(?:bitcoin\.)?(?:mainnet|testnet|signet)\b/);
  });
  it('CP-004/B9 vector README labels disposable regtest credentials', () => {
    const readme = readFileSync(join(vectorsDir, 'README.md'), 'utf8');
    expect(readme).toMatch(/throwaway regtest credentials from a disposable node/);
  });
