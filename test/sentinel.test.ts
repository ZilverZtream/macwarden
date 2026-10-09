import { revealSecret } from './helpers/secret-bytes.js';
import { render } from './helpers/render-adversarial.js';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { inspect } from 'node:util';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const sentinelPath = join(repo, 'test', 'sentinels', 'sentinel.macaroon');
const sentinelManifest = join(repo, 'test', 'sentinels.json');
const sentinel = () => readFileSync(sentinelPath);

function assertNoCredential(text: string, secret: Buffer): void {
  const base64 = secret.toString('base64');
  const forms = [secret.toString('utf8'), secret.toString('latin1'), secret.toString('hex'),
    secret.toString('hex').toUpperCase(), base64, base64.replace(/=+$/, ''),
    base64.replace(/\+/g, '-').replace(/\//g, '_'), secret.toString('base64url')];
  for (const value of forms) expect(text.includes(value), 'credential encoding leaked').toBe(false);
}

function leakCheck(text: string): number | null {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  process.env.MACWARDEN_TEST_TMP = base;
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp003-output-'));
  try {
    const output = join(dir, 'captured.txt');
    writeFileSync(output, text);
    const run = spawnSync(process.execPath,
      [join(repo, 'scripts', 'leak-check.mjs'), '--sentinels', sentinelManifest, output],
      { cwd: repo, encoding: 'utf8', timeout: 15_000 });
    return run.status;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('CP-003/B1 Secret redacts implicit representations and reveals the original bytes', async () => {
  const { Secret } = await import('../src/secret.js');
  const original = sentinel();
  const secret = new Secret(original);
  const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  const logged = (() => { try {
    console.log(secret);
    return inspect(log.mock.calls[0]?.[0]);
  } finally { log.mockRestore(); } })();
  const forms = [String(secret), `${secret}`, JSON.stringify({ secret }), inspect(secret), logged];
  for (const form of forms) {
    expect(/\[redacted fp:[0-9a-f]{16}\]/.test(form), 'Secret representation lacks redaction').toBe(true);
    assertNoCredential(form, original);
    expect(leakCheck(form)).toBe(0);
  }
  expect(Buffer.from(revealSecret(secret)).equals(original)).toBe(true);
});

it('CP-003/B2 Secret fingerprint uses the first 16 SHA-256 hex digits', async () => {
  const { Secret } = await import('../src/secret.js');
  expect(new Secret(Buffer.from('abc')).fingerprint).toBe('fp:ba7816bf8f01cfea');
});

it('CP-003/B8 sentinel manifest identifies one structurally valid v2 macaroon', () => {
  const globs = JSON.parse(readFileSync(sentinelManifest, 'utf8')) as string[];
  expect(globs).toEqual(['test/sentinels/*.macaroon']);
  expect(readdirSync(join(repo, 'test', 'sentinels')).filter(name => name.endsWith('.macaroon'))).toEqual(['sentinel.macaroon']);
  expect(existsSync(sentinelPath)).toBe(true);
  const bytes = sentinel();
  expect(bytes.subarray(0, 7).equals(Buffer.from([2, 1, 3, 108, 110, 100, 2]))).toBe(true);
  let at = 7;
  const identifierSize = bytes[at++];
  const identifier = bytes.subarray(at, at + identifierSize);
  at += identifierSize;
  expect(identifier[0]).toBe(3);
  // Protobuf field 2 is the storage ID; field 1 would identify an obsolete test oracle.
  expect(identifier.subarray(1, 3).equals(Buffer.from([0x12, 6]))).toBe(true);
  expect(identifier.subarray(3).toString('ascii')).toBe('424242');
  expect(bytes.subarray(at, at + 4).equals(Buffer.from([0, 0, 6, 32]))).toBe(true);
  at += 4;
  expect(bytes.subarray(at).length).toBe(32);
  expect(createHash('sha256').update(bytes).digest('hex').length).toBe(64);
});

it('CP-036/A3-valid-sentinel global sentinel has field-2 storage ID and independent fingerprint', async () => {
  const bytes = sentinel();
  const expected = JSON.parse(readFileSync(join(repo, 'test', 'sentinels', 'manifest.json'), 'utf8')) as {
    file: string; fingerprint: string; length: number; storageId: string };
  expect(expected.file).toBe('sentinel.macaroon');
  expect(bytes.length).toBe(expected.length);
  expect(bytes[0]).toBe(2);
  let at = 1;
  const readPacket = () => {
    const kind = bytes[at++];
    const length = bytes[at++];
    const value = bytes.subarray(at, at + length);
    at += length;
    return { kind, value };
  };
  expect(readPacket().kind).toBe(1);
  const identifier = readPacket();
  expect(identifier.kind).toBe(2);
  expect(identifier.value[0]).toBe(3);
  expect(identifier.value[1]).toBe(0x12);
  expect(identifier.value[2]).toBe(identifier.value.length - 3);
  expect(identifier.value.subarray(3).toString('ascii')).toBe(expected.storageId);
  expect(bytes[at++]).toBe(0);
  expect(bytes[at++]).toBe(0);
  const signature = readPacket();
  expect(signature.kind).toBe(6);
  expect(signature.value.length).toBe(32);
  expect(at).toBe(bytes.length);
  const fingerprint = `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
  expect(fingerprint).toBe(expected.fingerprint);
  const { decodeMacaroon } = await import('../src/decode/index.js');
  const { Secret } = await import('../src/secret.js');
  const decoded = decodeMacaroon(new Secret(bytes));
  expect(decoded.rootKeyId).toBe(424242n);
  expect(decoded.fingerprint).toBe(expected.fingerprint);
});

it('CP-036/A3-valid-sentinel global sentinel succeeds through inspect and scan without output leaks', async () => {
  const source = sentinel();
  const expected = JSON.parse(readFileSync(join(repo, 'test', 'sentinels', 'manifest.json'), 'utf8')) as {
    fingerprint: string; storageId: string };
  const run = spawnSync(process.execPath, [join(repo, 'dist', 'bin.js'), 'inspect', sentinelPath, '--json'],
    { cwd: repo, encoding: 'utf8', timeout: 10_000 });
  expect(run.status).toBe(0);
  const doc = JSON.parse(run.stdout);
  expect(doc.result.rootKeyId).toBe(expected.storageId);
  expect(doc.result.fingerprint).toBe(expected.fingerprint);
  assertNoCredential((run.stdout || '') + (run.stderr || ''), source);
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'cp036-sentinel-'));
  try {
    const planted = join(dir, 'credential.env');
    writeFileSync(planted, `LND_MACAROON=${source.toString('hex')}\n`);
    const { scan } = await import('../src/scan/index.js');
    const observed = await scan([planted], {});
    expect(observed.findings.some(item => item.fingerprint === expected.fingerprint)).toBe(true);
    assertNoCredential(JSON.stringify(observed), source);
    expect(leakCheck(JSON.stringify(observed))).toBe(0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-003/B9 unit sentinel check accepts captured redacted and escaped output', async () => {
  const { Secret } = await import('../src/secret.js');
  const output = await import('../src/output/index.js');
  const secret = new Secret(sentinel());
  const rendered = [String(secret), JSON.stringify({ secret }), inspect(secret),
    output.error('input-form', `unsafe ${sentinel().toString('hex')}`),
    render({schema:1,command:'inspect',ok:false,warnings:[],result:null,
      error:{code:3,step:'input-form',message:`path\x1b\x07\x7f\x9bé`}}, 'text')].join('\n');
  expect(leakCheck(rendered)).toBe(0);
});

it('CP-003/B10 the standalone leak check names an evidence file containing the sentinel', () => {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const evidence = mkdtempSync(join(base, 'cp003-evidence-'));
  try {
    writeFileSync(join(evidence, 'leak.txt'), sentinel().toString('base64'));
    const run = spawnSync(process.execPath,
      [join(repo, 'scripts', 'leak-check.mjs'), '--sentinels', sentinelManifest, evidence],
      { cwd: repo, encoding: 'utf8', timeout: 90_000 });
    expect(run.status).toBe(1);
    const output = (run.stdout || '') + (run.stderr || '');
    expect(output).toContain('leak.txt');
    assertNoCredential(output, sentinel());
  } finally { rmSync(evidence, { recursive: true, force: true }); }
}, 120_000);
