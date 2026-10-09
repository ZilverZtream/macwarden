// RR-02: Kubernetes Secret `data:` values (and Helm values, `kubectl get secret -o yaml`) hold
// the base64 of the stored text. A hex, base64 or lndconnect credential stored that way must be
// found, one level deep, at its location in the scanned file.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { run as scanCommand } from '../src/commands/scan.js';
import { scan, type ScanResult } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const reference = (name: string) => manifest.vectors.find(entry => entry.name === name)!;
const admin = vector('default-admin');
const b64 = (text: string) => Buffer.from(text).toString('base64');
const secret = (value: string) => `apiVersion: v1\nkind: Secret\nmetadata:\n  name: lnd\ndata:\n  LND_MACAROON: ${value}\n`;
const brief = (result: ScanResult) => result.findings.map(({ kind, line, column, fingerprint, grade }) => ({ kind, line, column, fingerprint, grade }));
const want = { fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' };

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr02-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('RR-02 finds hex, base64 and lndconnect credentials stored base64-encoded in a Kubernetes Secret', async () => temp(async dir => {
  const forms = [
    ['macaroon-hex', admin.toString('hex')],
    ['macaroon-hex', admin.toString('hex').toUpperCase()],
    ['macaroon-base64', admin.toString('base64')],
    ['lndconnect', `lndconnect://node.example:10009?macaroon=${admin.toString('base64url')}`],
  ] as const;
  for (const [index, [kind, stored]] of forms.entries()) {
    const path = join(dir, `secret-${index}.yaml`);
    writeFileSync(path, secret(b64(stored)));
    const result = await scan([path], {});
    expect(brief(result), `${kind} ${index}`).toEqual([{ kind, line: 6, column: 17, ...want }]);
    const run = await scanCommand([path, '--fail-on', 'READ', '--json'], { fs });
    expect(run.exitCode).toBe(1);
  }
}));

it('RR-02 finds the credential at every byte alignment inside the encoded text, at its encoded column', async () => temp(async dir => {
  const hex = admin.toString('hex');
  for (const lead of ['', 'x', 'xy', 'LND_MACAROON=', 'export MAC="']) {
    const path = join(dir, 'aligned.yaml');
    writeFileSync(path, `data: ${b64(lead + hex + '"\n')}\n`);
    const result = await scan([path], {});
    expect(brief(result), JSON.stringify(lead)).toEqual([{ kind: 'macaroon-hex', line: 1, column: 7 + Math.floor(lead.length * 4 / 3), ...want }]);
  }
}));

it('RR-02 an encoded candidate that does not decode is a candidate; unrelated base64 is not reported', async () => temp(async dir => {
  const path = join(dir, 'mixed.yaml');
  writeFileSync(path, [
    `cut: ${b64(admin.toString('hex').slice(0, 200))}`,
    `plain: ${b64('just some configuration text that is long enough to be base64')}`,
    `binary: ${Buffer.alloc(300, 7).toString('base64')}`,
  ].join('\n'));
  const result = await scan([path], {});
  expect(result.findings.map(({ kind, line, column }) => ({ kind, line, column }))).toEqual([
    { kind: 'undecodable-candidate', line: 1, column: 6 }]);
}));

it('RR-02 decoding stays one level deep and linear on hostile lines', async () => temp(async dir => {
  // Base64 of base64 of hex is not followed: one level only.
  const nested = join(dir, 'nested.yaml');
  writeFileSync(nested, `data: ${b64(b64(admin.toString('hex')))}\n`);
  expect((await scan([nested], {})).findings).toEqual([]);
  // Lines of encoded prefixes with no credential.
  const unit = b64(`0201036c6e6402${'0'.repeat(40)}`);
  const timings: number[] = [];
  for (const size of [1_000_000, 4_000_000]) {
    const path = join(dir, `hostile-${size}.txt`);
    writeFileSync(path, unit.repeat(Math.ceil(size / unit.length)).slice(0, size - (size % 4)));
    const started = performance.now();
    const result = await scan([path], {});
    timings.push(performance.now() - started);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.every(finding => finding.kind === 'undecodable-candidate')).toBe(true);
  }
  console.log(`RR-02 scan ms [1 MB, 4 MB]: ${timings.map(Math.round).join(', ')}`);
  expect(timings[1]).toBeLessThan(10_000);
  expect(timings[1]).toBeLessThan(8 * Math.max(timings[0], 25));
}), 60_000);
