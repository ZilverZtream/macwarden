// RR-03: JSON encoders that escape "/" as "\/" (PHP json_encode by default, some Java and Go
// encoders) must not hide a base64 macaroon or an lndconnect URI.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { run as scanCommand } from '../src/commands/scan.js';
import { scan } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const reference = (name: string) => manifest.vectors.find(entry => entry.name === name)!;
const escaped = (text: string) => text.replace(/\//g, '\\/');

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr03-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('RR-03 finds base64 macaroons with JSON-escaped slashes, wherever the first slash falls', async () => temp(async dir => {
  const names = manifest.vectors.map(entry => entry.name).filter(name => vector(name).toString('base64').includes('/'));
  // The invoice vector has a slash within its first 49 characters: before, nothing matched.
  expect(vector('default-invoice').toString('base64').indexOf('/')).toBeLessThan(49);
  expect(names).toContain('default-invoice');
  const brief = (findings: { kind: string; line: number | null; column: number | null; fingerprint: string; grade: string | null }[]) =>
    findings.map(({ kind, line, column, fingerprint, grade }) => ({ kind, line, column, fingerprint, grade }));
  for (const name of names) {
    // Each vector found as it is found unescaped.
    const plain = join(dir, `${name}.plain.json`);
    writeFileSync(plain, `{"macaroon":"${vector(name).toString('base64')}"}\n`);
    const baseline = brief((await scan([plain], {})).findings);
    expect(baseline.length, name).toBe(1);
    const path = join(dir, `${name}.json`);
    writeFileSync(path, `{"macaroon":"${escaped(vector(name).toString('base64'))}"}\n`);
    expect(brief((await scan([path], {})).findings), name).toEqual(baseline);
    const run = await scanCommand([path, '--fail-on', 'READ', '--json'], { fs });
    expect(run.exitCode, name).toBe(1);
  }
  expect(brief((await scan([join(dir, 'default-invoice.json')], {})).findings)).toEqual([{ kind: 'macaroon-base64', line: 1, column: 14,
    fingerprint: reference('default-invoice').fingerprint, grade: reference('default-invoice').expectedGrade }]);
}));

it('RR-03 finds an lndconnect URI with JSON-escaped slashes, and an escaped standard base64 parameter', async () => temp(async dir => {
  const admin = vector('default-admin');
  const path = join(dir, 'config.json');
  const uri = `lndconnect://node.example:10009?macaroon=${admin.toString('base64url')}`;
  const standard = `lndconnect://node.example:10009?macaroon=${admin.toString('base64')}`;
  writeFileSync(path, `{"a":"${escaped(uri)}"}\n{"b":"${escaped(standard)}"}\n`);
  const result = await scan([path], {});
  expect(result.findings.map(({ kind, line, column, fingerprint, grade }) => ({ kind, line, column, fingerprint, grade }))).toEqual([
    { kind: 'lndconnect', line: 1, column: 7, fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' },
    { kind: 'lndconnect', line: 2, column: 7, fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' }]);
  expect(result.summary.dropped).toBe(0);
}));

it('RR-03 an escaped candidate that does not decode is still a candidate, reported once', async () => temp(async dir => {
  const base64 = vector('default-invoice').toString('base64');
  const path = join(dir, 'cut.json');
  writeFileSync(path, `{"macaroon":"${escaped(base64.slice(0, -8))}"}\n`);
  const result = await scan([path], {});
  expect(result.findings.map(({ kind, column }) => ({ kind, column }))).toEqual([{ kind: 'undecodable-candidate', column: 14 }]);
}));
