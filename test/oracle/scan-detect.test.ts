import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";

type Finding = { path: string; line: number | null; column: number | null; kind: string;
  fingerprint: string; grade: string | null };
type Result = { findings: Finding[]; skipped: unknown[]; summary: Record<string, unknown>; failOn: unknown };
type Scanner = { scan: (paths: string[], opts: object) => Promise<Result> };
type Expected = { path: string; dropped: number; findings: Omit<Finding, 'path'>[] };
const repo = resolve();
const root = join(repo, 'test/scan-fixtures/detect');
const vectorRoot = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
  files: Expected[]; summary: Record<string, unknown> };
const vectors = JSON.parse(readFileSync(join(vectorRoot, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const vector = (name: string) => readFileSync(join(vectorRoot, `${name}.macaroon`));
const reference = (name: string) => vectors.vectors.find(item => item.name === name)!;

const scanner = (): Promise<Scanner> => import('../../src/scan/index.js') as Promise<Scanner>;
const slash = (path: string) => path.split(sep).join('/');
const fp = (bytes: Buffer | string) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
async function scanFixture(): Promise<Result> {
  const { scan } = await scanner();
  return scan(manifest.files.map(item => join(root, item.path)), {});
}
function projected(result: Result): Finding[] {
  return result.findings.map(finding => ({ path: slash(relative(root, finding.path)),
    line: finding.line, column: finding.column, kind: finding.kind,
    fingerprint: finding.fingerprint, grade: finding.grade }));
}

it('CP-009/detect-manifest every planted text item matches the independent manifest', async () => {
  const listed = manifest.files.map(item => item.path).sort();
  expect(readdirSync(root).filter(name => name !== 'manifest.json').sort()).toEqual(listed);
  expect(manifest.files.reduce((sum, item) => sum + item.dropped, 0)).toBe(manifest.summary.dropped);
  expect(manifest.files.flatMap(item => item.findings).length).toBe(manifest.summary.findings);
  expect(manifest.files.length).toBe(manifest.summary.filesScanned);
  expect(new Set(manifest.files.flatMap(item => item.findings.map(f => f.fingerprint))).size)
    .toBe(manifest.summary.distinct);
  for (const [prefix, name] of [
    ['hex', 'default-readonly'], ['base64', 'default-invoice'], ['lndconnect', 'preset-pay-only'],
  ]) for (const entry of manifest.files.filter(item => item.path.startsWith(`${prefix}.`))) {
    expect(entry.findings).toHaveLength(1);
    expect(entry.findings[0].fingerprint).toBe(reference(name).fingerprint);
    expect(entry.findings[0].grade).toBe(reference(name).expectedGrade);
  }
  const secret = Buffer.alloc(32, 0x11);
  for (const entry of manifest.files.filter(item => item.path.startsWith('nwc.')))
    expect(entry.findings[0].fingerprint).toBe(fp(secret));
  const admin = vector('default-admin');
  expect(manifest.files.find(item => item.path === 'wrapped-hex.txt')!.findings[0].fingerprint)
    .toBe(fp(admin.toString('hex').slice(0, 120)));
  expect(manifest.files.find(item => item.path === 'wrapped-base64.txt')!.findings[0].fingerprint)
    .toBe(fp(admin.toString('base64').slice(0, 76)));
  const result = await scanFixture();
  const expected = manifest.files.flatMap(item => item.findings.map(finding => ({ path: item.path, ...finding })));
  expect(projected(result)).toEqual(expected);
  expect(result.summary).toEqual(manifest.summary);
  expect(result.skipped).toEqual([]);
  expect(result.failOn).toBeNull();
});

it('CP-009/leak-check detect result contains no sentinel encoding', async () => {
  const result = await scanFixture();
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp009-leak-'));
  try {
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    for (const name of ['default-admin', 'default-readonly', 'default-invoice', 'preset-pay-only'])
      writeFileSync(join(sentinelDir, `${name}.macaroon`), vector(name));
    writeFileSync(join(sentinelDir, 'nwc.bin'), Buffer.alloc(32, 0x11));
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: JSON.stringify(result), testTmp, root: repo }), 'credential leaked').toBeNull();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
