import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";

type Finding = { path: string; line: number | null; column: number | null; kind: string;
  fingerprint: string; grade: string | null };
type Result = { findings: Finding[]; skipped: { path: string; reason: string }[];
  summary: Record<string, unknown>; failOn: unknown };
type Scanner = { scan: (paths: string[], options: object) => Promise<Result> };
type RelativeFinding = Omit<Finding, 'path'> & { path: string };

const scanner = (): Promise<Scanner> => import('../../src/scan/index.js') as Promise<Scanner>;
const repo = resolve();
const root = join(repo, 'test/scan-fixtures/walk');
const vectorRoot = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
  files: { path: string; findings: Omit<RelativeFinding, 'path'>[] }[];
  skipped: { path: string; reason: string }[];
  summary: Record<string, unknown> };
const vectors = JSON.parse(readFileSync(join(vectorRoot, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const reference = (name: string) => vectors.vectors.find(item => item.name === name)!;
const vector = (name: string) => readFileSync(join(vectorRoot, `${name}.macaroon`));
const fp = (bytes: Buffer) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
const slash = (path: string) => path.split(sep).join('/');
async function scanFixture() { return (await scanner()).scan([root], {}); }
function allEntries(path: string): string[] {
  return readdirSync(path).flatMap(name => {
    const child = join(path, name);
    const entry = slash(relative(root, child));
    return statSync(child).isDirectory() ? [entry, ...allEntries(child)] : [entry];
  });
}

it('CP-010/walk-manifest directory result equals the independent planted-item manifest', async () => {
  const expectedEntries = [
    'manifest.json', 'a.env', 'admin.macaroon', 'bad.macaroon', 'inv.MACAROON', 'ro.macaroon',
    'sub', 'sub/b.yml', 'node_modules', 'node_modules/x.env',
    'MACAROONS.DB', 'seed', 'seed/hidden.env', 'binary.txt',
  ];
  expect(allEntries(root).sort()).toEqual(expectedEntries.sort());
  for (const [path, name] of [
    ['a.env', 'default-readonly'], ['ro.macaroon', 'default-readonly'],
    ['sub/b.yml', 'default-invoice'], ['inv.MACAROON', 'default-invoice'],
    ['admin.macaroon', 'default-admin'],
  ]) {
    const expected = manifest.files.find(item => item.path === path)!.findings[0];
    expect(expected.fingerprint).toBe(reference(name).fingerprint);
    expect(expected.grade).toBe(reference(name).expectedGrade);
  }
  expect(manifest.files.find(item => item.path === 'bad.macaroon')!.findings[0].fingerprint)
    .toBe(fp(readFileSync(join(root, 'bad.macaroon'))));
  expect(manifest.files.length).toBe(manifest.summary.filesScanned);
  expect(manifest.skipped.length).toBe(manifest.summary.filesSkipped);
  expect(manifest.files.flatMap(item => item.findings).length).toBe(manifest.summary.findings);
  expect(new Set(manifest.files.flatMap(item => item.findings.map(f => f.fingerprint))).size)
    .toBe(manifest.summary.distinct);
  const result = await scanFixture();
  const findings = result.findings.map(item => ({
    path: slash(relative(root, item.path)), line: item.line, column: item.column,
    kind: item.kind, fingerprint: item.fingerprint, grade: item.grade,
  }));
  expect(findings).toEqual(manifest.files.flatMap(item => item.findings.map(f => ({ path: item.path, ...f }))));
  expect(result.skipped.map(item => ({ path: slash(relative(root, item.path)), reason: item.reason })))
    .toEqual(manifest.skipped);
  expect(result.summary).toEqual(manifest.summary);
  expect(result.failOn).toBeNull();
});

it('CP-010/leak-check walk result contains no sentinel encoding', async () => {
  const result = await scanFixture();
  expect(result.findings).toHaveLength(6);
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp010-leak-'));
  try {
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    for (const name of ['default-admin', 'default-readonly', 'default-invoice'])
      writeFileSync(join(sentinelDir, `${name}.macaroon`), vector(name));
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: JSON.stringify(result), testTmp, root: repo }), 'credential leaked').toBeNull();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
