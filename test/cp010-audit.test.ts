import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';

type Finding = { path: string; line: number | null; column: number | null;
  kind: string; fingerprint: string; grade: string | null };
type Result = { findings: Finding[]; skipped: { path: string; reason: string }[];
  summary: { filesScanned: number; filesSkipped: number; findings: number; distinct: number } };
type Scanner = { scan: (paths: string[], options: object) => Promise<Result> };

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const readonly = manifest.vectors.find(item => item.name === 'default-readonly')!;
const credential = () => readFileSync(join(vectors, 'default-readonly.macaroon'));
const display = (path: string) => path.replaceAll('\\', '/');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;

async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp010-audit-'));
  try { return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function put(dir: string, name: string, content: string): string {
  const path = join(dir, name);
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
  return path;
}

function expected(path: string, column: number): Pick<Finding, 'path' | 'line' | 'column' | 'kind' | 'fingerprint' | 'grade'> {
  return { path: display(path), line: 1, column, kind: 'macaroon-hex',
    fingerprint: readonly.fingerprint, grade: readonly.expectedGrade };
}

it('CP-010/B15 adjacent window lengths deduplicate Unicode-positioned matches', async () => temp(async dir => {
  const hex = credential().toString('hex');
  const firstStart = 32_768; // Zero-based Unicode code-point offset, inside the overlapping windows.
  const sizes = [65_535, 65_536, 65_537];
  const paths = sizes.map(size => {
    const lastStart = size - Array.from(hex).length;
    const line = 'é😀' + '.'.repeat(firstStart - 2) + hex +
      '.'.repeat(lastStart - firstStart - Array.from(hex).length) + hex;
    expect(Array.from(line)).toHaveLength(size);
    return put(dir, `line-${size}.txt`, line);
  });
  const result = await (await scanner()).scan([dir], {});
  expect(result.findings.map(({ path, line, column, kind, fingerprint, grade }) =>
    ({ path, line, column, kind, fingerprint, grade }))).toEqual(
    paths.flatMap((path, index) => [
      expected(path, firstStart + 1),
      expected(path, sizes[index] - Array.from(hex).length + 1),
    ]));
  expect(new Set(result.findings.map(item => `${item.path}:${item.line}:${item.column}`)).size).toBe(6);
  expect(result.summary).toMatchObject({ filesScanned: 3, findings: 6, distinct: 1 });
}));

// 1.1.1 (robustness review RR-07): only Windows treats a backslash as a separator. On POSIX a
// literal backslash in a supplied or discovered name is part of the name and is kept.
it('CP-010/B16 supplied and discovered paths display with / separators, keeping literal backslashes in POSIX names', async () => temp(async dir => {
  const hex = credential().toString('hex');
  const root = join(dir, process.platform === 'win32' ? 'tree' : 'literal\\component');
  const file = put(root, process.platform === 'win32' ? 'name.env' : 'name\\part.env', hex);
  const excluded = join(root, '.git');
  put(excluded, 'hidden.env', hex);
  const supplied = process.platform === 'win32' ? `${root.replaceAll('/', '\\')}\\` : `${root}${sep}`;
  const result = await (await scanner()).scan([supplied], {});
  const shown = (path: string) => process.platform === 'win32' ? display(path) : path;
  expect(result.findings.map(item => ({ path: item.path, kind: item.kind,
    fingerprint: item.fingerprint }))).toEqual([{
    path: shown(file), kind: 'macaroon-hex', fingerprint: readonly.fingerprint,
  }]);
  expect(result.skipped).toEqual([{ path: shown(excluded), reason: 'excluded-dir' }]);
  expect(result.summary).toMatchObject({ filesScanned: 1, filesSkipped: 1 });
}));

it('CP-010/B16 dot argument reports a relative path without a prefix', async () => temp(async dir => {
  const hex = credential().toString('hex');
  put(dir, 'a.env', hex);
  put(dir, '.git/hidden.env', hex);
  const map = (entry: string) => {
    const normalized = entry.replaceAll('\\', '/');
    if (normalized === '.' || normalized === repo.replaceAll('\\', '/')) return dir;
    if (normalized.startsWith(`${repo.replaceAll('\\', '/')}/`))
      return join(dir, normalized.slice(repo.length + 1));
    return join(dir, normalized.replace(/^\.\//, ''));
  };
  const fileSystem = { ...fs,
    stat: (entry: string, options?: { bigint?: boolean }) => fs.stat(map(entry), options as never),
    lstat: (entry: string, options?: { bigint?: boolean }) => fs.lstat(map(entry), options as never),
    readdir: (entry: string, options?: object) => fs.readdir(map(entry), options as never),
    open: (entry: string, flags: string | number) => fs.open(map(entry), flags),
    readFile: (entry: string) => fs.readFile(map(entry)),
    realpath: async (entry: string) => entry,
  };
  const result = await (await scanner()).scan(['.'], { fs: fileSystem });
  expect(result.findings.map(item => item.path)).toEqual(['a.env']);
  expect(result.skipped).toEqual([{ path: '.git', reason: 'excluded-dir' }]);
}));

it('CP-010/B17 explicit file close failures reject at input-read without disclosure', async () => temp(async dir => {
  const bytes = credential();
  const path = put(dir, 'explicit.env', bytes.toString('hex'));
  const marker = 'cp010-close-explicit-marker';
  let closes = 0;
  const fileSystem = { ...fs,
    open: vi.fn(async (entry: string, flags: string | number) => {
      const handle = await fs.open(entry, flags);
      return new Proxy(handle, { get(target, key) {
        if (key === 'close') return async () => {
          closes++;
          await target.close();
          throw new Error(marker);
        };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }),
  };
  let failure: unknown;
  try { await (await scanner()).scan([path], { fs: fileSystem }); }
  catch (error) { failure = error; }
  expect(failure).toMatchObject({ name: 'InputError', stage: 'input-read' });
  expect(closes).toBe(1);
  const shown = `${String(failure)}\n${String((failure as Error).stack)}\n${JSON.stringify(failure)}`;
  expect(shown.includes(marker)).toBe(false);
  expect(shown.includes(bytes.toString('hex'))).toBe(false);
  expect(shown.includes(bytes.toString('base64'))).toBe(false);
}));

it('CP-010/B17 discovered file close failures skip unreadable and continue', async () => temp(async dir => {
  const bytes = credential();
  const failed = put(dir, 'a.env', bytes.toString('hex'));
  const good = put(dir, 'b.env', bytes.toString('hex'));
  const marker = 'cp010-close-discovered-marker';
  let closes = 0;
  const fileSystem = { ...fs,
    open: vi.fn(async (entry: string, flags: string | number) => {
      const handle = await fs.open(entry, flags);
      return new Proxy(handle, { get(target, key) {
        if (key === 'close' && entry === failed) return async () => {
          closes++;
          await target.close();
          throw new Error(marker);
        };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }),
  };
  const result = await (await scanner()).scan([dir], { fs: fileSystem });
  expect(closes).toBe(1);
  expect(result.skipped).toEqual([{ path: display(failed), reason: 'unreadable' }]);
  expect(result.findings.map(item => ({ path: item.path, kind: item.kind,
    fingerprint: item.fingerprint }))).toEqual([{
    path: display(good), kind: 'macaroon-hex', fingerprint: readonly.fingerprint,
  }]);
  expect(result.summary).toMatchObject({ filesScanned: 1, filesSkipped: 1, findings: 1 });
  const shown = JSON.stringify(result);
  expect(shown.includes(marker)).toBe(false);
  expect(shown.includes(bytes.toString('hex'))).toBe(false);
  expect(shown.includes(bytes.toString('base64'))).toBe(false);
}));
