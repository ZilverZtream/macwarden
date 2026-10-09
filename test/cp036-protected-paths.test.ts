import { revealSecret } from './helpers/secret-bytes.js';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';

type Manifest = {
  protected: string[];
  resolvedTargets: { supplied: string; resolved: string }[];
  ordinary: string[];
};
const repo = resolve();
const manifest = JSON.parse(readFileSync(join(repo, 'test/scan-fixtures/protected/manifest.json'), 'utf8')) as Manifest;
const source = readFileSync(join(repo, 'test/vectors/default-invoice.macaroon'));
const slash = (path: string) => path.split(sep).join('/');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp-cp036-protected');
process.env.MACWARDEN_TEST_TMP = testTmp;

async function owned<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'paths-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function guardedFs(resolved: string) {
  const meta = { dev: 23n, ino: 31n, size: source.length,
    isFile: () => true, isDirectory: () => false, isSymbolicLink: (): boolean => false };
  const opened = vi.fn(async () => { throw new Error('protected content was opened'); });
  const read = vi.fn(async () => { throw new Error('protected content was read'); });
  return {
    ...fs,
    stat: vi.fn(async () => meta) as unknown as typeof fs.stat,
    lstat: vi.fn(async () => meta) as unknown as typeof fs.lstat,
    realpath: vi.fn(async () => resolved) as unknown as typeof fs.realpath,
    open: opened as unknown as typeof fs.open,
    readFile: read as unknown as typeof fs.readFile,
    opened, read,
  };
}

const protectedCases = [
  ...manifest.protected.map(name => ({ supplied: name, resolved: name })),
  ...manifest.resolvedTargets,
];

it('CP-036/A8-protected-input-scan inspect refuses every protected component before opening', async () => owned(async dir => {
  const { readCredential } = await import('../src/input/index.js');
  for (const item of protectedCases) {
    const supplied = join(dir, item.supplied);
    const guarded = guardedFs(join(dir, item.resolved));
    let inputError: { name?: string; stage?: string; message?: string } | undefined;
    try { await readCredential(supplied, { stdin: Readable.from([]), fs: guarded }, { unsafeArg: false }); }
    catch (error) { inputError = error as typeof inputError; }
    expect.soft(inputError?.name, item.supplied).toBe('InputError');
    expect.soft(inputError?.stage, item.supplied).toBe('input-read');
    expect.soft(inputError?.message?.includes(supplied), item.supplied).toBe(false);
    expect.soft(guarded.opened, item.supplied).not.toHaveBeenCalled();
    expect.soft(guarded.read, item.supplied).not.toHaveBeenCalled();
  }
}));

it('CP-036/A8-protected-input-scan explicit scan paths use never-open before a content read', async () => owned(async dir => {
  const { scan } = await import('../src/scan/index.js');
  for (const item of protectedCases) {
    const supplied = join(dir, item.supplied);
    const guarded = guardedFs(join(dir, item.resolved));
    let result: Awaited<ReturnType<typeof scan>> | undefined;
    let failed = false;
    try { result = await scan([supplied], { fs: guarded }); }
    catch { failed = true; }
    expect.soft(failed, item.supplied).toBe(false);
    if (result) {
      expect.soft(result.skipped, item.supplied).toEqual([{ path: slash(supplied), reason: 'never-open' }]);
      expect.soft(result.summary.filesScanned, item.supplied).toBe(0);
    }
    expect.soft(guarded.opened, item.supplied).not.toHaveBeenCalled();
    expect.soft(guarded.read, item.supplied).not.toHaveBeenCalled();
  }
}));

it('CP-036/A8-protected-input-scan a protected target substituted at open is never read or cleanly skipped', async () => owned(async dir => {
  const { scan } = await import('../src/scan/index.js');
  const supplied = join(dir, 'ordinary.txt');
  const target = join(dir, 'seeds.txt');
  writeFileSync(supplied, 'harmless ordinary content\n');
  writeFileSync(target, 'harmless protected target content\n');
  let swapped = false;
  const protectedRead = vi.fn(async () => Buffer.from('harmless protected target content\n'));
  const fake = {
    ...fs,
    realpath: vi.fn(async (path: Parameters<typeof fs.realpath>[0]) =>
      resolve(String(path)) === resolve(supplied) && swapped ? target : fs.realpath(path)),
    lstat: vi.fn(async (path: Parameters<typeof fs.lstat>[0], options?: { bigint?: boolean }) =>
      resolve(String(path)) === resolve(supplied) && swapped
        ? { ...(await fs.lstat(target, options as never)), isSymbolicLink: (): boolean => true }
        : fs.lstat(path, options as never)),
    open: vi.fn(async (path: Parameters<typeof fs.open>[0]) => {
      expect(resolve(String(path))).toBe(resolve(supplied));
      swapped = true;
      return {
        stat: (...args: Parameters<Awaited<ReturnType<typeof fs.open>>['stat']>) => fs.stat(target, ...args),
        readFile: protectedRead,
        read: protectedRead,
        close: async () => {},
      };
    }),
  } as unknown as typeof fs;
  let result: Awaited<ReturnType<typeof scan>> | undefined;
  let failure: unknown;
  try { result = await scan([supplied], { fs: fake }); }
  catch (error) { failure = error; }
  expect(swapped).toBe(true);
  expect(protectedRead).not.toHaveBeenCalled();
  expect(result, 'the substituted protected target cannot succeed as a clean skip').toBeUndefined();
  expect((failure as { step?: string; stage?: string } | undefined)?.step
    ?? (failure as { step?: string; stage?: string } | undefined)?.stage).toBe('input-read');
}));

it('CP-036/A8-protected-input-scan boundary names remain readable without writes', async () => owned(async dir => {
  const { readCredential } = await import('../src/input/index.js');
  const { scan } = await import('../src/scan/index.js');
  for (const name of manifest.ordinary) {
    const path = join(dir, name);
    mkdirSync(resolve(path, '..'), { recursive: true });
    writeFileSync(path, source.toString('hex'));
    const before = { bytes: readFileSync(path), mtime: statSync(path).mtimeMs };
    const fileSystem = { ...fs, open: vi.fn(fs.open) as unknown as typeof fs.open & ReturnType<typeof vi.fn>, readFile: vi.fn(fs.readFile) as unknown as typeof fs.readFile & ReturnType<typeof vi.fn> };
    const inspected = await readCredential(path, { stdin: Readable.from([]), fs: fileSystem }, { unsafeArg: false });
    expect(Buffer.from(revealSecret(inspected.secret)).equals(source), name).toBe(true);
    const scanned = await scan([path], { fs: fileSystem });
    expect(scanned.summary.filesScanned, name).toBe(1);
    expect(scanned.skipped, name).toEqual([]);
    expect(fileSystem.open.mock.calls.length + fileSystem.readFile.mock.calls.length, name).toBeGreaterThan(0);
    expect(readFileSync(path).equals(before.bytes), name).toBe(true);
    expect(statSync(path).mtimeMs, name).toBe(before.mtime);
  }
}));
