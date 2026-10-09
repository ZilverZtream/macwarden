import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';

const repo = resolve();
const slash = (path: string) => path.split(sep).join('/');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp-cp036-protected');
process.env.MACWARDEN_TEST_TMP = testTmp;

async function owned<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'paths-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('CP-036/A8-protected-input-scan Windows alternate data streams refuse protected base names', async () => owned(async dir => {
  const { readCredential } = await import('../src/input/index.js');
  const { scan } = await import('../src/scan/index.js');
  const contents = Buffer.from('harmless stream contents\n');
  for (const name of ['wallet.db', 'MaCaRoOnS.Db', 'TLS.KEY', 'password', 'passwd', 'seed',
    'WALLETPASSWORD', 'wallet_password.dat', 'SEEDS.TXT', 'TLS-PRIVKEY', 'tls.key.pem']) {
    const base = join(dir, name);
    const stream = `${base}:side`;
    writeFileSync(base, 'harmless base contents\n');
    writeFileSync(stream, contents);
    expect(readFileSync(stream).equals(contents)).toBe(true);
    const before = { base: readFileSync(base), stream: readFileSync(stream),
      baseMtime: statSync(base).mtimeMs, streamMtime: statSync(stream).mtimeMs };
    const fileSystem = { ...fs, open: vi.fn(fs.open) as unknown as typeof fs.open & ReturnType<typeof vi.fn>, readFile: vi.fn(fs.readFile) as unknown as typeof fs.readFile & ReturnType<typeof vi.fn> };
    let error: { name?: string; stage?: string; message?: string } | undefined;
    try { await readCredential(stream, { stdin: Readable.from([]), fs: fileSystem }, { unsafeArg: false }); }
    catch (caught) { error = caught as typeof error; }
    expect.soft(error?.name, name).toBe('InputError');
    expect.soft(error?.stage, name).toBe('input-read');
    expect.soft(error?.message?.includes(stream), name).toBe(false);
    const result = await scan([stream], { fs: fileSystem });
    expect.soft(result.skipped, name).toEqual([{ path: slash(stream), reason: 'never-open' }]);
    expect.soft(result.summary.filesScanned, name).toBe(0);
    expect.soft(fileSystem.open, name).not.toHaveBeenCalled();
    expect.soft(fileSystem.readFile, name).not.toHaveBeenCalled();
    expect(readFileSync(base).equals(before.base), name).toBe(true);
    expect(readFileSync(stream).equals(before.stream), name).toBe(true);
    expect(statSync(base).mtimeMs, name).toBe(before.baseMtime);
    expect(statSync(stream).mtimeMs, name).toBe(before.streamMtime);
  }
  for (const ordinary of ['seedling.txt', 'walletpasswords.txt', 'tls-keyed']) {
    const ordinaryBase = join(dir, ordinary);
    const ordinaryStream = `${ordinaryBase}:side`;
    writeFileSync(ordinaryBase, 'harmless base contents\n');
    writeFileSync(ordinaryStream, contents);
    const ordinaryFs = { ...fs, open: vi.fn(fs.open) as unknown as typeof fs.open & ReturnType<typeof vi.fn>, readFile: vi.fn(fs.readFile) as unknown as typeof fs.readFile & ReturnType<typeof vi.fn> };
    let ordinaryError: { stage?: string } | undefined;
    try { await readCredential(ordinaryStream,
      { stdin: Readable.from([]), fs: ordinaryFs }, { unsafeArg: false }); }
    catch (caught) { ordinaryError = caught as typeof ordinaryError; }
    expect(ordinaryError?.stage, ordinary).toBe('input-form');
    const ordinaryResult = await scan([ordinaryStream], { fs: ordinaryFs });
    expect(ordinaryResult.summary.filesScanned, ordinary).toBe(1);
    expect(ordinaryResult.skipped, ordinary).toEqual([]);
    expect(ordinaryFs.open, ordinary).toHaveBeenCalled();
    expect(readFileSync(ordinaryStream).equals(contents), ordinary).toBe(true);
  }
}));

it('CP-036/A8-protected-input-scan Windows file swapped to a protected symlink before open fails input-read', async () => owned(async dir => {
  const { scan } = await import('../src/scan/index.js');
  const supplied = join(dir, 'ordinary.txt');
  const target = join(dir, 'seeds.txt');
  writeFileSync(supplied, 'harmless ordinary content\n');
  writeFileSync(target, 'harmless protected target content\n');
  const before = { bytes: readFileSync(target), mtime: statSync(target).mtimeMs };
  let swapped = false;
  const protectedRead = vi.fn(async () => Buffer.from('harmless protected target content\n'));
  const fileSystem = {
    ...fs,
    open: vi.fn(async (...args: Parameters<typeof fs.open>) => {
      if (resolve(String(args[0])) === resolve(supplied) && !swapped) {
        unlinkSync(supplied);
        symlinkSync(target, supplied, 'file');
        swapped = true;
      }
      const handle = await fs.open(...args);
      return { stat: (...statArgs: Parameters<typeof handle.stat>) => handle.stat(...statArgs),
        readFile: protectedRead, read: protectedRead, close: () => handle.close() };
    }),
  } as unknown as typeof fs;
  let result: Awaited<ReturnType<typeof scan>> | undefined;
  let failure: unknown;
  try { result = await scan([supplied], { fs: fileSystem }); }
  catch (error) { failure = error; }
  expect(swapped).toBe(true);
  expect(protectedRead).not.toHaveBeenCalled();
  expect(result, 'a substituted protected symlink cannot succeed as a clean skip').toBeUndefined();
  expect((failure as { step?: string; stage?: string } | undefined)?.step
    ?? (failure as { step?: string; stage?: string } | undefined)?.stage).toBe('input-read');
  expect(readFileSync(target).equals(before.bytes)).toBe(true);
  expect(statSync(target).mtimeMs).toBe(before.mtime);
}));
