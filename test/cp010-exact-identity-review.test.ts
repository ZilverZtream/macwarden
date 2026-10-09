import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

type Result = { findings: { path: string; kind: string; fingerprint: string }[];
  summary: { filesScanned: number } };
type Scanner = { scan: (paths: string[], options: object) => Promise<Result> };

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
const vectorRoot = join(resolve(), 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectorRoot, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const fingerprint = manifest.vectors.find(item => item.name === 'default-readonly')!.fingerprint;
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;

async function temp<T>(body: (path: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp010-identity-'));
  try {
    const path = join(dir, 'a.env');
    writeFileSync(path, readFileSync(join(vectorRoot, 'default-readonly.macaroon')).toString('hex'));
    return await body(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function identityFs(path: string, openedIno: bigint, postOpenIno: number,
  marker: string, guardReads: boolean) {
  let opened = false;
  let reads = 0;
  let postOpenStats = 0;
  const withIdentity = (stat: object, ino: bigint | number) =>
    Object.assign(Object.create(stat) as object, {
      dev: typeof ino === 'bigint' ? 7n : 7,
      ino,
      nlink: typeof ino === 'bigint' ? 1n : 1,
    });
  const pathStat = async (entry: string, options: { bigint?: boolean } | undefined,
    operation: typeof fs.stat | typeof fs.lstat) => {
    const stat = await operation(entry, options as never);
    if (entry !== path) return stat;
    if (opened) postOpenStats++;
    return withIdentity(stat, opened ? postOpenIno : openedIno);
  };
  const fileSystem = { ...fs,
    stat: vi.fn((entry: string, options?: { bigint?: boolean }) => pathStat(entry, options, fs.stat)),
    lstat: vi.fn((entry: string, options?: { bigint?: boolean }) => pathStat(entry, options, fs.lstat)),
    open: vi.fn(async (entry: string, flags: string | number, mode?: number) => {
      const handle = await fs.open(entry, flags, mode);
      if (entry === path) opened = true;
      return new Proxy(handle, { get(target, key) {
        if (key === 'stat') return async (options?: { bigint?: boolean }) =>
          withIdentity(await target.stat(options as never), openedIno);
        if (key === 'read' || key === 'readFile') return async (...args: unknown[]) => {
          reads++;
          if (guardReads) throw new Error(marker);
          return (target[key] as (...args: unknown[]) => Promise<unknown>).apply(target, args);
        };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }),
    readFile: vi.fn(async (...args: Parameters<typeof fs.readFile>) => {
      reads++;
      if (guardReads) throw new Error(marker);
      return fs.readFile(...args);
    }),
  };
  return { fileSystem, counts: () => ({ reads, postOpenStats }) };
}

async function rejection(path: string, fileSystem: object, marker: string) {
  let failure: unknown;
  try { await (await scanner()).scan([path], { fs: fileSystem }); }
  catch (error) { failure = error; }
  expect(failure).toMatchObject({ name: 'InputError', stage: 'input-read' });
  const shown = `${String(failure)}\n${String((failure as Error).stack)}\n${JSON.stringify(failure)}`;
  expect(shown).not.toContain(marker);
}

it('CP-010/B12 unsafe rounded post-open identity cannot establish an explicit file match', async () =>
  temp(async path => {
    const openedIno = 9_851_624_198_645_556n;
    const adjacentIno = openedIno + 1n;
    expect(Number(openedIno)).toBe(Number(adjacentIno));
    const marker = 'cp010-unsafe-identity-read-marker';
    const observed = identityFs(path, openedIno, Number(adjacentIno), marker, true);
    await rejection(path, observed.fileSystem, marker);
    expect(observed.counts().postOpenStats).toBeGreaterThan(0);
    expect(observed.counts().reads).toBe(0);
  }));

it('CP-010/B10 equal safe-number and bigint identities scan an explicit file once', async () =>
  temp(async path => {
    const observed = identityFs(path, 123n, 123, 'cp010-safe-identity-marker', false);
    const result = await (await scanner()).scan([path, path], { fs: observed.fileSystem });
    expect(result.findings.map(item => ({ path: item.path, kind: item.kind,
      fingerprint: item.fingerprint }))).toEqual([{
      path: path.replaceAll('\\', '/'), kind: 'macaroon-hex', fingerprint,
    }]);
    expect(result.summary.filesScanned).toBe(1);
    expect(observed.counts().postOpenStats).toBeGreaterThan(0);
  }));

it('CP-010/B12 different safe-number and bigint identities reject before content reads', async () =>
  temp(async path => {
    const marker = 'cp010-safe-mismatch-read-marker';
    const observed = identityFs(path, 123n, 124, marker, true);
    await rejection(path, observed.fileSystem, marker);
    expect(observed.counts().postOpenStats).toBeGreaterThan(0);
    expect(observed.counts().reads).toBe(0);
  }));
