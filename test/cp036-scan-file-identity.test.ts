import { linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { BigIntStats, PathLike, Stats } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';

type ScanResult = {
  findings: { path: string }[];
  skipped: { path: string; reason: string }[];
  summary: { filesScanned: number; filesSkipped: number };
};
type Scanner = { scan: (paths: string[], opts: { fs?: typeof fs }) => Promise<ScanResult> };

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
const testTmp = process.env.MACWARDEN_TEST_TMP || resolve('test/.tmp-cp036-identity');
process.env.MACWARDEN_TEST_TMP = testTmp;
const slash = (path: string) => path.split(sep).join('/');

async function ownedTemp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp036-identity-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

// The default Node stat representation loses the low bit of these two distinct
// IDs. A bigint stat retains it. Real files carry the content, so the injected
// filesystem changes only the identity information presented at the fs boundary.
const adjacentIds = [9007199254740992n, 9007199254740993n] as const;
function identityFs(ids: Map<string, bigint>, observed?: Map<string, bigint>) {
  const calls: string[] = [];
  const withIdentity = <T extends Stats | BigIntStats>(
    original: T, path: string, bigint: boolean, beforeOpen: boolean,
  ): T => {
    const id = beforeOpen ? (observed?.get(resolve(path)) ?? ids.get(resolve(path))) : ids.get(resolve(path));
    if (id === undefined) return original;
    return Object.assign(original, { dev: bigint ? 17n : 17, ino: bigint ? id : Number(id) });
  };
  const fake = {
    ...fs,
    lstat: async (path: PathLike, options?: { bigint?: boolean }) => {
      const name = String(path);
      calls.push(`lstat:${resolve(name)}`);
      return withIdentity(await fs.lstat(path, options as never), name, !!options?.bigint, true);
    },
    stat: async (path: PathLike, options?: { bigint?: boolean }) => {
      const name = String(path);
      calls.push(`stat:${resolve(name)}`);
      return withIdentity(await fs.stat(path, options as never), name, !!options?.bigint, true);
    },
    open: async (...args: Parameters<typeof fs.open>) => {
      const name = String(args[0]);
      calls.push(`open:${resolve(name)}`);
      const handle = await fs.open(...args);
      return {
        stat: async (options?: { bigint?: boolean }) => {
          calls.push(`fstat:${resolve(name)}`);
          return withIdentity(await handle.stat(options as never), name, !!options?.bigint, false);
        },
        readFile: async (...readArgs: Parameters<typeof handle.readFile>) => {
          calls.push(`read:${resolve(name)}`);
          return handle.readFile(...readArgs);
        },
        read: async (...readArgs: Parameters<typeof handle.read>) => {
          calls.push(`read:${resolve(name)}`);
          return handle.read(...readArgs);
        },
        close: () => handle.close(),
      };
    },
  } as unknown as typeof fs;
  return { fake, calls };
}

it('CP-036/B15-scan-file-identity distinct exact opened IDs survive Number collisions', async () => ownedTemp(async dir => {
  const first = join(dir, 'first.txt');
  const second = join(dir, 'second.txt');
  writeFileSync(first, 'ordinary first file\n');
  writeFileSync(second, 'ordinary second file\n');
  expect(Number(adjacentIds[0])).toBe(Number(adjacentIds[1]));
  const { fake, calls } = identityFs(new Map([[resolve(first), adjacentIds[0]], [resolve(second), adjacentIds[1]]]));
  const result = await (await scanner()).scan([first, second], { fs: fake });
  expect(result.summary.filesScanned).toBe(2);
  expect(result.summary.filesSkipped).toBe(0);
  expect(result.skipped).toEqual([]);
  expect(result.findings).toEqual([]);
  for (const path of [first, second]) {
    expect(calls).toContain(`open:${resolve(path)}`);
    expect(calls).toContain(`fstat:${resolve(path)}`);
  }
}));

it('CP-036/B15-scan-file-identity changed identity at open cannot disappear as an already scanned path', async () => ownedTemp(async dir => {
  const first = join(dir, 'first.txt');
  const changed = join(dir, 'changed.txt');
  writeFileSync(first, 'ordinary first file\n');
  writeFileSync(changed, 'ordinary changed file\n');
  const ids = new Map([[resolve(first), adjacentIds[0]], [resolve(changed), adjacentIds[1]]]);
  const observed = new Map([[resolve(changed), adjacentIds[0]]]);
  const { fake, calls } = identityFs(ids, observed);
  let result: ScanResult | undefined;
  let error: unknown;
  try { result = await (await scanner()).scan([first, changed], { fs: fake }); }
  catch (caught) { error = caught; }
  expect(calls).toContain(`open:${resolve(changed)}`);
  expect(calls).toContain(`fstat:${resolve(changed)}`);
  if (error) {
    const failure = error as { step?: string; stage?: string };
    expect(failure.step ?? failure.stage).toBe('input-read');
  } else {
    // docs/spec.md#2-scan-offline-safe-07 and CP-036/B15: a readable explicit input
    // cannot succeed by labeling a distinct opened file "unreadable".
    expect(result).toBeDefined();
    expect(result!.summary.filesScanned).toBe(2);
    expect(result!.summary.filesSkipped).toBe(0);
    expect(result!.skipped).toEqual([]);
  }
}));

it('CP-036/B15-scan-file-identity an actual explicit opened-file read failure is input-read', async () => ownedTemp(async dir => {
  const path = join(dir, 'unreadable.txt');
  writeFileSync(path, 'ordinary content\n');
  const denied = vi.fn(async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); });
  const fake = {
    ...fs,
    open: async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      return { stat: (...statArgs: Parameters<typeof handle.stat>) => handle.stat(...statArgs),
        readFile: denied, read: denied, close: () => handle.close() };
    },
    readFile: denied,
  } as unknown as typeof fs;
  let failure: unknown;
  try { await (await scanner()).scan([path], { fs: fake }); }
  catch (error) { failure = error; }
  expect(denied).toHaveBeenCalled();
  expect((failure as { step?: string; stage?: string } | undefined)?.step
    ?? (failure as { step?: string; stage?: string } | undefined)?.stage).toBe('input-read');
}));

it('CP-036/B15-scan-file-identity native distinct files and a hard link retain the first path', async () => ownedTemp(async dir => {
  const first = join(dir, 'first.txt');
  const second = join(dir, 'second.txt');
  const alias = join(dir, 'alias.txt');
  writeFileSync(first, readFileSync(join('test/vectors', 'default-readonly.macaroon')).toString('hex'));
  writeFileSync(second, 'ordinary second file\n');
  linkSync(first, alias);
  const result = await (await scanner()).scan([first, second, alias, first], {});
  expect(result.summary.filesScanned).toBe(2);
  expect(result.summary.filesSkipped).toBe(0);
  expect(result.skipped).toEqual([]);
  expect(result.findings.map(finding => finding.path)).toEqual([slash(first)]);
}));
