import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, posix, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

type Result = {
  findings: unknown[];
  skipped: { path: string; reason: string }[];
  summary: { filesScanned: number; filesSkipped: number };
};
type Scanner = { scan: (paths: string[], options: object) => Promise<Result> };

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'node_modules/.cache/cp010-system-exclusion/tmp');

async function virtualTree<T>(body: (sandbox: ReturnType<typeof injectedTree>) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const root = mkdtempSync(join(testTmp, 'virtual-root-'));
  try { return await body(injectedTree(root)); }
  finally { rmSync(root, { recursive: true, force: true }); }
}

function injectedTree(root: string) {
  for (const name of ['proc', 'sys', 'dev', 'process', 'sysadmin', 'device']) {
    const directory = join(root, name, 'sub');
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, 'harmless.txt'), 'ordinary harmless text\n');
  }
  mkdirSync(join(root, 'ordinary'));

  const canonical = (entry: string): string => {
    const slash = entry.replaceAll('\\', '/').replace(/^[A-Za-z]:/, '');
    const absolute = posix.normalize(slash.startsWith('/') ? slash : `/${slash}`);
    return absolute.replace(/^\/link-to-proc(?=\/|$)/, '/proc')
      .replace(/^\/link-to-dev(?=\/|$)/, '/dev');
  };
  const physical = (entry: string) => join(root, canonical(entry).replace(/^\//, ''));
  const entered: string[] = [];
  const opened: string[] = [];
  const readFiles: string[] = [];
  const fileSystem = {
    stat: vi.fn((entry: string, options?: { bigint?: boolean }) =>
      fs.stat(physical(entry), options as never)),
    lstat: vi.fn(async (entry: string, options?: { bigint?: boolean }) => {
      const stat = await fs.lstat(physical(entry), options as never);
      if (!/^\/link-to-(?:proc|dev)$/.test(entry.replaceAll('\\', '/').replace(/^[A-Za-z]:/, ''))) {
        return stat;
      }
      return Object.assign(Object.create(stat) as object, {
        isSymbolicLink: () => true,
        isDirectory: () => false,
        isFile: () => false,
      }) as typeof stat;
    }),
    realpath: vi.fn(async (entry: string) => canonical(entry)),
    readdir: vi.fn(async (entry: string, options?: object) => {
      entered.push(canonical(entry));
      return fs.readdir(physical(entry), options as never);
    }),
    open: vi.fn(async (entry: string, flags: string | number) => {
      opened.push(canonical(entry));
      return fs.open(physical(entry), flags);
    }),
    readFile: vi.fn((entry: string) => {
      readFiles.push(canonical(entry));
      return fs.readFile(physical(entry));
    }),
  };
  return { fileSystem, entered, opened, readFiles };
}

function expectExcluded(result: Result, argument: string,
  entered: string[], opened: string[], readFiles: string[]) {
  expect.soft(result.skipped).toEqual([{ path: argument, reason: 'excluded-dir' }]);
  expect.soft(result.summary).toMatchObject({ filesScanned: 0, filesSkipped: 1 });
  expect.soft(result.findings).toEqual([]);
  expect.soft(entered, 'no excluded directory is descended').toEqual([]);
  expect.soft(opened, 'no excluded file is opened').toEqual([]);
  expect.soft(readFiles, 'no excluded file is read through readFile').toEqual([]);
}

it.each(['/proc', '/sys', '/dev'])(
  'CP-010/B9 direct system directory %s is excluded before descent',
  async argument => virtualTree(async ({ fileSystem, entered, opened, readFiles }) => {
    const result = await (await scanner()).scan([argument], { fs: fileSystem });
    expectExcluded(result, argument, entered, opened, readFiles);
  }),
);

it.each(['/proc/sub', '/sys/sub/harmless.txt', '/dev/sub'])(
  'CP-010/B9 system descendant argument %s is excluded before content access',
  async argument => virtualTree(async ({ fileSystem, entered, opened, readFiles }) => {
    const result = await (await scanner()).scan([argument], { fs: fileSystem });
    expectExcluded(result, argument, entered, opened, readFiles);
  }),
);

it.each(['/link-to-proc', '/link-to-dev/sub', '/ordinary/../sys'])(
  'CP-010/B9 resolved system path %s is excluded before descent',
  async argument => virtualTree(async ({ fileSystem, entered, opened, readFiles }) => {
    const result = await (await scanner()).scan([argument], { fs: fileSystem });
    expectExcluded(result, argument, entered, opened, readFiles);
  }),
);

it.each(['/process', '/sysadmin', '/device'])(
  'CP-010/B9 similarly named ordinary directory %s remains scannable',
  async argument => virtualTree(async ({ fileSystem, entered, opened }) => {
    const result = await (await scanner()).scan([argument], { fs: fileSystem });
    expect(result.skipped).toEqual([]);
    expect(result.summary).toMatchObject({ filesScanned: 1, filesSkipped: 0 });
    expect(entered).toContain(argument);
    expect(opened).toContain(`${argument}/sub/harmless.txt`);
  }),
);
