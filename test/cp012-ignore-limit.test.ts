import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type { BigIntStats, Stats } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const MAX_IGNORE_BYTES = 5_242_880;
const READ_BUDGET = MAX_IGNORE_BYTES + 1;
const testTmp = process.env.MACWARDEN_TEST_TMP || resolve('test/.tmp-cp012-ignore-limit');
process.env.MACWARDEN_TEST_TMP = testTmp;

type Envelope = {
  ok: boolean;
  result: { summary: { ignored: number; findings: number } } | null;
  error: { code: number; step: string | null } | null;
};
type Command = { run: (args: string[], deps: { fs: typeof fs }) => Promise<Envelope> };

const command = (): Promise<Command> => import('../src/commands/scan.js') as Promise<Command>;

async function inTemp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'ignore-limit-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function virtualIgnoreFile(path: string, totalBytes: number, reportedBytes: number) {
  const target = resolve(path);
  const observed = { opened: 0, closed: 0, readFile: 0, reads: 0,
    bytes: 0, largestRequest: 0, readPastBudget: false };
  const matches = (candidate: unknown) => typeof candidate === 'string' && resolve(candidate) === target;
  const reportedStat = async (stat: Promise<Stats | BigIntStats>, bigint: boolean) => {
    const value = await stat;
    return Object.assign(value, { size: bigint ? BigInt(reportedBytes) : reportedBytes });
  };
  const fake = {
    ...fs,
    stat: (candidate: string, options?: { bigint?: boolean }) => matches(candidate)
      ? reportedStat(fs.stat(candidate, options as never), !!options?.bigint)
      : fs.stat(candidate, options as never),
    lstat: (candidate: string, options?: { bigint?: boolean }) => matches(candidate)
      ? reportedStat(fs.lstat(candidate, options as never), !!options?.bigint)
      : fs.lstat(candidate, options as never),
    readFile: async (candidate: string, options?: Parameters<typeof fs.readFile>[1]) => {
      if (matches(candidate)) {
        observed.readFile++;
        throw new Error('ignore input used an unbounded readFile call');
      }
      return fs.readFile(candidate, options as never);
    },
    open: async (candidate: string, flags: string | number, mode?: number) => {
      const handle = await fs.open(candidate, flags, mode);
      if (!matches(candidate)) return handle;
      observed.opened++;
      return {
        stat: (options?: { bigint?: boolean }) =>
          reportedStat(handle.stat(options as never), !!options?.bigint),
        readFile: async () => {
          observed.readFile++;
          throw new Error('ignore handle used an unbounded readFile call');
        },
        read: async (...args: unknown[]) => {
          const buffer = args[0];
          if (!Buffer.isBuffer(buffer)) throw new Error('ignore handle must use bounded buffer reads');
          const options = typeof args[1] === 'object' && args[1] !== null
            ? args[1] as { offset?: number; length?: number } : undefined;
          const offset = options?.offset ?? (typeof args[1] === 'number' ? args[1] : 0);
          const length = options?.length ?? (typeof args[2] === 'number' ? args[2] : buffer.length - offset);
          observed.reads++;
          observed.largestRequest = Math.max(observed.largestRequest, length);
          if (observed.bytes >= READ_BUDGET && totalBytes > READ_BUDGET) {
            observed.readPastBudget = true;
            throw new Error('ignore input read beyond the permitted budget');
          }
          const bytesRead = Math.min(length, 8192, totalBytes - observed.bytes);
          buffer.fill('#', offset, offset + bytesRead);
          observed.bytes += bytesRead;
          return { bytesRead, buffer };
        },
        close: async () => { observed.closed++; await handle.close(); },
      };
    },
  } as unknown as typeof fs;
  return { fake, observed };
}

for (const mode of ['local', 'explicit'] as const) {
  it(`CP-012/B3 ${mode} ignore input with stale small size stops at the read budget`, async () => inTemp(async dir => {
    const tree = join(dir, 'tree'); mkdirSync(tree);
    const file = mode === 'local' ? join(tree, '.macwardenignore') : join(dir, 'ignore.txt');
    writeFileSync(file, '# physical file is deliberately small\n');
    const { fake, observed } = virtualIgnoreFile(file, READ_BUDGET + 1, 1);
    const args = mode === 'local' ? [tree, '--json'] : [tree, '--ignore-file', file, '--json'];
    const result = await (await command()).run(args, { fs: fake });
    expect(result).toMatchObject({ ok: false, result: null,
      error: { code: 3, step: 'input-read' } });
    expect(observed.opened).toBe(1);
    expect(observed.closed).toBe(1);
    expect(observed.readFile).toBe(0);
    expect(observed.reads).toBeGreaterThan(1);
    expect(observed.bytes).toBe(READ_BUDGET);
    expect(observed.largestRequest).toBeLessThanOrEqual(READ_BUDGET);
    expect(observed.readPastBudget).toBe(false);
  }));
}

it('CP-012/B3 accepts a comment-only ignore file at the exact byte limit', async () => inTemp(async dir => {
  const tree = join(dir, 'tree'); mkdirSync(tree);
  const file = join(dir, 'ignore.txt'); writeFileSync(file, '# physical placeholder\n');
  const { fake, observed } = virtualIgnoreFile(file, MAX_IGNORE_BYTES, 1);
  const result = await (await command()).run([tree, '--ignore-file', file, '--json'], { fs: fake });
  expect(result).toMatchObject({ ok: true, error: null,
    result: { summary: { ignored: 0, findings: 0 } } });
  expect(observed.opened).toBe(1);
  expect(observed.closed).toBe(1);
  expect(observed.readFile).toBe(0);
  expect(observed.reads).toBeGreaterThan(1);
  expect(observed.bytes).toBe(MAX_IGNORE_BYTES);
  expect(observed.largestRequest).toBeLessThanOrEqual(READ_BUDGET);
  expect(observed.readPastBudget).toBe(false);
}));

for (const mode of ['local', 'explicit'] as const) {
  it(`CP-012/B4 ordinary ${mode} comment-only ignore file remains accepted`, async () => inTemp(async dir => {
    const tree = join(dir, 'tree'); mkdirSync(tree);
    const file = mode === 'local' ? join(tree, '.macwardenignore') : join(dir, 'ignore.txt');
    writeFileSync(file, '# ordinary ignore comment\n');
    const args = mode === 'local' ? [tree, '--json'] : [tree, '--ignore-file', file, '--json'];
    const result = await (await command()).run(args, { fs });
    expect(result).toMatchObject({ ok: true, error: null,
      result: { summary: { ignored: 0, findings: 0 } } });
  }));
}
