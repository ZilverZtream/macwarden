import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';

// A file in the walk is swapped for a link to a protected file after the walk's lstat
// (a race no fixed tree can produce, so the injected lstat and realpath report the swap). The protected target holds a real credential vector: if it were ever opened, the
// scan would report it. Expected: the file is skipped as never-open and the protected
// file is never opened.
const roots: string[] = [];
afterEach(() => { for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function tree() {
  const base = resolve(process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp'));
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, 'scan-realpath-'));
  roots.push(root);
  const walked = join(root, 'walked');
  const elsewhere = join(root, 'node-data');
  mkdirSync(walked); mkdirSync(elsewhere);
  writeFileSync(join(walked, 'notes.txt'), 'nothing to see\n');
  const vectorHex = readFileSync(join(resolve(), 'test/vectors/default-admin.macaroon')).toString('hex');
  const wallet = join(elsewhere, 'wallet.db');
  writeFileSync(wallet, `${vectorHex}\n`);
  return { walked, notes: join(walked, 'notes.txt'), wallet };
}

function swapped(t: ReturnType<typeof tree>) {
  const opened: string[] = [];
  // After the walk's first lstat the path is a link: every later lstat says so, and realpath
  // resolves it to the protected file (1.1.1, RR-05: the scanner resolves a walked file only
  // when its lstat shows it changed, so the swap is presented to both calls, as a real swap is).
  let lstats = 0;
  const io = {
    ...fs,
    lstat: (async (path: Parameters<typeof fs.lstat>[0], options?: { bigint?: boolean }) => {
      const stat = await fs.lstat(path, options as never);
      if (resolve(String(path)) !== resolve(t.notes) || lstats++ === 0) return stat;
      return Object.assign(Object.create(stat) as object, { isFile: () => false, isSymbolicLink: () => true });
    }) as typeof fs.lstat,
    realpath: (async (path: Parameters<typeof fs.realpath>[0]) =>
      resolve(String(path)) === resolve(t.notes) ? t.wallet : fs.realpath(path)) as typeof fs.realpath,
    open: (async (path: Parameters<typeof fs.open>[0], ...rest: unknown[]) => {
      opened.push(resolve(String(path)));
      return (fs.open as (...args: unknown[]) => ReturnType<typeof fs.open>)(path, ...rest);
    }) as typeof fs.open,
  } as typeof fs;
  return { io, opened };
}

it('SCAN/realpath-protected a walked file that resolves to a protected file is never opened', async () => {
  const t = tree();
  const { io, opened } = swapped(t);
  const result = await scan([t.walked], { fs: io });
  expect(opened).not.toContain(resolve(t.wallet));
  expect(result.findings).toEqual([]);
  expect(result.skipped).toContainEqual(expect.objectContaining({ reason: 'never-open' }));
});

it('SCAN/realpath-protected the same swap on a single file argument is never opened', async () => {
  const t = tree();
  const { io, opened } = swapped(t);
  const result = await scan([t.notes], { fs: io });
  expect(opened).not.toContain(resolve(t.wallet));
  expect(result.findings).toEqual([]);
});
