// Journal durability details (audit follow-up, conditional concerns): a new journal's directory
// entry is synced on POSIX like --out files, and a second close() waits for the first one's drain.
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { openJournal } from './helpers/payment-journal.js';

const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(resolve(), 'test/.tmp');
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(): string {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'payment-journal-durability-'));
  dirs.push(dir);
  return dir;
}

// The owner-only creation compares the file's uid with the process's own (process.getuid), so the fake
// reports whatever this host's uid is (1000 on a workstation, 1001 on a GitHub runner).
const UID = process.getuid?.() ?? 1000;

/** fs reporting owner-only POSIX files of this uid (any host), recording directory syncs. */
function posixFs(journalDir: string, synced: string[]) {
  return { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    if (resolve(String(args[0])) === resolve(journalDir) && args[1] === 'r')
      return { sync: async () => { synced.push(String(args[0])); }, close: async () => undefined } as unknown as fs.FileHandle;
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'stat') return async () => {
        const real = await target.stat();
        return { isFile: () => true, dev: real.dev, ino: real.ino, size: real.size, mode: 0o100600, uid: UID };
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
}

it('PAYJ/durability a new journal syncs its directory on POSIX, not for an existing journal or on Windows', async () => {
  const dir = scratch(), path = join(dir, 'payments.journal'), synced: string[] = [];
  await (await openJournal(path, { fs: posixFs(dir, synced), platform: 'linux', uid: UID })).close();
  expect(synced.map(item => resolve(item))).toEqual([resolve(dirname(path))]);
  await (await openJournal(path, { fs: posixFs(dir, synced), platform: 'linux', uid: UID })).close();
  expect(synced).toHaveLength(1);
  const windows = join(scratch(), 'payments.journal'), none: string[] = [];
  await (await openJournal(windows, { fs: posixFs(dirname(windows), none), platform: 'win32' })).close();
  expect(none).toEqual([]);
});

it('PAYJ/durability a second close waits for the first close to append and sync the run-end', async () => {
  const path = join(scratch(), 'payments.journal');
  const journal = await openJournal(path);
  journal.registered();
  const first = journal.close(), second = journal.close();
  const stats = await second;
  // Read before awaiting the first close: the second must not resolve before the drain.
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n').map(line => JSON.parse(line).type);
  expect(lines.at(-1)).toBe('run-end');
  expect(await first).toBe(stats);
});
