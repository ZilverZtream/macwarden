import * as fs from 'node:fs/promises';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { acquireLock, type Deps } from '../src/commands/watch.js';

const depsFor = (pid: number, files: typeof fs) => ({ fs: files, env: {}, clock: () => new Date(), emit: () => undefined,
  hostname: () => hostname(), pid, processDomain: async () => null }) as unknown as Deps;
// Two live owners, as two real watches are: this process and its parent. A made-up PID names no
// process, so a watch that read the other's fresh lock late would rightly find it stale and take it
// over, which is not the race under test (and Linux, unlike Windows, reports such a PID as gone).
const [first, second] = [process.pid, process.ppid];
// A same-host owner PID that does not exist: the lock is stale.
const staleRecord = `${JSON.stringify({ pid: 2_147_483_000, hostname: hostname() })}\n`;

// Two watches start at the same moment against a stale lock. The race the final gate found:
// both read the stale record, A replaces the lock, then B acts on its stale read. Unlinking
// by path, B deleted A's fresh lock and created its own: both ran. This forces exactly that
// interleaving: the second reader of the lock waits until A's fresh lock exists. Owner
// records are read through one descriptor bound to the checked file (MW110-04), so the
// interception is at that open: B opens the stale record, then is held until A's lock
// replaced it, and reads the stale record from its descriptor afterwards.
it('WATCH/lock-race a watch acting on a stale read never removes the lock another watch just took', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mw-lock-race-'));
  try {
    for (let round = 0; round < 20; round++) {
      const path = join(dir, `r${round}.watch.lock`);
      writeFileSync(path, staleRecord);
      let reads = 0;
      let heldStale = false;
      const files = { ...fs, async open(...args: Parameters<typeof fs.open>) {
        const handle = await fs.open(...args);
        if (String(args[0]) !== path || args[1] === 'wx') return handle;
        const read = ++reads;
        if (read === 1) {
          // A: wait until B has opened the same stale record too, so both act on it.
          for (const until = performance.now() + 10_000; reads < 2 && performance.now() < until;)
            await new Promise(resolve => setTimeout(resolve, 1));
        } else if (read === 2) {
          // B: opened the stale record, then wait until A's own lock replaced it.
          // The path is briefly absent while A moves the stale record aside, and empty until
          // A has written its owner record.
          const replaced = () => {
            try { const text = readFileSync(path, 'utf8'); return text !== '' && text !== staleRecord; }
            catch { return false; }
          };
          for (const until = performance.now() + 10_000; !replaced() && performance.now() < until;)
            await new Promise(resolve => setTimeout(resolve, 1));
          const probe = Buffer.alloc(256);
          const { bytesRead } = await handle.read(probe, 0, probe.length, 0);
          heldStale = probe.subarray(0, bytesRead).toString('utf8') === staleRecord;
        }
        return handle;
      } } as typeof fs;
      const results = await Promise.allSettled([acquireLock(path, depsFor(first, files)),
        acquireLock(path, depsFor(second, files))]);
      // The interleaving really happened: B held the stale record while A replaced it.
      expect(heldStale).toBe(true);
      expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
      for (const result of results) if (result.status === 'fulfilled') await result.value();
      expect(existsSync(path)).toBe(false);
    }
    expect(readdirSync(dir).filter(name => name.includes('.stale-'))).toEqual([]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}, 60_000);

it('WATCH/lock-race two watches starting at once against a stale lock never both run', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mw-lock-race-'));
  try {
    for (let round = 0; round < 200; round++) {
      const path = join(dir, `r${round}.watch.lock`);
      writeFileSync(path, staleRecord);
      const results = await Promise.allSettled([acquireLock(path, depsFor(first, fs)), acquireLock(path, depsFor(second, fs))]);
      expect(results.filter(result => result.status === 'fulfilled').length).toBeLessThanOrEqual(1);
      for (const result of results) if (result.status === 'fulfilled') await result.value();
    }
    expect(readdirSync(dir).filter(name => name.includes('.stale-'))).toEqual([]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}, 60_000);

// The window the race above hit under load (1 in about 3,500 rounds): between A's exclusive
// create and A's check that the path is still the file it created, B (acting on its stale read)
// moves the lock aside, finds it is not the stale record and links it back. A must wait for its
// own file to return, not refuse the lock it just took (both watches then exited).
it('WATCH/lock-race a watch whose fresh lock a stale takeover briefly moves aside keeps it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mw-lock-race-'));
  try {
    const path = join(dir, 'aside.watch.lock');
    const aside = `${path}.stale-other`;
    let moved = false;
    let restored: Promise<void> = Promise.resolve();
    const files = { ...fs, async lstat(target: string, options?: { bigint?: boolean }) {
      if (target === path && !moved) {
        moved = true;
        await fs.rename(path, aside);
        restored = new Promise(resolve => setTimeout(resolve, 30)).then(async () => { await fs.link(aside, path); await fs.unlink(aside); });
      }
      return fs.lstat(target, options as never);
    } } as unknown as typeof fs;
    const release = await acquireLock(path, depsFor(first, files));
    await restored;
    expect(moved).toBe(true);
    await release();
    expect(readdirSync(dir)).toEqual([]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The other order: B starts first but is still looking up its process domain when A takes the
// lock, so B's exclusive create meets A's fresh lock and reads its record. A live owner keeps it.
it('WATCH/lock-race a watch that reads the fresh lock of another watch refuses it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mw-lock-race-'));
  try {
    const path = join(dir, 'late.watch.lock');
    writeFileSync(path, staleRecord);
    let go!: () => void;
    const gate = new Promise<null>(resolve => { go = () => resolve(null); });
    const late = acquireLock(path, { ...depsFor(second, fs), processDomain: () => gate } as Deps);
    const release = await acquireLock(path, depsFor(first, fs));
    go();
    await expect(late).rejects.toMatchObject({ code: 'EEXIST' });
    await release();
    expect(existsSync(path)).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
