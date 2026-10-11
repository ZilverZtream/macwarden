// Pre-1.4 audit, registry lock acquisition: links at the lock paths, ownership after a failed
// acquisition, incomplete lock records, quarantined stale locks, claim contention and errors,
// the directory owner and the Windows save back-off.
import { existsSync, readdirSync, readFileSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import type { BigIntStats, Stats } from 'node:fs';
import * as fs from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { ownProcessDomain } from '../src/registry/process-domain.js';
import { fixture } from './helpers/cp038-online.js';

const busy = () => Object.assign(new Error('injected busy file'), { code: 'EBUSY' });
const noSleep = async () => undefined;
const failure = (code: string) => Object.assign(new Error(`injected ${code}`), { code });

/**
 * fs whose exclusive create follows a symbolic link at the path, as Windows does (POSIX O_EXCL
 * refuses it): the Windows behaviour is exercised on every platform.
 */
function followingOpen() {
  return { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    const [path, flags, mode] = args;
    if (flags === 'wx') {
      const found = await fs.lstat(path).catch(() => null);
      if (found?.isSymbolicLink()) {
        const target = await fs.readlink(path);
        return fs.open(isAbsolute(target) ? target : resolve(dirname(String(path)), target), 'wx', mode);
      }
    }
    return fs.open(...args);
  }) as typeof fs.open };
}

for (const suffix of ['.lock', '.lock.claim']) {
  it(`REGISTRY-AUDIT/linked-create a dangling symlink at ${suffix} is refused and the file created through it removed`, async () => {
    const f = fixture();
    const target = join(f.dir, `elsewhere${suffix.replace(/\./g, '_')}.txt`);
    symlinkSync(target, f.registry + suffix, 'file');
    const view = await openRegistry(f.registry, { fs: followingOpen(), sleep: noSleep });
    await expect(view.lock()).rejects.toMatchObject({ code: 3, message: expect.stringMatching(/symbolic link/) });
    expect(existsSync(target), 'file created through the link').toBe(false);
    await expect(view.save()).rejects.toMatchObject({ code: 3, message: 'registry lock required' });
    // The planted link is the operator's to remove; nothing of this run is left beside it.
    expect(readdirSync(f.dir).filter(name => name.startsWith(basename(f.registry) + '.lock')).sort())
      .toEqual([basename(f.registry) + suffix]);
    // The test removes its own planted link: the full validation's leak scan refuses any link left
    // in the scratch tree (a link could point outside the tree it is asked to inspect).
    unlinkSync(f.registry + suffix);
  });
}

it('REGISTRY-AUDIT/acquire-ownership a lock that cannot be released after a failed acquisition stays owned and is released later', async () => {
  const f = fixture();
  const faults = { lock: 10 };
  const io = { ...fs, unlink: (async (path: Parameters<typeof fs.unlink>[0]) => {
    if (String(path) === `${f.registry}.lock.claim`) throw busy();
    if (String(path) === `${f.registry}.lock` && faults.lock > 0) { faults.lock -= 1; throw busy(); }
    return fs.unlink(path);
  }) as typeof fs.unlink };
  const view = await openRegistry(f.registry, { fs: io, sleep: noSleep });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: expect.stringMatching(/claim.*still held by this process/s) });
  expect(existsSync(`${f.registry}.lock`)).toBe(true);
  // The fault is over: the same view still owns the lock, and releasing it now removes it.
  await view.unlock();
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
});

/** fs whose new lock file cannot be written, and whose unlink of the lock fails `busyUnlinks` times. */
function unwritableLock(f: ReturnType<typeof fixture>, busyUnlinks: { left: number }) {
  return { ...fs,
    open: (async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      if (String(args[0]) !== `${f.registry}.lock` || args[1] !== 'wx') return handle;
      return new Proxy(handle, { get(target, key) {
        if (key === 'writeFile') return async () => { throw failure('ENOSPC'); };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }) as typeof fs.open,
    unlink: (async (path: Parameters<typeof fs.unlink>[0]) => {
      if (String(path) === `${f.registry}.lock` && busyUnlinks.left > 0) { busyUnlinks.left -= 1; throw busy(); }
      return fs.unlink(path);
    }) as typeof fs.unlink };
}

it('REGISTRY-AUDIT/incomplete-lock a lock whose record cannot be written is removed despite a transient busy delete', async () => {
  const f = fixture();
  const view = await openRegistry(f.registry, { fs: unwritableLock(f, { left: 1 }), sleep: noSleep });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: 'cannot create registry lock' });
  expect(existsSync(`${f.registry}.lock`), 'incomplete lock removed').toBe(false);
  const next = await openRegistry(f.registry);
  await next.lock(); await next.unlock();
});

it('REGISTRY-AUDIT/incomplete-lock an incomplete lock that cannot be removed is named in the error', async () => {
  const f = fixture();
  const view = await openRegistry(f.registry, { fs: unwritableLock(f, { left: 100 }), sleep: noSleep });
  await expect(view.lock()).rejects.toMatchObject({ code: 3,
    message: `cannot create registry lock; remove the incomplete lock file ${f.registry}.lock offline before retrying` });
});

async function staleLock(path: string) {
  const processDomain = await ownProcessDomain();
  expect(processDomain, 'process domain must be provable on the test platform').not.toBeNull();
  writeFileSync(path + '.lock', JSON.stringify({ pid: 900_001, hostname: 'host-a', startedAt: '2026-10-04T00:00:00.000Z', processDomain }));
}
const staleNames = (f: ReturnType<typeof fixture>) => readdirSync(f.dir).filter(name => name.endsWith('.stale'));

/** fs whose unlink of a quarantined stale lock fails with EBUSY `failures.left` times. */
function busyQuarantine(failures: { left: number }) {
  return { ...fs, unlink: (async (path: Parameters<typeof fs.unlink>[0]) => {
    if (String(path).endsWith('.stale') && failures.left > 0) { failures.left -= 1; throw busy(); }
    return fs.unlink(path);
  }) as typeof fs.unlink };
}

it('REGISTRY-AUDIT/break-lock a transient busy delete of the quarantined stale lock is retried and the lock acquired', async () => {
  const f = fixture();
  await staleLock(f.registry);
  const view = await openRegistry(f.registry, { fs: busyQuarantine({ left: 1 }), hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
  await view.lock({ breakLock: true });
  try {
    expect(staleNames(f)).toEqual([]);
    expect(statSync(`${f.registry}.lock`).nlink).toBe(1);
  } finally { await view.unlock(); }
});

it('REGISTRY-AUDIT/break-lock a verified stale lock that cannot be deleted is never linked back to the lock path', async () => {
  const f = fixture();
  await staleLock(f.registry);
  const view = await openRegistry(f.registry, { fs: busyQuarantine({ left: 100 }), hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, message: expect.stringMatching(/\.stale but could not be deleted/) });
  expect(existsSync(`${f.registry}.lock`), 'lock path left free, not relinked').toBe(false);
  expect(staleNames(f)).toHaveLength(1);
  // The next run acquires without --break-lock.
  const next = await openRegistry(f.registry);
  await next.lock(); await next.unlock();
});

/** fs whose lstat of a quarantined stale lock fails with EBUSY `failures.left` times. */
function busyQuarantineStat(failures: { left: number }) {
  return { ...fs, lstat: (async (...args: Parameters<typeof fs.lstat>) => {
    if (String(args[0]).endsWith('.stale') && failures.left > 0) { failures.left -= 1; throw busy(); }
    return fs.lstat(...args);
  }) as typeof fs.lstat };
}

it('REGISTRY-AUDIT/break-lock a transient busy stat of the quarantined stale lock is retried and the lock acquired', async () => {
  const f = fixture();
  await staleLock(f.registry);
  const view = await openRegistry(f.registry, { fs: busyQuarantineStat({ left: 1 }), hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
  await view.lock({ breakLock: true });
  try {
    expect(staleNames(f)).toEqual([]);
    expect(statSync(`${f.registry}.lock`).nlink).toBe(1);
  } finally { await view.unlock(); }
});

it('REGISTRY-AUDIT/break-lock a stale lock that cannot be verified after its move goes back under one name, and a later --break-lock recovers it', async () => {
  const f = fixture();
  await staleLock(f.registry);
  const view = await openRegistry(f.registry, { fs: busyQuarantineStat({ left: 100 }), hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, message: expect.stringContaining('cannot be established') });
  expect(statSync(`${f.registry}.lock`).nlink, 'the lock has its one name back').toBe(1);
  expect(staleNames(f)).toEqual([]);
  // The fault is over: the same stale lock is recovered by the next --break-lock.
  const next = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
  await next.lock({ breakLock: true });
  try { expect(staleNames(f)).toEqual([]); } finally { await next.unlock(); }
});

/**
 * fs that reports the file identifier `ino(path, real)` chooses for a path (undefined keeps the
 * real one), from lstat and from the stat of a handle opened at that path, as bigint or as Number
 * exactly as the caller asked: what NTFS reports for two files whose 64-bit identifiers differ only
 * beyond 53 bits.
 */
function remappedInodes(ino: (path: string, real: Stats | BigIntStats) => bigint | undefined) {
  const remap = <S extends Stats | BigIntStats>(path: string, real: S, bigint: boolean): S => {
    const chosen = ino(path, real);
    return chosen === undefined ? real : Object.assign(real, { ino: bigint ? chosen : Number(chosen) }) as unknown as S;
  };
  const wantsBigint = (options: unknown) => typeof options === 'object' && options !== null && (options as { bigint?: boolean }).bigint === true;
  return { ...fs,
    lstat: (async (...args: Parameters<typeof fs.lstat>) => remap(String(args[0]), await fs.lstat(...args), wantsBigint(args[1]))) as typeof fs.lstat,
    open: (async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      const path = String(args[0]);
      return new Proxy(handle, { get(target, key) {
        if (key === 'stat') return async (options?: unknown) => remap(path, await (target.stat as (o?: unknown) => Promise<Stats | BigIntStats>)(options), wantsBigint(options));
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }) as typeof fs.open };
}

it('REGISTRY-AUDIT/file-identity a claim replaced by a file whose identifier differs only beyond 53 bits is preserved, not removed', async () => {
  const f = fixture();
  const claimPath = `${f.registry}.lock.claim`;
  // Both convert to the same Number (2^53 + 4): only a full 64-bit comparison tells them apart.
  const created = 2n ** 53n + 3n, found = 2n ** 53n + 4n;
  expect(Number(created)).toBe(Number(found));
  // The claim this run creates reports `created` while it is empty (its creation check and its
  // identity) and `found` once an owner record is in it (the cleanup's look at the path).
  const io = remappedInodes((path, real) => path === claimPath ? (real.size > 0 ? found : created) : undefined);
  const view = await openRegistry(f.registry, { fs: io, sleep: noSleep });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: 'registry acquisition owner changed; preserved competing claim' });
  expect(existsSync(claimPath), 'competing claim preserved').toBe(true);
  expect(existsSync(`${f.registry}.lock`), 'the lock taken meanwhile was released').toBe(false);
  unlinkSync(claimPath);
});

it('REGISTRY-AUDIT/file-identity a quarantined stale lock whose identifier differs only beyond 53 bits is not taken as the moved lock', async () => {
  const f = fixture();
  const lockPath = `${f.registry}.lock`;
  await staleLock(f.registry);
  const text = readFileSync(lockPath, 'utf8');
  const before = 2n ** 53n + 3n, moved = 2n ** 53n + 4n;
  expect(Number(before)).toBe(Number(moved));
  const io = remappedInodes(path => path === lockPath ? before : path.endsWith('.stale') ? moved : undefined);
  const view = await openRegistry(f.registry, { fs: io, hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, message: expect.stringContaining('changed during recovery') });
  expect(readFileSync(lockPath, 'utf8'), 'the moved lock is back at the lock path').toBe(text);
});

it('REGISTRY-AUDIT/empty-lock a lock file without an owner record names the file and the offline remedy, with and without --break-lock', async () => {
  const f = fixture();
  const lockPath = `${f.registry}.lock`;
  writeFileSync(lockPath, '');
  for (const options of [{}, { breakLock: true }]) {
    const view = await openRegistry(f.registry, { hostname: () => 'host-a', pidAlive: () => false, sleep: noSleep });
    const error = await view.lock(options).then(() => undefined, (caught: unknown) => caught as { code: number; step: string; message: string });
    expect(error).toMatchObject({ code: 3, step: 'registry-lock' });
    expect(error?.message).toContain(lockPath);
    expect(error?.message).toContain('delete it offline');
    expect(statSync(lockPath).size, 'the empty lock is left for the operator').toBe(0);
  }
});

for (const [code, reason] of [['EACCES', 'permission denied in the registry directory'], ['EROFS', 'the file system is read-only'],
  ['ENOSPC', 'no space left on the device'], ['ENOENT', 'the registry directory does not exist']] as const) {
  it(`REGISTRY-AUDIT/claim-errors ${code} creating the claim names its cause and never advises deleting a claim`, async () => {
    const f = fixture();
    let sleeps = 0;
    const io = { ...directoryOwnedBy(f, 4242), open: (async (...args: Parameters<typeof fs.open>) => {
      if (String(args[0]) === `${f.registry}.lock.claim`) throw failure(code);
      return fs.open(...args);
    }) as typeof fs.open };
    const view = await openRegistry(f.registry, { fs: io, platform: 'linux', getuid: () => 4242, sleep: async () => { sleeps += 1; } });
    const error = await view.lock().then(() => undefined, (caught: unknown) => caught as { code: number; message: string });
    expect(error).toMatchObject({ code: 3, message: `cannot create registry lock ${f.registry}.lock.claim: ${reason}` });
    expect(error?.message).not.toMatch(/delete/);
    expect(sleeps, 'a non-contention error is not waited on').toBe(0);
  });
}

it('REGISTRY-AUDIT/claim-contention a claim released within the bounded wait lets the acquisition proceed', async () => {
  const f = fixture();
  writeFileSync(`${f.registry}.lock.claim`, JSON.stringify({ pid: process.pid, hostname: 'contender', startedAt: '2026-10-04T00:00:00.000Z' }));
  let sleeps = 0;
  const view = await openRegistry(f.registry, { sleep: async () => {
    sleeps += 1;
    if (sleeps === 3) unlinkSync(`${f.registry}.lock.claim`); // the other acquirer finishes
  } });
  await view.lock();
  try { expect(sleeps).toBe(3); } finally { await view.unlock(); }
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
});

it('REGISTRY-AUDIT/claim-contention a Windows claim being deleted (EPERM) is waited out', async () => {
  const f = fixture();
  let pending = 2;
  const io = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]) === `${f.registry}.lock.claim` && pending > 0) { pending -= 1; throw failure('EPERM'); }
    return fs.open(...args);
  }) as typeof fs.open };
  const view = await openRegistry(f.registry, { fs: io, platform: 'win32', sleep: noSleep });
  await view.lock();
  await view.unlock();
  expect(pending).toBe(0);
});

it('REGISTRY-AUDIT/lock-contention a Windows lock being deleted (EPERM) is waited out', async () => {
  const f = fixture();
  let pending = 2, sleeps = 0;
  const io = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]) === `${f.registry}.lock` && args[1] === 'wx' && pending > 0) { pending -= 1; throw failure('EPERM'); }
    return fs.open(...args);
  }) as typeof fs.open };
  const view = await openRegistry(f.registry, { fs: io, platform: 'win32', sleep: async () => { sleeps += 1; } });
  await view.lock();
  await view.unlock();
  expect(pending).toBe(0);
  expect(sleeps).toBe(2);
});

it('REGISTRY-AUDIT/lock-contention EPERM creating the lock on POSIX fails at once', async () => {
  const f = fixture();
  let sleeps = 0;
  const io = { ...directoryOwnedBy(f, 4242), open: (async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]) === `${f.registry}.lock` && args[1] === 'wx') throw failure('EPERM');
    return fs.open(...args);
  }) as typeof fs.open };
  const view = await openRegistry(f.registry, { fs: io, platform: 'linux', getuid: () => 4242, sleep: async () => { sleeps += 1; } });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: 'cannot create registry lock' });
  expect(sleeps, 'a non-contention error is not waited on').toBe(0);
  expect(existsSync(`${f.registry}.lock.claim`)).toBe(false);
});

it('REGISTRY-AUDIT/claim-contention a claim that stays past the bounded wait keeps the offline recovery advice', async () => {
  const f = fixture();
  writeFileSync(`${f.registry}.lock.claim`, '{"pid":');
  let sleeps = 0;
  const view = await openRegistry(f.registry, { sleep: async () => { sleeps += 1; } });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: expect.stringMatching(/^registry acquisition in progress or ambiguous: .*delete this \.claim file/) });
  expect(sleeps).toBe(14);
});

/** POSIX directory checks on any host: the registry directory reports private mode and `uid`. */
function directoryOwnedBy(f: ReturnType<typeof fixture>, uid: number) {
  return { ...fs,
    stat: (async (...args: Parameters<typeof fs.stat>) => {
      const found = await fs.stat(...args);
      return String(args[0]) === dirname(f.registry) ? Object.assign(found, { mode: 0o40700, uid }) : found;
    }) as typeof fs.stat,
    chmod: (async () => {}) as typeof fs.chmod };
}

it('REGISTRY-AUDIT/directory-owner a registry directory owned by another user is refused', async () => {
  const f = fixture();
  const view = await openRegistry(f.registry, { fs: directoryOwnedBy(f, 4243), platform: 'linux', getuid: () => 4242 });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: 'unsafe registry directory owner' });
  expect(existsSync(`${f.registry}.lock.claim`)).toBe(false);
  for (const owner of [4242, 0]) {
    const own = await openRegistry(f.registry, { fs: directoryOwnedBy(f, owner), platform: 'linux', getuid: () => 4242 });
    await own.lock(); await own.unlock();
  }
});

it('REGISTRY-AUDIT/save-busy a registry held open by another program on Windows is waited on for about ten seconds and named', async () => {
  const f = fixture();
  const delays: number[] = [];
  const io = { ...fs, rename: (async () => { throw failure('EPERM'); }) as typeof fs.rename };
  const view = await openRegistry(f.registry, { fs: io, platform: 'win32', sleep: async ms => { delays.push(ms); } });
  await view.lock();
  try {
    view.entries[0].label = 'Renamed';
    await expect(view.save()).rejects.toMatchObject({ code: 3, message: expect.stringMatching(/is open in another program.*registry unchanged$/) });
  } finally { await view.unlock(); }
  const total = delays.reduce((sum, ms) => sum + ms, 0);
  expect(total).toBeGreaterThanOrEqual(9000);
  expect(total).toBeLessThanOrEqual(11000);
});
