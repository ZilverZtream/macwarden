// Pre-1.4 audit, registry lock acquisition: links at the lock paths, ownership after a failed
// acquisition, incomplete lock records, quarantined stale locks, claim contention and errors,
// the directory owner and the Windows save back-off.
import { existsSync, readdirSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
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
