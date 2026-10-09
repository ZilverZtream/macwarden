import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { LOCK_FILE_LIMIT } from '../src/bounded-file.js';
import { acquireLock, type Deps } from '../src/commands/watch.js';
import { openRegistry } from '../src/registry/index.js';
import { ownProcessDomain } from '../src/registry/process-domain.js';

// MW110-04: lock owner records (<registry>.lock, <registry>.watch.lock) are read through one
// descriptor: the opened file must be the regular, non-symlink file that was checked, and
// at most LOCK_FILE_LIMIT + 1 bytes are ever read, so a file changed after the check is
// refused instead of being read whole. Covers the first owner read, the registry's stale
// recovery and quarantine reads, and watch's takeover and release reads. Each change below
// is a real local file change made deterministically at the named step.
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(): string {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'lock-read-'));
  dirs.push(dir);
  return dir;
}

const GROWN = ' '.repeat(LOCK_FILE_LIMIT * 2);
const same = (a: string, b: string) => resolve(a) === resolve(b);

/**
 * node:fs/promises counting every content byte read from `watched` (whole-file reads and
 * descriptor reads alike) and running `after` hooks once the named call on that path returns.
 */
function instrumented(watched: (path: string) => boolean,
  after: { lstat?: (path: string) => Promise<void>; rename?: (from: string, to: string) => Promise<void> } = {}) {
  const counts = { bytes: 0, contentOpens: 0, readFiles: 0 };
  const io = {
    ...fs,
    lstat: (async (path: string, ...rest: unknown[]) => {
      const meta = await (fs.lstat as (...args: unknown[]) => Promise<unknown>)(path, ...rest);
      if (watched(String(path))) await after.lstat?.(String(path));
      return meta;
    }) as typeof fs.lstat,
    rename: (async (from: string, to: string) => {
      await fs.rename(from, to);
      await after.rename?.(String(from), String(to));
    }) as typeof fs.rename,
    readFile: (async (path: string, ...rest: unknown[]) => {
      const content = await (fs.readFile as (...args: unknown[]) => Promise<string | Buffer>)(path, ...rest);
      if (watched(String(path))) { counts.readFiles++; counts.bytes += Buffer.byteLength(content); }
      return content;
    }) as typeof fs.readFile,
    open: (async (path: string, ...rest: unknown[]) => {
      const handle = await (fs.open as (...args: unknown[]) => Promise<fs.FileHandle>)(path, ...rest);
      if (!watched(String(path))) return handle;
      if (rest[0] !== 'wx') counts.contentOpens++;
      const read = handle.read.bind(handle) as (...args: unknown[]) => Promise<{ bytesRead: number }>;
      (handle as unknown as { read: unknown }).read = async (...args: unknown[]) => {
        const result = await read(...args);
        counts.bytes += result.bytesRead;
        return result;
      };
      const readFile = handle.readFile.bind(handle) as (...args: unknown[]) => Promise<string | Buffer>;
      (handle as unknown as { readFile: unknown }).readFile = async (...args: unknown[]) => {
        const content = await readFile(...args);
        counts.readFiles++; counts.bytes += Buffer.byteLength(content);
        return content;
      };
      return handle;
    }) as typeof fs.open,
  } as typeof fs;
  return { io, counts };
}

const watchDeps = (files: typeof fs, pid = 1_000_001) => ({ fs: files, env: {}, clock: () => new Date(),
  emit: () => undefined, hostname: () => hostname(), pid, processDomain: async () => null }) as unknown as Deps;

// --- registry lock -----------------------------------------------------------------------

it('LOCK/read-bounds a registry lock grown after its check is refused after at most limit + 1 bytes', async () => {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  const lock = `${registry}.lock`;
  writeFileSync(lock, JSON.stringify({ pid: 2_147_483_000, hostname: 'elsewhere', startedAt: '2026-10-08T00:00:00.000Z' }));
  let changed = false;
  const { io, counts } = instrumented(path => same(path, lock), { lstat: async () => {
    if (!changed) { changed = true; await fs.writeFile(lock, GROWN); }
  } });
  const view = await openRegistry(registry, { fs: io });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, step: 'registry-lock', message: 'invalid registry lock' });
  expect(changed).toBe(true);
  expect(counts.bytes).toBeLessThanOrEqual(LOCK_FILE_LIMIT + 1);
  expect(counts.readFiles).toBe(0);
});

it('LOCK/read-bounds a registry lock replaced by another file after its check is refused without reading it', async () => {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  const lock = `${registry}.lock`;
  const owner = JSON.stringify({ pid: 2_147_483_000, hostname: 'elsewhere', startedAt: '2026-10-08T00:00:00.000Z' });
  writeFileSync(lock, owner);
  let changed = false;
  const { io, counts } = instrumented(path => same(path, lock), { lstat: async () => {
    if (changed) return;
    changed = true;
    // A different file (another inode) takes the checked path: same small owner record.
    writeFileSync(`${lock}.new`, owner);
    await fs.rename(`${lock}.new`, lock);
  } });
  const view = await openRegistry(registry, { fs: io });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, step: 'registry-lock', message: 'invalid registry lock' });
  expect(changed).toBe(true);
  expect(counts.bytes).toBe(0);
});

it('LOCK/read-bounds an ordinary registry lock is still read and reported as held', async () => {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  writeFileSync(`${registry}.lock`, JSON.stringify({ pid: 2_147_483_000, hostname: 'elsewhere', startedAt: '2026-10-08T00:00:00.000Z' }));
  const view = await openRegistry(registry);
  await expect(view.lock()).rejects.toMatchObject({ code: 3, step: 'registry-lock',
    message: 'registry locked by pid 2147483000 on elsewhere since 2026-10-08T00:00:00.000Z' });
});

/** A stale same-host registry lock that --break-lock may recover. */
async function staleRegistry() {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  const domain = await ownProcessDomain();
  expect(domain, 'process domain must be provable on the test platform').not.toBeNull();
  const owner = JSON.stringify({ pid: 900_001, hostname: 'host-a', startedAt: '2026-10-04T00:00:00.000Z', processDomain: domain });
  writeFileSync(`${registry}.lock`, owner);
  return { dir, registry, lock: `${registry}.lock`, owner };
}

it('LOCK/read-bounds a registry lock grown during stale recovery is read at most limit + 1 bytes and preserved', async () => {
  const s = await staleRegistry();
  let lstats = 0;
  const { io, counts } = instrumented(path => same(path, s.lock), { lstat: async () => {
    // The first lstat is the owner read's check; the second is recovery's own identity check.
    if (++lstats === 2) await fs.writeFile(s.lock, GROWN);
  } });
  const view = await openRegistry(s.registry, { fs: io, hostname: () => 'host-a', pidAlive: () => false });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, step: 'registry-lock' });
  expect(lstats).toBeGreaterThanOrEqual(2);
  expect(counts.bytes).toBeLessThanOrEqual(2 * Buffer.byteLength(s.owner) + LOCK_FILE_LIMIT + 1);
  expect(counts.readFiles).toBe(0);
  // Never removed: the grown file stays in place for offline recovery.
  expect(readFileSync(s.lock, 'utf8')).toBe(GROWN);
});

it('LOCK/read-bounds a quarantined registry lock grown after the rename is read at most limit + 1 bytes and restored', async () => {
  const s = await staleRegistry();
  let quarantine = '';
  const { io, counts } = instrumented(path => same(path, s.lock) || (quarantine !== '' && same(path, quarantine)), {
    rename: async (from, to) => {
      if (!same(from, s.lock)) return;
      quarantine = to;
      await fs.writeFile(to, GROWN);
    } });
  const view = await openRegistry(s.registry, { fs: io, hostname: () => 'host-a', pidAlive: () => false });
  await expect(view.lock({ breakLock: true })).rejects.toMatchObject({ code: 3, step: 'registry-lock' });
  expect(quarantine).not.toBe('');
  expect(counts.bytes).toBeLessThanOrEqual(2 * Buffer.byteLength(s.owner) + LOCK_FILE_LIMIT + 1);
  expect(counts.readFiles).toBe(0);
  expect(readFileSync(s.lock, 'utf8')).toBe(GROWN);
});

it('LOCK/read-bounds stale registry recovery still succeeds for an unchanged lock', async () => {
  const s = await staleRegistry();
  const view = await openRegistry(s.registry, { hostname: () => 'host-a', pidAlive: () => false });
  await view.lock({ breakLock: true });
  expect(JSON.parse(readFileSync(s.lock, 'utf8'))).toMatchObject({ pid: process.pid, hostname: 'host-a' });
  await view.unlock();
});

// --- watch lock --------------------------------------------------------------------------

const staleWatchRecord = `${JSON.stringify({ pid: 2_147_483_000, hostname: hostname() })}\n`;

it('LOCK/read-bounds a watch lock grown after its check is refused after at most limit + 1 bytes', async () => {
  const dir = scratch();
  const lock = join(dir, 'registry.json.watch.lock');
  writeFileSync(lock, staleWatchRecord);
  let changed = false;
  const { io, counts } = instrumented(path => same(path, lock), { lstat: async () => {
    if (!changed) { changed = true; await fs.writeFile(lock, GROWN); }
  } });
  await expect(acquireLock(lock, watchDeps(io))).rejects.toThrow('watch lock without owner record');
  expect(changed).toBe(true);
  expect(counts.bytes).toBeLessThanOrEqual(LOCK_FILE_LIMIT + 1);
  expect(counts.readFiles).toBe(0);
});

it('LOCK/read-bounds a watch lock replaced by another file after its check is refused without reading it', async () => {
  const dir = scratch();
  const lock = join(dir, 'registry.json.watch.lock');
  writeFileSync(lock, staleWatchRecord);
  let changed = false;
  const { io, counts } = instrumented(path => same(path, lock), { lstat: async () => {
    if (changed) return;
    changed = true;
    writeFileSync(`${lock}.new`, staleWatchRecord);
    await fs.rename(`${lock}.new`, lock);
  } });
  await expect(acquireLock(lock, watchDeps(io))).rejects.toThrow('watch lock without owner record');
  expect(counts.bytes).toBe(0);
});

it('LOCK/read-bounds a watch lock symlink is refused without opening it for reading', async () => {
  const dir = scratch();
  const target = join(dir, 'owner.json');
  writeFileSync(target, staleWatchRecord);
  const lock = join(dir, 'registry.json.watch.lock');
  symlinkSync(target, lock, 'file');
  const { io, counts } = instrumented(path => same(path, lock) || same(path, target));
  await expect(acquireLock(lock, watchDeps(io))).rejects.toThrow('watch lock without owner record');
  expect(counts.contentOpens).toBe(0);
  expect(counts.bytes).toBe(0);
});

it('LOCK/read-bounds a watch lock taken over grows after the rename: read at most limit + 1 bytes, never removed', async () => {
  const dir = scratch();
  const lock = join(dir, 'registry.json.watch.lock');
  writeFileSync(lock, staleWatchRecord);
  let quarantine = '';
  const { io, counts } = instrumented(path => same(path, lock) || (quarantine !== '' && same(path, quarantine)), {
    rename: async (from, to) => {
      if (!same(from, lock)) return;
      quarantine = to;
      await fs.writeFile(to, GROWN);
    } });
  await expect(acquireLock(lock, watchDeps(io))).rejects.toMatchObject({ code: 'EEXIST' });
  expect(quarantine).not.toBe('');
  expect(counts.bytes).toBeLessThanOrEqual(Buffer.byteLength(staleWatchRecord) + LOCK_FILE_LIMIT + 1);
  expect(counts.readFiles).toBe(0);
  // Not the stale record: it is put back in place rather than deleted.
  expect(readFileSync(lock, 'utf8')).toBe(GROWN);
});

it('LOCK/read-bounds a watch lock grown before release is read at most limit + 1 bytes and left in place', async () => {
  const dir = scratch();
  const lock = join(dir, 'registry.json.watch.lock');
  const { io, counts } = instrumented(path => same(path, lock));
  const release = await acquireLock(lock, watchDeps(io));
  await fs.writeFile(lock, GROWN);
  await release();
  expect(counts.bytes).toBeLessThanOrEqual(LOCK_FILE_LIMIT + 1);
  expect(counts.readFiles).toBe(0);
  expect(readFileSync(lock, 'utf8')).toBe(GROWN);
});

it('LOCK/read-bounds a stale watch lock is still taken over and released normally', async () => {
  const dir = scratch();
  const lock = join(dir, 'registry.json.watch.lock');
  writeFileSync(lock, staleWatchRecord);
  const release = await acquireLock(lock, watchDeps(fs));
  expect(JSON.parse(readFileSync(lock, 'utf8'))).toMatchObject({ pid: 1_000_001 });
  await release();
  await expect(fs.lstat(lock)).rejects.toMatchObject({ code: 'ENOENT' });
});

// --- registry release identity -------------------------------------------------------------

it('LOCK/registry-release a lock replaced by another owner whose file reuses the same device and inode is never removed', async () => {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  const lock = `${registry}.lock`;
  // Once the lock is replaced, every lstat and fstat of it reports the original file's
  // device, inode and birth time: what a file system recycling the freed inode would show
  // (Linux does, which made the identity-only release remove another owner's lock).
  type Identity = { plain: Awaited<ReturnType<typeof fs.lstat>>; big: Awaited<ReturnType<typeof fs.lstat>> };
  const world: { reused?: Identity } = {};
  const disguise = <T extends object>(meta: T, big: boolean): T => {
    const reused = world.reused;
    if (reused === undefined) return meta;
    const from = (big ? reused.big : reused.plain) as unknown as Record<string, unknown>;
    const fields = Object.fromEntries(['dev', 'ino', 'birthtimeMs', 'birthtimeNs', 'birthtime']
      .filter(key => key in from).map(key => [key, from[key]]));
    return Object.assign(Object.create(Object.getPrototypeOf(meta) as object) as T, meta, fields);
  };
  const io = { ...fs,
    lstat: (async (path: string, options?: { bigint?: boolean }) => {
      const meta = await fs.lstat(path, options as never);
      return same(path, lock) ? disguise(meta, options?.bigint === true) : meta;
    }) as typeof fs.lstat,
    open: (async (path: string, ...rest: unknown[]) => {
      const handle = await (fs.open as (...args: unknown[]) => Promise<fs.FileHandle>)(path, ...rest);
      if (!same(path, lock)) return handle;
      const stat = handle.stat.bind(handle) as (options?: { bigint?: boolean }) => Promise<object>;
      (handle as unknown as { stat: unknown }).stat = async (options?: { bigint?: boolean }) =>
        disguise(await stat(options), options?.bigint === true);
      return handle;
    }) as typeof fs.open,
  } as typeof fs;
  const view = await openRegistry(registry, { fs: io });
  await view.lock();
  const mine = JSON.parse(readFileSync(lock, 'utf8')) as Record<string, unknown>;
  const identity = { plain: await fs.lstat(lock), big: await fs.lstat(lock, { bigint: true }) } as Identity;
  // Another process (same pid, host and start time) creates its own lock in the freed slot.
  rmSync(lock);
  const competitor = JSON.stringify({ ...mine, token: '00000000-0000-4000-8000-000000000000' });
  writeFileSync(lock, competitor);
  world.reused = identity;
  await expect(view.unlock()).rejects.toMatchObject({ code: 3, step: 'registry-lock', message: 'cannot release registry lock' });
  expect(readFileSync(lock, 'utf8')).toBe(competitor);
});

it('LOCK/registry-release the owner record carries a per-acquisition token and older records stay readable', async () => {
  const dir = scratch();
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [] }));
  const lock = `${registry}.lock`;
  const tokens = new Set<string>();
  for (let n = 0; n < 2; n++) {
    const view = await openRegistry(registry);
    await view.lock();
    const record = JSON.parse(readFileSync(lock, 'utf8')) as { token?: unknown };
    expect(record.token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    tokens.add(record.token as string);
    await view.unlock();
    await expect(fs.lstat(lock)).rejects.toMatchObject({ code: 'ENOENT' });
  }
  expect(tokens.size).toBe(2);
  // A record written by 1.1.0 (no token) is still a valid, held lock.
  writeFileSync(lock, JSON.stringify({ pid: 2_147_483_000, hostname: 'elsewhere', startedAt: '2026-10-08T00:00:00.000Z' }));
  await expect((await openRegistry(registry)).lock()).rejects.toMatchObject({ code: 3, step: 'registry-lock',
    message: 'registry locked by pid 2147483000 on elsewhere since 2026-10-08T00:00:00.000Z' });
});
