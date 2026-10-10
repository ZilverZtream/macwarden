// Registry lock release and claim faults (audit N11, N12) and the save size bound.
import { existsSync, readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { expect, it } from 'vitest';
import { openRegistry, REGISTRY_FILE_LIMIT } from '../src/registry/index.js';
import { fixture } from './helpers/cp038-online.js';

const busy = () => Object.assign(new Error('injected busy unlink'), { code: 'EBUSY' });
const noSleep = async () => undefined;

/** fs whose unlink of `<registry>.lock` fails with EBUSY while `failures.left` > 0. */
function busyUnlink(registry: string, failures: { left: number; calls: number }) {
  return { ...fs, unlink: (async (path: Parameters<typeof fs.unlink>[0]) => {
    if (String(path) === `${registry}.lock`) {
      failures.calls += 1;
      if (failures.left > 0) { failures.left -= 1; throw busy(); }
    }
    return fs.unlink(path);
  }) as typeof fs.unlink };
}

it('REGISTRY/release a transient EBUSY on the lock unlink is retried and the lock released', async () => {
  const f = fixture(), failures = { left: 1, calls: 0 };
  const view = await openRegistry(f.registry, { fs: busyUnlink(f.registry, failures), sleep: noSleep });
  await view.lock();
  await view.unlock();
  expect(failures.calls).toBe(2);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
});

it('REGISTRY/release after exhausted retries the owner keeps the lock: it can re-lock and a second unlock releases it', async () => {
  const f = fixture(), failures = { left: 10, calls: 0 };
  const view = await openRegistry(f.registry, { fs: busyUnlink(f.registry, failures), sleep: noSleep });
  await view.lock();
  await expect(view.unlock()).rejects.toMatchObject({ code: 3, message: 'cannot release registry lock' });
  expect(failures.calls).toBe(10);
  expect(existsSync(`${f.registry}.lock`)).toBe(true);
  // Still this process's lock: re-locking is not refused, saving still works, and a retry releases it.
  await view.lock();
  await view.save();
  await view.unlock();
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
});

it('REGISTRY/release a lock that is no longer ours is preserved and ownership is given up', async () => {
  const f = fixture();
  const view = await openRegistry(f.registry);
  await view.lock();
  const competing = JSON.stringify({ pid: 1, hostname: 'other', startedAt: '2026-10-04T00:00:00.000Z', processDomain: null });
  await fs.writeFile(`${f.registry}.lock`, competing);
  await expect(view.unlock()).rejects.toMatchObject({ code: 3, message: 'cannot release registry lock' });
  expect(readFileSync(`${f.registry}.lock`, 'utf8')).toBe(competing);
  await view.unlock(); // a no-op: nothing of ours is left to release
  await expect(view.save()).rejects.toMatchObject({ code: 3, message: 'registry lock required' });
});

it('REGISTRY/claim a failing stat of the new claim closes it, removes it and reports a lock failure', async () => {
  const f = fixture();
  let closes = 0;
  const io = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    if (String(args[0]) !== `${f.registry}.lock.claim`) return handle;
    return new Proxy(handle, { get(target, key) {
      if (key === 'stat') return async () => { throw Object.assign(new Error('injected EIO'), { code: 'EIO' }); };
      if (key === 'close') return async () => { closes += 1; return target.close(); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  }) as typeof fs.open };
  const view = await openRegistry(f.registry, { fs: io });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: 'cannot create registry lock' });
  expect(closes).toBeGreaterThanOrEqual(1);
  expect(existsSync(`${f.registry}.lock.claim`)).toBe(false);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  // Nothing is left behind: the next acquisition succeeds.
  const next = await openRegistry(f.registry);
  await next.lock(); await next.unlock();
});

it('REGISTRY/save refuses a registry larger than the reader accepts and leaves the file unchanged', async () => {
  const f = fixture();
  const before = readFileSync(f.registry);
  const view = await openRegistry(f.registry);
  await view.lock();
  try {
    view.entries[0].caveats = [{ type: 'unknown', value: 'x'.repeat(REGISTRY_FILE_LIMIT) }];
    await expect(view.save()).rejects.toMatchObject({ code: 3, message: expect.stringContaining('64 MiB') });
    expect(readFileSync(f.registry).equals(before)).toBe(true);
  } finally { await view.unlock(); }
});

it('REGISTRY/reload replaces the entries of a large registry without a spread', async () => {
  const f = fixture();
  const view = await openRegistry(f.registry);
  await view.lock();
  try {
    const base = view.entries[0];
    // Enough entries to exceed an engine's argument limit for a spread into splice.
    const many = Array.from({ length: 200_000 }, (_, index) => ({ ...base, rootKeyId: String(4_294_967_296 + index), label: null,
      status: 'revoked' as const, revokedAt: base.createdAt, revokeEvidence: 'by-id-only' as const }));
    view.reload(many);
    expect(view.entries).toHaveLength(200_000);
    expect(view.entries[0]).not.toBe(many[0]);
  } finally { await view.unlock(); }
});
