import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { hostname } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { expect, it } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { entry, fixture, oldId, pubkey } from './helpers/cp038-online.js';

const busy = () => Object.assign(new Error('injected busy file'), { code: 'EBUSY' });
const noSleep = async () => {};

it('REGISTRY/claim-cleanup a transient EBUSY removing the claim still acquires, and the lock is released normally', async () => {
  const f = fixture(); let failures = 1;
  const io = { ...fs, unlink: (async (path: Parameters<typeof fs.unlink>[0]) => {
    if (String(path).endsWith('.lock.claim') && failures-- > 0) throw busy();
    return fs.unlink(path);
  }) as typeof fs.unlink };
  const view = await openRegistry(f.registry, { fs: io, sleep: noSleep });
  await view.lock();
  expect(existsSync(f.registry + '.lock.claim')).toBe(false);
  await view.unlock();
  const again = await openRegistry(f.registry);
  await again.lock(); await again.unlock();
  expect(existsSync(f.registry + '.lock')).toBe(false);
});

it('REGISTRY/claim-cleanup a persistent claim cleanup failure reports the claim and leaves no stale registry lock', async () => {
  const f = fixture();
  const io = { ...fs, unlink: (async (path: Parameters<typeof fs.unlink>[0]) => {
    if (String(path).endsWith('.lock.claim')) throw busy();
    return fs.unlink(path);
  }) as typeof fs.unlink };
  const view = await openRegistry(f.registry, { fs: io, sleep: noSleep });
  await expect(view.lock()).rejects.toMatchObject({ code: 3, message: expect.stringMatching(/claim/) });
  expect(existsSync(f.registry + '.lock')).toBe(false);
  // The left claim blocks writers until removed offline, as the message says.
  await fs.unlink(f.registry + '.lock.claim');
  const again = await openRegistry(f.registry);
  await again.lock(); await again.unlock();
});

it('REGISTRY/lock-close a failure closing the new lock file releases it instead of leaking it', async () => {
  const f = fixture();
  const io = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    if (String(args[0]) !== f.registry + '.lock') return handle;
    return new Proxy(handle, { get(target, key) {
      if (key === 'close') return async () => { await target.close(); throw busy(); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  }) as typeof fs.open };
  const view = await openRegistry(f.registry, { fs: io, sleep: noSleep });
  await expect(view.lock()).rejects.toMatchObject({ code: 3 });
  expect(existsSync(f.registry + '.lock')).toBe(false);
  expect(existsSync(f.registry + '.lock.claim')).toBe(false);
  const again = await openRegistry(f.registry);
  await again.lock(); await again.unlock();
});

function recordingFs(f: ReturnType<typeof fixture>, events: string[]) {
  const directory = dirname(f.registry);
  return { ...fs,
    // POSIX directory checks on any host: the test directory reports private mode.
    stat: (async (...args: Parameters<typeof fs.stat>) => {
      const stat = await fs.stat(...args);
      return String(args[0]) === directory ? Object.assign(stat, { mode: 0o40700 }) : stat;
    }) as typeof fs.stat,
    chmod: (async () => {}) as typeof fs.chmod,
    rename: (async (...args: Parameters<typeof fs.rename>) => { events.push('rename'); return fs.rename(...args); }) as typeof fs.rename,
    open: (async (...args: Parameters<typeof fs.open>) => {
      if (String(args[0]) === directory && args[1] === 'r') {
        events.push('open-directory');
        return { sync: async () => { events.push('sync-directory'); }, close: async () => { events.push('close-directory'); } };
      }
      return fs.open(...args);
    }) as typeof fs.open };
}

it('REGISTRY/durable-save on POSIX the registry directory is synced after the rename', async () => {
  const f = fixture(); const events: string[] = [];
  const view = await openRegistry(f.registry, { fs: recordingFs(f, events), platform: 'linux', sleep: noSleep });
  await view.lock();
  view.add(entry(oldId + 1000n, 'Bob'));
  await view.save();
  await view.unlock();
  expect(events).toEqual(['rename', 'open-directory', 'sync-directory', 'close-directory']);
});

it('REGISTRY/durable-save Windows has no directory sync and still saves', async () => {
  const f = fixture(); const events: string[] = [];
  const view = await openRegistry(f.registry, { fs: recordingFs(f, events), platform: 'win32', sleep: noSleep });
  await view.lock();
  view.add(entry(oldId + 1001n, 'Bob'));
  await view.save();
  await view.unlock();
  expect(events).toEqual(['rename']);
});

it('REGISTRY/stale-temps acquiring the lock removes only this registry\'s leftover save temp files', async () => {
  const f = fixture();
  const name = basename(f.registry);
  const stale = [`${name}.0f8e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b.tmp`, `${name}.aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.tmp`];
  const kept = [`${name}.not-a-save.tmp`, `other.json.0f8e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b.tmp`, `${name}.0f8e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b.tmp.bak`];
  for (const file of [...stale, ...kept]) writeFileSync(join(f.dir, file), '{}');
  const directoryLike = `${name}.11111111-2222-4333-8444-555555555555.tmp`;
  mkdirSync(join(f.dir, directoryLike));
  const view = await openRegistry(f.registry);
  await view.lock(); await view.unlock();
  const left = readdirSync(f.dir);
  for (const file of stale) expect(left).not.toContain(file);
  for (const file of [...kept, directoryLike]) expect(left).toContain(file);
});

it('REGISTRY/stale-temps nothing is removed when the lock is held by another live writer', async () => {
  const f = fixture();
  const stale = `${basename(f.registry)}.0f8e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b.tmp`;
  writeFileSync(join(f.dir, stale), '{}');
  writeFileSync(f.registry + '.lock', JSON.stringify({ pid: process.pid, hostname: hostname(), startedAt: new Date().toISOString(),
    processDomain: null }));
  const view = await openRegistry(f.registry);
  await expect(view.lock()).rejects.toMatchObject({ code: 3 });
  expect(readdirSync(f.dir)).toContain(stale);
});

it('REGISTRY/validation-scale 20,000 active entries open quickly', async () => {
  const f = fixture(); const base = entry(oldId);
  const entries = Array.from({ length: 20_000 }, (_, index) => ({ ...base,
    rootKeyId: String(4294967296n + BigInt(index)), label: `app-${index}` }));
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries }));
  const started = performance.now();
  const view = await openRegistry(f.registry);
  expect(performance.now() - started).toBeLessThan(5_000);
  expect(view.entries).toHaveLength(20_000);
}, 30_000);

it('REGISTRY/validation-scale label uniqueness keeps its exact semantics', async () => {
  const f = fixture();
  const first = entry(4294967401n, 'Alice'), second = entry(4294967402n, 'Alice');
  const write = async (rows: unknown[]) => {
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: rows }));
    try { await openRegistry(f.registry); return 'accepted'; } catch { return 'rejected'; }
  };
  const otherNode = '03' + 'cd'.repeat(32);
  expect(await write([first, second])).toBe('rejected');
  // The node key compares case-insensitively: the same node written in upper case
  // is valid on its own and still conflicts on the shared label.
  expect(await write([first, { ...second, label: 'Bob', nodePubkey: pubkey.toUpperCase() }])).toBe('accepted');
  expect(await write([first, { ...second, nodePubkey: pubkey.toUpperCase() }])).toBe('rejected');
  expect(await write([first, { ...second, nodePubkey: otherNode }])).toBe('accepted');
  expect(await write([first, { ...second, replaces: first.rootKeyId }])).toBe('accepted');
  expect(await write([first, { ...second, replaces: first.rootKeyId }, { ...entry(4294967403n, 'Alice'), replaces: second.rootKeyId }])).toBe('rejected');
  // Labels compare exactly; only the node key is case-insensitive.
  expect(await write([first, { ...second, label: 'alice' }])).toBe('accepted');
  expect(await write([first, { ...second, status: 'revoked', revokedAt: '2026-01-01T00:00:00.000Z', revokeEvidence: 'by-id-only' }])).toBe('accepted');
});
