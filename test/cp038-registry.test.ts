import { deadProductLock, liveProductLock } from './helpers/cp042-lock-process.js';
import { ownProcessDomain } from '../src/registry/process-domain.js';
import { readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { expect, it, vi } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { fixture } from './helpers/cp038-online.js';

it.each([0o755, 0o1777, 0o775])('CP-038/A1-existing-directory pre-existing mode %s is preserved including sticky bit', async mode => {
  const f = fixture(); let observedMode = mode;
  const chmod = vi.fn(async (path: Parameters<typeof fs.chmod>[0], value: Parameters<typeof fs.chmod>[1]) => {
    if (String(path) === f.dir) observedMode = Number(value);
  });
  const injected = { ...fs, chmod };
  for (const operation of ['stat', 'lstat'] as const) {
    injected[operation] = (async (...args: Parameters<typeof fs.stat>) => {
      const value = await fs[operation](...args);
      if (String(args[0]) === f.dir) return new Proxy(value, { get(target, key) {
        if (key === 'mode') return 0o040000 | observedMode;
        const result: unknown = Reflect.get(target, key, target);
        return typeof result === 'function' ? result.bind(target) : result;
      } });
      return value;
    }) as typeof fs.stat;
  }
  const registry = await openRegistry(f.registry, { fs: injected, platform: 'linux' });
  let refused: unknown;
  try { await registry.lock(); } catch (error) { refused = error; }
  finally { await registry.unlock(); }
  expect(observedMode).toBe(mode); expect(chmod.mock.calls.filter(([path]) => String(path) === f.dir)).toEqual([]);
  if (mode & 0o022) expect(refused).toMatchObject({ code: 3 }); else expect(refused).toBeUndefined();
});

it('CP-038/B6-lock-races replacement lock during stale-owner check remains intact', async () => {
  const f = fixture(), lock = f.registry + '.lock';
  await deadProductLock(f.registry);
  const competitor = await liveProductLock(f.registry + '.competitor');
  const replacement = competitor.bytes.toString('utf8');
  let raced = false;
  const registry = await openRegistry(f.registry, { pidAlive: () => {
    raced = true;
    writeFileSync(lock, replacement); return false;
  } });
  let refused: unknown;
  try { await registry.lock({ breakLock: true }); } catch (error) { refused = error; }
  expect(raced).toBe(true); expect(refused).toMatchObject({ code: 3 }); expect(readFileSync(lock, 'utf8')).toBe(replacement);
  await competitor.view.unlock();
});
it('CP-038/B6-lock-races live same-host owner cannot be broken', async () => {
  const f = fixture(), lock = f.registry + '.lock';
  const processDomain = await ownProcessDomain();
  expect(processDomain).not.toBeNull();
  const original = JSON.stringify({ pid: process.pid, hostname: 'same-host', startedAt: '2026-10-05T12:00:00Z', processDomain });
  writeFileSync(lock, original);
  const registry = await openRegistry(f.registry, { hostname: () => 'same-host', pidAlive: () => true });
  await expect(registry.lock({ breakLock: true })).rejects.toMatchObject({ code: 3,
    message: `registry locked by pid ${process.pid} on same-host since 2026-10-05T12:00:00Z` });
  expect(readFileSync(lock, 'utf8')).toBe(original);
});
it('CP-038/B6-lock-races registry errors have a distinct safe classification', async () => {
  const f = fixture(); writeFileSync(f.registry, '{');
  await expect(openRegistry(f.registry)).rejects.toMatchObject({ name: 'RegistryInputError', code: 3 });
});
