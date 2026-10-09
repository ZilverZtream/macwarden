import { existsSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { fixture } from './helpers/cp038-online.js';

// The temp name is made predictable here so a test can occupy it beforehand, exactly as
// a hostile local user could if the name were guessable.
const fixedUuid = { value: undefined as string | undefined };
vi.mock('node:crypto', async importOriginal => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, randomUUID: () => (fixedUuid.value ?? actual.randomUUID()) as ReturnType<typeof actual.randomUUID> };
});
afterEach(() => { fixedUuid.value = undefined; });

const { openRegistry } = await import('../src/registry/index.js');

it('REGISTRY/save-safeguards save without holding the lock is refused and changes nothing', async () => {
  const f = fixture();
  const before = readFileSync(f.registry);
  const view = await openRegistry(f.registry);
  await expect(view.save()).rejects.toMatchObject({ code: 3, message: 'registry lock required' });
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('REGISTRY/save-safeguards an invalid entry list is never written', async () => {
  const f = fixture();
  const before = readFileSync(f.registry);
  const view = await openRegistry(f.registry);
  await view.lock();
  try {
    // Bypasses add(): two active entries with the same label on the same node.
    const copy = { ...view.entries[0], rootKeyId: '4294967999', fingerprint: 'fp:0123456789abcdef' };
    view.entries.push(copy);
    await expect(view.save()).rejects.toMatchObject({ code: expect.any(Number) });
    expect(readFileSync(f.registry).equals(before)).toBe(true);
  } finally { await view.unlock(); }
});

it('REGISTRY/save-safeguards the temp file is synced to disk before it replaces the registry', async () => {
  const f = fixture();
  const events: string[] = [];
  const io = { ...fs,
    open: (async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      if (!String(args[0]).endsWith('.tmp')) return handle;
      return new Proxy(handle, { get(target, key) {
        const value = Reflect.get(target, key, target);
        if (key === 'writeFile' || key === 'sync') return async (...rest: unknown[]) => {
          events.push(String(key)); return (value as (...a: unknown[]) => unknown).apply(target, rest);
        };
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }) as typeof fs.open,
    rename: (async (from: string, to: string) => { events.push(`rename:${String(to) === f.registry}`); return fs.rename(from, to); }) as typeof fs.rename,
  };
  const view = await openRegistry(f.registry, { fs: io });
  await view.lock();
  try { await view.save(); } finally { await view.unlock(); }
  expect(events).toEqual(['writeFile', 'sync', 'rename:true']);
});

it('REGISTRY/save-safeguards a pre-existing file or symlink at the temp path is never written through', async () => {
  const f = fixture();
  const before = readFileSync(f.registry);
  const victim = join(dirname(f.registry), 'victim.txt');
  writeFileSync(victim, 'victim');
  fixedUuid.value = '00000000-0000-4000-8000-000000000000';
  const temp = `${f.registry}.${fixedUuid.value}.tmp`;
  let planted = 'file';
  try { symlinkSync(victim, temp, 'file'); planted = 'symlink'; } catch { writeFileSync(temp, 'occupied'); }
  const view = await openRegistry(f.registry);
  await view.lock();
  try {
    // lock() removes stale *.tmp files left by crashed saves; plant again after it.
    if (!existsSync(temp)) {
      if (planted === 'symlink') symlinkSync(victim, temp, 'file'); else writeFileSync(temp, 'occupied');
    }
    await expect(view.save()).rejects.toMatchObject({ code: 3, message: 'cannot save registry' });
  } finally { await view.unlock(); }
  expect(readFileSync(victim, 'utf8')).toBe('victim');
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});
