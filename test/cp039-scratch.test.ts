import { join, resolve } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const disk = vi.hoisted(() => ({
  nodes: new Map<string, { kind?: 'link' | 'file'; mode?: number; ino?: number }>(),
  missing: new Set<string>(), created: [] as Array<{ path: string; mode: number }>,
  removed: [] as string[], child: '',
}));
vi.mock('node:fs', async importOriginal => {
  const original = await importOriginal<typeof import('node:fs')>();
  const { resolve } = await import('node:path');
  return { ...original,
    lstatSync(path: string) {
      const name = resolve(path);
      if (disk.missing.has(name)) throw Object.assign(new Error('Absent test directory'), { code: 'ENOENT' });
      // Real metadata comes solely from the allowed test directory, never the synthetic caller paths.
      const stat = original.lstatSync(resolve('test'));
      const node = disk.nodes.get(name);
      stat.mode = node?.kind === 'link' ? 0o120777 : node?.kind === 'file' ? 0o100600 : 0o040700;
      if (node?.mode !== undefined) stat.mode = node.mode;
      stat.ino = node?.ino ?? 39;
      return stat;
    },
    realpathSync: (path: string) => resolve(path),
    mkdirSync(path: string, options: { mode: number }) {
      disk.created.push({ path: resolve(path), mode: options.mode }); disk.missing.delete(resolve(path));
    },
    mkdtempSync: (prefix: string) => disk.child || prefix + 'unique',
    rmSync: (path: string) => { disk.removed.push(resolve(path)); },
  };
});
import { root, scratchDirectory } from './support/cp039-scratch.js';

const caller = resolve('caller-private-scratch');
beforeEach(() => {
  disk.nodes.clear(); disk.missing.clear(); disk.created.length = 0; disk.removed.length = 0; disk.child = '';
  vi.stubEnv('MACWARDEN_TEST_TMP', caller);
  vi.stubEnv('MACWARDEN_SENTINEL_DIR', resolve('caller-private-sentinels'));
});
afterEach(() => { vi.unstubAllEnvs(); });

it('CP-039/A3-leak-encodings scratch accepts caller-owned absolute roots outside test without modifying them', () => {
  expect(root()).toBe(caller);
  expect(root('MACWARDEN_SENTINEL_DIR')).toBe(resolve('caller-private-sentinels'));
  expect(disk.created).toEqual([]);
  expect(disk.removed).toEqual([]);
});
it('CP-039/A3-leak-encodings scratch refuses missing and relative root configuration', () => {
  vi.stubEnv('MACWARDEN_TEST_TMP', undefined);
  expect(() => root()).toThrow('must be an absolute scratch directory');
  vi.stubEnv('MACWARDEN_TEST_TMP', 'relative-scratch');
  expect(() => root()).toThrow('must be an absolute scratch directory');
});
it('CP-039/A3-leak-encodings scratch creates only missing components with private modes', () => {
  const nested = join(caller, 'new', 'nested');
  vi.stubEnv('MACWARDEN_TEST_TMP', nested);
  disk.missing.add(join(caller, 'new')); disk.missing.add(nested);
  expect(root()).toBe(nested);
  expect(disk.created).toEqual([{ path: join(caller, 'new'), mode: 0o700 }, { path: nested, mode: 0o700 }]);
});
it('CP-039/A3-leak-encodings scratch rejects symlink roots and ancestors before creating children', () => {
  for (const path of [caller, join(caller, 'ancestor')]) {
    vi.stubEnv('MACWARDEN_TEST_TMP', join(caller, 'ancestor', 'child'));
    disk.nodes.set(path, { kind: 'link' });
    expect(() => scratchDirectory()).toThrow('without symlinks');
    expect(disk.created).toEqual([]); expect(disk.removed).toEqual([]);
    disk.nodes.clear();
  }
});
it('CP-039/A3-leak-encodings scratch rejects nondirectory roots without changing them', () => {
  disk.nodes.set(caller, { kind: 'file' });
  expect(() => root()).toThrow('real directories');
  expect(disk.created).toEqual([]); expect(disk.removed).toEqual([]);
});
it('CP-039/A3-leak-encodings scratch cleanup retains caller roots and post-run artifacts', () => {
  const lease = scratchDirectory();
  lease.cleanup();
  // Only the newly created direct child is removed; caller captures, declarations and sentinels remain.
  expect(disk.removed).toEqual([lease.dir]);
  expect(disk.removed).not.toContain(caller);
  expect(disk.removed).not.toContain(join(caller, 'caller-capture.json'));
});
it('CP-039/A3-leak-encodings scratch refuses cleanup of a sibling with a matching path prefix', () => {
  disk.child = join(caller + '-sibling', 'cp039-unique');
  expect(() => scratchDirectory()).toThrow('Unsafe scratch cleanup target');
  expect(disk.removed).toEqual([]);
});
it('CP-039/A3-leak-encodings scratch refuses cleanup after parent or child replacement', () => {
  for (const target of ['parent', 'child'] as const) {
    const lease = scratchDirectory();
    disk.nodes.set(target === 'parent' ? caller : lease.dir, { ino: 40 });
    expect(() => lease.cleanup()).toThrow('identity changed');
    expect(disk.removed).toEqual([]); disk.nodes.clear();
  }
});
it('CP-039/A3-leak-encodings scratch refuses cleanup after a child becomes a symlink', () => {
  const lease = scratchDirectory(); disk.nodes.set(lease.dir, { kind: 'link' });
  expect(() => lease.cleanup()).toThrow('without symlinks');
  expect(disk.removed).toEqual([]);
});
