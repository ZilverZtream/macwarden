import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, expect, it, vi } from 'vitest';

// Paths that are listed but gone when they are read: another worker removed them in between.
const removed = new Set<string>();
vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  const readFileSync = ((path: Parameters<typeof actual.readFileSync>[0], ...rest: unknown[]) => {
    if (removed.has(String(path))) throw Object.assign(new Error(`ENOENT: no such file or directory, open '${String(path)}'`), { code: 'ENOENT' });
    return (actual.readFileSync as (...args: unknown[]) => unknown)(path, ...rest);
  }) as typeof actual.readFileSync;
  return { ...actual, default: { ...actual, readFileSync }, readFileSync };
});

const { findLeaks } = await import('../../scripts/leak-check.mjs');
const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP || tmpdir(), 'leak-removed-'));
afterAll(() => { rmSync(root, { recursive: true, force: true }); });

it('LEAK/removed-sentinel a runtime sentinel removed between listing and read is skipped; the others are still found', () => {
  const dir = join(root, 'runtime');
  mkdirSync(dir);
  const kept = 'kept-runtime-sentinel-0123456789abcdef', gone = 'gone-runtime-sentinel-fedcba9876543210';
  writeFileSync(join(dir, 'kept.macaroon'), kept);
  writeFileSync(join(dir, 'gone.macaroon'), gone);
  removed.add(join(dir, 'gone.macaroon'));
  try {
    const sentinels = join(root, 'none.json');
    expect(findLeaks({ sentinels, sentinelDir: dir, root, commandOutput: 'nothing here' })).toBeNull();
    expect(findLeaks({ sentinels, sentinelDir: dir, root, commandOutput: `x ${kept} y` })).not.toBeNull();
  } finally { removed.clear(); }
});

it('LEAK/removed-sentinel a registered sentinel source that cannot be read still fails the check', () => {
  const project = join(root, 'project');
  mkdirSync(join(project, 'sentinels'), { recursive: true });
  writeFileSync(join(project, 'sentinels', 'registered.macaroon'), 'registered-sentinel-0123456789abcdef');
  const sentinels = join(project, 'sentinels.json');
  writeFileSync(sentinels, JSON.stringify(['sentinels/*.macaroon']));
  removed.add(join(project, 'sentinels', 'registered.macaroon'));
  try {
    expect(() => findLeaks({ sentinels, root: project, commandOutput: 'nothing here' })).toThrow(/ENOENT/);
  } finally { removed.clear(); }
});
