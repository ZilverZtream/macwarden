import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, expect, it, vi } from 'vitest';

// Reads of sentinel files are counted, and a path can report EBUSY a number of times first,
// as another worker's exclusive reservation does on Windows while it sets permissions.
const fake = vi.hoisted(() => ({ reads: new Map<string, number>(), busy: new Map<string, number>() }));
vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  const readFileSync = ((path: Parameters<typeof actual.readFileSync>[0], ...rest: unknown[]) => {
    const key = String(path);
    const busy = fake.busy.get(key) ?? 0;
    if (busy > 0) {
      fake.busy.set(key, busy - 1);
      throw Object.assign(new Error(`EBUSY: resource busy or locked, open '${key}'`), { code: 'EBUSY' });
    }
    fake.reads.set(key, (fake.reads.get(key) ?? 0) + 1);
    return (actual.readFileSync as (...args: unknown[]) => unknown)(path, ...rest);
  }) as typeof actual.readFileSync;
  return { ...actual, default: { ...actual, readFileSync }, readFileSync };
});

const { findLeaks } = await import('../../scripts/leak-check.mjs');
const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP || tmpdir(), 'leak-sources-'));
afterAll(() => { rmSync(root, { recursive: true, force: true }); });
beforeEach(() => { fake.reads.clear(); fake.busy.clear(); });

let count = 0;
function runtimeDirectory(files: number) {
  const dir = join(root, `runtime-${count++}`);
  mkdirSync(dir);
  const sentinels = join(root, `list-${count}.json`);
  writeFileSync(sentinels, '[]');
  const values = Array.from({ length: files }, (_, index) => `runtime-sentinel-${count}-${index}-0123456789abcdef`);
  values.forEach((value, index) => writeFileSync(join(dir, `s${index}.macaroon`), value));
  return { dir, sentinels, values };
}
const readsUnder = (dir: string) => [...fake.reads].filter(([path]) => path.startsWith(dir)).reduce((sum, [, n]) => sum + n, 0);

// Coordinator item 1: a runtime sentinel held busy by another worker was a hard failure.
it('LEAK/busy a runtime sentinel that is busy twice is retried and still found', () => {
  const { dir, sentinels, values } = runtimeDirectory(3);
  fake.busy.set(join(dir, 's1.macaroon'), 2);
  expect(findLeaks({ sentinels, sentinelDir: dir, root, commandOutput: `x ${values[1]} y` })).not.toBeNull();
  expect(fake.busy.get(join(dir, 's1.macaroon'))).toBe(0);
});

it('LEAK/busy a runtime sentinel that stays busy fails the check after the bounded retry', () => {
  const { dir, sentinels } = runtimeDirectory(2);
  fake.busy.set(join(dir, 's0.macaroon'), Number.POSITIVE_INFINITY);
  const started = performance.now();
  expect(() => findLeaks({ sentinels, sentinelDir: dir, root, commandOutput: 'nothing here' })).toThrow(/EBUSY/);
  const elapsed = performance.now() - started;
  expect(elapsed, 'retried for the bound').toBeGreaterThanOrEqual(4_500);
  expect(elapsed, 'then stopped').toBeLessThan(20_000);
}, 60_000);

// Coordinator item 2: every check re-read the whole growing runtime directory.
it('LEAK/cache an unchanged runtime sentinel is not re-read; a changed or new one is, and leaks are still reported', () => {
  const files = 200;
  const { dir, sentinels, values } = runtimeDirectory(files);
  const check = (output: string) => findLeaks({ sentinels, sentinelDir: dir, root, commandOutput: output });
  expect(check(`a ${values[7]} b`), 'first call finds the leak').not.toBeNull();
  expect(readsUnder(dir), 'first call reads every file').toBe(files);
  fake.reads.clear();
  expect(check(`a ${values[7]} b`), 'second call still finds the leak').not.toBeNull();
  expect(check('nothing here')).toBeNull();
  expect(readsUnder(dir), 'unchanged files are not read again').toBe(0);
  const changed = 'runtime-sentinel-changed-content-fedcba9876543210';
  writeFileSync(join(dir, 's3.macaroon'), changed);
  writeFileSync(join(dir, 'new.macaroon'), 'runtime-sentinel-new-file-0011223344556677');
  expect(check(`a ${changed} b`), 'changed content is found').not.toBeNull();
  expect(check('a runtime-sentinel-new-file-0011223344556677 b'), 'a new file is found').not.toBeNull();
  expect(fake.reads.get(join(dir, 's3.macaroon')), 'the changed file is read once').toBe(1);
  expect(fake.reads.get(join(dir, 'new.macaroon')), 'the new file is read once').toBe(1);
  expect(readsUnder(dir), 'nothing else is read').toBe(2);
});
