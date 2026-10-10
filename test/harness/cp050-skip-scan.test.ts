import { relative, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';
import { PRIVATE_TEST_SCRATCH, skippedSourceCount, testFiles } from '../../scripts/validation-support.mjs';

// A virtual test tree under a root that does not exist on disk; every other path goes to the
// real file system, so the module and its imports load normally.
const virtual = vi.hoisted(() => ({ root: '', files: new Map<string, string>() }));

vi.mock('node:fs', async importOriginal => {
  const real = await importOriginal<typeof import('node:fs')>();
  const inside = (path: unknown) => typeof path === 'string' && virtual.root !== '' &&
    (path === virtual.root || path.startsWith(virtual.root + sep));
  const local = (path: string) => relative(virtual.root, path).split(sep).join('/');
  const directory = (path: string) => {
    const prefix = path === virtual.root ? '' : `${local(path)}/`;
    return [...virtual.files.keys()].some(file => file.startsWith(prefix));
  };
  const children = (path: string) => {
    const prefix = path === virtual.root ? '' : `${local(path)}/`;
    const names = new Map<string, boolean>();
    for (const file of virtual.files.keys()) {
      if (!file.startsWith(prefix)) continue;
      const [name, ...rest] = file.slice(prefix.length).split('/');
      names.set(name, (names.get(name) ?? false) || rest.length > 0);
    }
    return [...names].map(([name, isDirectory]) => ({ name, isDirectory: () => isDirectory, isFile: () => !isDirectory }));
  };
  const mocked = {
    ...real,
    existsSync: (path: string) => inside(path) ? virtual.files.has(local(path)) || directory(path) : real.existsSync(path),
    readdirSync: ((path: string, options?: unknown) => inside(path) ? children(path)
      : real.readdirSync(path, options as never)) as typeof real.readdirSync,
    readFileSync: ((path: string, options?: unknown) => {
      if (!inside(path)) return real.readFileSync(path, options as never);
      const text = virtual.files.get(local(path));
      if (text === undefined) throw Object.assign(new Error(`ENOENT: ${path}`), { code: 'ENOENT' });
      return text;
    }) as typeof real.readFileSync,
  };
  return { ...mocked, default: mocked };
});


function tree(files: Record<string, string>): string {
  virtual.root = resolve('.virtual-macwarden-root');
  virtual.files = new Map(Object.entries(files));
  return virtual.root;
}
const passing = "import { it } from 'vitest';\nit('runs', () => {});\n";
const skipped = "import { it } from 'vitest';\nit.skip('left behind', () => {});\n";
const only = "import { it } from 'vitest';\nit.only('left behind', () => {});\n";

// Audit F21: the inventory and Vitest exclude test/.tmp and test/.sentinels, but the final
// no-skips scan read them, so a scratch fixture left by an interrupted or concurrent run failed
// full validation although it is outside the suite.
it('CP-050/B5 the no-skips scan ignores the private scratch directories the suite inventory excludes', () => {
  expect(PRIVATE_TEST_SCRATCH).toEqual(['test/.tmp', 'test/.sentinels']);
  const root = tree({
    'test/real.test.ts': passing,
    'test/.tmp/leftover/old.test.ts': skipped,
    'test/.sentinels/run/fixture.test.ts': only,
  });
  expect(testFiles(root)).toEqual(['test/real.test.ts']);
  expect(skippedSourceCount(root)).toBe(0);
});

it('CP-050/B5 a skip in a real test file still counts, including under a nested .tmp directory', () => {
  const root = tree({
    'test/real.test.ts': passing,
    'test/skipped.test.ts': skipped,
    // Only the top-level scratch directories are private; the same name deeper is a test directory.
    'test/nested/.tmp/inner.test.ts': only,
    'test/.tmp/leftover/old.test.ts': skipped,
  });
  expect(testFiles(root).sort()).toEqual(['test/nested/.tmp/inner.test.ts', 'test/real.test.ts', 'test/skipped.test.ts']);
  expect(skippedSourceCount(root)).toBe(2);
});
