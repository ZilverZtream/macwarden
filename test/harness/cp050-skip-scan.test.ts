import { relative, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';
import { PRIVATE_TEST_SCRATCH, SOURCE_SKIP_ALLOWANCE, skippedSourceCount, skippedSourceFindings, testFiles } from '../../scripts/validation-support.mjs';

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

// Audit TESTS-03 / TOOLING-11: each of these disables, inverts or empties a test while the
// earlier scan, which saw only .skip/.only/.todo on a direct chain, counted nothing.
const smuggled: Record<string, string> = {
  'aliased test function': "const t = it;\nt('aliased', () => { expect(1).toBe(2); });",
  'aliased skip': "const t = it;\nt.skip('aliased skip', () => {});",
  'computed skip': "it['sk' + 'ip']('computed skip', () => {});",
  'computed literal skip': "it['skip']('literal computed skip', () => {});",
  'skipIf': "it.skipIf(true)('skipIf true', () => {});",
  'runIf': "describe.runIf(false)('runIf false', () => { it('inner', () => {}); });",
  'fails': "it.fails('inverted', () => { expect(1).toBe(2); });",
  'unknown chain property': "it.extend({})('custom', () => {});",
  'context skip': "it('context skip', ({ skip }) => { skip(); expect(1).toBe(2); });",
  'context skip member': "it('context skip', context => { context.skip(); expect(1).toBe(2); });",
  'empty each table': "it.each([] as number[])('empty table %i', n => { expect(n).toBe(-1); });",
  'empty for table': "test.for([] as number[])('empty for %i', n => { expect(n).toBe(-1); });",
  'early return': "it('early return', () => { if (process.env.NOPE === undefined) return; expect(1).toBe(2); });",
  'test passed as a value': "[it].forEach(f => f('indirect', () => {}));",
  'namespace skip': "vt.it.skip('namespace', () => {});",
};
it.each(Object.entries(smuggled))('TESTS-03 the no-skips scan counts %s', (_, body) => {
  const header = "import { describe, expect, it, test } from 'vitest';\nimport * as vt from 'vitest';\n";
  const root = tree({ 'test/real.test.ts': passing, 'test/smuggle.test.ts': header + body + '\n' });
  expect(skippedSourceCount(root)).toBeGreaterThan(0);
});

it('TESTS-03 ordinary chains, filled tables, final returns and unrelated names are not counted', () => {
  const root = tree({ 'test/ordinary.test.ts': `import { describe, expect, it, test } from 'vitest';
type Grader = { describe: (facts: string) => string[]; test: number };
const options = { test: 1 };
describe('group', () => {
  it.each([1, 2])('case %i', n => { expect(n).toBeGreaterThan(0); });
  test.for([[1, 2]])('pair %j', ([a, b]) => { expect(a).toBeLessThan(b); });
  it.concurrent('concurrent', async () => { expect(options.test).toBe(1); });
  it('final return', () => { const value = 1; expect(value).toBe(1); return; });
  it('nested function returns early', () => { const f = (x: number) => { if (x) return 1; return 2; }; expect(f(0)).toBe(2); });
});
export type { Grader };
` });
  expect(skippedSourceFindings(root)).toEqual([]);
});

it('TESTS-03 no capability skip is allowed: the allowance is empty and every skipIf or early return counts in every file', () => {
  const skipIf = "import { it } from 'vitest';\nit.skipIf(process.platform === 'darwin')('a', () => {});\n";
  const early = "import { expect, it } from 'vitest';\nit('a', () => { if (process.platform === 'darwin') return; expect(1).toBe(1); });\n";
  expect(SOURCE_SKIP_ALLOWANCE).toEqual({});
  // The files that used to be allowed are ordinary files now (audit 1.4.0).
  for (const file of ['test/out-registry-collision.test.ts', 'test/protected-path-symlink.test.ts', 'test/registry-lock-recovery.test.ts',
    'test/cp023-acl.windows-fs.test.ts', 'test/redteam-files.test.ts', 'test/elsewhere.test.ts']) {
    expect(skippedSourceCount(tree({ [file]: skipIf })), file).toBe(1);
    expect(skippedSourceCount(tree({ [file]: early })), file).toBe(1);
  }
});
