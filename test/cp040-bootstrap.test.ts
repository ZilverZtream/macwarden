import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';
import { bootstrap, type TestEnvironment } from './global-setup.js';
import { assertPrivateDirectories, createPrivateDirectory } from '../scripts/private-scratch.mjs';

it('CP-043/B4-clean-platform-suite plural private inspection accepts fresh real directories without changing contents', async () => {
  const root = await createPrivateDirectory(process.env.MACWARDEN_TEST_TMP!, 'plural-private-');
  try {
    const paths = [];
    for (const prefix of ['first-', 'second-', 'third-']) paths.push(await createPrivateDirectory(root, prefix));
    for (const path of paths) writeFileSync(join(path, 'control.txt'), 'retained control');
    await assertPrivateDirectories(paths);
    for (const path of paths) expect(readFileSync(join(path, 'control.txt'), 'utf8')).toBe('retained control');
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 30000);

it('CP-043/B4-clean-platform-suite plural private inspection refuses every unsafe member and rechecks later operations', async () => {
  const root = await createPrivateDirectory(process.env.MACWARDEN_TEST_TMP!, 'plural-refusal-');
  try {
    const first = await createPrivateDirectory(root, 'first-'), second = await createPrivateDirectory(root, 'second-');
    const file = join(root, 'file.txt'), linked = join(root, 'linked');
    writeFileSync(file, 'retained control');
    symlinkSync(second, linked, process.platform === 'win32' ? 'junction' : 'dir');
    for (const unsafe of [file, linked, join(root, 'absent')]) {
      await expect(assertPrivateDirectories([unsafe, first])).rejects.toThrow();
      await expect(assertPrivateDirectories([first, unsafe])).rejects.toThrow();
    }
    await assertPrivateDirectories([first, second]);
    if (process.platform === 'win32') {
      rmSync(second, { recursive: true });
      writeFileSync(second, 'changed directory');
    } else chmodSync(second, 0o755);
    await expect(assertPrivateDirectories([first, second])).rejects.toThrow();
    expect(readFileSync(file, 'utf8')).toBe('retained control');
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 30000);

// Global setup has already protected the caller root. Lifecycle controls use
// inherited privacy here; independent filesystem controls exercise real ACLs.
function lifecycleDirectories() {
  const owner = process.env.MACWARDEN_TEST_TMP;
  if (!owner) throw new Error('Protected caller scratch is required');
  const base = resolve('test/.tmp/runs');
  const assertInherited = (path: string) => {
    const local = relative(owner, path);
    if (!isAbsolute(path) || isAbsolute(local) || local === '..' || local.startsWith('..' + sep))
      throw new Error('Lifecycle directory must inherit caller privacy');
    for (let current = resolve(path); ; current = dirname(current)) {
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Unsafe lifecycle directory');
      if (current === resolve(owner)) break;
    }
  };
  return {
    create: vi.fn(async (parent: string, prefix: string) => {
      const backing = parent === base ? owner : parent;
      assertInherited(backing);
      return mkdtempSync(join(backing, prefix));
    }),
    assert: vi.fn(async (path: string) => { assertInherited(path); }),
  };
}

it('CP-040/A8-clean-suite clean environment receives fresh disjoint scratch and private registry roots', async () => {
  const a: TestEnvironment = {}, b: TestEnvironment = {};
  const directories = lifecycleDirectories();
  const states: Awaited<ReturnType<typeof bootstrap>>[] = [];
  let evidence!: string;
  try {
    states.push(await bootstrap(a, resolve(), directories));
    states.push(await bootstrap(b, resolve(), directories));
    evidence = join(process.env.MACWARDEN_TEST_TMP!, `caller-${basename(states[0]!.root)}.txt`);
    writeFileSync(evidence, 'preserve caller evidence');
    expect(a.MACWARDEN_TEST_TMP).not.toBe(b.MACWARDEN_TEST_TMP);
    expect(a.MACWARDEN_SENTINEL_DIR).not.toBe(a.MACWARDEN_TEST_TMP);
    expect([a.TMP, a.TEMP, a.TMPDIR]).toEqual(Array(3).fill(a.MACWARDEN_TEST_TMP));
    expect([a.HOME, a.USERPROFILE, a.APPDATA, a.XDG_CONFIG_HOME]).toEqual(Array(4).fill(a.HOME));
    expect(a.MACWARDEN_REGISTRY).toBe(join(a.HOME!, 'macwarden/registry.json'));
    expect(existsSync(a.MACWARDEN_TEST_TMP!)).toBe(true);
    expect(existsSync(a.MACWARDEN_SENTINEL_DIR!)).toBe(true);
    const roots = [a, b].flatMap(env => [env.MACWARDEN_TEST_TMP!, env.MACWARDEN_SENTINEL_DIR!, env.HOME!, env.MACWARDEN_FIXTURE_COPY_ROOT!]);
    expect(new Set(roots).size).toBe(8);
    for (const env of [a, b]) {
      const disjoint = [env.MACWARDEN_TEST_TMP!, env.MACWARDEN_SENTINEL_DIR!, env.MACWARDEN_FIXTURE_COPY_ROOT!];
      for (const left of disjoint) for (const right of disjoint.filter(path => path !== left)) {
        const local = relative(left, right);
        expect(isAbsolute(local) || local === '..' || local.startsWith('..' + sep)).toBe(true);
      }
      expect(dirname(env.HOME!)).toBe(env.MACWARDEN_TEST_TMP);
    }
    expect(directories.create.mock.calls).toEqual([a, b].flatMap((env, index) => [
      [resolve('test/.tmp/runs'), 'run-'], [states[index]!.root, 'tmp-'],
      [states[index]!.root, 'sentinels-'], [env.MACWARDEN_TEST_TMP!, 'config-'],
      [states[index]!.root, 'fixture-root-'],
    ]));
    expect(directories.assert.mock.calls).toEqual([a, b].flatMap(env => [
      [env.MACWARDEN_TEST_TMP!], [env.MACWARDEN_SENTINEL_DIR!], [env.MACWARDEN_FIXTURE_COPY_ROOT!],
    ]));
  } finally { for (const state of states) state.teardown(); }
  expect(states.map(state => existsSync(state.root))).toEqual([false, false]);
  expect(readFileSync(evidence, 'utf8')).toBe('preserve caller evidence');
  expect(existsSync(process.env.MACWARDEN_SENTINEL_DIR!)).toBe(true);
}, 30000);

it('CP-040/A8-clean-suite runner-provided private roots and their contents survive teardown', async () => {
  const base = process.env.MACWARDEN_TEST_TMP ?? resolve('test/.scratch-cp040');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const root = await createPrivateDirectory(base, 'preserved-');
  const tmp = await createPrivateDirectory(root, 'tmp-'), sentinel = await createPrivateDirectory(root, 'sentinels-');
  writeFileSync(join(tmp, 'evidence.txt'), 'preserve');
  const env = { MACWARDEN_TEST_TMP: tmp, MACWARDEN_SENTINEL_DIR: sentinel };
  const state = await bootstrap(env); state.teardown();
  expect(env.MACWARDEN_TEST_TMP).toBe(tmp); expect(env.MACWARDEN_SENTINEL_DIR).toBe(sentinel);
  expect(readFileSync(join(tmp, 'evidence.txt'), 'utf8')).toBe('preserve');
  rmSync(root, { recursive: true, force: true });
}, 30000);

it('CP-040/B11-meaningful-tests bootstrap removes host online credentials and diagnostic configuration', async () => {
  const env: TestEnvironment = { MACWARDEN_LND_REST: 'host.invalid:1', MACWARDEN_MACAROON: 'host-path',
    MACWARDEN_TLS_CERT: 'host-cert', NODE_OPTIONS: '--inspect', NODE_DEBUG: 'https',
    MACWARDEN_FIXTURE_DIR: 'stale-copy-path', MACWARDEN_CP038_FIXTURE_TURN: 'exclusive',
    MACWARDEN_CP039_FIXTURE_EXCLUSIVE: '1' };
  const directories = lifecycleDirectories();
  const state = await bootstrap(env, resolve(), directories);
  try {
    expect([env.MACWARDEN_LND_REST, env.MACWARDEN_MACAROON, env.MACWARDEN_TLS_CERT]).toEqual([undefined, undefined, undefined]);
    expect([env.NODE_OPTIONS, env.NODE_DEBUG]).toEqual(['', '']);
    expect([env.MACWARDEN_FIXTURE_DIR, env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE]).toEqual([undefined, undefined, undefined]);
    expect(directories.create).toHaveBeenCalledTimes(5);
    expect(directories.assert).toHaveBeenCalledTimes(3);
  } finally { state.teardown(); }
  expect(existsSync(state.root)).toBe(false);
}, 30000);

it('CP-040/A8-clean-suite overlapping caller roots fail without removing caller evidence', async () => {
  const path = process.env.MACWARDEN_TEST_TMP ?? resolve('test/.scratch-cp040');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  await expect(bootstrap({ MACWARDEN_TEST_TMP: path, MACWARDEN_SENTINEL_DIR: path })).rejects.toThrow('must be disjoint');
  expect(existsSync(path)).toBe(true);
}, 30000);

it('CP-040/A10-evidence-integrity oracle teardown waits for startup and failed validation to settle', async () => {
  // Ordinary files retain the caller's fixture. These three existing files
  // regenerate root keys and replace wallet/container configuration.
  for (const file of ['cp024-bake.test.ts', 'cp015-facts.test.ts', 'cp020-inventory.test.ts', 'cp033-guide.test.ts']) {
    const resets = file !== 'cp024-bake.test.ts';
    const events: string[] = [];
    let finishUp!: () => void, failValidation!: (error: Error) => void;
    let enteredUp!: () => void, enteredValidation!: () => void;
    const up = new Promise<void>(resolve => { finishUp = resolve; });
    const validation = new Promise<void>((_resolve, reject) => { failValidation = reject; });
    void validation.catch(() => {});
    const upStarted = new Promise<void>(resolve => { enteredUp = resolve; });
    const validationStarted = new Promise<void>(resolve => { enteredValidation = resolve; });
    let start!: (context: object, suite: { file: { filepath: string } }) => Promise<void>, stop!: () => Promise<void>;
    let startupTimeout: number | undefined, teardownTimeout: number | undefined, preparationTimeout: number | undefined;
    let validations = 0;
    const resetFailure = new Error('disposable reset validation failure');
    const create = vi.fn(() => ({
      up: async () => { events.push('up'); enteredUp(); await up; events.push('up settled'); },
      down: async () => { events.push('down'); },
    }));
    vi.resetModules();
    vi.doMock('vitest', () => ({
      beforeAll: (hook: typeof start, timeout?: number) => { start = hook; startupTimeout = timeout; },
      beforeEach: (_hook: unknown, timeout?: number) => { preparationTimeout = timeout; },
      afterAll: (hook: () => Promise<void>, timeout?: number) => { stop = hook; teardownTimeout = timeout; },
    }));
    vi.doMock('./fixture/fixture.mjs', () => ({ createFixture: create }));
    vi.doMock('./helpers/fixture-copies.js', () => ({
      prepareFixtureTurn: async () => {
        if (++validations > 1) {
          events.push('reset validation');
          if (file === 'cp015-facts.test.ts') throw resetFailure;
          return;
        }
        events.push('validation'); enteredValidation();
        try { await validation; } finally { events.push('validation settled'); }
      },
      clearFixtureTurn: () => { events.push('clear'); },
    }));
    let setupResult: Promise<unknown> | undefined, teardownResult: Promise<unknown> | undefined;
    const failure = new Error('disposable validation failure');
    try {
      await import('./oracle/setup.js');
      // Both hooks inherit the oracle project's complete 180000 ms budget.
      expect([startupTimeout, teardownTimeout]).toEqual([undefined, undefined]);
      expect(preparationTimeout).toBe(60000);
      setupResult = start({}, { file: { filepath: resolve('test/oracle', file) } }).catch((error: unknown) => error);
      await validationStarted;
      expect(create).toHaveBeenCalledTimes(resets ? 1 : 0);
      teardownResult = stop().catch((error: unknown) => error);
      await Promise.resolve();
      expect(events).toEqual(['validation']);
      failValidation(failure);
      expect(await setupResult).toBe(failure);
      if (resets) {
        await upStarted;
        expect(events).toEqual(['validation', 'validation settled', 'up']);
        finishUp();
        expect(await teardownResult).toBe(file === 'cp015-facts.test.ts' ? resetFailure : undefined);
        expect(events).toEqual(['validation', 'validation settled', 'up', 'up settled', 'reset validation', 'clear']);
      } else {
        expect(await teardownResult).toBeUndefined();
        expect(events).toEqual(['validation', 'validation settled', 'clear']);
      }
      expect(validations).toBe(resets ? 2 : 1);
    } finally {
      finishUp(); failValidation(failure);
      await setupResult; await teardownResult;
      vi.doUnmock('vitest');
      vi.doUnmock('./fixture/fixture.mjs');
      vi.doUnmock('./helpers/fixture-copies.js');
      vi.resetModules();
    }
  }
}, 30000);
