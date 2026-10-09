import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import type { TestEnvironment } from '../global-setup.js';
import { clearFixtureTurn, fixtureCopies, inside, prepareFixtureTurn } from '../helpers/fixture-copies.js';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';

// Per-test regtest fixture copies: private ownership, sentinel registration and cleanup.
const repo = resolve();
const scratch = process.env.MACWARDEN_TEST_TMP;
const sentinels = process.env.MACWARDEN_SENTINEL_DIR;
if (!scratch || !sentinels) throw new Error('Private control scratch and sentinels are required');

it('CP-040/A8-clean-suite copy roots satisfy legacy consumers with external scratch and clean ownership initialization', async () => {
  // Reuse the caller's private scratch and bootstrap-owned copy root. The
  // standing scan reads this exact scratch root's output manifest.
  const owner = process.env.MACWARDEN_FIXTURE_COPY_ROOT;
  if (!owner) throw new Error('Protected bootstrap copy owner is required');
  // These children inherit the already-verified outer ACLs. Source snapshots
  // remain under actual outer SENT, and retained copies under the copy owner.
  const env: TestEnvironment = { MACWARDEN_TEST_TMP: scratch,
    MACWARDEN_SENTINEL_DIR: mkdtempSync(join(sentinels!, 'copy-sources-')),
    MACWARDEN_FIXTURE_COPY_ROOT: mkdtempSync(join(owner, 'lifecycle-')) };
  const assertInherited = (path: string) => {
    const backing = [scratch!, sentinels!, owner].find(root => inside(root, path));
    if (!isAbsolute(path) || !backing) throw new Error('Copy control must inherit caller privacy');
    for (let current = resolve(path); ; current = dirname(current)) {
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Unsafe copy control directory');
      if (current === resolve(backing)) break;
    }
  };
  const directories = {
    create: vi.fn(async (parent: string, prefix: string) => {
      assertInherited(parent);
      return mkdtempSync(join(parent, prefix));
    }),
    assert: vi.fn(async (path: string) => { assertInherited(path); }),
    assertMany: vi.fn(async (paths: string[]) => { for (const path of paths) assertInherited(path); }),
  };
  const prepare = (validate: () => void, read: (name: 'tls.cert' | 'admin.macaroon') => Buffer) =>
    prepareFixtureTurn(env, validate, read, repo, directories);
  const copies = () => fixtureCopies(env, repo, directories);
  const evidence = join(scratch!, `caller-${basename(env.MACWARDEN_FIXTURE_COPY_ROOT!)}.txt`);
  writeFileSync(evidence, 'preserve caller evidence');
  const manifest = join(scratch!, 'declared-out.txt');
  const declared = () => existsSync(manifest) ? readFileSync(manifest, 'utf8').split(/\r?\n/).filter(Boolean) : [];
  const priorDeclarations = declared().length;
  try {
    // Source snapshots stay in a unique subtree of the actual outer corpus.
    const read = (name: 'tls.cert' | 'admin.macaroon') => name === 'tls.cert' ? Buffer.from('disposable certificate') : readFileSync(join(repo, 'test/sentinels/sentinel.macaroon'));
    let validations = 0;
    const validate = () => {
      expect([env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE, env.MACWARDEN_FIXTURE_DIR]).toEqual([undefined, undefined, undefined]);
      validations++;
    };
    await prepare(validate, read);
    const first = await copies();
    expect(inside(repo, first)).toBe(true);
    const local = relative(join(repo, 'test'), first);
    expect(Boolean(local) && !isAbsolute(local) && !local.startsWith('..')).toBe(true);
    for (const root of [env.MACWARDEN_TEST_TMP!, env.MACWARDEN_SENTINEL_DIR!])
      expect(inside(root, first) || inside(first, root)).toBe(false);
    expect([env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE]).toEqual(['exclusive', '1']);
    expect(readFileSync(join(first, 'admin.macaroon')).equals(readFileSync(join(env.MACWARDEN_TEST_TMP!, 'macwarden-fixture/admin.macaroon')))).toBe(true);
    await prepare(validate, read);
    const second = await copies();
    expect(second).not.toBe(first);
    expect(directories.assertMany.mock.calls).toEqual(Array.from({ length: 4 }, () => [[
      env.MACWARDEN_FIXTURE_COPY_ROOT!, env.MACWARDEN_TEST_TMP!, env.MACWARDEN_SENTINEL_DIR!,
    ]]));
    expect(directories.assert.mock.calls).toEqual([
      [join(scratch!, 'macwarden-fixture')], [first], [first],
      [join(scratch!, 'macwarden-fixture')], [second], [second],
    ]);
    expect(validations).toBe(2);
    expect(readdirSync(env.MACWARDEN_SENTINEL_DIR!).length).toBe(2);
    expect(directories.create.mock.calls.filter(call => call[0] === env.MACWARDEN_FIXTURE_COPY_ROOT && call[1] === 'copies-')).toHaveLength(2);
    for (const directory of [first, second]) {
      expect(readFileSync(join(directory, 'admin.macaroon')).equals(read('admin.macaroon'))).toBe(true);
      expect(readFileSync(join(env.MACWARDEN_SENTINEL_DIR!, `${basename(directory)}.macaroon`)).equals(read('admin.macaroon'))).toBe(true);
      expect(directories.assert).toHaveBeenCalledWith(directory);
    }
    // Other workers may append unrelated declarations to the outer manifest.
    // Keep exact ordering and counts for this turn's copy/source roots and alias.
    expect(declared().slice(priorDeclarations).filter(path =>
      path === join(scratch!, 'macwarden-fixture/admin.macaroon') ||
      [first, second, env.MACWARDEN_SENTINEL_DIR!].some(directory => inside(directory, path)),
    )).toEqual([first, second].flatMap(directory => [
      join(directory, 'admin.macaroon'), join(scratch!, 'macwarden-fixture/admin.macaroon'),
      join(env.MACWARDEN_SENTINEL_DIR!, `${basename(directory)}.macaroon`),
    ]));
    const createdBeforeInvalid = directories.create.mock.calls.length;
    const refusedRead = vi.fn(read);
    directories.assertMany.mockImplementationOnce(async () => { throw new Error('disposable root privacy refusal'); });
    await expect(prepare(validate, refusedRead)).rejects.toThrow('disposable root privacy refusal');
    expect(refusedRead).not.toHaveBeenCalled();
    expect(validations).toBe(2);
    expect(directories.create).toHaveBeenCalledTimes(createdBeforeInvalid);
    expect([env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE, env.MACWARDEN_FIXTURE_DIR]).toEqual([undefined, undefined, undefined]);
    await expect(prepare(() => { throw new FixtureInvalidError('disposable invalid fixture'); }, read)).rejects.toThrow('disposable invalid fixture');
    expect(directories.create).toHaveBeenCalledTimes(createdBeforeInvalid);
    expect([env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE, env.MACWARDEN_FIXTURE_DIR]).toEqual([undefined, undefined, undefined]);
    await expect(prepare(validate, () => { throw new Error('disposable copy failure'); })).rejects.toThrow('disposable copy failure');
    expect([env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE, env.MACWARDEN_FIXTURE_DIR]).toEqual([undefined, undefined, undefined]);
    env.MACWARDEN_FIXTURE_DIR = join(env.MACWARDEN_TEST_TMP!, 'macwarden-fixture');
    await expect(copies()).rejects.toThrow('bootstrap-owned');
    const linked = join(env.MACWARDEN_FIXTURE_COPY_ROOT!, 'linked-copies');
    symlinkSync(first, linked, process.platform === 'win32' ? 'junction' : 'dir');
    env.MACWARDEN_FIXTURE_DIR = linked;
    await expect(copies()).rejects.toThrow('Unsafe copy control directory');
    clearFixtureTurn(env);
    expect([env.MACWARDEN_CP038_FIXTURE_TURN, env.MACWARDEN_CP039_FIXTURE_EXCLUSIVE, env.MACWARDEN_FIXTURE_DIR]).toEqual([undefined, undefined, undefined]);
    expect([first, second].map(directory => existsSync(join(directory, 'admin.macaroon')))).toEqual([true, true]);
    expect(readFileSync(evidence, 'utf8')).toBe('preserve caller evidence');
  } finally { clearFixtureTurn(env); }
}, 60000);
