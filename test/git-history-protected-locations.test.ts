import * as childProcess from 'node:child_process';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

// MW110-03: repository-location preflight (gitfile, commondir, alternates, config
// include/includeIf targets) must apply SAFE-02 to every location it would read: the
// supplied path, each directory component and the resolved target. A protected location
// refuses the whole history operation (exit 3, step git-history) before its content is
// opened and before any git process starts, because git would read the same include.
// The protected files here hold only harmless valid git configuration.
vi.mock('node:child_process', async original => {
  const actual = await original<typeof import('node:child_process')>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const PROTECTED = 'git history would open a protected file';
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const HARMLESS = '[core]\n\tbare = false\n';
const roots: string[] = [];
afterEach(() => { for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true }); });

/** A minimal repository layout (no git needed): <root>/repo/.git with an empty config. */
function layout() {
  mkdirSync(testTmp, { recursive: true });
  const root = realpathSync(mkdtempSync(join(testTmp, 'git-protected-')));
  roots.push(root);
  const repo = join(root, 'repo');
  const gitDir = join(repo, '.git');
  mkdirSync(join(gitDir, 'objects', 'info'), { recursive: true });
  writeFileSync(join(gitDir, 'config'), '[core]\n\trepositoryformatversion = 0\n');
  return { root, repo, gitDir };
}

/** fs/promises with every open and readFile recorded by resolved path. */
function recording(overrides: Partial<typeof fs> = {}) {
  const opened: string[] = [];
  const io = {
    ...fs,
    ...overrides,
    open: (async (path: Parameters<typeof fs.open>[0], ...rest: unknown[]) => {
      opened.push(resolve(String(path)));
      return (fs.open as (...args: unknown[]) => ReturnType<typeof fs.open>)(path, ...rest);
    }) as typeof fs.open,
    readFile: (async (path: Parameters<typeof fs.readFile>[0], ...rest: unknown[]) => {
      opened.push(resolve(String(path)));
      return (fs.readFile as (...args: unknown[]) => ReturnType<typeof fs.readFile>)(path, ...rest);
    }) as typeof fs.readFile,
  } as typeof fs;
  return { io, opened };
}

const same = (a: string, b: string) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;

async function expectRefused(repo: string, protectedFile: string, io = recording()) {
  const { locateRepository } = await import('../src/scan/git-history.js');
  await expect(locateRepository(repo, { io: io.io })).rejects.toThrow(PROTECTED);
  // Zero opens of the protected file, by any path that resolves to it.
  const real = await fs.realpath(protectedFile).catch(() => resolve(protectedFile));
  for (const path of io.opened) {
    expect(same(path, resolve(protectedFile)), path).toBe(false);
    expect(same(await fs.realpath(path).catch(() => path), real), path).toBe(false);
  }
  return io;
}

const appendConfig = (gitDir: string, text: string) =>
  writeFileSync(join(gitDir, 'config'), `${readFileSync(join(gitDir, 'config'), 'utf8')}${text}`);

it.each([
  ['wallet.db'], ['tls.key'], ['seed.json'],
])('git-history/protected a config include of ../../%s (relative) is refused without opening it', async name => {
  const { root, repo, gitDir } = layout();
  const target = join(root, name);
  writeFileSync(target, HARMLESS);
  appendConfig(gitDir, `[include]\n\tpath = ../../${name}\n`);
  const { opened } = await expectRefused(repo, target);
  // The config itself was read through a descriptor; the protected target never was.
  expect(opened.some(path => same(path, join(gitDir, 'config')))).toBe(true);
});

it('git-history/protected an absolute includeIf path to wallet.db is refused without opening it', async () => {
  const { root, repo, gitDir } = layout();
  const target = join(root, 'wallet.db');
  writeFileSync(target, HARMLESS);
  appendConfig(gitDir, `[includeIf "gitdir:**"]\n\tpath = "${target.replaceAll('\\', '/')}"\n`);
  await expectRefused(repo, target);
});

it('git-history/protected an include through a protected directory component is refused', async () => {
  const { root, repo, gitDir } = layout();
  mkdirSync(join(root, 'seed'));
  const target = join(root, 'seed', 'extra.cfg');
  writeFileSync(target, HARMLESS);
  appendConfig(gitDir, '[include]\n\tpath = ../../seed/extra.cfg\n');
  await expectRefused(repo, target);
});

it('git-history/protected an include of a protected name that does not exist is still refused', async () => {
  const { repo, gitDir } = layout();
  appendConfig(gitDir, '[include]\n\tpath = ../../macaroons.db\n');
  await expectRefused(repo, join(repo, '..', 'macaroons.db'));
});

it('git-history/protected an include whose resolved target is wallet.db (a symlink alias) is refused', async () => {
  const { root, repo, gitDir } = layout();
  const target = join(root, 'wallet.db');
  writeFileSync(target, HARMLESS);
  const alias = join(root, 'alias.cfg');
  writeFileSync(alias, HARMLESS);
  appendConfig(gitDir, '[include]\n\tpath = ../../alias.cfg\n');
  // alias.cfg resolves to wallet.db, as a file symlink would make realpath report.
  const realpath = (async (path: Parameters<typeof fs.realpath>[0]) =>
    same(resolve(String(path)), alias) ? target : fs.realpath(path)) as typeof fs.realpath;
  await expectRefused(repo, target, recording({ realpath }));
});

it('git-history/protected an include through a directory link to a protected directory is refused', async () => {
  const { root, repo, gitDir } = layout();
  mkdirSync(join(root, 'seed'));
  const target = join(root, 'seed', 'extra.cfg');
  writeFileSync(target, HARMLESS);
  // A junction on Windows (no privilege needed), a directory symlink elsewhere.
  symlinkSync(join(root, 'seed'), join(root, 'plain'), 'junction');
  appendConfig(gitDir, '[include]\n\tpath = ../../plain/extra.cfg\n');
  await expectRefused(repo, target);
});

it('git-history/protected a nested include reaching tls.key is refused', async () => {
  const { root, repo, gitDir } = layout();
  const target = join(root, 'tls.key');
  writeFileSync(target, HARMLESS);
  writeFileSync(join(root, 'middle.cfg'), '[include]\n\tpath = tls.key\n');
  appendConfig(gitDir, '[include]\n\tpath = ../../middle.cfg\n');
  await expectRefused(repo, target);
});

it('git-history/protected a config.worktree include of wallet.db is refused', async () => {
  const { root, repo, gitDir } = layout();
  const target = join(root, 'wallet.db');
  writeFileSync(target, HARMLESS);
  writeFileSync(join(gitDir, 'config.worktree'), '[include]\n\tpath = ../../wallet.db\n');
  await expectRefused(repo, target);
});

it('git-history/protected an alternates entry under a protected directory is refused', async () => {
  const { root, repo, gitDir } = layout();
  const objects = join(root, 'seed', 'objects');
  mkdirSync(join(objects, 'info'), { recursive: true });
  const target = join(objects, 'info', 'alternates');
  writeFileSync(target, '');
  writeFileSync(join(gitDir, 'objects', 'info', 'alternates'), `${objects}\n`);
  await expectRefused(repo, target);
});

it('git-history/protected a gitfile naming a protected git directory is refused before it is read', async () => {
  const { root, repo, gitDir } = layout();
  const moved = join(root, 'wallet.db');
  await fs.rename(gitDir, moved);
  writeFileSync(join(repo, '.git'), `gitdir: ${moved}\n`);
  await expectRefused(repo, join(moved, 'config'));
});

it('git-history/protected a gitfile that is itself protected by a directory component is refused unread', async () => {
  const { root } = layout();
  const repo = join(root, 'seed');
  mkdirSync(repo);
  writeFileSync(join(repo, '.git'), 'gitdir: ../repo/.git\n');
  await expectRefused(repo, join(repo, '.git'));
});

it('git-history/protected a commondir naming a protected directory is refused', async () => {
  const { root, repo, gitDir } = layout();
  const common = join(root, 'wallet.db');
  mkdirSync(join(common, 'objects', 'info'), { recursive: true });
  writeFileSync(join(common, 'config'), HARMLESS);
  writeFileSync(join(gitDir, 'commondir'), '../../wallet.db\n');
  await expectRefused(repo, join(common, 'config'));
});

it('git-history/protected ordinary includes and alternates are still accepted', async () => {
  const { root, repo, gitDir } = layout();
  writeFileSync(join(root, 'shared.cfg'), HARMLESS);
  appendConfig(gitDir, '[include]\n\tpath = ../../shared.cfg\n');
  const { locateRepository } = await import('../src/scan/git-history.js');
  const stats: Record<string, number> = {};
  const located = await locateRepository(repo, { stats });
  expect(located.workTree).toBe(repo);
  expect(stats.bytes).toBe(Buffer.byteLength(readFileSync(join(gitDir, 'config'))) + Buffer.byteLength(HARMLESS));
});

it('git-history/protected the CLI refuses with exit 3 before any git process starts', async () => {
  const { root, repo, gitDir } = layout();
  writeFileSync(join(root, 'wallet.db'), HARMLESS);
  appendConfig(gitDir, '[include]\n\tpath = ../../wallet.db\n');
  const spawn = vi.mocked(childProcess.spawn);
  spawn.mockClear();
  const { main } = await import('../src/cli.js');
  const run = await captureMain(main, ['scan', repo, '--git-history', '--json']);
  expect(run.code).toBe(3);
  const document = JSON.parse(run.stdout) as { error: unknown; result: unknown };
  expect(document.error).toEqual({ code: 3, step: 'git-history', message: PROTECTED });
  expect(document.result).toBeNull();
  expect(spawn).not.toHaveBeenCalled();
});
