import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { createPrivateDirectory } from '../scripts/private-scratch.mjs';

// Pre-1.4 audit, repository location preflight for scan --git-history:
// - every location is resolved link by link (lstat and readlink), so a symlink to a UNC path
//   is refused before realpath, stat or open would make a network connection;
// - include values are read exactly as git's config parser reads them;
// - nested includes resolve from the including file's path as git forms it;
// - links inside the git directory (refs, objects) are checked like any other location;
// - gitfiles are read as git reads them; ~user/ includes are refused; HOME is pinned.
// Windows-only expectations branch on the platform: elsewhere the same paths are ordinary local paths.
const windows = process.platform === 'win32';
const NOT_LOCAL = 'git history requires a repository on a local file system';
const PROTECTED = 'git history would open a protected file';
const UNREADABLE = 'git history could not be read';
const NOT_WORK_TREE = 'path is not inside a git work tree';
const HARMLESS = '[core]\n\tbare = false\n';

let scratch = '';
beforeAll(async () => {
  const parent = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(parent, { recursive: true });
  scratch = await createPrivateDirectory(parent, 'githist-location-');
});
afterAll(() => { if (scratch) rmSync(scratch, { recursive: true, force: true }); });

function git(dir: string, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
  return run.stdout.trim();
}

/** <root>/repo with one commit; <root> is a fresh directory under the private scratch root. */
function repository() {
  const root = mkdtempSync(join(scratch, 'r-'));
  const repo = join(root, 'repo');
  mkdirSync(repo);
  git(repo, 'init', '-q');
  writeFileSync(join(repo, 'README'), 'synthetic\n');
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'add');
  return { root, repo, gitDir: join(repo, '.git') };
}

/** fs/promises with the path of every location call recorded. */
function recording() {
  const calls: string[] = [];
  const wrap = <K extends 'realpath' | 'stat' | 'lstat' | 'open' | 'readlink' | 'readdir'>(name: K) =>
    (async (path: unknown, ...rest: unknown[]) => {
      calls.push(String(path));
      return (fs[name] as (...args: unknown[]) => Promise<unknown>)(path, ...rest);
    }) as unknown as typeof fs[K];
  const io = { ...fs, realpath: wrap('realpath'), stat: wrap('stat'), lstat: wrap('lstat'), open: wrap('open'),
    readlink: wrap('readlink'), readdir: wrap('readdir') } as typeof fs;
  return { io, calls };
}

const networkCalls = (calls: string[]) => calls.filter(path => /^[\\/]{2}/.test(path));

async function locate(repo: string, io?: typeof fs) {
  const { locateRepository } = await import('../src/scan/git-history.js');
  return locateRepository(repo, io ? { io } : {});
}

it('githist-audit/location a .git/config symlink to a UNC path is refused before anything touches the UNC path', async () => {
  for (const unc of ['\\\\localhost\\C$\\macwarden-unreachable\\config', '\\\\attacker.invalid\\s\\x']) {
    const { gitDir } = repository();
    const config = join(gitDir, 'config');
    renameSync(config, `${config}.orig`);
    symlinkSync(unc, config, 'file');
    const { io, calls } = recording();
    if (windows) await expect(locate(join(gitDir, '..'), io), unc).rejects.toThrow(NOT_LOCAL);
    else await expect(locate(join(gitDir, '..'), io), unc).resolves.toBeTruthy();
    // No realpath, stat, open, lstat, readlink or readdir ever received the network path.
    expect(networkCalls(calls), unc).toEqual([]);
  }
});

it('githist-audit/location links inside the git directory are checked: refs to a protected file, objects to UNC', async () => {
  // A branch ref linked to tls.key: git would read the file to resolve the ref.
  const { root, repo, gitDir } = repository();
  const key = join(root, 'lnd', 'tls.key');
  mkdirSync(dirname(key));
  writeFileSync(key, `${git(repo, 'rev-parse', 'HEAD')}\n`);
  symlinkSync(key, join(gitDir, 'refs', 'heads', 'evil'), 'file');
  const refs = recording();
  await expect(locate(repo, refs.io)).rejects.toThrow(PROTECTED);
  expect(refs.calls.some(path => /tls\.key$/i.test(path) && !path.startsWith(join(gitDir, 'refs')))).toBe(false);
  // A local, unprotected link inside the git directory is still accepted.
  rmSync(join(gitDir, 'refs', 'heads', 'evil'));
  const plain = join(root, 'plain-ref');
  writeFileSync(plain, `${git(repo, 'rev-parse', 'HEAD')}\n`);
  symlinkSync(plain, join(gitDir, 'refs', 'heads', 'linked'), 'file');
  await expect(locate(repo)).resolves.toBeTruthy();
  // The objects directory linked to a network share (elsewhere an ordinary missing local path).
  const objects = join(gitDir, 'objects');
  renameSync(objects, `${objects}.orig`);
  symlinkSync(windows ? '\\\\127.0.0.1\\C$\\macwarden-unreachable\\objects' : '//127.0.0.1/C$/macwarden-unreachable/objects',
    objects, 'dir');
  const network = recording();
  if (windows) await expect(locate(repo, network.io)).rejects.toThrow(NOT_LOCAL);
  else await expect(locate(repo, network.io)).resolves.toBeTruthy();
  expect(networkCalls(network.calls)).toEqual([]);
});

it('githist-audit/alias a link whose target text is unprotected but whose canonical name is protected is refused', async () => {
  // The file system's own aliases (a Windows 8.3 short name; see the windows-fs variant) are
  // stood in for here by a realpath that maps the alias to macaroons.db.
  const { root, repo, gitDir } = repository();
  const alias = join(root, 'MACARO~1.DB');
  const target = join(root, 'macaroons.db');
  writeFileSync(alias, `${git(repo, 'rev-parse', 'HEAD')}\n`);
  symlinkSync(alias, join(gitDir, 'refs', 'heads', 'evil'), 'file');
  const { io } = recording();
  const same = (a: string, b: string) => windows ? a.toLowerCase() === b.toLowerCase() : a === b;
  const realpath = (async (path: Parameters<typeof fs.realpath>[0]) =>
    same(String(path), alias) ? target : fs.realpath(path)) as typeof fs.realpath;
  await expect(locate(repo, { ...io, realpath } as typeof fs)).rejects.toThrow(PROTECTED);
  await expect(locate(repo)).resolves.toBeTruthy();
});

it.each([
  ['quotes joined inside the value', 'path = "wal"let.db'],
  ['# comment without whitespace', 'path = wallet.db#c'],
  ['; comment without whitespace', 'path = wallet.db;c'],
  ['line continuation', 'path = \\\nwallet.db'],
  ['quoted value with a trailing comment', 'path = "wallet.db" ; comment'],
])('githist-audit/include %s naming wallet.db is refused as git would read it', async (_shape, entry) => {
  const { gitDir } = repository();
  writeFileSync(join(gitDir, 'wallet.db'), HARMLESS);
  writeFileSync(join(gitDir, 'config'), `${readFileSync(join(gitDir, 'config'), 'utf8')}[include]\n\t${entry}\n`);
  await expect(locate(join(gitDir, '..'))).rejects.toThrow(PROTECTED);
});

it.each([
  ['quotes joined inside the value', 'path = "//attacker.invalid"/share/x'],
  ['line continuation', 'path = \\\n//attacker.invalid/share/x'],
  ['comment without whitespace', 'path = //attacker.invalid/share/x#'],
])('githist-audit/include %s naming a network path is refused on Windows', async (_shape, entry) => {
  const { gitDir } = repository();
  writeFileSync(join(gitDir, 'config'), `${readFileSync(join(gitDir, 'config'), 'utf8')}[include]\n\t${entry}\n`);
  const { io, calls } = recording();
  if (windows) await expect(locate(join(gitDir, '..'), io)).rejects.toThrow(NOT_LOCAL);
  else await expect(locate(join(gitDir, '..'), io)).resolves.toBeTruthy();
  expect(networkCalls(calls)).toEqual([]);
});

// Config shapes for the differential check: what git reads as include.path / includeIf.*.path.
const SHAPES = [
  '[include]\n\tpath = a.cfg\n',
  '[include]\n\tpath = "a b.cfg"  # trailing\n',
  '[include]\n\tpath = "wal"let.db\n',
  '[include]\n\tpath = x#y\n\tpath = x;y\n',
  '[include]\n\tpath = \\\n  cont.cfg\n',
  '[include]\n\tpath = "esc\\"q\\\\b"\n',
  '[include]\n\tpath = a\\tb\n',
  '[include]\n\tpath = "  spaced  "\n\tpath =   lead and trail   \n',
  '[include]\r\n\tpath = crlf.cfg\r\n',
  '\xef\xbb\xbf[include]\n\tpath = bom.cfg\n',
  '[INCLUDE]\n\tPATH = upper.cfg\n',
  '[include] path = same-line.cfg\n',
  '[core]\n\tbare = false\n[include]\n\tpath = after.cfg\n[core]\n\tpath = not-include.cfg\n',
  '[includeIf "gitdir:**"]\n\tpath = cond.cfg\n[includeIf "onbranch:main"]\n\tpath = branch.cfg\n',
  '[includeIf "gitdir:a\\"b"]\n\tpath = quoted-sub.cfg\n',
  '[include.x]\n\tpath = deprecated-sub.cfg\n',
  '; comment\n# comment\n[include]\n; path = commented.cfg\n\tpath=nospace.cfg\n',
  '[include]\n\tpath = "unterminated\n',
  '[include]\n\tpath = bad\\qescape\n',
  '[include]\n\tpath = esc\\e-\\a-\\f-\\v-\\r-\\0.cfg\n',
  '[include]\n\tpath = utf8-\xc3\xa9.cfg\n',
  '[include]\n\tpath = latin1-\xe9.cfg\n',
  '[include]\n\tpath = nul\x00tail.cfg\n',
  '\xef\xbb[include]\n\tpath = partial-bom.cfg\n',
  '[include\n\tpath = broken-header.cfg\n',
  '[include]\n\tpath\n',
];

it('githist-audit/include the preflight checks exactly the include paths git reads', async () => {
  const { configIncludePaths } = await import('../src/scan/git-history.js');
  const dir = mkdtempSync(join(scratch, 'shapes-'));
  const env = { PATH: process.env.PATH ?? '', SystemRoot: process.env.SystemRoot ?? '', GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CEILING_DIRECTORIES: dirname(dir), HOME: dir, LC_ALL: 'C' };
  const config = (file: string, ...args: string[]) =>
    spawnSync('git', ['config', '--file', file, '--no-includes', '--null', ...args], { cwd: dir, env, encoding: 'latin1' });
  const decode = (value: string) => Buffer.from(value, 'latin1').toString('utf8');
  for (const [index, shape] of SHAPES.entries()) {
    const file = join(dir, `c${index}.cfg`);
    writeFileSync(file, shape, 'latin1');
    const label = JSON.stringify(shape);
    // git's parser rejecting the file stops git (exit 128 or 3); so does an include with no value.
    const run = config(file, '--get-regexp', '^(include|includeif\\..*)\\.path$');
    let mine: string[] | null;
    try { mine = configIncludePaths(Buffer.from(shape, 'latin1')); } catch { mine = null; }
    if (run.status !== 0 && run.status !== 1) { expect(mine, `${label}: ${run.stderr}`).toBeNull(); continue; }
    const pairs = run.stdout.split('\0').filter(Boolean)
      .map(item => item.includes('\n') ? { key: item.slice(0, item.indexOf('\n')), value: item.slice(item.indexOf('\n') + 1) }
        : { key: item, value: null });
    if (pairs.some(pair => pair.value === null)) { expect(mine, label).toBeNull(); continue; }
    // A value that is not UTF-8 names no path macwarden can check exactly: refused (fail closed).
    const utf8 = (value: string) => Buffer.from(decode(value), 'utf8').equals(Buffer.from(value, 'latin1'));
    if (!pairs.every(pair => utf8(pair.value!))) { expect(mine, label).toBeNull(); continue; }
    expect(mine, label).toEqual(pairs.map(pair => decode(pair.value!)));
    // The include.path values are exactly what git config --get-all include.path reports.
    const all = config(file, '--get-all', 'include.path');
    expect(pairs.filter(pair => pair.key === 'include.path').map(pair => decode(pair.value!)), label)
      .toEqual(all.stdout.split('\0').filter(Boolean).map(decode));
  }
});

it('githist-audit/include a nested include resolves from the including path as git writes it, not its link target', async () => {
  // <root>/alias.cfg is a file symlink to <root>/sub/real.cfg; real.cfg includes nested.cfg,
  // which git opens next to alias.cfg (the path it formed), not next to real.cfg.
  const { root, gitDir } = repository();
  mkdirSync(join(root, 'sub'));
  writeFileSync(join(root, 'sub', 'real.cfg'), '[include]\n\tpath = nested.cfg\n');
  symlinkSync(join(root, 'sub', 'real.cfg'), join(root, 'alias.cfg'), 'file');
  writeFileSync(join(root, 'nested.cfg'), '[include]\n\tpath = wallet.db\n');
  writeFileSync(join(root, 'wallet.db'), HARMLESS);
  writeFileSync(join(gitDir, 'config'), `${readFileSync(join(gitDir, 'config'), 'utf8')}[include]\n\tpath = ${join(root, 'alias.cfg').replaceAll('\\', '/')}\n`);
  await expect(locate(join(gitDir, '..'))).rejects.toThrow(PROTECTED);
});

it('githist-audit/include `..` after a directory link follows the platform: lexical on Windows, physical elsewhere', async () => {
  const { root, gitDir } = repository();
  const other = join(root, 'other', 'deep', 'dir');
  mkdirSync(other, { recursive: true });
  writeFileSync(join(other, 'inc'), '[include]\n\tpath = ../x\n');
  symlinkSync(other, join(gitDir, 'link'), 'junction');
  // Windows opens <.git>/link/../x as <.git>/x; POSIX opens <other>/deep/x.
  writeFileSync(join(gitDir, 'x'), '[include]\n\tpath = wallet.db\n');
  writeFileSync(join(gitDir, 'wallet.db'), HARMLESS);
  writeFileSync(join(root, 'other', 'deep', 'x'), '[include]\n\tpath = seed.cfg\n');
  writeFileSync(join(root, 'other', 'deep', 'seed.cfg'), HARMLESS);
  writeFileSync(join(gitDir, 'config'), `${readFileSync(join(gitDir, 'config'), 'utf8')}[include]\n\tpath = link/inc\n`);
  // Either way the file git would open next includes a protected name.
  await expect(locate(join(gitDir, '..'))).rejects.toThrow(PROTECTED);
  // And git agrees on which file that is.
  const { gitEnvironment, PINNED_CONFIG } = await import('../src/scan/git-history.js');
  writeFileSync(join(gitDir, 'x'), '[probe]\n\tread = lexical\n');
  writeFileSync(join(root, 'other', 'deep', 'x'), '[probe]\n\tread = physical\n');
  const shown = spawnSync('git', [...PINNED_CONFIG, 'config', '--get', 'probe.read'],
    { cwd: join(gitDir, '..'), env: gitEnvironment({ gitDir, workTree: join(gitDir, '..') }), encoding: 'utf8' });
  expect(shown.stdout.trim()).toBe(windows ? 'lexical' : 'physical');
});

it('githist-audit/include ~user/ is refused and git expands ~/ from the same home directory', async () => {
  const { gitDir } = repository();
  writeFileSync(join(gitDir, 'config'), `${readFileSync(join(gitDir, 'config'), 'utf8')}[include]\n\tpath = ~nobody/x.cfg\n`);
  await expect(locate(join(gitDir, '..'))).rejects.toThrow(UNREADABLE);
  const { gitEnvironment } = await import('../src/scan/git-history.js');
  const saved = process.env.HOME;
  process.env.HOME = join(scratch, 'elsewhere');
  try {
    expect(gitEnvironment({ gitDir, workTree: join(gitDir, '..') }).HOME).toBe(homedir());
  } finally { if (saved === undefined) delete process.env.HOME; else process.env.HOME = saved; }
});

it('githist-audit/gitfile a gitfile is read as git reads it: "gitdir: " on the first line only', async () => {
  const { root, repo, gitDir } = repository();
  const moved = join(root, 'moved.git');
  renameSync(gitDir, moved);
  writeFileSync(join(repo, '.git'), `junk\ngitdir: ${moved}\n`);
  await expect(locate(repo)).rejects.toThrow(NOT_WORK_TREE);
  writeFileSync(join(repo, '.git'), `gitdir:${moved}\n`);
  await expect(locate(repo)).rejects.toThrow(NOT_WORK_TREE);
  writeFileSync(join(repo, '.git'), `gitdir: ${moved}\r\n`);
  await expect(locate(repo)).resolves.toMatchObject({ workTree: await fs.realpath(repo) });
});
