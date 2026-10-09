import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';

// scan --git-history must not follow repository locations off the local file system:
// a .git gitfile, commondir, objects/info/alternates or a config include naming a UNC
// or device path would make an offline scan open network connections (SAFE-07/08).
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const readonlyBytes = readFileSync(join(vectors, 'default-readonly.macaroon'));
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const readonlyFingerprint = manifest.vectors.find(item => item.name === 'default-readonly')!.fingerprint;
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const windows = process.platform === 'win32';
const NOT_LOCAL = 'git history requires a repository on a local file system';

function git(dir: string, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
  return run.stdout.trim();
}

/** A repository whose history holds the read-only vector in a.macaroon, deleted at HEAD. */
async function withRepo<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'git-location-'));
  try {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'a.macaroon'), readonlyBytes);
    git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'add');
    rmSync(join(dir, 'a.macaroon'));
    git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'delete');
    return await body(dir);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

async function scanJson(path: string) {
  const { main } = await import('../src/cli.js');
  const run = await captureMain(main, ['scan', path, '--git-history', '--json']);
  return { code: run.code, document: JSON.parse(run.stdout) as {
    error: { step: string; message: string } | null;
    result: { findings: { fingerprint: string; commit?: string }[]; summary: { blobsScanned?: number } } | null } };
}

function expectRefused(run: Awaited<ReturnType<typeof scanJson>>): void {
  expect(run.code).toBe(3);
  expect(run.document.error).toEqual({ code: 3, step: 'git-history', message: NOT_LOCAL });
  expect(run.document.result).toBeNull();
}

function expectFound(run: Awaited<ReturnType<typeof scanJson>>): void {
  expect(run.document.error).toBeNull();
  expect(run.document.result!.findings.map(finding => finding.fingerprint)).toContain(readonlyFingerprint);
}

it('git-history/location classifies Windows network and device paths and treats POSIX paths as local', async () => {
  const { nonLocalPath } = await import('../src/scan/git-history.js');
  const remote = ['\\\\server\\share\\repo\\.git', '//server/share/repo/.git', '\\\\127.0.0.1\\C$\\x',
    '\\\\?\\UNC\\server\\share\\x', '//?/UNC/server/share', '\\\\.\\pipe\\x', '\\\\?\\Volume{0}\\x', 'relative\\path'];
  const local = ['C:\\repo\\.git', 'c:/repo/.git', '\\\\?\\C:\\repo\\.git', '//?/D:/repo'];
  for (const path of remote) expect(nonLocalPath(path, 'win32'), path).toBe(true);
  for (const path of local) expect(nonLocalPath(path, 'win32'), path).toBe(false);
  for (const path of [...remote, ...local, '/srv/repo/.git', '//server/share']) expect(nonLocalPath(path, 'linux'), path).toBe(false);
});

it.each([
  '//127.0.0.1/C$/macwarden-unreachable/.git',
  '\\\\127.0.0.1\\C$\\macwarden-unreachable\\.git',
  '//?/UNC/127.0.0.1/C$/macwarden-unreachable/.git',
  '\\\\.\\pipe\\macwarden-unreachable',
])('git-history/location a .git gitfile naming %s is refused before any git process runs', async target => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'git-gitfile-'));
  try {
    writeFileSync(join(dir, '.git'), `gitdir: ${target}\n`);
    const started = performance.now();
    const run = await scanJson(dir);
    if (windows) {
      expectRefused(run);
      // The refusal comes from the location check, not a network timeout.
      expect(performance.now() - started).toBeLessThan(5_000);
    } else {
      // On POSIX these are ordinary local paths that do not exist.
      expect(run.code).toBe(3);
      expect(run.document.error).toEqual({ code: 3, step: 'git-history', message: 'path is not inside a git work tree' });
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('git-history/location an alternates entry or a nested alternate on a network path is refused', async () => {
  await withRepo(async dir => {
    const objects = join(dir, '.git', 'objects');
    mkdirSync(join(objects, 'info'), { recursive: true });
    writeFileSync(join(objects, 'info', 'alternates'), '//127.0.0.1/C$/macwarden-unreachable/objects\n');
    const direct = await scanJson(dir);
    if (windows) expectRefused(direct); else expectFound(direct);
    // A local alternate whose own alternates file names a network path.
    const nested = join(dir, 'nested-objects');
    mkdirSync(join(nested, 'info'), { recursive: true });
    writeFileSync(join(nested, 'info', 'alternates'), '"\\\\\\\\127.0.0.1\\\\C$\\\\objects"\n');
    writeFileSync(join(objects, 'info', 'alternates'), `${nested}\n`);
    const indirect = await scanJson(dir);
    if (windows) expectRefused(indirect); else expectFound(indirect);
    rmSync(join(objects, 'info', 'alternates'));
    expectFound(await scanJson(dir));
  });
});

it.each([
  ['include', '[include]\n\tpath = //127.0.0.1/C$/macwarden-unreachable.cfg\n'],
  ['includeIf', '[includeIf "gitdir:**"]\n\tpath = "\\\\\\\\127.0.0.1\\\\C$\\\\x.cfg"\n'],
  ['nested include', 'NESTED'],
])('git-history/location a config %s naming a network path is refused', async (_kind, section) => {
  await withRepo(async dir => {
    const config = join(dir, '.git', 'config');
    let addition = section;
    if (section === 'NESTED') {
      const local = join(dir, 'local.cfg');
      writeFileSync(local, '[include]\n\tpath = //127.0.0.1/C$/macwarden-unreachable.cfg\n');
      addition = `[include]\n\tpath = ${local.replaceAll('\\', '/')}\n`;
    }
    writeFileSync(config, `${readFileSync(config, 'utf8')}${addition}`);
    const run = await scanJson(dir);
    if (windows) expectRefused(run); else expectFound(run);
  });
});

it('git-history/location local gitfiles are followed: a linked worktree and a moved git directory', async () => {
  await withRepo(async dir => {
    const worktree = join(dir, '..', `${dir.split(/[\\/]/).pop()}-wt`);
    git(dir, 'worktree', 'add', '-q', '--detach', worktree, 'HEAD');
    try {
      const run = await scanJson(worktree);
      expectFound(run);
      expect(run.document.result!.summary.blobsScanned).toBeGreaterThan(0);
    } finally {
      git(dir, 'worktree', 'remove', '--force', worktree);
      rmSync(worktree, { recursive: true, force: true });
    }
    // The repository's own .git moved elsewhere locally, referenced by a relative gitfile.
    const moved = join(dir, 'elsewhere.git');
    renameSync(join(dir, '.git'), moved);
    writeFileSync(join(dir, '.git'), 'gitdir: elsewhere.git\n');
    expectFound(await scanJson(dir));
  });
});
