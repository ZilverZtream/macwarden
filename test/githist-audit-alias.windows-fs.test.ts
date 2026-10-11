import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { createPrivateDirectory } from '../scripts/private-scratch.mjs';

// Pre-1.4 audit verification (GITHIST-01): a link inside the git directory whose target text
// is a Windows alias of a protected file (its 8.3 short name) passes a textual check, and git
// then reads the protected file. (A trailing dot or space in a link target is not stripped:
// git cannot resolve such a ref, so those spellings are not aliases here.)
// The location check must refuse it from the target's canonical name. Windows variant of
// githist-audit/alias in test/githist-audit-location.test.ts (registered in
// scripts/platform-variants.mjs).
const PROTECTED = 'git history would open a protected file';
const system32 = (name: string) => join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', name);

let scratch = '';
beforeAll(async () => {
  const parent = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(parent, { recursive: true });
  scratch = await createPrivateDirectory(parent, 'githist-alias-');
});
afterAll(() => { if (scratch) rmSync(scratch, { recursive: true, force: true }); });

function git(dir: string, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
  return run.stdout.trim();
}

/** The 8.3 short name of `path`, giving it one (fsutil, as the CI administrator) when the volume generated none. */
function shortName(path: string): string {
  const list = () => spawnSync(system32('cmd.exe'), ['/d', '/c', 'dir', '/x', dirname(path)], { encoding: 'latin1' }).stdout;
  const find = () => new RegExp(`\\s(\\S+~\\d\\S*)\\s+${basename(path).replace('.', '\\.')}\\s*$`, 'im').exec(list())?.[1];
  let name = find();
  if (!name) {
    spawnSync(system32('fsutil.exe'), ['file', 'setshortname', path, 'MACARO~1.DB'], { encoding: 'latin1' });
    name = find();
  }
  if (!name) throw new Error(`no 8.3 short name could be read or set for ${path}; this Windows variant requires one`);
  return join(dirname(path), name);
}

/** A repository whose only reference to a credential commit is a ref linked to `target` (holding that commit's hash). */
function repositoryWithLinkedRef(target: (file: string) => string) {
  const root = mkdtempSync(join(scratch, 'r-'));
  const repo = join(root, 'repo');
  mkdirSync(repo);
  git(repo, 'init', '-q');
  writeFileSync(join(repo, 'README'), 'synthetic\n');
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'base');
  const hidden = git(repo, 'commit-tree', git(repo, 'write-tree'), '-m', 'hidden');
  const outside = join(root, 'lnd');
  mkdirSync(outside);
  const file = join(outside, 'macaroons.db');
  writeFileSync(file, `${hidden}\n`);
  symlinkSync(target(file), join(repo, '.git', 'refs', 'heads', 'evil'), 'file');
  return { repo, hidden };
}

it('githist-audit/alias-windows a ref linked to macaroons.db through its 8.3 short name is refused', async () => {
  const { repo, hidden } = repositoryWithLinkedRef(shortName);
  // git itself reads the protected file through this link.
  expect(git(repo, 'rev-parse', 'refs/heads/evil')).toBe(hidden);
  const { locateRepository } = await import('../src/scan/git-history.js');
  await expect(locateRepository(repo)).rejects.toThrow(PROTECTED);
  const { scan } = await import('../src/scan/index.js');
  await expect(scan([resolve(repo)], { gitHistory: true })).rejects.toThrow(PROTECTED);
});
