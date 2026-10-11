import { spawnSync } from 'node:child_process';
import { copyFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { createPrivateDirectory } from '../scripts/private-scratch.mjs';

// Pre-1.4 audit, what scan --git-history lists and how it reports it:
// - a file argument spelled in another case still selects the committed file's history;
// - tags naming a blob or tree, and older stash entries, are scanned;
// - the commit table holds only commits that added something; path bytes are bounded;
// - git is found only through absolute PATH entries, never in the scanned directory;
// - committed names with '\', '..' or ':' stay below the argument (Windows);
// - paths that are not UTF-8 stay distinct.
const windows = process.platform === 'win32';
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const fingerprint = (name: string) => manifest.vectors.find(item => item.name === name)!.fingerprint;
const vector = (name: string) => readFileSync(join(vectors, `${name}.macaroon`));
const hexLine = (name: string) => `TOKEN=${vector(name).toString('hex')}\n`;

let scratch = '';
beforeAll(async () => {
  const parent = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(parent, { recursive: true });
  scratch = await createPrivateDirectory(parent, 'githist-history-');
});
afterAll(() => { if (scratch) rmSync(scratch, { recursive: true, force: true }); });

function run(dir: string, args: string[], input?: string | Buffer): string {
  const result = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, input });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr}`);
  return result.stdout.toString('utf8').trim();
}
const git = (dir: string, ...args: string[]) => run(dir, args);
function commit(dir: string, message: string): string {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '--allow-empty', '-m', message);
  return git(dir, 'rev-parse', 'HEAD');
}
function repository(): string {
  const dir = mkdtempSync(join(scratch, 'r-'));
  git(dir, 'init', '-q');
  return dir;
}
/** A commit whose tree holds `entries` exactly as given (names as raw bytes), on refs/heads/main. */
function rawCommit(dir: string, entries: { name: Buffer; content: string }[]): string {
  const sorted = entries.map(entry => ({ ...entry, blob: run(dir, ['hash-object', '-w', '--stdin'], entry.content) }))
    .sort((a, b) => Buffer.compare(a.name, b.name));
  const tree = run(dir, ['hash-object', '-w', '-t', 'tree', '--literally', '--stdin'], Buffer.concat(sorted.map(entry =>
    Buffer.concat([Buffer.from('100644 '), entry.name, Buffer.from([0]), Buffer.from(entry.blob, 'hex')]))));
  const hash = git(dir, 'commit-tree', tree, '-m', 'raw');
  git(dir, 'update-ref', 'refs/heads/main', hash);
  return hash;
}

type Result = { findings: { path: string; fingerprint: string; commit?: string }[]; skipped: { path: string; reason: string }[] };
async function scan(path: string): Promise<Result> {
  const { scan: scanPaths } = await import('../src/scan/index.js');
  return await scanPaths([path], { gitHistory: true }) as Result;
}
async function table(dir: string, pathspec: string[] = [], limits = {}) {
  const { historyEntries, locateRepository, resolveGit } = await import('../src/scan/git-history.js');
  return historyEntries(await resolveGit(), dir, await locateRepository(dir), pathspec, limits);
}

it('githist-audit/pathspec a file argument in another case scans the committed file on a case-insensitive file system', async () => {
  const dir = repository();
  writeFileSync(join(dir, 'Admin.env'), hexLine('default-admin'));
  commit(dir, 'add');
  writeFileSync(join(dir, 'Admin.env'), 'TOKEN=removed\n');
  commit(dir, 'scrub');
  // Selected by what the file system does with the other spelling, not by platform name.
  const argument = existsSync(join(dir, 'admin.env')) ? join(dir, 'admin.env') : join(dir, 'Admin.env');
  const result = await scan(argument);
  expect(result.findings.map(finding => finding.fingerprint)).toEqual([fingerprint('default-admin')]);
  // Reported under the argument as given, like the walk reports the file.
  expect(result.findings[0].path).toBe(argument.replaceAll('\\', '/'));
  expect(result.findings[0].commit).toMatch(/^[0-9a-f]{40,64}$/);
});

it('githist-audit/refs a tag naming a blob or a tree, and an older stash entry, are scanned', async () => {
  const dir = repository();
  writeFileSync(join(dir, 'x.txt'), 'x\n');
  commit(dir, 'base');
  // A *.macaroon blob named only by a lightweight and an annotated tag.
  writeFileSync(join(dir, 'tmp.macaroon'), vector('default-admin'));
  const blob = git(dir, 'hash-object', '-w', 'tmp.macaroon');
  rmSync(join(dir, 'tmp.macaroon'));
  git(dir, 'tag', 'blobtag', blob);
  git(dir, 'tag', '-a', '-m', 'm', 'annotated-blob', blob);
  // A tree holding a credential, named only by a tag.
  writeFileSync(join(dir, 'y.env'), hexLine('default-readonly'));
  git(dir, 'add', 'y.env');
  const tree = git(dir, 'write-tree');
  git(dir, 'rm', '-q', '--cached', 'y.env');
  rmSync(join(dir, 'y.env'));
  git(dir, 'tag', 'treetag', tree);
  const tagged = await scan(dir);
  const found = new Set(tagged.findings.map(finding => finding.fingerprint));
  expect(found.has(fingerprint('default-admin')), JSON.stringify(tagged)).toBe(true);
  expect(found.has(fingerprint('default-readonly')), JSON.stringify(tagged)).toBe(true);
  expect(tagged.findings.find(finding => finding.fingerprint === fingerprint('default-readonly'))!.path).toMatch(/\/y\.env$/);

  // Two stashes: the credential is only in the older one (stash@{1}).
  const stashed = repository();
  writeFileSync(join(stashed, 'base.txt'), 'x\n');
  commit(stashed, 'base');
  writeFileSync(join(stashed, 'base.txt'), hexLine('default-readonly'));
  git(stashed, 'stash', '-q');
  writeFileSync(join(stashed, 'base.txt'), 'other\n');
  git(stashed, 'stash', '-q');
  const result = await scan(stashed);
  expect(result.findings.map(finding => finding.fingerprint)).toContain(fingerprint('default-readonly'));
});

it('githist-audit/table only commits that added an entry are kept', async () => {
  const dir = repository();
  for (let index = 0; index < 40; index++) git(dir, 'commit', '-q', '--allow-empty', '-m', `empty ${index}`);
  writeFileSync(join(dir, 'a.txt'), 'a\n');
  const added = commit(dir, 'add');
  const listed = await table(dir);
  expect(listed.length).toBe(1);
  expect(listed.commits).toEqual([added]);
});

it('githist-audit/table path bytes and path length are bounded, failing as too large to scan', async () => {
  const dir = repository();
  writeFileSync(join(dir, 'a-long-enough-name.txt'), 'a\n');
  writeFileSync(join(dir, 'another-long-name.txt'), 'b\n');
  commit(dir, 'add');
  await expect(table(dir, [], { pathBytes: 30 })).rejects.toThrow('git history is too large to scan (more than 30 bytes of paths)');
  await expect(table(dir, [], { tokenBytes: 16 })).rejects.toThrow(/^git history is too large to scan \(a path or line longer than 16 bytes\)$/);
  await expect(table(dir)).resolves.toMatchObject({ length: 2 });
});

it('githist-audit/git a git program in the scanned directory never runs, even with a relative PATH entry', async () => {
  const { resolveGit, gitEnvironment } = await import('../src/scan/git-history.js');
  const dir = repository();
  writeFileSync(join(dir, 'a.env'), hexLine('default-readonly'));
  commit(dir, 'add');
  rmSync(join(dir, 'a.env'));
  commit(dir, 'remove');
  // A planted program that fails whatever it is asked: if it ran, the history scan would fail.
  if (windows) copyFileSync(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe'), join(dir, 'git.exe'));
  else { writeFileSync(join(dir, 'git'), '#!/bin/sh\nexit 7\n'); chmodSync(join(dir, 'git'), 0o755); }
  const saved = process.env.PATH;
  process.env.PATH = ['.', '', 'relative-bin', saved ?? ''].join(delimiter);
  try {
    const result = await scan(dir);
    expect(result.findings.map(finding => finding.fingerprint)).toEqual([fingerprint('default-readonly')]);
    expect(await resolveGit()).toMatch(windows ? /^[A-Za-z]:\\.*\\git\.exe$/i : /^\/.*\/git$/);
    const env = gitEnvironment({ gitDir: join(dir, '.git'), workTree: dir });
    expect(env.PATH!.split(delimiter).every(entry => windows ? /^[A-Za-z]:[\\/]/.test(entry) : entry.startsWith('/'))).toBe(true);
  } finally { process.env.PATH = saved; }
  await expect(resolveGit(['.', 'bin'].join(delimiter))).rejects.toThrow('git history requires git on PATH');
});

it('githist-audit/paths committed names with backslashes, `..` or a colon stay below the argument', async () => {
  const dir = repository();
  rawCommit(dir, [
    { name: Buffer.from('a\\..\\..\\elsewhere\\x.env'), content: hexLine('default-readonly') },
    { name: Buffer.from('node_modules\\y.env'), content: hexLine('default-admin') },
  ]);
  const result = await scan(dir);
  const root = dir.replaceAll('\\', '/');
  for (const finding of result.findings) expect(finding.path.startsWith(`${root}/`), finding.path).toBe(true);
  for (const item of result.skipped) expect(item.path.startsWith(`${root}/`), item.path).toBe(true);
  expect(result.findings.map(finding => finding.fingerprint)).toContain(fingerprint('default-readonly'));
  if (windows) {
    // On Windows '\' separates names, so node_modules\y.env is in an excluded directory.
    expect(result.skipped).toContainEqual({ path: `${root}/node_modules`, reason: 'excluded-dir' });
    expect(result.findings.map(finding => finding.fingerprint)).not.toContain(fingerprint('default-admin'));
  } else expect(result.findings.map(finding => finding.fingerprint)).toContain(fingerprint('default-admin'));
});

it('githist-audit/paths names that are not UTF-8 stay distinct paths', async () => {
  const dir = repository();
  rawCommit(dir, [
    { name: Buffer.from([0xff, 0x2e, 0x74, 0x78, 0x74]), content: 'same\n' },
    { name: Buffer.from([0xfe, 0x2e, 0x74, 0x78, 0x74]), content: 'same\n' },
  ]);
  const listed = await table(dir);
  expect(listed.length).toBe(2);
  expect(listed.paths.length).toBe(2);
  expect(listed.path[0]).not.toBe(listed.path[1]);
});
