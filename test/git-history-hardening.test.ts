import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { gitEnvironment, PINNED_CONFIG } from '../src/scan/git-history.js';
import { captureMain } from './support/capture.js';

// Hardening of scan --git-history against the scanned repository and the scanning
// account's environment. Each behavioural case is built so the credential is visible
// only if the defence holds; a removed defence hides it or changes the outcome.
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const admin = manifest.vectors.find(item => item.name === 'default-admin')!;
const adminHex = readFileSync(join(vectors, 'default-admin.macaroon')).toString('hex');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;

function git(dir: string, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${run.stderr}`);
  return run.stdout.trim();
}
function commit(dir: string, message: string): string {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '--allow-empty', '-m', message);
  return git(dir, 'rev-parse', 'HEAD');
}
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function repository(): string {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'git-hardening-'));
  dirs.push(dir);
  git(dir, 'init', '-q');
  return dir;
}
type Result = { findings: { fingerprint: string; commit?: string; path: string }[]; skipped: { path: string; reason: string }[] };
async function scan(path: string): Promise<Result> {
  const { scan: run } = await import('../src/scan/index.js');
  return await run([path], { gitHistory: true }) as Result;
}

it('git-history/environment git runs with global and system config disabled and no inherited git variables', () => {
  const planted = { GIT_CONFIG_GLOBAL: '/tmp/evil', GIT_CONFIG_SYSTEM: '/tmp/evil', GIT_CONFIG_PARAMETERS: "'core.fsmonitor'='evil'",
    GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.fsmonitor', GIT_CONFIG_VALUE_0: 'evil', GIT_EXEC_PATH: '/tmp/evil',
    GIT_SSH_COMMAND: 'evil', GIT_ALTERNATE_OBJECT_DIRECTORIES: '/tmp/evil', GIT_REPLACE_REF_BASE: 'refs/evil/',
    GIT_NAMESPACE: 'evil', GIT_OBJECT_DIRECTORY: '/tmp/evil', GIT_INDEX_FILE: '/tmp/evil', NODE_OPTIONS: '--evil' };
  const saved = Object.fromEntries(Object.keys(planted).map(key => [key, process.env[key]]));
  Object.assign(process.env, planted);
  try {
    const env = gitEnvironment({ gitDir: resolve('x/.git'), workTree: resolve('x') });
    expect(env).toMatchObject({ GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1',
      GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_LITERAL_PATHSPECS: '1',
      GIT_DIR: resolve('x/.git'), GIT_WORK_TREE: resolve('x') });
    expect(env.GIT_GRAFT_FILE).toMatch(/nonexistent/);
    for (const key of Object.keys(planted)) if (key !== 'GIT_CONFIG_GLOBAL') expect(env[key], key).toBeUndefined();
    const inherited = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'HOME', 'USERPROFILE', 'TMPDIR', 'TEMP', 'TMP'];
    const pinned = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_CEILING_DIRECTORIES', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL',
      'GIT_TERMINAL_PROMPT', 'GIT_OPTIONAL_LOCKS', 'GIT_NO_LAZY_FETCH', 'GIT_NO_REPLACE_OBJECTS', 'GIT_GRAFT_FILE',
      'GIT_LITERAL_PATHSPECS', 'GIT_PAGER', 'LC_ALL'];
    for (const key of Object.keys(env)) expect([...inherited, ...pinned], key).toContain(key);
  } finally {
    for (const [key, value] of Object.entries(saved)) if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
});

it('git-history/environment network transport is disabled on every git command line', () => {
  const settings = PINNED_CONFIG.filter((_, index) => index % 2 === 1);
  expect(PINNED_CONFIG.filter((_, index) => index % 2 === 0).every(flag => flag === '-c')).toBe(true);
  expect(settings).toEqual(expect.arrayContaining(['protocol.allow=never', 'core.fsmonitor=false', 'log.showSignature=false',
    'log.showRoot=true', 'log.follow=false', 'diff.renames=false', 'log.mailmap=false']));
  for (const key of ['core.hooksPath', 'gpg.program', 'gpg.ssh.program', 'gpg.x509.program'])
    expect(settings.find(setting => setting.startsWith(`${key}=`)), key).toMatch(/=\/nonexistent\//);
});

// The repository's diff.orderFile names a file git log --raw opens (a UNC path would make a
// network connection); -c cannot pin it empty, so the scan passes -O/dev/null.
it('git-history/order-file a repository diff.orderFile is never opened', async () => {
  const dir = repository();
  writeFileSync(join(dir, 's.env'), `TOKEN=${adminHex}
`);
  const added = commit(dir, 'add');
  rmSync(join(dir, 's.env'));
  commit(dir, 'remove');
  git(dir, 'config', 'diff.orderFile', join(dir, 'missing-order-file'));
  // Sanity: git itself opens the order file and fails without it.
  expect(spawnSync('git', ['log', '--raw', '--format=%H'], { cwd: dir }).status).not.toBe(0);
  const result = await scan(dir);
  expect(result.findings).toEqual([expect.objectContaining({ fingerprint: admin.fingerprint, commit: added })]);
});

it('git-history/replace-refs a replacement object cannot hide a credential blob from the history scan', async () => {
  const dir = repository();
  writeFileSync(join(dir, 's.env'), `TOKEN=${adminHex}\n`);
  const added = commit(dir, 'add');
  const secretBlob = git(dir, 'rev-parse', 'HEAD:s.env');
  writeFileSync(join(dir, 'benign.txt'), 'A=1\n');
  const benign = git(dir, 'hash-object', '-w', 'benign.txt');
  rmSync(join(dir, 'benign.txt'));
  git(dir, 'replace', secretBlob, benign);
  rmSync(join(dir, 's.env'));
  commit(dir, 'remove');
  // Sanity: with replace refs honoured, git itself serves the benign content for the secret blob.
  expect(git(dir, 'cat-file', '-p', secretBlob)).toBe('A=1');
  const result = await scan(dir);
  expect(result.findings).toEqual([expect.objectContaining({ fingerprint: admin.fingerprint, commit: added })]);
});

it('git-history/grafts a graft file cannot cut the commit that added a credential out of history', async () => {
  const dir = repository();
  writeFileSync(join(dir, 'b.txt'), 'benign\n');
  commit(dir, 'base');
  writeFileSync(join(dir, 's.env'), `TOKEN=${adminHex}\n`);
  const added = commit(dir, 'add');
  rmSync(join(dir, 's.env'));
  const removed = commit(dir, 'remove');
  mkdirSync(join(dir, '.git', 'info'), { recursive: true });
  writeFileSync(join(dir, '.git', 'info', 'grafts'), `${removed}\n`);
  // Sanity: with grafts honoured, git itself sees only the last commit.
  expect(git(dir, '-c', 'advice.graftFileDeprecated=false', 'rev-list', '--all').split('\n')).toEqual([removed]);
  const result = await scan(dir);
  expect(result.findings).toEqual([expect.objectContaining({ fingerprint: admin.fingerprint, commit: added })]);
});

it('git-history/partial-clone a blob missing from a partial clone fails the scan and is never fetched', async () => {
  const source = repository();
  writeFileSync(join(source, 's.env'), `TOKEN=${adminHex}\n`);
  commit(source, 'add');
  const secretBlob = git(source, 'rev-parse', 'HEAD:s.env');
  rmSync(join(source, 's.env'));
  commit(source, 'remove');
  git(source, 'config', 'uploadpack.allowFilter', 'true');
  const clone = join(source, '..', `${source.split(/[\\/]/).pop()}-clone`);
  dirs.push(clone);
  const url = `file://${source.replaceAll('\\', '/').replace(/^([A-Za-z]):/, '/$1:')}`;
  git(join(source, '..'), '-c', 'protocol.file.allow=always', 'clone', '-q', '--filter=blob:none', '--no-checkout', url, clone);
  const missing = () => spawnSync('git', ['cat-file', '-e', secretBlob], { cwd: clone,
    env: { ...process.env, GIT_NO_LAZY_FETCH: '1' } }).status !== 0;
  expect(missing()).toBe(true);
  const run = await captureMain((await import('../src/cli.js')).main, ['scan', clone, '--git-history', '--json']);
  expect(run.code).toBe(3);
  expect(JSON.parse(run.stdout).error).toMatchObject({ code: 3, step: 'git-history' });
  expect(missing()).toBe(true); // no lazy fetch from the promisor remote happened
});

it('git-history/symlink-blob a symlink whose target text contains a credential is skipped, not scanned', async () => {
  const dir = repository();
  writeFileSync(join(dir, 'target.txt'), `TOKEN=${adminHex}`);
  const blob = git(dir, 'hash-object', '-w', 'target.txt');
  rmSync(join(dir, 'target.txt'));
  git(dir, 'update-index', '--add', '--cacheinfo', `120000,${blob},link`);
  git(dir, 'commit', '-q', '-m', 'symlink');
  git(dir, 'rm', '-q', '--cached', 'link');
  git(dir, 'commit', '-q', '-m', 'remove');
  expect(existsSync(join(dir, 'link'))).toBe(false);
  const result = await scan(dir);
  expect(result.findings).toEqual([]);
  expect(result.skipped).toContainEqual({ path: join(dir, 'link').replaceAll('\\', '/'), reason: 'symlink' });
});
