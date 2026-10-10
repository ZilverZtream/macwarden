import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';
import { captureMain } from './support/capture.js';

// scan --git-history: owner-approved feature after the v1 non-goal was lifted (2026-10-07).
// Titles use the git-history/ prefix: no checkpoint contract owns these cases yet.
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const readonly = manifest.vectors.find(item => item.name === 'default-readonly')!;
const admin = manifest.vectors.find(item => item.name === 'default-admin')!;
const bytes = (name: string) => readFileSync(join(vectors, `${name}.macaroon`));
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
const scanSchema = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));

type Finding = { path: string; line: number | null; column: number | null; kind: string;
  fingerprint: string; grade: string | null; commit?: string };
type Result = { findings: Finding[]; skipped: { path: string; reason: string }[];
  summary: { findings: number; blobsScanned?: number }; failOn: { count: number } | null };

function git(dir: string, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
  return run.stdout.trim();
}

function commit(dir: string, message: string): string {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '--allow-empty', '-m', message);
  return git(dir, 'rev-parse', 'HEAD');
}

async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'git-history-'));
  try { git(dir, 'init', '-q'); return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

async function scan(paths: string[], options: object = {}): Promise<Result> {
  const { scan: run } = await import('../src/scan/index.js');
  return await run(paths, { gitHistory: true, ...options }) as Result;
}

async function cli(args: string[]) {
  const { main } = await import('../src/cli.js');
  return captureMain(main, args);
}

const display = (path: string) => path.replaceAll('\\', '/');

it('git-history/deleted-file a macaroon file deleted in a later commit is found with its adding commit', async () => temp(async dir => {
  writeFileSync(join(dir, 'readonly.macaroon'), bytes('default-readonly'));
  const added = commit(dir, 'add');
  rmSync(join(dir, 'readonly.macaroon'));
  commit(dir, 'remove');
  const { scan: plain } = await import('../src/scan/index.js');
  expect((await plain([dir], {})).findings).toEqual([]);
  const result = await scan([dir]);
  expect(result.findings).toEqual([expect.objectContaining({ path: display(join(dir, 'readonly.macaroon')),
    kind: 'macaroon-file', fingerprint: readonly.fingerprint, grade: readonly.expectedGrade, commit: added, line: null })]);
  expect(result.summary.blobsScanned).toBe(1);
}));

it('git-history/deleted-text a hex macaroon removed from a config file keeps its line, column and fingerprint', async () => temp(async dir => {
  writeFileSync(join(dir, 'app.env'), 'A=1\nB=2\nTOKEN=' + bytes('default-admin').toString('hex') + '\n');
  const added = commit(dir, 'add');
  writeFileSync(join(dir, 'app.env'), 'A=1\nB=2\n');
  commit(dir, 'scrub');
  const result = await scan([dir]);
  expect(result.findings).toEqual([expect.objectContaining({ path: display(join(dir, 'app.env')), line: 3, column: 7,
    kind: 'macaroon-hex', fingerprint: admin.fingerprint, grade: 'ADMIN', commit: added })]);
}));

it('git-history/dedupe a credential still in the work tree or re-added later is reported once', async () => temp(async dir => {
  writeFileSync(join(dir, 'kept.macaroon'), bytes('default-readonly'));
  writeFileSync(join(dir, 'cfg.txt'), bytes('default-admin').toString('base64') + '\n');
  const first = commit(dir, 'add');
  writeFileSync(join(dir, 'cfg.txt'), 'clean\n');
  commit(dir, 'scrub');
  writeFileSync(join(dir, 'cfg.txt'), 'x\n' + bytes('default-admin').toString('base64') + '\n');
  commit(dir, 'leak again');
  writeFileSync(join(dir, 'cfg.txt'), 'clean\n');
  commit(dir, 'scrub again');
  const result = await scan([dir]);
  const kept = result.findings.filter(finding => finding.fingerprint === readonly.fingerprint);
  expect(kept).toEqual([expect.objectContaining({ kind: 'macaroon-file' })]);
  expect(kept[0].commit).toBeUndefined();
  const leaked = result.findings.filter(finding => finding.fingerprint === admin.fingerprint);
  expect(leaked).toEqual([expect.objectContaining({ kind: 'macaroon-base64', line: 1, commit: first })]);
}));

it('git-history/all-refs a credential committed only on another branch is found', async () => temp(async dir => {
  commit(dir, 'root');
  git(dir, 'checkout', '-q', '-b', 'side');
  writeFileSync(join(dir, 'side.macaroon'), bytes('default-admin'));
  const side = commit(dir, 'side');
  git(dir, 'checkout', '-q', '-');
  const result = await scan([dir]);
  expect(result.findings).toEqual([expect.objectContaining({ fingerprint: admin.fingerprint, commit: side })]);
}));

it('git-history/ignore-file a .macwardenignore entry suppresses the history finding', async () => temp(async dir => {
  writeFileSync(join(dir, 'old.macaroon'), bytes('default-readonly'));
  commit(dir, 'add');
  rmSync(join(dir, 'old.macaroon'));
  commit(dir, 'remove');
  expect((await scan([dir])).findings).toEqual([expect.objectContaining({ fingerprint: readonly.fingerprint })]);
  writeFileSync(join(dir, '.macwardenignore'), `${readonly.fingerprint} old.macaroon\n`);
  const result = await scan([dir]) as Result & { summary: { ignored: number } };
  expect(result.findings).toEqual([]);
  expect(result.summary.ignored).toBe(1);
}));

it('git-history/never-open protected names in history are skipped without reading their blobs', async () => temp(async dir => {
  writeFileSync(join(dir, 'tls.key'), bytes('default-admin').toString('hex'));
  writeFileSync(join(dir, 'wallet.db'), bytes('default-admin').toString('hex'));
  commit(dir, 'add');
  rmSync(join(dir, 'tls.key'));
  rmSync(join(dir, 'wallet.db'));
  commit(dir, 'remove');
  const result = await scan([dir]);
  expect(result.findings).toEqual([]);
  expect(result.skipped).toEqual(expect.arrayContaining([
    { path: display(join(dir, 'tls.key')), reason: 'never-open' },
    { path: display(join(dir, 'wallet.db')), reason: 'never-open' }]));
  expect(result.summary.blobsScanned).toBe(0);
}));

it('git-history/read-only scanning history changes nothing in the repository', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.macaroon'), bytes('default-readonly'));
  commit(dir, 'add');
  const snapshot = () => {
    const out: string[] = [];
    const walk = (path: string) => {
      for (const name of readdirSync(path)) {
        const child = join(path, name);
        const stat = statSync(child);
        if (stat.isDirectory()) walk(child);
        else out.push(`${child}:${stat.size}:${stat.mtimeMs}:${readFileSync(child).toString('base64')}`);
      }
    };
    walk(dir);
    return out.sort().join('\n');
  };
  const before = snapshot();
  await scan([dir]);
  expect(snapshot()).toBe(before);
}));

it('git-history/cli text and JSON show the commit, never the credential, and --fail-on counts history', async () => temp(async dir => {
  const hex = bytes('default-admin').toString('hex');
  writeFileSync(join(dir, 'notes.txt'), `token ${hex}\n`);
  const added = commit(dir, 'add');
  writeFileSync(join(dir, 'notes.txt'), 'gone\n');
  commit(dir, 'remove');
  const text = await cli(['scan', dir, '--git-history', '--fail-on', 'ADMIN']);
  expect(text.code).toBe(1);
  expect(text.stdout).toContain(`${added.slice(0, 7)}:${display(join(dir, 'notes.txt'))}:1:7  macaroon-hex  ${admin.fingerprint} ADMIN`);
  expect(text.stdout).toMatch(/and 2 history blobs/);
  const json = await cli(['scan', dir, '--git-history', '--json']);
  expect(json.code).toBe(0);
  const document = JSON.parse(json.stdout) as { result: Result };
  expect(scanSchema(document)).toBe(true);
  expect(document.result.findings[0].commit).toBe(added);
  const base64 = bytes('default-admin').toString('base64');
  for (const output of [text.stdout, text.stderr, json.stdout, json.stderr]) {
    expect(output.toLowerCase()).not.toContain(hex.slice(0, 48).toLowerCase());
    expect(output).not.toContain(base64.slice(0, 48));
  }
}));

it('git-history/errors a non-repository or missing git exits 3 at step git-history', async () => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'git-history-plain-'));
  const ceiling = process.env.GIT_CEILING_DIRECTORIES;
  // The test temp root can sit inside this checkout; stop git's upward search above it.
  process.env.GIT_CEILING_DIRECTORIES = testTmp;
  try {
    const run = await cli(['scan', dir, '--git-history', '--json']);
    expect(run.code).toBe(3);
    const document = JSON.parse(run.stdout) as { error: { step: string; message: string } };
    expect(scanSchema(document)).toBe(true);
    expect(document.error).toMatchObject({ step: 'git-history', message: 'path is not inside a git work tree' });
    // No test-only hook: the built CLI runs with a PATH that contains no git at all.
    git(dir, 'init', '-q');
    const noGit = mkdtempSync(join(testTmp, 'git-history-nopath-'));
    try {
      const env: NodeJS.ProcessEnv = {};
      for (const [key, value] of Object.entries(childEnvironment())) if (key.toLowerCase() !== 'path') env[key] = value;
      env.PATH = noGit;
      const child = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'scan', dir, '--git-history', '--json'],
        { cwd: dir, env, encoding: 'utf8', timeout: 20_000, windowsHide: true });
      expect(child.status).toBe(3);
      const missing = JSON.parse(child.stdout) as { error: { step: string; message: string } };
      expect(scanSchema(missing)).toBe(true);
      expect(missing.error).toEqual({ code: 3, step: 'git-history', message: 'git history requires git on PATH' });
    } finally { rmSync(noGit, { recursive: true, force: true }); }
    expect((await cli(['scan', dir, '--git-history', '--git-history'])).code).toBe(2);
  } finally {
    if (ceiling === undefined) delete process.env.GIT_CEILING_DIRECTORIES; else process.env.GIT_CEILING_DIRECTORIES = ceiling;
    rmSync(dir, { recursive: true, force: true });
  }
});

// Review fixes 2026-10-07: the scanned repository is untrusted, so its own .git/config must
// not start programs or change what is listed, and every listed blob must be read or fail.

function json(run: { stdout: string }) {
  return JSON.parse(run.stdout) as { error: { code: number; step: string; message: string } | null; result: Result | null };
}
const posix = (path: string) => path.replaceAll('\\', '/');

function markerProgram(dir: string, name: string): { program: string; marker: string } {
  const marker = join(dir, `${name}.ran`);
  const program = join(dir, `${name}.sh`);
  writeFileSync(program, `#!/bin/sh\necho ran > "${posix(marker)}"\nexit 1\n`);
  chmodSync(program, 0o755);
  return { program: posix(program), marker };
}

// A commit object carrying a gpgsig header, so `log.showSignature` asks gpg.program to verify it.
function signedCommit(dir: string, parent: string): string {
  const tree = git(dir, 'write-tree');
  const body = `tree ${tree}\nparent ${parent}\nauthor t <t@example.invalid> 1700000000 +0000\n` +
    'committer t <t@example.invalid> 1700000000 +0000\n' +
    'gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nsigned\n';
  const run = spawnSync('git', ['hash-object', '-t', 'commit', '-w', '--stdin'], { cwd: dir, input: body, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`hash-object failed: ${run.stderr}`);
  return run.stdout.trim();
}

it('git-history/signature-program repository config cannot make the scan run gpg.program', async () => temp(async dir => {
  writeFileSync(join(dir, 'base.txt'), 'base\n');
  const base = commit(dir, 'base');
  writeFileSync(join(dir, 'signed.macaroon'), bytes('default-admin'));
  git(dir, 'add', '-A');
  const signed = signedCommit(dir, base);
  git(dir, 'update-ref', 'refs/heads/signed', signed);
  git(dir, 'rm', '-q', '--cached', 'signed.macaroon');
  rmSync(join(dir, 'signed.macaroon'));
  const { program, marker } = markerProgram(dir, 'gpg');
  git(dir, 'config', 'log.showSignature', 'true');
  git(dir, 'config', 'gpg.program', program);
  git(dir, 'config', 'gpg.ssh.program', program);
  git(dir, 'config', 'gpg.x509.program', program);
  // Proof the setup is live: plain git with this repository config does run the program.
  spawnSync('git', ['log', '-1', 'signed'], { cwd: dir, encoding: 'utf8' });
  expect(existsSync(marker)).toBe(true);
  rmSync(marker);
  const run = await cli(['scan', dir, '--git-history', '--json']);
  expect(existsSync(marker)).toBe(false);
  expect(run.code).toBe(0);
  expect(json(run).result!.findings).toEqual([expect.objectContaining({ kind: 'macaroon-file', fingerprint: admin.fingerprint, commit: signed })]);
}));

// The isolation itself (GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM, no inherited GIT_* variables) is asserted
// by git-history/environment; no global setting that is not also pinned on the command line changes the listing.
it('git-history/user-config settings pinned on the command line have no effect from the account\'s global git config', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.txt'), 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  const added = commit(dir, 'add');
  const home = join(dir, 'home');
  mkdirSync(home);
  const { program, marker } = markerProgram(dir, 'fsmonitor');
  writeFileSync(join(home, '.gitconfig'), `[core]\n\tfsmonitor = ${program}\n[log]\n\tshowRoot = false\n\tdiffMerges = combined\n`);
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, XDG: process.env.XDG_CONFIG_HOME };
  process.env.HOME = home; process.env.USERPROFILE = home; delete process.env.XDG_CONFIG_HOME;
  try {
    const result = await scan([dir]);
    expect(existsSync(marker)).toBe(false);
    expect(result.findings).toEqual([expect.objectContaining({ kind: 'macaroon-hex', fingerprint: admin.fingerprint })]);
    expect(result.findings[0].commit).toBeUndefined();
    expect(added).toMatch(/^[0-9a-f]{40,64}$/);
  } finally {
    for (const [key, value] of [['HOME', saved.HOME], ['USERPROFILE', saved.USERPROFILE], ['XDG_CONFIG_HOME', saved.XDG]] as const)
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
}));

it('git-history/missing-object a history blob absent from the object store fails the scan with exit 3', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.macaroon'), bytes('default-admin'));
  commit(dir, 'add');
  const blob = git(dir, 'rev-parse', 'HEAD:a.macaroon');
  rmSync(join(dir, 'a.macaroon'));
  commit(dir, 'remove');
  const object = join(dir, '.git', 'objects', blob.slice(0, 2), blob.slice(2));
  chmodSync(object, 0o644);
  rmSync(object);
  const run = await cli(['scan', dir, '--git-history', '--fail-on', 'ADMIN', '--json']);
  expect(run.code).toBe(3);
  const document = json(run);
  expect(scanSchema(document)).toBe(true);
  expect(document.error).toEqual({ code: 3, step: 'git-history', message: 'git history could not be read' });
}));

it('git-history/root-commit a credential in the root commit is found even when log.showRoot is false', async () => temp(async dir => {
  writeFileSync(join(dir, 'first.env'), 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  const root = commit(dir, 'root');
  writeFileSync(join(dir, 'first.env'), 'TOKEN=\n');
  commit(dir, 'scrub');
  git(dir, 'config', 'log.showRoot', 'false');
  const result = await scan([dir]);
  expect(result.findings).toEqual([expect.objectContaining({ kind: 'macaroon-hex', fingerprint: admin.fingerprint, commit: root })]);
}));

it('git-history/merge-resolution content that exists only in a merge resolution is found under any log.diffMerges', async () => temp(async dir => {
  writeFileSync(join(dir, 'x.txt'), 'base\n');
  commit(dir, 'base');
  const main = git(dir, 'rev-parse', '--abbrev-ref', 'HEAD');
  git(dir, 'checkout', '-q', '-b', 'side');
  writeFileSync(join(dir, 'x.txt'), 'side\n');
  commit(dir, 'side');
  git(dir, 'checkout', '-q', main);
  writeFileSync(join(dir, 'x.txt'), 'main\n');
  commit(dir, 'main');
  spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'merge', '-q', 'side'], { cwd: dir });
  writeFileSync(join(dir, 'x.txt'), 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  const merge = commit(dir, 'merge');
  expect(git(dir, 'rev-list', '--parents', '-n', '1', 'HEAD').split(' ')).toHaveLength(3);
  writeFileSync(join(dir, 'x.txt'), 'clean\n');
  commit(dir, 'scrub');
  for (const mode of ['separate', 'combined', 'dense-combined', 'off']) {
    git(dir, 'config', 'log.diffMerges', mode);
    const result = await scan([dir]);
    expect(result.findings, mode).toEqual([expect.objectContaining({ kind: 'macaroon-hex', fingerprint: admin.fingerprint, commit: merge })]);
  }
}));

it('git-history/rename a renamed credential file is one finding naming both paths, without breaking the parser', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.macaroon'), bytes('default-readonly'));
  const added = commit(dir, 'add');
  git(dir, 'mv', 'a.macaroon', 'b.macaroon');
  const renamed = commit(dir, 'rename');
  rmSync(join(dir, 'b.macaroon'));
  commit(dir, 'remove');
  git(dir, 'config', 'diff.renames', 'copies');
  git(dir, 'config', 'log.follow', 'true');
  const result = await scan([dir]);
  // The rename adds the same content at a new path: one finding at the oldest commit and
  // path, with the new name in alsoAt (red-team fan-out fix, 2026-10-08).
  void renamed;
  expect(result.findings.map(finding => [display(finding.path), finding.fingerprint, finding.commit,
    (finding as { alsoAt?: { count: number; paths: string[] } }).alsoAt])).toEqual([
    [display(join(dir, 'a.macaroon')), readonly.fingerprint, added, { count: 1, paths: [display(join(dir, 'b.macaroon'))] }]]);
}));

it('git-history/literal-pathspec a file argument with glob characters selects only that file\'s history', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.txt'), 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  writeFileSync(join(dir, '[ab].txt'), 'nothing here\n');
  commit(dir, 'add');
  rmSync(join(dir, 'a.txt'));
  commit(dir, 'remove');
  const result = await scan([join(dir, '[ab].txt')]);
  expect(result.findings).toEqual([]);
  expect((await scan([dir])).findings).toEqual([expect.objectContaining({ fingerprint: admin.fingerprint })]);
}));

it('git-history/excluded-dir history excludes node_modules exactly as the walk does', async () => temp(async dir => {
  // Separate parents: a case-insensitive file system cannot hold both spellings in one folder.
  mkdirSync(join(dir, 'pkg', 'Node_Modules'), { recursive: true });
  mkdirSync(join(dir, 'node_modules'));
  writeFileSync(join(dir, 'pkg', 'Node_Modules', 'x.env'), 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  writeFileSync(join(dir, 'node_modules', 'y.env'), 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  const added = commit(dir, 'add');
  const walk = (await import('../src/scan/index.js')).scan;
  const walked = (await walk([dir], {})).findings.map(finding => display(finding.path));
  rmSync(join(dir, 'pkg'), { recursive: true, force: true });
  rmSync(join(dir, 'node_modules'), { recursive: true, force: true });
  commit(dir, 'remove');
  const history = (await scan([dir])).findings;
  // The walk compares directory names as the platform's default file system does (1.1.1,
  // RR-08): case-insensitively on Windows and macOS, exactly elsewhere. History must exclude
  // the same paths.
  const caseInsensitive = process.platform === 'win32' || process.platform === 'darwin';
  expect(walked).toEqual(caseInsensitive ? [] : [display(join(dir, 'pkg', 'Node_Modules', 'x.env'))]);
  expect(history.map(finding => display(finding.path))).toEqual(walked);
  const included = (await scan([dir], { includeDirs: true })).findings;
  // Both files hold the same content: one finding at the first path, the other in alsoAt.
  expect(included.map(finding => [display(finding.path), finding.commit,
    (finding as { alsoAt?: { count: number; paths: string[] } }).alsoAt])).toEqual([
    [display(join(dir, 'node_modules', 'y.env')), added, { count: 1, paths: [display(join(dir, 'pkg', 'Node_Modules', 'x.env'))] }]]);
}));

it('git-history/oversized-macaroon an oversized .macaroon blob is undecodable with the walk\'s fingerprint, not skipped', async () => temp(async dir => {
  const big = randomBytes(5_242_881 + 4096);
  writeFileSync(join(dir, 'big.macaroon'), big);
  const added = commit(dir, 'add');
  const walk = (await import('../src/scan/index.js')).scan;
  const walked = (await walk([dir], {})).findings;
  rmSync(join(dir, 'big.macaroon'));
  commit(dir, 'remove');
  const expected = `fp:${createHash('sha256').update(big.subarray(0, 65_537)).digest('hex').slice(0, 16)}`;
  expect(walked).toEqual([expect.objectContaining({ kind: 'undecodable', fingerprint: expected })]);
  const result = await scan([dir]);
  expect(result.findings).toEqual([expect.objectContaining({ kind: 'undecodable', fingerprint: expected, commit: added })]);
  expect(result.skipped.filter(item => item.reason === 'size')).toEqual([]);
}));

// 1.2.1 (audit F16): an empty blob is scanned and counted like the empty file the walk scans,
// never skipped for size.
it('git-history/empty-blob an empty file and an empty .macaroon are scanned as the walk scans them, not skipped for size', async () => temp(async dir => {
  writeFileSync(join(dir, 'empty.txt'), '');
  writeFileSync(join(dir, 'empty.macaroon'), '');
  const added = commit(dir, 'add');
  const walk = (await import('../src/scan/index.js')).scan;
  const walked = await walk([dir], {}) as Result;
  rmSync(join(dir, 'empty.txt'));
  rmSync(join(dir, 'empty.macaroon'));
  commit(dir, 'remove');
  const result = await scan([dir]);
  const notExcluded = (items: { reason: string }[]) => items.filter(item => item.reason !== 'excluded-dir');
  expect(notExcluded(walked.skipped)).toEqual([]);
  expect(notExcluded(result.skipped)).toEqual([]);
  // Both files have the same (empty) content: one blob, read as text and as a *.macaroon file.
  expect(result.summary.blobsScanned).toBe(1);
  expect(walked.findings).toEqual([expect.objectContaining({ kind: 'undecodable', path: display(join(dir, 'empty.macaroon')) })]);
  expect(result.findings).toEqual([expect.objectContaining({ kind: 'undecodable', path: display(join(dir, 'empty.macaroon')),
    fingerprint: walked.findings[0].fingerprint, commit: added })]);
}));

// 1.2.1 (audit F17): summary.dropped counts history blobs exactly as it counts work-tree files.
it('git-history/dropped an lndconnect URI without a macaroon in history is counted in summary.dropped like the walk counts it', async () => temp(async dir => {
  const text = 'node: lndconnect://127.0.0.1:10009?cert=MIIB\n';
  writeFileSync(join(dir, 'connect.txt'), text);
  commit(dir, 'add');
  const walk = (await import('../src/scan/index.js')).scan;
  const walked = await walk([dir], {}) as Result & { summary: { dropped: number } };
  expect(walked.summary.dropped).toBe(1);
  rmSync(join(dir, 'connect.txt'));
  commit(dir, 'remove');
  const history = await scan([dir]) as Result & { summary: { dropped: number } };
  expect(history.summary.blobsScanned).toBe(1);
  expect(history.summary.dropped).toBe(1);
  // A blob with findings adds its dropped count as well.
  writeFileSync(join(dir, 'mixed.env'), text + 'TOKEN=' + bytes('default-admin').toString('hex') + '\n');
  commit(dir, 'mixed');
  rmSync(join(dir, 'mixed.env'));
  commit(dir, 'remove mixed');
  const mixed = await scan([dir]) as Result & { summary: { dropped: number } };
  expect(mixed.findings).toEqual([expect.objectContaining({ fingerprint: admin.fingerprint })]);
  expect(mixed.summary.blobsScanned).toBe(2);
  expect(mixed.summary.dropped).toBe(2);
}));

// 1.2.1 (verifier, F17): the walk already counted a work-tree file's URIs, so --git-history counts
// a blob only when it was also committed at a path where the work tree does not hold that content,
// as a history finding is skipped only at the (path, fingerprint) pairs the work tree reported.
it('git-history/dropped a blob the work tree holds unchanged at every path is not counted again', async () => temp(async dir => {
  const two = 'a lndconnect://h1:10009?cert=AAA\nb lndconnect://h2:10009?cert=BBB\n';
  const dropped = async () => ((await scan([dir])) as Result & { summary: { dropped: number; blobsScanned: number } }).summary;
  writeFileSync(join(dir, 'uris.txt'), two);
  commit(dir, 'add');
  const walk = (await import('../src/scan/index.js')).scan;
  expect(((await walk([dir], {})) as Result & { summary: { dropped: number } }).summary.dropped).toBe(2);
  expect(await dropped()).toMatchObject({ blobsScanned: 1, dropped: 2 });
  // Line endings git may convert on checkout (core.autocrlf) do not make the content differ.
  writeFileSync(join(dir, 'uris.txt'), two.replaceAll('\n', '\r\n'));
  expect(await dropped()).toMatchObject({ dropped: 2 });
  // The same content committed at a second path the work tree also holds: still the walk's.
  writeFileSync(join(dir, 'uris.txt'), two);
  writeFileSync(join(dir, 'copy.txt'), two);
  commit(dir, 'copy');
  expect(await dropped()).toMatchObject({ blobsScanned: 1, dropped: 4 });
  // uris.txt changes: its old blob (also copy.txt's) is no longer what the work tree holds there.
  writeFileSync(join(dir, 'uris.txt'), `${two}c lndconnect://h3:10009?cert=CCC\n`);
  commit(dir, 'third');
  expect(await dropped()).toMatchObject({ blobsScanned: 2, dropped: 3 + 2 + 2 });
}));
