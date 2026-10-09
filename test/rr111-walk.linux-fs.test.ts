// Linux variant of the 1.1.1 scan walk fixes (robustness review RR-04, RR-07, RR-08, RR-12).
// These need Linux file system semantics: a backslash inside a file name, case-sensitive
// names and FIFOs. The Windows counterpart is test/rr111-walk.windows-fs.test.ts.
import { closeSync, constants, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { childEnvironment } from './helpers/environment.js';
import { compare } from './helpers/growth.js';
import { expect, it } from 'vitest';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { scan } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as
  { vectors: { name: string; file: string; fingerprint: string; expectedGrade: string }[] };
const readonly = manifest.vectors.find(vector => vector.name === 'default-readonly')!;
const readonlyHex = readFileSync(join(repo, 'test/vectors', readonly.file)).toString('hex');

async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr111-linux-'));
  try { return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function rendered(result: OutputResult['result'], format: 'sarif' | 'github', root: string): string {
  return [...renderChunks({ command: 'scan', ok: true, warnings: [], error: null, result,
    display: { format, scanRoot: root, toolVersion: '0.0.0' } } as OutputResult, 'text')].join('');
}

it('RR-111/walk-linux RR-07 a backslash in a file name is part of the name, not a separator', async () => temp(async dir => {
  writeFileSync(join(dir, 'back\\slash.env'), `X=${readonlyHex}\n`);
  const result = await scan([dir]);
  expect(result.findings.map(finding => finding.path)).toEqual([`${dir}/back\\slash.env`]);
  const sarif = JSON.parse(rendered(result, 'sarif', dir)) as
    { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
  expect(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe('back%5Cslash.env');
  expect(rendered(result, 'github', dir)).toContain('file=back\\slash.env,');
}));

it('RR-111/walk-linux RR-12 a real FIFO named as a scan argument exits 3 under --fail-on', async () => temp(async dir => {
  const fifo = join(dir, 'pipe.env');
  const made = spawnSync('mkfifo', [fifo]);
  expect(made.status).toBe(0);
  const { run } = await import('../src/commands/scan.js');
  const outcome = await run([fifo, '--fail-on', 'READ']);
  expect(outcome).toMatchObject({ ok: false, error: { code: 3, step: 'input-read', message: 'scan path is not a regular file or directory' } });
  // In a walked directory a FIFO is still a not-regular skip.
  const walked = await scan([dir]);
  expect(walked.skipped).toEqual([{ path: fifo, reason: 'not-regular' }]);
}));

// The review's deterministic proof: the injected open first lets an "attacker" replace the
// walked regular file with a real FIFO, then performs the real open with the scan's flags.
function fifoAtOpen(victim: string) {
  let swapped = false;
  const io = { ...fs, open: (async (path: string, flags: number) => {
    if (!swapped && path === victim) {
      swapped = true;
      rmSync(victim);
      expect(spawnSync('mkfifo', [victim]).status).toBe(0);
    }
    return fs.open(path, flags);
  }) as unknown as typeof fs.open };
  return io;
}

async function settles<T>(work: Promise<T>, ms: number): Promise<{ value?: T; error?: unknown } | 'timeout'> {
  return Promise.race([work.then(value => ({ value }), (error: unknown) => ({ error })),
    new Promise<'timeout'>(done => setTimeout(() => done('timeout'), ms))]);
}

it('RR-111/walk-linux RR-04 a walked file replaced by a FIFO after lstat is skipped instead of blocking open', async () => temp(async dir => {
  const victim = join(dir, 'f.env');
  writeFileSync(victim, 'hello\n');
  writeFileSync(join(dir, 'g.env'), `X=${readonlyHex}\n`);
  const started = performance.now();
  const outcome = await settles(scan([dir], { fs: fifoAtOpen(victim) }), 5_000);
  // Unblock a stuck open (if any) so the worker can finish, then judge.
  if (outcome === 'timeout') closeSync(openSync(victim, constants.O_RDWR));
  expect(outcome).not.toBe('timeout');
  expect(performance.now() - started).toBeLessThan(5_000);
  const result = (outcome as { value: Awaited<ReturnType<typeof scan>> }).value;
  expect(result.skipped).toEqual([{ path: victim, reason: 'not-regular' }]);
  expect(result.findings.map(finding => finding.path)).toEqual([join(dir, 'g.env')]);
}));

it('RR-111/walk-linux RR-04 a .macwardenignore replaced by a FIFO fails closed instead of blocking', async () => temp(async dir => {
  const victim = join(dir, '.macwardenignore');
  writeFileSync(victim, '# none\n');
  const outcome = await settles(scan([dir], { fs: fifoAtOpen(victim) }), 5_000);
  if (outcome === 'timeout') closeSync(openSync(victim, constants.O_RDWR));
  expect(outcome).not.toBe('timeout');
  expect((outcome as { error: unknown }).error).toMatchObject({ code: 3, stage: 'input-read', message: 'cannot read ignore file' });
}));

it('RR-111/walk-linux RR-04 smoke: the CLI never hangs while a real process keeps swapping a FIFO into the scanned tree', async () => temp(async dir => {
  const scanned = join(dir, 'scanned');
  const side = join(dir, 'side');
  mkdirSync(scanned); mkdirSync(side);
  writeFileSync(join(scanned, 'f'), 'hello\n');
  for (let i = 0; i < 9; i++) writeFileSync(join(scanned, `pad${i}.env`), 'X=1\n');
  const swapper = spawn(process.execPath, [resolve('test/helpers/rr111-fifo-swapper.mjs'), side, join(scanned, 'f'), '200'],
    { stdio: ['ignore', 'pipe', 'ignore'] });
  try {
    await new Promise<void>((ready, failed) => {
      swapper.stdout.once('data', () => ready());
      swapper.once('exit', code => failed(new Error(`swapper exited ${code}`)));
    });
    const deadline = performance.now() + 20_000;
    const codes: (number | null)[] = [];
    while (codes.length < 60 && performance.now() < deadline) {
      const child = spawn(process.execPath, [resolve('dist/bin.js'), 'scan', scanned, '--json'],
        { stdio: ['ignore', 'ignore', 'ignore'], env: childEnvironment() });
      const exited = new Promise<number | null>(done => child.once('exit', code => done(code)));
      const outcome = await Promise.race([exited, new Promise<'hung'>(done => setTimeout(() => done('hung'), 5_000))]);
      if (outcome === 'hung') {
        child.kill('SIGKILL');
        await exited;
      }
      codes.push(outcome === 'hung' ? -1 : outcome);
    }
    expect(codes.length).toBeGreaterThanOrEqual(10);
    expect(codes.filter(code => code !== 0)).toEqual([]);
  } finally {
    swapper.kill('SIGKILL');
  }
}), 60_000);

// RR-05: realpath per entry made the walk's cost grow with the cube of directory depth (Linux:
// 2,000 nested directories 52 s against 1 s flat; 2,000 files at depth 1,000 22 s against 1.5 s).
// The bounds below are small constant factors of work timed in the same process. They are a
// Linux proof: Windows realpath was already linear per call, and its path lookups cost far more
// per component, so the portable proof (rr111-walk.test.ts) counts realpath calls instead.
async function timed(work: () => Promise<unknown>): Promise<number> {
  const started = performance.now();
  await work();
  return performance.now() - started;
}
// Node's recursive rmSync recurses per level and overflows the stack on a 2,000-deep chain,
// so a chain is removed bottom-up, one level at a time.
function removeChain(deepest: string, top: string): void {
  for (let path = deepest; path.length >= top.length; path = dirname(path)) rmSync(path, { recursive: true, force: true });
}
const DEPTH_FACTOR = 5;
const DEPTH_SLACK_MS = 5_000;
// The chain walk is measured against a reference workload, not against flat directories: one
// lstat of every directory in the chain by its full path. The kernel resolves every component of
// such a path, so the reference grows with the square of the depth, as the fixed walk does with
// its lstat per entry (1.5 s for 2,000 levels on a workstation, 8 s on a two-core CI runner).
// realpath per entry repeats that for every component, one more factor of the depth. Measured on
// Linux: the walk takes about 33 times the reference now, idle or with both cores of a two-core
// slice busy, and up to 60 times during a full parallel test run (the walk's asynchronous calls
// wait for a busy scheduler, the synchronous reference does not); about 540 times before the fix.
const LSTAT_FACTOR = 180;

it('RR-111/walk-linux RR-05 a directory chain about 2,000 deep is walked within a small factor of one lstat per level', async () => temp(async dir => {
  const chain = join(dir, 'c');
  // As deep as Linux PATH_MAX (4,096 bytes) allows under this test's temp root, at most 2,000 levels:
  // the full validation runs in a deeper temp directory than a plain run.
  const depth = Math.min(2_000, Math.floor((4_000 - Buffer.byteLength(chain) - 8) / 2));
  expect(depth).toBeGreaterThan(1_500);
  const levels = Array.from({ length: depth + 1 }, (_, level) => join(chain, ...Array.from({ length: level }, () => 'd')));
  const deepest = levels.at(-1)!;
  try {
    mkdirSync(deepest, { recursive: true });
    writeFileSync(join(deepest, 'x.env'), `X=${readonlyHex}\n`);
    const reference = () => { for (const level of levels) lstatSync(level); };
    const walk = async () => {
      const result = await scan([chain]);
      expect(result.findings.map(finding => finding.fingerprint)).toEqual([readonly.fingerprint]);
      expect(result.skipped).toEqual([]);
    };
    const timing = await compare(reference, walk, 2);
    console.log(`RR-05 chain ${depth} deep, lstat per level against the walk: ${timing.summary}`);
    expect(timing.ratio, timing.summary).toBeLessThan(LSTAT_FACTOR);
  } finally { removeChain(deepest, chain); }
}), 300_000);

it('RR-111/walk-linux RR-05 2,000 files at depth 1,000 are scanned within a small factor of 2,000 files at the top', async () => temp(async dir => {
  const flat = join(dir, 'flat');
  const chain = join(dir, 'c');
  const deepest = join(chain, ...Array.from({ length: 1_000 }, () => 'd'));
  try {
    for (const where of [flat, deepest]) {
      mkdirSync(where, { recursive: true });
      for (let i = 0; i < 2_000; i++) writeFileSync(join(where, `f${i}.env`), i === 0 ? `X=${readonlyHex}\n` : `X=${i}\n`);
    }
    const expected = { filesScanned: 2_000, findings: 1 };
    const flatMs = await timed(async () => expect((await scan([flat])).summary).toMatchObject(expected));
    const deepMs = await timed(async () => expect((await scan([chain])).summary).toMatchObject(expected));
    expect(deepMs, `flat ${flatMs.toFixed(0)} ms, deep ${deepMs.toFixed(0)} ms`).toBeLessThan(DEPTH_FACTOR * flatMs + DEPTH_SLACK_MS);
  } finally { removeChain(deepest, chain); }
}), 300_000);

function git(dir: string, ...args: string[]): void {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
}

it('RR-111/walk-linux RR-08 case variants of .git and node_modules are ordinary directories on a case-sensitive file system', async () => temp(async dir => {
  for (const name of ['.GIT', 'Node_Modules', '.git', 'node_modules']) {
    mkdirSync(join(dir, name));
    writeFileSync(join(dir, name, 'x.env'), `X=${readonlyHex}\n`);
  }
  const result = await scan([dir]);
  expect(result.findings.map(finding => finding.path)).toEqual([`${dir}/.GIT/x.env`, `${dir}/Node_Modules/x.env`]);
  expect(result.skipped).toEqual([{ path: `${dir}/.git`, reason: 'excluded-dir' }, { path: `${dir}/node_modules`, reason: 'excluded-dir' }]);
}));

it('RR-111/walk-linux RR-08 git history applies the same case-sensitive rule as the walk', async () => temp(async dir => {
  git(dir, 'init', '-q');
  mkdirSync(join(dir, 'Node_Modules'));
  writeFileSync(join(dir, 'Node_Modules', 'x.env'), `X=${readonlyHex}\n`);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'add');
  rmSync(join(dir, 'Node_Modules'), { recursive: true });
  const result = await scan([dir], { gitHistory: true });
  expect(result.findings.map(finding => [finding.path, finding.fingerprint])).toEqual([[`${dir}/Node_Modules/x.env`, readonly.fingerprint]]);
  expect(result.skipped).toEqual([{ path: `${dir}/.git`, reason: 'excluded-dir' }]);
}));
