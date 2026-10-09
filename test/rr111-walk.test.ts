// Portable cases for the 1.1.1 scan walk fixes (robustness review 2026-10-09, RR-04 to RR-14).
// Platform-specific behaviour lives in rr111-walk.linux-fs.test.ts and rr111-walk.windows-fs.test.ts.
import { constants, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { dirname, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as
  { vectors: { name: string; file: string; fingerprint: string; expectedGrade: string }[] };
const readonly = manifest.vectors.find(vector => vector.name === 'default-readonly')!;
const readonlyHex = readFileSync(join(repo, 'test/vectors', readonly.file)).toString('hex');

async function temp<T>(body: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr111-'));
  try { return await body(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

it('RR-111/walk-portable RR-07 a .macwardenignore glob matches the /-separated path below the argument', async () => temp(async dir => {
  mkdirSync(join(dir, 'sub'));
  writeFileSync(join(dir, 'sub', 'a.env'), `X=${readonlyHex}\n`);
  writeFileSync(join(dir, '.macwardenignore'), `${readonly.fingerprint} sub/*.env\n`);
  const result = await scan([dir]);
  expect(result.findings).toEqual([]);
  expect(result.summary.ignored).toBe(1);
}));

// Presents a real regular file's stat as a FIFO's (the injected fs changes only the type).
function asFifo<T extends object>(stat: T): T {
  return Object.assign(stat, { isFile: () => false, isDirectory: () => false, isFIFO: () => true });
}

it('RR-111/walk-portable RR-12 an explicitly named FIFO argument fails with exit 3 instead of passing having scanned nothing', async () => temp(async dir => {
  const named = join(dir, 'pipe.env');
  writeFileSync(named, `X=${readonlyHex}\n`);
  const io = { ...fs, stat: (async (path: string, options?: object) => {
    const stat = await fs.stat(path, options);
    return resolve(path) === resolve(named) ? asFifo(stat) : stat;
  }) as typeof fs.stat };
  await expect(scan([named], { fs: io })).rejects.toMatchObject({ code: 3, stage: 'input-read',
    message: 'scan path is not a regular file or directory' });
  const { run } = await import('../src/commands/scan.js');
  const outcome = await run([named, '--fail-on', 'READ'], { fs: io as unknown as typeof fs });
  expect(outcome).toMatchObject({ ok: false, error: { code: 3, step: 'input-read' } });
}));

it('RR-111/walk-portable RR-12 an explicit file argument that is not regular once opened fails with exit 3', async () => temp(async dir => {
  const named = join(dir, 'swapped.env');
  writeFileSync(named, `X=${readonlyHex}\n`);
  const io = { ...fs, open: (async (path: string, flags: number) => {
    const handle = await fs.open(path, flags);
    const stat = handle.stat.bind(handle);
    return Object.assign(handle, { stat: async (options?: object) => asFifo(await stat(options)) });
  }) as unknown as typeof fs.open };
  await expect(scan([named], { fs: io })).rejects.toMatchObject({ code: 3, stage: 'input-read' });
  // Inside a walked directory the same file is a not-regular skip, as before.
  const walked = await scan([dir], { fs: io });
  expect(walked.skipped).toEqual([{ path: `${dir.replace(/\\/g, '/')}/swapped.env`, reason: 'not-regular' }]);
}));

it('RR-111/walk-portable RR-13 every hard-link name of a file with a finding is reported', async () => temp(async dir => {
  const root = dir.replace(/\\/g, '/');
  mkdirSync(join(dir, 'sub'));
  writeFileSync(join(dir, 'a.env'), `X=${readonlyHex}\n`);
  linkSync(join(dir, 'a.env'), join(dir, 'b.env'));
  linkSync(join(dir, 'a.env'), join(dir, 'sub', 'c.env'));
  const result = await scan([dir]);
  expect(result.findings).toHaveLength(1);
  expect(result.summary).toMatchObject({ filesScanned: 1, findings: 1 });
  const [only] = result.findings;
  // One name holds the finding; the others are its alsoAt. Together they are every name.
  expect([only!.path, ...only!.alsoAt!.paths].sort()).toEqual([`${root}/a.env`, `${root}/b.env`, `${root}/sub/c.env`]);
  expect(only!.alsoAt!.count).toBe(2);
  // Text output names the other paths.
  const text = [...renderChunks({ command: 'scan', ok: true, warnings: [], error: null, result } as OutputResult, 'text')].join('');
  expect(text).toContain(`(same file also at 2 other paths: ${only!.alsoAt!.paths.join(', ')})`);
  // The same file reached through another path argument stays one silent finding (SPEC).
  const across = await scan([join(dir, 'a.env'), join(dir, 'b.env')]);
  expect(across.findings.map(finding => [finding.path, finding.alsoAt])).toEqual([[`${root}/a.env`, undefined]]);
}));

it('RR-111/walk-portable RR-13 ignoring one hard-link name does not hide the credential under another', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.env'), `X=${readonlyHex}\n`);
  linkSync(join(dir, 'a.env'), join(dir, 'b.env'));
  const firstName = (await scan([dir])).findings[0]!.path.split('/').pop()!;
  writeFileSync(join(dir, '.macwardenignore'), `${readonly.fingerprint} ${firstName}\n`);
  expect((await scan([dir])).summary).toMatchObject({ findings: 1, ignored: 0 });
  writeFileSync(join(dir, '.macwardenignore'), `${readonly.fingerprint} *.env\n`);
  expect((await scan([dir])).summary).toMatchObject({ findings: 0, ignored: 1 });
}));

// A file system whose open (or read) of one file never completes, as an open of a FIFO
// without a writer or a stuck network mount would.
function stuckFs(stuck: string, at: 'open' | 'read') {
  let reached: () => void = () => {};
  const blocked = new Promise<void>(resolve => { reached = resolve; });
  const io = { ...fs, open: (async (path: string, flags: number) => {
    if (resolve(path) === resolve(stuck) && at === 'open') { reached(); return new Promise(() => {}); }
    const handle = await fs.open(path, flags);
    if (resolve(path) !== resolve(stuck)) return handle;
    return Object.assign(handle, { read: () => { reached(); return new Promise(() => {}); } });
  }) as unknown as typeof fs.open };
  return { io, blocked };
}

it.each(['open', 'read'] as const)('RR-111/walk-portable RR-04 an interrupt ends a scan whose file %s never completes (exit 6)', async at => temp(async dir => {
  for (let i = 0; i < 40; i++) writeFileSync(join(dir, `f${i}.env`), `X=${i}\n`);
  const stuck = join(dir, 'f7.env');
  const { withCancellation, Cancelled } = await import('../src/cancellation.js');
  {
    const { io, blocked } = stuckFs(stuck, at);
    const controller = new AbortController();
    const pending = withCancellation(controller.signal, () => scan([dir], { fs: io }));
    pending.catch(() => {});
    await blocked;
    const started = performance.now();
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(Cancelled);
    expect(performance.now() - started).toBeLessThan(2_000);
  }
  // The command reports the interrupt as exit 6, step cancelled.
  const { run } = await import('../src/commands/scan.js');
  const { io, blocked } = stuckFs(stuck, at);
  const controller = new AbortController();
  const outcome = withCancellation(controller.signal, () => run([dir, '--fail-on', 'READ'], { fs: io as unknown as typeof fs }));
  await blocked;
  controller.abort();
  expect(await outcome).toMatchObject({ ok: false, error: { code: 6, step: 'cancelled' } });
}));

it('RR-111/walk-portable RR-04 scanned files and the ignore file are opened read-only, non-blocking and no-follow', async () => temp(async dir => {
  writeFileSync(join(dir, 'a.env'), 'X=1\n');
  writeFileSync(join(dir, '.macwardenignore'), '# none\n');
  const flags: number[] = [];
  const io = { ...fs, open: (async (path: string, mode: number) => { flags.push(mode); return fs.open(path, mode); }) as unknown as typeof fs.open };
  await scan([dir], { fs: io });
  const wanted = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0);
  expect(flags).toEqual([wanted, wanted, wanted]);
}));

// RR-05: realpath resolves every component of its path, so calling it per entry made the walk's
// cost grow with the cube of directory depth on Linux. The walk now resolves each path argument
// once and carries resolved paths down; the timing proof is in rr111-walk.linux-fs.test.ts.
it('RR-111/walk-portable RR-05 realpath is called once per path argument, not per walked entry', async () => temp(async dir => {
  const chain = join(dir, 'c');
  const deepest = join(chain, ...Array.from({ length: 300 }, () => 'd'));
  mkdirSync(deepest, { recursive: true });
  for (let i = 0; i < 50; i++) writeFileSync(join(deepest, `f${i}.env`), i === 0 ? `X=${readonlyHex}\n` : `X=${i}\n`);
  const calls = { realpath: 0, lstat: 0 };
  const io = { ...fs,
    realpath: (async (...args: Parameters<typeof fs.realpath>) => { calls.realpath++; return fs.realpath(...args); }) as typeof fs.realpath,
    lstat: (async (...args: Parameters<typeof fs.lstat>) => { calls.lstat++; return fs.lstat(...args); }) as typeof fs.lstat };
  const result = await scan([chain], { fs: io });
  try {
    expect(result.summary).toMatchObject({ filesScanned: 50, findings: 1 });
    expect(result.skipped).toEqual([]);
    expect(calls.realpath).toBe(1);
    // A bounded number of lstat calls per entry: 300 directories and 50 files.
    expect(calls.lstat).toBeLessThanOrEqual(3 * 300 + 4 * 50);
  } finally {
    for (let path = deepest; path.length >= chain.length; path = dirname(path)) rmSync(path, { recursive: true, force: true });
  }
}));

function utf16(text: string, order: 'le' | 'be'): Buffer {
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
  if (order === 'le') return le;
  const be = Buffer.from(le);
  be.swap16();
  return be;
}

it.each(['le', 'be'] as const)('RR-111/walk-portable RR-14 a UTF-16 %s .macwardenignore with a BOM is read', async order => temp(async dir => {
  writeFileSync(join(dir, 'a.env'), `X=${readonlyHex}\n`);
  writeFileSync(join(dir, 'b.env'), `X=${readonlyHex}\n`);
  writeFileSync(join(dir, '.macwardenignore'), utf16(`# written by PowerShell\r\n${readonly.fingerprint} a.env\r\n`, order));
  const result = await scan([dir]);
  expect(result.findings.map(finding => finding.path)).toEqual([`${dir.replace(/\\/g, '/')}/b.env`]);
  expect(result.summary.ignored).toBe(1);
  // --ignore-file decodes the same way.
  const explicit = join(dir, 'explicit.ignore');
  writeFileSync(explicit, utf16(`${readonly.fingerprint}\r\n`, order));
  expect((await scan([dir], { ignoreFile: explicit })).summary).toMatchObject({ findings: 0, ignored: 2 });
}));

it('RR-111/walk-portable RR-14 a leading / anchors a .macwardenignore glob at the argument directory', async () => temp(async dir => {
  mkdirSync(join(dir, 'sub'));
  writeFileSync(join(dir, 'top.env'), `X=${readonlyHex}\n`);
  writeFileSync(join(dir, 'sub', 'top.env'), `X=${readonlyHex}\n`);
  writeFileSync(join(dir, '.macwardenignore'), `${readonly.fingerprint} /top.env\n`);
  const result = await scan([dir]);
  expect(result.findings.map(finding => finding.path)).toEqual([`${dir.replace(/\\/g, '/')}/sub/top.env`]);
  expect(result.summary.ignored).toBe(1);
}));

it('RR-111/walk-portable RR-14 with --ignore-file a leading / anchors at a relative reported path and stays literal for an absolute one', async () => temp(async dir => {
  writeFileSync(join(dir, 'top.env'), `X=${readonlyHex}\n`);
  const argument = relative(process.cwd(), dir).replace(/\\/g, '/');
  const ignore = join(dir, 'explicit.ignore');
  writeFileSync(ignore, `${readonly.fingerprint} /${argument}/top.env\n`);
  expect((await scan([argument], { ignoreFile: ignore })).summary).toMatchObject({ findings: 0, ignored: 1 });
  // The same glob does not match the file reported under a different (absolute) path.
  const absolute = await scan([dir], { ignoreFile: ignore });
  expect(absolute.summary).toMatchObject({ findings: 1, ignored: 0 });
}));
