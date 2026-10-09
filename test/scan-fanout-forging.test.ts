import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { render, type OutputResult } from '../src/output/index.js';
import { childEnvironment } from './helpers/environment.js';
import { captureMain } from './support/capture.js';

// Red-team round 2 (2026-10-08): attacker-controlled git history and file names.
// Titles use the SCAN/ prefix: no checkpoint contract owns these cases.
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const ajv = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false });
const scanSchema = ajv.compile(JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));

function git(dir: string, input: string | null, ...args: string[]): string {
  const run = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8', input: input ?? undefined, maxBuffer: 64 << 20 });
  if (run.status !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr}`);
  return run.stdout.trim();
}

function temp(): string {
  mkdirSync(testTmp, { recursive: true });
  return mkdtempSync(join(testTmp, 'scan-fanout-'));
}

/** K distinct read-only macaroons (only the signature differs), one base64 line each. */
function credentials(k: number): string {
  const base = readFileSync(join(vectors, 'default-readonly.macaroon'));
  const lines: string[] = [];
  for (let i = 0; i < k; i++) {
    const copy = Buffer.from(base);
    copy.writeUInt16BE(i, copy.length - 2);
    lines.push(copy.toString('base64'));
  }
  return lines.join('\n') + '\n';
}

/**
 * A repository whose history added one blob of K credentials at N paths in one commit
 * (cheap tree entries pointing at the same content) and removed them in the next.
 */
function fanOutRepository(k: number, n: number): string {
  const dir = temp();
  git(dir, null, 'init', '-q');
  writeFileSync(join(dir, 'README'), 'hi\n');
  git(dir, null, 'add', '-A');
  git(dir, null, 'commit', '-q', '-m', 'init');
  writeFileSync(join(dir, '..', `${dir.split(/[\\/]/).pop()}.blob`), credentials(k));
  const blob = git(dir, null, 'hash-object', '-w', join(dir, '..', `${dir.split(/[\\/]/).pop()}.blob`));
  const entries = Array.from({ length: n }, (_, i) => `100644 blob ${blob}\tf${String(i + 1).padStart(6, '0')}.txt\n`).join('');
  const sub = git(dir, entries, 'mktree');
  const root = git(dir, `${git(dir, null, 'ls-tree', 'HEAD')}\n040000 tree ${sub}\td\n`, 'mktree');
  const added = git(dir, null, 'commit-tree', root, '-p', 'HEAD', '-m', 'add');
  const removed = git(dir, null, 'commit-tree', git(dir, null, 'rev-parse', 'HEAD^{tree}'), '-p', added, '-m', 'remove');
  git(dir, null, 'reset', '-q', '--hard', removed);
  return dir;
}

async function scanJson(args: string[]) {
  const { main } = await import('../src/cli.js');
  const run = await captureMain(main, ['scan', ...args, '--json']);
  return { code: run.code, document: JSON.parse(run.stdout) as { ok: boolean; error: unknown;
    result: { findings: { path: string; fingerprint: string; alsoAt?: { count: number; paths: string[] } }[];
      summary: { findings: number; ignored: number } } } };
}

it('SCAN/history-fanout one blob added at many paths is one finding per credential with an alsoAt count', async () => {
  const dir = fanOutRepository(50, 200);
  try {
    const started = performance.now();
    const { code, document } = await scanJson([dir, '--git-history']);
    expect(code).toBe(0);
    expect(scanSchema(document), JSON.stringify(scanSchema.errors)).toBe(true);
    // Before the fix: 50 x 200 = 10,000 findings, growing with paths x credentials.
    expect(document.result.summary.findings).toBe(50);
    expect(new Set(document.result.findings.map(finding => finding.fingerprint)).size).toBe(50);
    for (const finding of document.result.findings) {
      expect(finding.path.replaceAll('\\', '/')).toMatch(/\/d\/f000001\.txt$/);
      expect(finding.alsoAt?.count).toBe(199);
      expect(finding.alsoAt?.paths).toHaveLength(5);
    }
    expect(performance.now() - started).toBeLessThan(30_000);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 60_000);

it('SCAN/history-fanout an ignore entry drops a multi-path finding only when every path is known and ignored', async () => {
  for (const [paths, dropped] of [[3, true], [8, false]] as const) {
    const dir = fanOutRepository(1, paths);
    try {
      const { document: first } = await scanJson([dir, '--git-history']);
      const fingerprint = first.result.findings[0].fingerprint;
      writeFileSync(join(dir, '.macwardenignore'), `${fingerprint} d/*\n`);
      const { document } = await scanJson([dir, '--git-history']);
      // Three paths: all are listed and all match, so the finding is ignored. Eight: only five
      // of the seven other paths are listed, so it cannot be proven ignored and stays (fail closed).
      expect(document.result.summary.ignored).toBe(dropped ? 1 : 0);
      expect(document.result.summary.findings).toBe(dropped ? 0 : 1);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}, 60_000);

it('SCAN/findings-limit a scan that would exceed 250,000 findings fails closed with exit 3 and a named step', () => {
  const dir = temp();
  try {
    // Four files of 75,000 credential-shaped lines (68 bytes each, under the 5 MiB file limit): 300,000 findings.
    const line = `LND_MACAROON=0201036c6e6402${'a'.repeat(40)}\n`;
    const content = line.repeat(75_000);
    for (const name of ['a.env', 'b.env', 'c.env', 'd.env']) writeFileSync(join(dir, name), content);
    const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'scan', dir, '--fail-on', 'READ'],
      { env: childEnvironment(), encoding: 'utf8', stdio: ['ignore', 'ignore', 'pipe'], timeout: 120_000, windowsHide: true });
    expect(run.status).toBe(3);
    expect(run.stderr).toMatch(/findings-limit: more than 250,000 findings/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 180_000);

const finding = (path: string) => ({ path, line: 1, column: 7, kind: 'macaroon-hex', fingerprint: 'fp:0123456789abcdef',
  grade: 'READ', rootKeyId: '0', permissions: [], caveats: [], warnings: [], unassessed: [] });
const scanResult = (paths: string[]) => ({ command: 'scan', ok: true, warnings: [], error: null, result: {
  findings: paths.map(finding), skipped: [],
  summary: { findings: paths.length, distinct: 1, filesScanned: paths.length, filesSkipped: 0, ignored: 0 }, failOn: null } }) as unknown as OutputResult;
// Lines a GitHub Actions runner would treat as workflow commands: optional Unicode
// whitespace (the runner trims it) followed by '::', or the legacy '##[' marker anywhere.
const forged = (text: string) => text.split('\n').some(line => /^[\s\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*::/.test(line) || line.includes('##['));

it('SCAN/output-forging scanned file names cannot produce workflow commands in text output', () => {
  const names = [' ::error file=README.md,line=1::No credentials found', '\u00a0::stop-commands::x', '\u3000::add-mask::secret',
    'a##[warning]forged', 'x\u2028::add-mask::y', '::set-output name=a::b', '\ufeff::error::bom'];
  const text = render(scanResult(names), 'text');
  expect(forged(text)).toBe(false);
  expect(text.split('\n').filter(line => line.includes('macaroon-hex'))).toHaveLength(names.length);
});

it('SCAN/output-forging every text rendering guards line starts and the legacy marker', () => {
  const forgedText = { command: null, ok: true, warnings: [], error: null, result: { text: '::stop-commands::x\n  ::error::y\nok ##[warning]z' } } as unknown as OutputResult;
  expect(forged(render(forgedText, 'text'))).toBe(false);
  const failure = { command: 'scan', ok: false, warnings: [], result: null,
    error: { code: 3, step: 'input-read', message: 'cannot read ::add-mask::x ##[error]y' } } as unknown as OutputResult;
  expect(forged(render(failure, 'text'))).toBe(false);
});
