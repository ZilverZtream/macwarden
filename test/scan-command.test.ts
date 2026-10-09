import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';
import { findLeaks } from "./helpers/leak-check.js";

const networkCalls = vi.hoisted(() => [] as string[]);
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https') & { default: typeof import('node:https') }>();
  const blocked = () => { networkCalls.push('https'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:http', async importOriginal => {
  const original = await importOriginal<typeof import('node:http') & { default: typeof import('node:http') }>();
  const blocked = () => { networkCalls.push('http'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:net', async importOriginal => {
  const original = await importOriginal<typeof import('node:net') & { default: typeof import('node:net') }>();
  const blocked = () => { networkCalls.push('net'); throw new Error('network called'); };
  return { ...original, connect: blocked, createConnection: blocked,
    default: { ...original.default, connect: blocked, createConnection: blocked } };
});

type Finding = { path: string; line: number | null; column: number | null; kind: string;
  fingerprint: string; grade: string | null; rootKeyId: string | null;
  permissions: string[] | null; caveats: unknown[] | null; warnings: string[]; unassessed: string[] };
type Summary = { filesScanned: number; filesSkipped: number; dropped: number; ignored: number;
  findings: number; distinct: number; byGrade: Record<string, number> };
type Result = { findings: Finding[]; skipped: { path: string; reason: string }[];
  summary: Summary; failOn: { threshold: string; count: number } | null };
type Envelope = { schema: number; command: string; ok: boolean; warnings: string[];
  result: Result | null; error: { code: number; step: string | null; message: string } | null };
const repo = resolve();
const fixtures = join(repo, 'test/scan-fixtures');
const vectors = join(repo, 'test/vectors');
const tempRoot = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = tempRoot;
const vector = (name: string) => readFileSync(join(vectors, `${name}.macaroon`));
const full = JSON.parse(readFileSync(join(fixtures, 'full/manifest.json'), 'utf8')) as {
  files: { path: string; findings: Omit<Finding, 'path' | 'rootKeyId' | 'permissions' | 'caveats' | 'warnings' | 'unassessed'>[] }[];
  skipped: { path: string; reason: string }[]; summary: Summary };
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const slash = (path: string) => path.split(sep).join('/');
const fingerprint = (bytes: Buffer | string) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
const project = (finding: Finding) => ({ path: slash(finding.path), line: finding.line,
  column: finding.column, kind: finding.kind, fingerprint: finding.fingerprint, grade: finding.grade });
const main = async (args: string[]) => (await import('../src/cli.js')).main(args);
async function cli(args: string[]) { return captureMain(main, ['scan', ...args]); }
function document(run: Awaited<ReturnType<typeof cli>>): Envelope {
  let value: unknown;
  try { value = JSON.parse(run.stdout); } catch { throw new Error('scan stdout is not one JSON document'); }
  expect(validate(value), 'scan schema validation').toBe(true);
  expect(run.stderr).toBe('');
  return value as Envelope;
}
function cleanTemp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(tempRoot, { recursive: true });
  const dir = mkdtempSync(join(tempRoot, 'cp011-'));
  return work(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}
function put(dir: string, name: string, bytes: string | Buffer) {
  const path = join(dir, name);
  writeFileSync(path, bytes);
  return path;
}
function b1Tree(dir: string) {
  for (const name of ['admin.macaroon', 'ro.macaroon', 'inv.macaroon', 'app.env', 'app.yml', 'app.json'])
    copyFileSync(join(fixtures, 'full', name), join(dir, name));
  return dir;
}
const b1Summary = { ...full.summary, filesScanned: 6, filesSkipped: 0 };

it('CP-011/B1 scans all planted kinds with exact JSON summary and schema', async () => cleanTemp(async dir => {
  b1Tree(dir);
  const run = await cli([dir, '--json']);
  expect(run.code).toBe(0);
  const value = document(run);
  expect(value).toMatchObject({ command: 'scan', ok: true, error: null });
  expect(value.result?.summary).toEqual(b1Summary);
  expect(value.result?.failOn).toBeNull();
  expect(value.result?.findings.map(f => ({ ...project(f), path: slash(relative(dir, f.path)) })))
    .toEqual(full.files.filter(file => file.path !== 'manifest.json').flatMap(file =>
      file.findings.map(finding => ({ path: file.path, ...finding }))));
}));

it('CP-011/B2 counts each ladder threshold and exits one with a successful envelope', async () => cleanTemp(async dir => {
  b1Tree(dir);
  for (const [grade, count] of [['ADMIN', 1], ['SPEND', 7], ['OPERATE', 7], ['RECEIVE', 11], ['READ', 15]] as const) {
    const run = await cli([dir, '--json', '--fail-on', grade]);
    expect(run.code).toBe(1);
    const value = document(run);
    expect(value).toMatchObject({ ok: true, error: null, result: { failOn: { threshold: grade, count } } });
  }
}));

it('CP-011/B3 ignores lower grades under SPEND and counts OPERATE at its rung', async () => cleanTemp(async dir => {
  const operate = put(dir, 'operate.env', vector('grade-peers-pair').toString('hex'));
  const low = put(dir, 'low.env', `${vector('default-readonly').toString('hex')}\n${vector('default-invoice').toString('base64')}`);
  for (const [path, grade, count, code] of [[operate, 'SPEND', 0, 0], [low, 'SPEND', 0, 0],
    [operate, 'OPERATE', 1, 1]] as const) {
    const run = await cli([path, '--json', '--fail-on', grade]);
    expect(run.code).toBe(code);
    expect(document(run).result?.failOn).toEqual({ threshold: grade, count });
  }
}));

it('CP-011/B4 fails closed for unassessed, candidates, undecodable files and NWC', async () => cleanTemp(async dir => {
  const unassessed = put(dir, 'unassessed.env', vector('grade-unknown-entity').toString('hex'));
  const base64 = vector('default-admin').toString('base64');
  const candidate = put(dir, 'candidate.env', `${base64.slice(0, 76)}\n${base64.slice(76)}`);
  const bad = put(dir, 'bad.macaroon', 'not a macaroon');
  const nwc = put(dir, 'nwc.env', `nostr+walletconnect://${'22'.repeat(32)}?secret=${'11'.repeat(32)}`);
  for (const [path, bucket] of [[unassessed, 'UNASSESSED'], [candidate, 'UNDECODABLE'],
    [bad, 'UNDECODABLE']] as const) {
    const run = await cli([path, '--json', '--fail-on', 'ADMIN']);
    expect(run.code).toBe(1);
    const result = document(run).result!;
    expect(result.failOn?.count).toBe(1);
    expect(result.summary.byGrade[bucket]).toBe(1);
  }
  for (const [grade, count, code] of [['ADMIN', 0, 0], ['SPEND', 1, 1]] as const) {
    const run = await cli([nwc, '--json', '--fail-on', grade]);
    expect(run.code).toBe(code);
    expect(document(run).result?.failOn).toEqual({ threshold: grade, count });
  }
}));

it('CP-011/B5 reports wrapped candidate and drops undecodable URI once', async () => cleanTemp(async dir => {
  const base64 = vector('default-admin').toString('base64');
  put(dir, 'wrapped.env', `${base64.slice(0, 76)}\n${base64.slice(76)}`);
  put(dir, 'uri.env', 'lndconnect://h:1?macaroon=AAAA');
  const run = await cli([dir, '--json', '--fail-on', 'ADMIN']);
  expect(run.code).toBe(1);
  const result = document(run).result!;
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({ kind: 'undecodable-candidate', fingerprint: fingerprint(base64.slice(0, 76)) });
  expect(result.summary).toMatchObject({ dropped: 1, byGrade: { UNDECODABLE: 1 } });
}));

it('CP-011/B6 rejects unknown, missing and repeated fail-on flags and accepts a grade in any case', async () => cleanTemp(async dir => {
  b1Tree(dir);
  for (const flags of [['--fail-on', 'UNASSESSED'], ['--fail-on'],
    ['--fail-on', 'SPEND', '--fail-on', 'ADMIN'], ['--frob']]) {
    const run = await cli([dir, ...flags, '--json']);
    expect(run.code).toBe(2);
    expect(document(run)).toMatchObject({ command: 'scan', ok: false, result: null,
      error: { code: 2, step: null } });
  }
  const upper = await cli([dir, '--fail-on', 'SPEND', '--json']);
  const lower = await cli([dir, '--fail-on', 'spend', '--json']);
  expect(lower.code).toBe(upper.code);
  expect(document(lower)).toEqual(document(upper));
  expect(document(lower).result!.failOn).toMatchObject({ threshold: 'SPEND' });
}));

it('CP-011/B7 missing path fails input-read and an injected unreadable file is skipped', async () => cleanTemp(async dir => {
  const missing = await cli([join(dir, 'missing'), '--json']);
  expect(missing.code).toBe(3);
  expect(document(missing)).toMatchObject({ ok: false, error: { code: 3, step: 'input-read', message: 'cannot read scan path' } });
  b1Tree(dir);
  const blocked = join(dir, 'app.env');
  const injected = { ...fs, open: vi.fn(async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]) === blocked) throw Object.assign(new Error('access refused'), { code: 'EACCES' });
    return fs.open(...args);
  }) };

  const command = await import('../src/commands/scan.js') as {
    run: (args: string[], deps: { fs: typeof fs }) => Promise<Envelope> };
  const value = await command.run([dir, '--json'], { fs: injected });
  expect(value).toMatchObject({ ok: true, error: null,
    result: { skipped: expect.arrayContaining([{ path: slash(blocked), reason: 'unreadable' }]) } });
}));

it('CP-011/B8 defaults to cwd and reports paths without a dot prefix', async () => cleanTemp(async dir => {
  b1Tree(dir);
  const prior = process.cwd();
  try {
    process.chdir(dir);
    const run = await cli(['--json']);
    expect(run.code).toBe(0);
    const result = document(run).result!;
    expect(result.summary).toEqual(b1Summary);
    expect(result.findings.map(f => f.path)).toContain('app.env');
    expect(result.findings.every(f => !f.path.startsWith('./'))).toBe(true);
  } finally { process.chdir(prior); }
}));

it('CP-011/B9 renders one safe text line per finding and exact summary line', async () => cleanTemp(async dir => {
  b1Tree(dir);
  for (const [flags, summary] of [[[], '15 findings (5 distinct) in 6 files; 0 skipped; 0 ignored'],
    [['--fail-on', 'SPEND'], '15 findings (5 distinct) in 6 files; 0 skipped; 0 ignored; 7 at or above SPEND']] as const) {
    const run = await cli([dir, ...flags]);
    expect(run.code).toBe(flags.length ? 1 : 0);
    const lines = run.stdout.trimEnd().split(/\r?\n/);
    expect(lines).toHaveLength(16);
    expect(lines.at(-1)).toBe(summary);
    for (const line of lines.slice(0, -1)) {
      expect(line).toContain('fp:');
      expect(line).toMatch(/(macaroon-|lndconnect|nwc)/);
    }
    expect(lines.filter(line => line.includes('nwc')).every(line => line.includes('(counted as SPEND)'))).toBe(true);
  }
}));

it('CP-011/B10 text and JSON scan output pass the standing sentinel leak check', async () => cleanTemp(async dir => {
  const tree = join(dir, 'tree'); mkdirSync(tree); b1Tree(tree);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  for (const name of ['default-admin', 'default-readonly', 'default-invoice', 'preset-pay-only'])
    copyFileSync(join(vectors, `${name}.macaroon`), join(sentinelDir, `${name}.macaroon`));
  writeFileSync(join(sentinelDir, 'nwc.bin'), Buffer.alloc(32, 0x11));
  for (const flags of [['--json'], ['--json', '--fail-on', 'SPEND'], [], ['--fail-on', 'SPEND']]) {
    const run = await cli([tree, ...flags]);
    expect([0, 1]).toContain(run.code);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: run.stdout + run.stderr, testTmp: tempRoot, root: repo }), 'credential leaked').toBeNull();
  }
}));

it('CP-011/B11 repeats byte-identically without network or filesystem writes', async () => cleanTemp(async dir => {
  b1Tree(dir);
  const names = readdirSync(dir);
  const before = names.map(name => [name, readFileSync(join(dir, name)), statSync(join(dir, name)).mtimeMs] as const);
  networkCalls.length = 0;
  const one = await cli([dir, '--json']);
  const two = await cli([dir, '--json']);
  expect(one.code).toBe(0);
  expect(two.code).toBe(0);
  expect(one.stdout).toBe(two.stdout);
  expect(networkCalls).toEqual([]);
  for (const [name, bytes, mtime] of before) {
    expect(readFileSync(join(dir, name)).equals(bytes)).toBe(true);
    expect(statSync(join(dir, name)).mtimeMs).toBe(mtime);
  }
}));
