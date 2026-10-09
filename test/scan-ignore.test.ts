import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const vectors = join(repo, 'test/vectors');
const tempRoot = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = tempRoot;
const vectorManifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const reference = (name: string) => {
  const entry = vectorManifest.vectors.find(item => item.name === name);
  if (!entry) throw new Error(`missing vector manifest entry: ${name}`);
  return entry;
};
const readonly = reference('default-readonly');
const invoice = reference('default-invoice');
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
type Finding = { path: string; line: number | null; column: number | null;
  kind: string; fingerprint: string; grade: string | null };
type Summary = { filesScanned: number; filesSkipped: number; dropped: number; ignored: number;
  findings: number; distinct: number; byGrade: Record<string, number> };
type Envelope = { ok: boolean; result: { findings: Finding[]; summary: Summary;
  failOn: { threshold: string; count: number } | null; ignoredFingerprints?: string[] } | null;
  error: { code: number; step: string | null } | null };
const slash = (path: string) => path.split(sep).join('/');
const projected = (root: string, findings: Finding[]) => findings.map(finding => ({
  path: slash(relative(root, finding.path)), line: finding.line, column: finding.column,
  kind: finding.kind, fingerprint: finding.fingerprint, grade: finding.grade }));

async function scan(args: string[]) {
  const { main } = await import('../src/cli.js');
  const run = await captureMain(main, ['scan', ...args]);
  let value: unknown;
  try { value = JSON.parse(run.stdout); } catch { throw new Error('scan stdout is not one JSON document'); }
  expect(validate(value), `scan output schema: ${JSON.stringify(validate.errors)}`).toBe(true);
  expect(run.stderr).toBe('');
  return { code: run.code, value: value as Envelope };
}
async function inTemp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(tempRoot, { recursive: true });
  const dir = mkdtempSync(join(tempRoot, 'cp012-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function tree(parent: string, name = 'tree') {
  const root = join(parent, name);
  mkdirSync(join(root, 'sub'), { recursive: true });
  const ro = readFileSync(join(vectors, 'default-readonly.macaroon')).toString('hex');
  const inv = readFileSync(join(vectors, 'default-invoice.macaroon')).toString('hex');
  writeFileSync(join(root, 'a.env'), ro);
  writeFileSync(join(root, 'sub/b.env'), ro);
  writeFileSync(join(root, 'c.env'), inv);
  return root;
}
function ignore(root: string, lines: string) { writeFileSync(join(root, '.macwardenignore'), lines); }
function paths(root: string, findings: Finding[]) { return projected(root, findings).map(item => item.path); }

it('CP-012/B1 suppresses bare fingerprint twice and excludes it from fail-on', async () => inTemp(async dir => {
  const root = tree(dir);
  ignore(root, `# accepted\n\n${readonly.fingerprint}\n`);
  const { code, value } = await scan([root, '--json', '--fail-on', 'READ']);
  expect(code).toBe(1);
  expect(value).toMatchObject({ ok: true, error: null,
    result: { failOn: { threshold: 'READ', count: 1 }, summary: {
      ignored: 2, findings: 1, distinct: 1, byGrade: { READ: 0, RECEIVE: 1 } } } });
  expect(projected(root, value.result!.findings)).toEqual([{
    path: 'c.env', line: 1, column: 1, kind: 'macaroon-hex',
    fingerprint: invoice.fingerprint, grade: invoice.expectedGrade }]);
}));

it('CP-012/B2 applies literal, recursive and single-character globs to relative paths', async () => inTemp(async dir => {
  const root = tree(dir);
  for (const [glob, ignored, remaining] of [
    ['a.env', 1, ['c.env', 'sub/b.env']],
    ['**/*.env', 2, ['c.env']],
    ['sub/?.env', 1, ['a.env', 'c.env']],
  ] as const) {
    ignore(root, `${readonly.fingerprint} ${glob}\n`);
    const { code, value } = await scan([root, '--json']);
    expect(code).toBe(0);
    expect(value.result?.summary.ignored).toBe(ignored);
    expect(paths(root, value.result!.findings)).toEqual(remaining);
  }
}));

it('CP-012/B3 rejects each malformed local ignore entry with schema-valid input error', async () => inTemp(async dir => {
  const root = tree(dir);
  for (const line of ['fp:XYZ', 'fp:0123', 'hello']) {
    ignore(root, `${line}\n`);
    const { code, value } = await scan([root, '--json']);
    expect(code).toBe(3);
    expect(value).toMatchObject({ ok: false, result: null, error: { code: 3, step: 'ignore-file' } });
  }
}));

it('CP-012/B4 explicit ignore file replaces local file and distinguishes missing path from missing flag value', async () => inTemp(async dir => {
  const root = tree(dir);
  ignore(root, `${invoice.fingerprint}\n`);
  const elsewhere = join(dir, 'elsewhere'); mkdirSync(elsewhere);
  const file = join(elsewhere, 'ig.txt'); writeFileSync(file, `${readonly.fingerprint}\n`);
  const applied = await scan([root, '--ignore-file', file, '--json']);
  expect(applied.code).toBe(0);
  expect(applied.value.result?.summary).toMatchObject({ ignored: 2, findings: 1 });
  expect(paths(root, applied.value.result!.findings)).toEqual(['c.env']);
  const missing = await scan([root, '--ignore-file', join(elsewhere, 'missing.txt'), '--json']);
  expect(missing.code).toBe(3);
  expect(missing.value).toMatchObject({ ok: false, result: null, error: { code: 3, step: 'input-read', message: 'cannot read ignore file' } });
  writeFileSync(file, 'not-an-ignore-entry\n');
  const malformed = await scan([root, '--ignore-file', file, '--json']);
  expect(malformed.code).toBe(3);
  expect(malformed.value).toMatchObject({ ok: false, result: null, error: { code: 3, step: 'ignore-file' } });
  const noValue = await scan([root, '--json', '--ignore-file']);
  expect(noValue.code).toBe(2);
  expect(noValue.value).toMatchObject({ ok: false, result: null, error: { code: 2, step: null } });
}));

it('CP-012/B5 scopes each local ignore file to its own directory argument', async () => inTemp(async dir => {
  const t1 = join(dir, 'T1'); const t2 = join(dir, 'T2');
  mkdirSync(t1); mkdirSync(t2);
  const ro = readFileSync(join(vectors, 'default-readonly.macaroon')).toString('hex');
  writeFileSync(join(t1, 'a.env'), ro); writeFileSync(join(t2, 'a.env'), ro);
  ignore(t1, `${readonly.fingerprint}\n`);
  const { code, value } = await scan([t1, t2, '--json']);
  expect(code).toBe(0);
  expect(value.result?.summary).toMatchObject({ ignored: 1, findings: 1, distinct: 1 });
  expect(value.result?.findings).toMatchObject([{
    path: slash(join(t2, 'a.env')), fingerprint: readonly.fingerprint, grade: readonly.expectedGrade }]);
}));

it('CP-012/B6 repository root ignore file keeps its committed READ vector scan clean under READ', async () => inTemp(async snapshot => {
  const vectorPath = 'test/vectors/default-readonly.macaroon';
  const bytes = readFileSync(join(repo, vectorPath));
  const fingerprint = `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
  expect(readonly.expectedGrade).toBe('READ');
  expect(fingerprint).toBe(readonly.fingerprint);
  const target = join(snapshot, vectorPath);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  copyFileSync(join(repo, vectorPath), target);
  copyFileSync(join(repo, '.macwardenignore'), join(snapshot, '.macwardenignore'));
  expect(readFileSync(join(snapshot, '.macwardenignore')).equals(readFileSync(join(repo, '.macwardenignore')))).toBe(true);
  const child = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'scan', '.', '--json', '--fail-on', 'READ'],
    { cwd: snapshot, encoding: 'utf8', timeout: 25_000, maxBuffer: 5_000_000, env: childEnvironment() });
  if (child.error || child.signal) throw new Error('Repository scan child failed or exceeded its time budget');
  const value = JSON.parse(child.stdout) as Envelope;
  expect(validate(value), `scan output schema: ${JSON.stringify(validate.errors)}`).toBe(true);
  expect(child.stderr).toBe('');
  const code = child.status;
  expect(code).toBe(0);
  expect(value).toMatchObject({ ok: true, error: null, result: { findings: [] } });
  expect(value.result?.summary.findings).toBe(0);
  expect(value.result?.summary.ignored).toBeGreaterThanOrEqual(1);
  expect(value.result?.failOn).toEqual({ threshold: 'READ', count: 0 });
  expect(value.result?.ignoredFingerprints).toEqual([fingerprint]);
}), 30_000);

it('CP-012/B7 normalizes uppercase fingerprint and strips trailing and whole-line comments', async () => inTemp(async dir => {
  const root = tree(dir);
  ignore(root, `${readonly.fingerprint.slice(0, 3)}${readonly.fingerprint.slice(3).toUpperCase()} a.env   # reviewed\n# ${invoice.fingerprint}\n`);
  const { code, value } = await scan([root, '--json']);
  expect(code).toBe(0);
  expect(value.result?.summary).toMatchObject({ ignored: 1, findings: 2 });
  expect(paths(root, value.result!.findings)).toEqual(['c.env', 'sub/b.env']);
}));

it('CP-012/B8 explicit ignore glob matches the reported relative path', async () => inTemp(async dir => {
  tree(dir);
  const elsewhere = join(dir, 'elsewhere'); mkdirSync(elsewhere);
  const file = join(elsewhere, 'ig.txt');
  writeFileSync(file, `${readonly.fingerprint} tree/sub/*.env\n`);
  const prior = process.cwd();
  try {
    process.chdir(dir);
    const { code, value } = await scan(['tree', '--ignore-file', file, '--json']);
    expect(code).toBe(0);
    expect(value.result?.summary).toMatchObject({ ignored: 1, findings: 2 });
    expect(value.result?.findings.map(finding => finding.path)).toEqual(['tree/a.env', 'tree/c.env']);
  } finally { process.chdir(prior); }
}));
