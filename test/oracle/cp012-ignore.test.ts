import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { captureMain } from '../support/capture.js';

const repo = resolve();
const root = join(repo, 'test/scan-fixtures/ignore');
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
  files: { path: string; findings: { line: number; column: number; kind: string;
    fingerprint: string; grade: string; ignored: boolean }[] }[];
  skipped: unknown[];
  summary: { filesScanned: number; filesSkipped: number; dropped: number; ignored: number;
    findings: number; distinct: number; byGrade: Record<string, number> };
  failOn: { threshold: string; count: number } };
const vectors = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const reference = (name: string) => {
  const entry = vectors.vectors.find(item => item.name === name);
  if (!entry) throw new Error(`missing vector manifest entry: ${name}`);
  return entry;
};
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const slash = (path: string) => path.split(sep).join('/');
function entries(at = root): string[] {
  return readdirSync(at).flatMap(name => {
    const path = join(at, name);
    return statSync(path).isDirectory() ? entries(path) : [slash(relative(root, path))];
  });
}
async function scan(flags: string[]) {
  const { main } = await import('../../src/cli.js');
  const run = await captureMain(main, ['scan', root, '--json', ...flags]);
  let value: unknown;
  try { value = JSON.parse(run.stdout); } catch { throw new Error('scan stdout is not one JSON document'); }
  expect(validate(value), `scan output schema: ${JSON.stringify(validate.errors)}`).toBe(true);
  expect(run.stderr).toBe('');
  return { code: run.code, value: value as { ok: boolean; error: unknown; result: {
    findings: { path: string; line: number; column: number; kind: string;
      fingerprint: string; grade: string }[];
    skipped: unknown[]; summary: object; failOn: unknown } } };
}

it('CP-012/ignore-manifest committed fixture and scan equal independent ignore expectations', async () => {
  expect(entries().sort()).toEqual(manifest.files.map(file => file.path).sort());
  const ro = reference('default-readonly');
  const inv = reference('default-invoice');
  expect(manifest.files.filter(file => file.findings.some(finding => finding.ignored)).map(file => file.path))
    .toEqual(['a.env', 'sub/b.env']);
  for (const [path, vector, ignored] of [
    ['a.env', 'default-readonly', true],
    ['c.env', 'default-invoice', false],
    ['sub/b.env', 'default-readonly', true],
  ] as const) {
    const entry = manifest.files.find(file => file.path === path);
    const expected = reference(vector);
    expect(entry?.findings).toEqual([{ line: 1, column: 1, kind: 'macaroon-hex',
      fingerprint: expected.fingerprint, grade: expected.expectedGrade, ignored }]);
    expect(readFileSync(join(root, path), 'utf8').trim())
      .toBe(readFileSync(join(repo, 'test/vectors', `${vector}.macaroon`)).toString('hex'));
  }
  expect(readFileSync(join(root, '.macwardenignore'), 'utf8')).toContain(ro.fingerprint);
  expect(manifest.summary.ignored).toBe(2);
  expect(manifest.summary.findings).toBe(1);
  expect(manifest.summary.byGrade.RECEIVE).toBe(1);
  expect(manifest.files.find(file => file.path === 'c.env')?.findings[0].fingerprint).toBe(inv.fingerprint);
  const expectedFindings = manifest.files.flatMap(file => file.findings.filter(finding => !finding.ignored)
    .map(finding => ({ path: file.path, line: finding.line, column: finding.column,
      kind: finding.kind, fingerprint: finding.fingerprint, grade: finding.grade })));
  for (const [flags, code, failOn] of [
    [[], 0, null],
    [['--fail-on', 'READ'], 1, manifest.failOn],
  ] as const) {
    const run = await scan([...flags]);
    expect(run.code).toBe(code);
    expect(run.value).toMatchObject({ ok: true, error: null });
    expect(run.value.result.summary).toEqual(manifest.summary);
    expect(run.value.result.skipped).toEqual(manifest.skipped);
    expect(run.value.result.findings.map(({ path, line, column, kind, fingerprint, grade }) => ({
      path: slash(relative(root, path)), line, column, kind, fingerprint, grade,
    }))).toEqual(expectedFindings);
    expect(run.value.result.failOn).toEqual(failOn);
  }
});
