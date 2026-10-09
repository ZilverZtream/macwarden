import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import { findLeaks } from "../helpers/leak-check.js";
import { captureMain } from '../support/capture.js';

const repo = resolve();
const fixtureRoot = join(repo, 'test/scan-fixtures');
const vectorRoot = join(repo, 'test/vectors');
const tmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = tmp;
const vectorManifest = JSON.parse(readFileSync(join(vectorRoot, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const reference = (name: string) => vectorManifest.vectors.find(entry => entry.name === name)!;
const schema = JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8'));
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(schema);
const slash = (path: string) => path.split(sep).join('/');
const fp = (bytes: Buffer) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
function entries(root: string, at = root): string[] {
  return readdirSync(at).flatMap(name => {
    const path = join(at, name);
    return statSync(path).isDirectory() ? [slash(relative(root, path)), ...entries(root, path)]
      : [slash(relative(root, path))];
  });
}
async function scan(root: string) {
  const { main } = await import('../../src/cli.js');
  const run = await captureMain(main, ['scan', root, '--json']);
  expect(run.code).toBe(0);
  expect(run.stderr).toBe('');
  let value: unknown;
  try { value = JSON.parse(run.stdout); } catch { throw new Error('scan stdout is not one JSON document'); }
  expect(validate(value)).toBe(true);
  return value as { ok: boolean; result: { findings: Array<{ path: string; line: number | null;
    column: number | null; kind: string; fingerprint: string; grade: string | null }>;
    skipped: { path: string; reason: string }[]; summary: object; failOn: unknown } };
}
function projected(root: string, value: Awaited<ReturnType<typeof scan>>) {
  return value.result.findings.map(finding => ({ path: slash(relative(root, finding.path)),
    line: finding.line, column: finding.column, kind: finding.kind,
    fingerprint: finding.fingerprint, grade: finding.grade }));
}

it('CP-011/full-manifest planted fixture tree equals independent literal manifest', async () => {
  const root = join(fixtureRoot, 'full');
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
    files: { path: string; findings: { line: number | null; column: number | null;
      kind: string; fingerprint: string; grade: string | null }[] }[];
    skipped: { path: string; reason: string }[]; summary: { filesScanned: number;
      filesSkipped: number; findings: number; distinct: number; dropped: number; ignored: number } };
  expect(entries(root).sort()).toEqual([...manifest.files.map(file => file.path),
    ...manifest.skipped.map(item => item.path), 'node_modules/x.env'].sort());
  const names = new Map([['admin.macaroon', 'default-admin'], ['ro.macaroon', 'default-readonly'],
    ['inv.macaroon', 'default-invoice']]);
  for (const file of manifest.files) for (const finding of file.findings) {
    const name = names.get(file.path) || ({ 'macaroon-hex': 'default-readonly',
      'macaroon-base64': 'default-invoice', lndconnect: 'preset-pay-only' } as Record<string, string>)[finding.kind];
    if (name) {
      expect(finding.fingerprint).toBe(reference(name).fingerprint);
      expect(finding.grade).toBe(reference(name).expectedGrade);
    } else if (finding.kind === 'nwc') {
      expect(finding.fingerprint).toBe(fp(Buffer.alloc(32, 0x11)));
      expect(finding.grade).toBeNull();
    }
    if (finding.line !== null && finding.column !== null) {
      const lines = readFileSync(join(root, file.path), 'utf8').split(/\r\n|\n|\r/);
      const planted = lines[finding.line - 1].slice(finding.column - 1);
      const prefix = finding.kind === 'macaroon-hex'
        ? readFileSync(join(vectorRoot, 'default-readonly.macaroon')).toString('hex')
        : finding.kind === 'macaroon-base64'
          ? readFileSync(join(vectorRoot, 'default-invoice.macaroon')).toString('base64')
          : finding.kind === 'lndconnect'
            ? `lndconnect://h:10009?macaroon=${readFileSync(join(vectorRoot, 'preset-pay-only.macaroon')).toString('base64url')}`
            : `nostr+walletconnect://${'22'.repeat(32)}?secret=${'11'.repeat(32)}`;
      expect(planted.startsWith(prefix), 'manifest position must point at the planted item').toBe(true);
    }
  }
  expect(manifest.files.filter(file => file.path.endsWith('.macaroon'))).toHaveLength(3);
  for (const file of ['app.env', 'app.yml', 'app.json'])
    expect(manifest.files.find(entry => entry.path === file)?.findings.map(f => f.kind))
      .toEqual(['macaroon-hex', 'macaroon-base64', 'lndconnect', 'nwc']);
  expect(manifest.files.length).toBe(manifest.summary.filesScanned);
  expect(manifest.skipped.length).toBe(manifest.summary.filesSkipped);
  expect(manifest.skipped.map(item => item.reason)).toEqual(['binary', 'excluded-dir', 'never-open']);
  expect(readFileSync(join(root, 'binary.dat')).includes(0)).toBe(true);
  expect(manifest.files.flatMap(file => file.findings)).toHaveLength(manifest.summary.findings);
  expect(new Set(manifest.files.flatMap(file => file.findings.map(f => f.fingerprint))).size)
    .toBe(manifest.summary.distinct);
  const value = await scan(root);
  expect(value.ok).toBe(true);
  expect(projected(root, value)).toEqual(manifest.files.flatMap(file =>
    file.findings.map(finding => ({ path: file.path, ...finding }))));
  expect(value.result.skipped.map(item => ({ path: slash(relative(root, item.path)), reason: item.reason })))
    .toEqual(manifest.skipped);
  expect(value.result.summary).toEqual(manifest.summary);
  expect(value.result.failOn).toBeNull();
});

it('CP-011/lookalike-manifest decoys yield no findings and literal dropped count', async () => {
  const root = join(fixtureRoot, 'lookalike');
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
    files: { path: string; findings: unknown[]; dropped: number }[];
    skipped: unknown[]; summary: { dropped: number } };
  expect(entries(root).sort()).toEqual(manifest.files.map(file => file.path).sort());
  expect(manifest.files.every(file => file.findings.length === 0)).toBe(true);
  expect(manifest.files.reduce((count, file) => count + file.dropped, 0)).toBe(manifest.summary.dropped);
  const value = await scan(root);
  expect(value.result.findings).toEqual([]);
  expect(value.result.skipped).toEqual(manifest.skipped);
  expect(value.result.summary).toEqual(manifest.summary);
});

it('CP-011/leak-check fixture output excludes all registered sentinels', async () => {
  mkdirSync(tmp, { recursive: true });
  const dir = mkdtempSync(join(tmp, 'cp011-oracle-'));
  try {
    const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
    for (const name of ['default-admin', 'default-readonly', 'default-invoice', 'preset-pay-only'])
      writeFileSync(join(sentinelDir, `${name}.macaroon`), readFileSync(join(vectorRoot, `${name}.macaroon`)));
    writeFileSync(join(sentinelDir, 'nwc.bin'), Buffer.alloc(32, 0x11));
    const root = join(fixtureRoot, 'full');
    const { main } = await import('../../src/cli.js');
    const run = await captureMain(main, ['scan', root, '--json']);
    expect(run.code).toBe(0);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: run.stdout + run.stderr, testTmp: tmp, root: repo }), 'credential leaked').toBeNull();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
