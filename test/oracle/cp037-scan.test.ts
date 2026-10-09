import { readFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { expect, it } from 'vitest';

type Finding = { path: string; line: number | null; column: number | null;
  kind: string; fingerprint: string; grade: string | null };
type Scan = { findings: Finding[]; skipped: unknown[];
  summary: { findings: number; distinct: number; filesScanned: number }; failOn: unknown };
const repo = resolve();
const fixtures = join(repo, 'test/scan-fixtures/cp037');
const manifest = JSON.parse(readFileSync(join(fixtures, 'manifest.json'), 'utf8')) as {
  files: { path: string; encoding: string; findings: Omit<Finding, 'path'>[] }[] };
const slash = (path: string) => path.split(sep).join('/');

const scanner = () => import('../../src/scan/index.js') as Promise<{
  scan: (paths: string[], options: object) => Promise<Scan> }>;

it('CP-037/scan-independent-manifest committed Unicode positions match literal fixture manifest', async () => {
  const { scan } = await scanner();
  for (const entry of manifest.files) {
    const path = join(fixtures, entry.path);
    const result = await scan([path], {});
    const projected = result.findings.map(finding => ({
      path: slash(finding.path), line: finding.line, column: finding.column,
      kind: finding.kind, fingerprint: finding.fingerprint, grade: finding.grade,
    }));
    expect(projected).toEqual(entry.findings.map(finding => ({ path: slash(path), ...finding })));
    expect(result.summary.findings).toBe(entry.findings.length);
    expect(result.summary.distinct).toBe(1);
    expect(result.summary.filesScanned).toBe(1);
    expect(result.skipped).toEqual([]);
    expect(result.failOn).toBeNull();
  }
});
