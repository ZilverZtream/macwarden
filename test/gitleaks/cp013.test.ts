import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { runGitleaks, type Hit } from './run.js';
import { repo } from './rules-support.js';

type Item = { path: string; line?: number; kind?: string; status: 'expected' | 'excluded'; reason?: string };
type Manifest = { files: Array<{ path: string; findings: Array<{ line: number | null; kind: string }> }> };

const expected = JSON.parse(readFileSync(resolve(repo, 'test/gitleaks/expected.json'), 'utf8')) as { items: Item[] };
const source = JSON.parse(readFileSync(resolve(repo, 'test/scan-fixtures/full/manifest.json'), 'utf8')) as Manifest;
let outcome: { hits: Hit[] } | { error: Error } | undefined;
function observed(): Hit[] {
  if (!outcome) {
    try { outcome = { hits: runGitleaks() }; }
    catch (error) { outcome = { error: error as Error }; }
  }
  if ('error' in outcome) throw outcome.error;
  return outcome.hits;
}

function key(path: string, line: number | null, kind: string): string {
  return `${path}:${line ?? '-'}:${kind}`;
}

function pathOf(hit: Hit): string {
  return hit.File.replace(/\\/g, '/').replace(/^.*\/tree\//, '');
}

it('CP-013/gitleaks-expected pinned gitleaks finds every independently planted text item', () => {
  const planted = source.files.flatMap(file => file.findings.map(finding =>
    key(file.path, finding.line, finding.kind)));
  const marked = expected.items.map(item => key(item.path, item.line ?? null,
    item.kind ?? (item.status === 'excluded' ? 'macaroon-file' : '')));
  expect(marked.sort()).toEqual(planted.sort());
  expect(expected.items.filter(item => item.status === 'excluded').every(item =>
    item.path.endsWith('.macaroon') && Boolean(item.reason))).toBe(true);
  const wanted = expected.items.filter(item => item.status === 'expected');
  expect(wanted).toHaveLength(12);
  const found = new Set(observed().map(hit => key(pathOf(hit), hit.StartLine,
    hit.RuleID.replace(/^macwarden-/, ''))));
  for (const item of wanted) expect(found.has(key(item.path, item.line!, item.kind!)),
    `${item.path}:${item.line} macwarden-${item.kind}`).toBe(true);
  const expectedKeys = new Set(wanted.map(item => key(item.path, item.line!, item.kind!)));
  const extras = [...found].filter(item => !expectedKeys.has(item));
  if (extras.length) console.info(`CP-013/gitleaks-expected extra hits: ${extras.join(', ')}`);
});

it('CP-013/gitleaks-report-redacted report and process output contain no fixture credentials', () => {
  const findings = observed();
  expect(findings.length).toBeGreaterThan(0);
  for (const hit of findings) {
    expect(hit.Secret, `${pathOf(hit)}:${hit.StartLine} Secret`).toContain('REDACTED');
    expect(hit.Match, `${pathOf(hit)}:${hit.StartLine} Match`).toContain('REDACTED');
  }
});
