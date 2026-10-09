import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";

type Entry = { nodePubkey: string; rootKeyId: string; label: string | null; status: string;
  fingerprint: string; grade: string; [field: string]: unknown };
type Registry = { entries: Entry[]; lock: () => Promise<void>; save: () => Promise<void>;
  unlock: () => Promise<void> };
const repo = resolve();
const root = join(repo, 'test/registry-fixtures');
const fixture = JSON.parse(readFileSync(join(root, 'registry.json'), 'utf8')) as {
  schema: number; entries: Entry[] };
const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
  source: string; schema: number; entryCount: number; entries: Entry[] };
const vectors = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { fingerprint: string; expectedGrade: string }[] };
const modulePath = '../../src/registry/index.js';
const registry = (): Promise<{ openRegistry: (path: string) => Promise<Registry> }> =>
  import(/* @vite-ignore */ modulePath) as Promise<{ openRegistry: (path: string) => Promise<Registry> }>;

it('CP-017/registry-ground-truth independent fixture and manifest survive load and round-trip', async () => {
  expect(manifest.source).toBe('docs/spec.md#registry-format and test/vectors/manifest.json');
  expect(fixture.schema).toBe(1);
  expect(manifest.schema).toBe(1);
  expect(fixture.entries).toHaveLength(manifest.entryCount);
  const fields = ['nodePubkey', 'label', 'rootKeyId', 'permissions', 'caveats', 'grade',
    'fingerprint', 'outPath', 'createdAt', 'verified', 'status', 'revokedAt',
    'revokeEvidence', 'replaces', 'replacedBy'];
  for (const [index, entry] of fixture.entries.entries()) {
    expect(Object.keys(entry).sort()).toEqual([...fields].sort());
    expect(entry.rootKeyId).toMatch(/^(0|[1-9][0-9]*)$/);
    expect(BigInt(entry.rootKeyId)).toBeLessThanOrEqual(18446744073709551615n);
    expect(entry.fingerprint).toMatch(/^fp:[0-9a-f]{16}$/);
    expect(vectors.vectors.some(vector => vector.fingerprint === entry.fingerprint
      && vector.expectedGrade === entry.grade)).toBe(true);
    expect(entry).toMatchObject(manifest.entries[index]);
  }
  expect(fixture.entries[0].rootKeyId).toBe('18446744073709551615');
  expect(new Set(fixture.entries.map(entry => `${entry.nodePubkey}/${entry.rootKeyId}`)).size)
    .toBe(fixture.entries.length);
  const base = join(repo, 'node_modules/.cp017-tests');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'oracle-registry-'));
  try {
    const path = join(dir, 'registry.json');
    writeFileSync(path, JSON.stringify(fixture));
    const view = await (await registry()).openRegistry(path);
    expect(view.entries).toEqual(fixture.entries);
    await view.lock();
    try { await view.save(); } finally { await view.unlock(); }
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual(fixture);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-017/leak-check registry fixture, errors and owned temp files contain no sentinel', async () => {
  const base = join(repo, 'node_modules/.cp017-tests');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'oracle-leak-'));
  try {
    const path = join(dir, 'registry.json');
    writeFileSync(path, JSON.stringify(fixture));
    const view = await (await registry()).openRegistry(path);
    const output = JSON.stringify({ entries: view.entries, fixture: manifest });
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), commandOutput: output,
      paths: [root, dir], testTmp: dir, root: repo })).toBeNull();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
