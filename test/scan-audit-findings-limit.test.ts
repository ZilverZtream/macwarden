import { writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { scratch } from './support/cp039-audit.js';

// runeFindings runs once for every text file whose bytes the scan analyses, so its calls count
// the files analysed.
const analysed = vi.hoisted(() => ({ count: 0 }));
vi.mock('../src/scan/runes.js', async original => {
  const actual = await original<typeof import('../src/scan/runes.js')>();
  return { ...actual, runeFindings: (...args: Parameters<typeof actual.runeFindings>) => {
    analysed.count++;
    return actual.runeFindings(...args);
  } };
});

const scanner = await import('../src/scan/index.js');

it('FINDINGS_LIMIT bounds the findings created, not only those committed: a slow first file does not let every other file be analysed', async () => scratch(async dir => {
  // Each file holds about 95,000 synthetic undecodable candidates (a macaroon hex prefix and
  // 40 hex digits), so three files exceed the limit.
  const unit = '0201036c6e6402' + 'ab'.repeat(20) + ' ';
  const files = 20;
  for (let i = 0; i < files; i++) {
    const salt = String(i).padStart(4, '0');
    writeFileSync(join(dir, `f${salt}.txt`), unit.replace('abab', salt).repeat(Math.floor(5_000_000 / unit.length)));
  }
  const perFile = Math.floor(5_000_000 / unit.length);
  // The first file's open waits until every other file was read, or the scan ended.
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  let closed = 0;
  const io = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]).endsWith('f0000.txt')) await gate;
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'close') return async () => { await target.close(); if (++closed === files - 1) setImmediate(release); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  analysed.count = 0;
  const pending = scanner.scan([dir], { fs: io });
  pending.finally(release).catch(() => {});
  await expect(pending).rejects.toBeInstanceOf(scanner.FindingsLimitError);
  // Findings created: at most the limit plus one file's worth beyond it.
  expect(analysed.count * perFile).toBeLessThanOrEqual(scanner.FINDINGS_LIMIT + 2 * perFile);
}), 180_000);

it('hard links to a file still being scanned share its one analysis: read and analysed once, reported once', async () => scratch(async dir => {
  const { linkSync } = await import('node:fs');
  const unit = '0201036c6e6402' + 'ab'.repeat(20) + ' ';
  writeFileSync(join(dir, 'a00.txt'), unit.replace('abab', '0000').repeat(10));
  writeFileSync(join(dir, 'b0000.txt'), unit.replace('abab', '1111').repeat(2_000));
  const links = 15;
  for (let i = 1; i < links; i++) linkSync(join(dir, 'b0000.txt'), join(dir, `b${String(i).padStart(4, '0')}.txt`));
  // The first file's open waits until every link was opened and closed again, or the scan ended.
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  let closed = 0;
  let reads = 0;
  const io = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const name = String(args[0]);
    if (name.endsWith('a00.txt')) await gate;
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'close') return async () => { await target.close(); if (/b\d{4}\.txt$/.test(name) && ++closed === links) setImmediate(release); };
      if (key === 'read' && /b\d{4}\.txt$/.test(name)) return async (...readArgs: Parameters<typeof target.read>) => { reads++; return target.read(...readArgs); };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } } as typeof fs;
  analysed.count = 0;
  const pending = scanner.scan([dir], { fs: io });
  pending.finally(release).catch(() => {});
  const result = await pending;
  expect(analysed.count).toBe(2);
  expect(result.findings).toHaveLength(10 + 2_000);
  const shared = result.findings.filter(finding => finding.path.endsWith('b0000.txt'));
  expect(shared).toHaveLength(2_000);
  expect(shared[0].alsoAt?.count).toBe(links - 1);
  // One file's bytes were read once (readBounded reads a small file in one or two reads).
  expect(reads).toBeLessThanOrEqual(2);
}), 120_000);
