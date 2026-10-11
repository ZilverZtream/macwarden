import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';
import * as ignore from '../src/scan/ignore.js';
import { scratch } from './support/cp039-audit.js';

// A 251-token glob prefix that never matches (no path here holds 'Z'); entries append a number.
const FAILING = '*?'.repeat(125) + 'Z';
// An undecodable candidate: a macaroon hex prefix and 60 hex digits, synthetic.
const CANDIDATE = '0201036c6e6402' + 'ab'.repeat(30);

it('ignore matching work is bounded: 1,024 failing globs against 2,000 deep finding paths finish and keep every finding', async () => scratch(async dir => {
  let deep = join(dir, 'tree');
  for (let i = 0; i < 40; i++) deep = join(deep, 'd');
  mkdirSync(deep, { recursive: true });
  const files = 2_000;
  for (let i = 0; i < files; i++) writeFileSync(join(deep, `${'x'.repeat(40)}${String(i).padStart(5, '0')}.env`), `A=${CANDIDATE}\n`);
  const probe = await scan([join(deep, `${'x'.repeat(40)}00000.env`)]);
  const fingerprint = probe.findings[0].fingerprint;
  writeFileSync(join(dir, 'tree', '.macwardenignore'), Array.from({ length: 1_024 }, (_, i) => `${fingerprint} ${FAILING}${i}`).join('\n') + '\n');
  const started = Date.now();
  const result = await scan([join(dir, 'tree')]);
  const elapsed = Date.now() - started;
  expect(result.summary).toMatchObject({ findings: files, ignored: 0 });
  // Unbounded, this ignore file costs about 2,000 x 1,024 x 256 x 100 steps (minutes).
  expect(elapsed).toBeLessThan(30_000);
}), 120_000);

it('the ignore decider stops evaluating globs once its work budget is spent, and then keeps findings', () => {
  const entries = ignore.parseIgnoreFile(Array.from({ length: 1_024 }, (_, i) => `fp:0123456789abcdef ${FAILING}${i}`).join('\n'));
  const path = 'd/'.repeat(40) + 'x'.repeat(45) + '.env';
  let calls = 0;
  const counted = entries.map(entry => ({ ...entry, matches: (value: string) => { calls++; return entry.matches(value); } }));
  const budget = { remaining: ignore.IGNORE_MATCH_WORK_LIMIT };
  const ignored = ignore.ignoreDecider(counted, budget);
  for (let i = 0; i < 2_000; i++) expect(ignored('fp:0123456789abcdef', `${i}/${path}`)).toBe(false);
  // Each entry has at least 252 tokens; each path is at least path.length + 2 long.
  const perMatch = 253 * (path.length + 3);
  expect(calls).toBeLessThanOrEqual(Math.ceil(ignore.IGNORE_MATCH_WORK_LIMIT / perMatch) + 1);
  expect(budget.remaining).toBeLessThanOrEqual(0);
});

it('the ignore decider still ignores within its budget and dedupes identical globs', () => {
  const entries = ignore.parseIgnoreFile(['fp:0123456789ABCDEF *.env', 'fp:0123456789abcdef *.env', 'fp:0123456789abcdef', 'fp:1111111111111111 a/*'].join('\n'));
  let calls = 0;
  const counted = entries.map(entry => ({ ...entry, matches: (value: string) => { calls++; return entry.matches(value); } }));
  const ignored = ignore.ignoreDecider(counted, { remaining: ignore.IGNORE_MATCH_WORK_LIMIT });
  expect(ignored('fp:0123456789abcdef', 'x/y.txt')).toBe(true);
  expect(ignored('fp:1111111111111111', 'a/b')).toBe(true);
  expect(ignored('fp:1111111111111111', 'b/a')).toBe(false);
  expect(ignored('fp:2222222222222222', 'a/b')).toBe(false);
  calls = 0;
  const twice = ignore.ignoreDecider(ignore.parseIgnoreFile('fp:0123456789abcdef *.env\nfp:0123456789abcdef *.env\n')
    .map(entry => ({ ...entry, matches: (value: string) => { calls++; return entry.matches(value); } })), { remaining: ignore.IGNORE_MATCH_WORK_LIMIT });
  expect(twice('fp:0123456789abcdef', 'a.txt')).toBe(false);
  expect(calls).toBe(1);
});
