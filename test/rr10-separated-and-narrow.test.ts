// RR-10: hex written with byte separators (colon hex, `xxd -g1`, spaced bytes), `xxd` default
// dumps, and credentials wrapped narrower than the 40-character continuation must not pass.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { scan, type ScanResult } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const admin = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));
const fingerprint = manifest.vectors.find(entry => entry.name === 'default-admin')!.fingerprint;
const hex = admin.toString('hex');
const brief = (result: ScanResult) => result.findings.map(({ kind, line, column, grade }) => ({ kind, line, column, grade }));

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr10-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
async function scanned(dir: string, name: string, content: string): Promise<ScanResult> {
  const path = join(dir, name);
  writeFileSync(path, content);
  return scan([path], {});
}

it('RR-10 decodes hex with a separator between every byte', async () => temp(async dir => {
  for (const [name, separator, upper] of [['colon', ':', false], ['space', ' ', false], ['dash', '-', false], ['colon-upper', ':', true]] as const) {
    const bytes = hex.match(/../g)!.join(separator);
    const result = await scanned(dir, `${name}.txt`, `macaroon: ${upper ? bytes.toUpperCase() : bytes}\n`);
    expect(result.findings.map(({ kind, line, column, fingerprint: fp, grade }) => ({ kind, line, column, fp, grade })), name)
      .toEqual([{ kind: 'macaroon-hex', line: 1, column: 11, fp: fingerprint, grade: 'ADMIN' }]);
  }
}));

it('RR-10 an xxd default dump is an undecodable candidate at either byte alignment', async () => temp(async dir => {
  const dump = (data: string) => {
    let out = '';
    for (let i = 0; i < data.length; i += 32)
      out += `${(i / 2).toString(16).padStart(8, '0')}: ${data.slice(i, i + 32).match(/.{1,4}/g)!.join(' ')}\n`;
    return out;
  };
  expect(brief(await scanned(dir, 'even.txt', dump(hex)))).toEqual([{ kind: 'undecodable-candidate', line: 1, column: 11, grade: null }]);
  expect(brief(await scanned(dir, 'odd.txt', dump(`ff${hex}`)))).toEqual([{ kind: 'undecodable-candidate', line: 1, column: 13, grade: null }]);
}));

it('RR-10 base64 and hex wrapped narrower than 49 columns are joined and decoded', async () => temp(async dir => {
  const base64 = admin.toString('base64');
  const want = { grade: 'ADMIN' };
  for (const width of [12, 32, 48]) {
    const yaml = `macaroon: |\n${base64.match(new RegExp(`.{1,${width}}`, 'g'))!.map(part => `  ${part}`).join('\n')}\nnext: value\n`;
    const result = await scanned(dir, `b64-${width}.yml`, yaml);
    expect(brief(result), `base64 ${width}`).toEqual([{ kind: 'macaroon-base64', line: 2, column: 3, ...want }]);
    expect(result.findings[0].fingerprint).toBe(fingerprint);
    const hexWidth = width + 6;
    const wrapped = `${hex.match(new RegExp(`.{1,${hexWidth}}`, 'g'))!.join('\n')}\n`;
    // From 54 columns on, the first line already holds a candidate for the published pattern.
    expect(brief(await scanned(dir, `hex-${width}.txt`, wrapped)), `hex ${hexWidth}`).toEqual(hexWidth < 54
      ? [{ kind: 'macaroon-hex', line: 1, column: 1, ...want }]
      : [{ kind: 'undecodable-candidate', line: 1, column: 1, grade: null }]);
  }
  // A wrap at 76 is unchanged: one candidate for the first line.
  const wide = `${base64.slice(0, 76)}\n${base64.slice(76)}\n`;
  expect(brief(await scanned(dir, 'wide.txt', wide))).toEqual([{ kind: 'undecodable-candidate', line: 1, column: 1, grade: null }]);
  // A narrow wrap that does not decode once joined is not reported.
  const cut = `${base64.slice(0, 30)}\n${base64.slice(30, 60)}\n`;
  expect((await scanned(dir, 'cut.txt', cut)).findings).toEqual([]);
}));

it('RR-10 joining narrow wraps stays linear on hostile text', async () => temp(async dir => {
  const timings: number[] = [];
  for (const count of [100_000, 400_000]) {
    const path = join(dir, `prefixes-${count}.txt`);
    writeFileSync(path, 'AgEDbG5kA\n'.repeat(count));
    const started = performance.now();
    const result = await scan([path], {});
    timings.push(performance.now() - started);
    expect(result.findings).toEqual([]);
  }
  console.log(`RR-10 scan ms [100 K, 400 K lines]: ${timings.map(Math.round).join(', ')}`);
  expect(timings[1]).toBeLessThan(10_000);
  expect(timings[1]).toBeLessThan(8 * Math.max(timings[0], 25));
}), 60_000);

it('RR-10 a short prefix that does not end its line is not reported', async () => temp(async dir => {
  const result = await scanned(dir, 'prose.txt', 'the token AgEDbG5kA is a prefix, and 0201036c6e6402 too.\nAgEDbG5kAb trailing text\n');
  expect(result.findings).toEqual([]);
}));
