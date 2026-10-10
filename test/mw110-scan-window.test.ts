// MW110-01: a credential-bearing candidate longer than one detector window must never be
// silently dropped. Candidates up to CANDIDATE_LIMIT code points are matched whole wherever
// they start; anything still cut by a window end is an undecodable-candidate (fail closed).
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { run as scanCommand } from '../src/commands/scan.js';
import { addFirstPartyCaveat, decodeMacaroon } from '../src/decode/index.js';
import { gradeFacts } from '../src/grade/index.js';
import { CANDIDATE_LIMIT, scan, type ScanResult } from '../src/scan/index.js';
import { Secret } from '../src/secret.js';
import { compare, LINEAR_4X } from './helpers/growth.js';
import { revealSecret } from './helpers/secret-bytes.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const admin = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));

// Fixed independently of src/: the documented bound and the window geometry it implies
// (windows of 2 * BOUND - 1 code points starting every BOUND code points).
const BOUND = 262_144;
const STEP = BOUND;

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'mw110-01-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

/** The committed ADMIN vector with one long, valid time-before caveat (LND accepts it). */
function longAdmin(digits: number): Buffer {
  return Buffer.from(revealSecret(addFirstPartyCaveat(new Secret(admin),
    `time-before 2099-01-01T00:00:00.${'0'.repeat(digits)}Z`)));
}
/** A long ADMIN credential of exactly `size` bytes. */
function adminOfSize(size: number): Buffer {
  let digits = size - admin.length - 80;
  for (let tries = 0; tries < 8; tries++) {
    const bytes = longAdmin(digits);
    if (bytes.length === size) return bytes;
    digits += size - bytes.length;
  }
  throw new Error(`cannot build a ${size}-byte credential`);
}
function expected(bytes: Buffer) {
  const facts = decodeMacaroon(new Secret(bytes));
  return { fingerprint: facts.fingerprint, grade: gradeFacts(facts).grade };
}
const uriPrefix = (bytes: Buffer) => `lndconnect://localhost:10009?macaroon=${bytes.toString('base64url')}`;
/** An lndconnect URI of exactly `length` code points (padded with an ignored parameter). */
function uriOfLength(bytes: Buffer, length: number): string {
  const head = `${uriPrefix(bytes)}&pad=`;
  if (head.length > length) throw new Error('URI too short for its credential');
  return head + 'x'.repeat(length - head.length);
}
/** One line: `candidate` starting at zero-based code point `start`, padded with '.' to `total`. */
function line(candidate: string, start: number, total = start + candidate.length + 1_000): string {
  return '.'.repeat(start - 1) + ' ' + candidate + ' ' + '.'.repeat(Math.max(0, total - start - candidate.length - 1));
}
const brief = (result: ScanResult) => result.findings.map(({ kind, column, fingerprint, grade }) => ({ kind, column, fingerprint, grade }));

it('MW110-01 exports the documented candidate bound', () => {
  expect(CANDIDATE_LIMIT).toBe(BOUND);
  // It covers the largest supported encodings: hex of a 64 KiB credential, and
  // base64url of 64 KiB plus lndconnect host and certificate overhead.
  expect(Buffer.alloc(65_536).toString('hex').length).toBeLessThan(BOUND);
  expect(Buffer.alloc(65_536).toString('base64url').length + 4_096).toBeLessThan(BOUND);
});

it('MW110-01 a long valid lndconnect URI is found with its grade and fails --fail-on', async () => temp(async dir => {
  const child = longAdmin(50_000);
  expect(child.length).toBeGreaterThan(50_000);
  expect(child.length).toBeLessThan(65_536);
  const want = expected(child);
  expect(want.grade).toBe('ADMIN');
  const path = join(dir, 'connection.txt');
  writeFileSync(path, uriPrefix(child));
  const result = await scan([path], {});
  expect(brief(result)).toEqual([{ kind: 'lndconnect', column: 1, ...want }]);
  expect(result.summary.dropped).toBe(0);
  for (const threshold of ['READ', 'ADMIN']) {
    const run = await scanCommand([path, '--fail-on', threshold, '--json'], { fs });
    expect(run.exitCode, threshold).toBe(1);
    expect((run.result as ScanResult).failOn).toEqual({ threshold, count: 1 });
  }
}));

it('MW110-01 a 64 KiB credential is found whole in every encoding at every window edge', async () => temp(async dir => {
  const child = adminOfSize(65_536);
  const want = expected(child);
  expect(want.grade).toBe('ADMIN');
  const forms = [
    ['macaroon-hex', child.toString('hex')],
    ['macaroon-base64', child.toString('base64')],
    ['lndconnect', uriPrefix(child)],
  ] as const;
  // Starting at a window start, one before it (the least room), crossing it, and so that the
  // candidate ends just after the previous window's end.
  for (const [kind, text] of forms) {
    const starts = [1, STEP - 1, STEP, STEP + 1, STEP - 10, 2 * STEP - 1, (2 * STEP - 1) - text.length + 5];
    const lines = starts.map(start => line(text, start));
    const path = join(dir, `${kind}.txt`);
    writeFileSync(path, lines.join('\n'));
    const result = await scan([path], {});
    expect(result.findings.map(({ kind: k, line: l, column, fingerprint, grade }) => ({ kind: k, line: l, column, fingerprint, grade })), kind)
      .toEqual(starts.map((start, index) => ({ kind, line: index + 1, column: start + 1, ...want })));
    expect(result.summary.dropped).toBe(0);
  }
}));

it('MW110-01 candidates of exactly the bound are matched whole at the worst offset; bound + 1 fails closed', async () => temp(async dir => {
  const child = longAdmin(50_000);
  const want = expected(child);
  const worst = STEP - 1; // zero-based start with the least room before its window ends
  const exact = join(dir, 'exact.txt');
  writeFileSync(exact, line(uriOfLength(child, BOUND), worst));
  expect(brief(await scan([exact], {}))).toEqual([{ kind: 'lndconnect', column: worst + 1, ...want }]);
  // The same at a window start, where more room is available, and on a line ending at the bound.
  const start = join(dir, 'start.txt');
  writeFileSync(start, `${uriOfLength(child, BOUND + 1)}\n${uriOfLength(child, BOUND)}`);
  expect(brief(await scan([start], {}))).toEqual([
    { kind: 'lndconnect', column: 1, ...want }, { kind: 'lndconnect', column: 1, ...want }]);
  // One code point more at the worst offset cannot be matched whole: it is reported, never dropped.
  const over = join(dir, 'over.txt');
  writeFileSync(over, line(uriOfLength(child, BOUND + 1), worst));
  const result = await scan([over], {});
  // The cut URI does not hide the complete credential inside it (RR-01): that is reported too.
  const inner = worst + 1 + 'lndconnect://localhost:10009?macaroon='.length;
  expect(result.findings.map(({ kind, column, grade }) => ({ kind, column, grade })))
    .toEqual([{ kind: 'undecodable-candidate', column: worst + 1, grade: null },
      { kind: 'macaroon-base64', column: inner, grade: 'ADMIN' }]);
  expect(result.summary.dropped).toBe(0);
  const run = await scanCommand([over, '--fail-on', 'ADMIN', '--json'], { fs });
  expect(run.exitCode).toBe(1);
  expect((run.result as ScanResult).failOn).toEqual({ threshold: 'ADMIN', count: 2 });
}));

it('MW110-01 hex and base64 candidates at and over the bound at the worst offset', async () => temp(async dir => {
  const worst = STEP - 1;
  // A 128 KiB credential: its hex is exactly the bound.
  const big = adminOfSize(BOUND / 2);
  const hexWant = expected(big);
  const hex = join(dir, 'hex.txt');
  writeFileSync(hex, [line(big.toString('hex'), worst), line(big.toString('hex') + 'a', worst)].join('\n'));
  expect((await scan([hex], {})).findings.map(({ kind, line: l, column, fingerprint, grade }) => ({ kind, line: l, column, fingerprint, grade })))
    .toEqual([{ kind: 'macaroon-hex', line: 1, column: worst + 1, ...hexWant },
      { kind: 'undecodable-candidate', line: 2, column: worst + 1, fingerprint: expect.stringMatching(/^fp:[0-9a-f]{16}$/), grade: null }]);
  // Base64 of 196,608 bytes is exactly the bound; one more character is cut by the window.
  const wide = adminOfSize(196_608);
  const encoded = wide.toString('base64');
  expect(encoded.length).toBe(BOUND);
  const b64 = join(dir, 'base64.txt');
  writeFileSync(b64, [line(encoded, worst), line(`${encoded}A`, worst)].join('\n'));
  expect((await scan([b64], {})).findings.map(({ kind, line: l, column, grade }) => ({ kind, line: l, column, grade })))
    .toEqual([{ kind: 'macaroon-base64', line: 1, column: worst + 1, grade: 'ADMIN' },
      { kind: 'undecodable-candidate', line: 2, column: worst + 1, grade: null }]);
}));

it('MW110-01 an NWC URI longer than the window room is reported, not missed', async () => temp(async dir => {
  const worst = STEP - 1;
  const secret = '11'.repeat(32);
  const nwcOfLength = (length: number) => {
    const head = `nostr+walletconnect://${'22'.repeat(32)}?relay=wss://r&pad=`;
    const tail = `&secret=${secret}`;
    return head + 'x'.repeat(length - head.length - tail.length) + tail;
  };
  const path = join(dir, 'nwc.txt');
  // The matcher consumes one delimiter after the secret, so the match is one longer than the URI.
  writeFileSync(path, [line(nwcOfLength(BOUND - 1), worst), line(nwcOfLength(BOUND + 1), worst)].join('\n'));
  const result = await scan([path], {});
  expect(result.findings.map(({ kind, line: l, column }) => ({ kind, line: l, column })))
    .toEqual([{ kind: 'nwc', line: 1, column: worst + 1 }, { kind: 'undecodable-candidate', line: 2, column: worst + 1 }]);
  const run = await scanCommand([path, '--fail-on', 'ADMIN', '--json'], { fs });
  expect(run.exitCode).toBe(1);
}));

it('MW110-01 hostile 5 MB lines of open candidates scan in linear time', async () => temp(async dir => {
  const shapes = {
    lndconnect: (n: number) => `lndconnect://h?${'x'.repeat(n)}`,
    base64: (n: number) => ('AgEDbG5kA' + 'A'.repeat(4_087)).repeat(Math.ceil(n / 4_096)).slice(0, n),
    hex: (n: number) => ('0201036c6e6402' + 'a'.repeat(4_082)).repeat(Math.ceil(n / 4_096)).slice(0, n),
    nwc: (n: number) => `nostr+walletconnect:${'a'.repeat(64)}?${'x'.repeat(n)}`,
  };
  // Each shape is timed at both sizes alternately, keeping each size's fastest round, so a
  // loaded runner slows both alike: four times the input takes at most about four times as
  // long (LINEAR_4X, the bound every growth test shares), far below the sixteen times of quadratic rescanning.
  for (const [name, shape] of Object.entries(shapes)) {
    const scanOf = (size: number) => {
      const path = join(dir, `${name}-${size}.txt`);
      writeFileSync(path, shape(size));
      return async () => {
        const result = await scan([path], {});
        expect(result.findings.length).toBeGreaterThan(0);
        expect(result.findings.every(finding => finding.kind === 'undecodable-candidate')).toBe(true);
      };
    };
    const timing = await compare(scanOf(1_250_000), scanOf(5_000_000));
    console.log(`MW110-01 ${name} scan 1.25 MB and 5 MB: ${timing.summary}`);
    expect(timing.ratio, `${name}: ${timing.summary}`).toBeLessThan(LINEAR_4X);
  }
}), 180_000);
