import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { decodeMacaroon, DecodeError } from '../src/decode/index.js';
import { gradeFacts } from '../src/grade/index.js';
import { render } from '../src/output/index.js';
import { nwc } from '../src/scan/patterns.js';
import { nwcMatches } from '../src/scan/nwc-match.js';
import { run as scanCommand } from '../src/commands/scan.js';
import { Secret } from '../src/secret.js';
import { LINEAR_4X, compare } from './helpers/growth.js';

// Threat model: the attacker controls the bytes and names of every scanned or inspected
// file. Each test states the bound it proves.

// Structurally valid LND-style macaroon v2 bytes (the signature is random: only structure
// matters to the decoder), built independently of the product code.
function varint(n: number): Buffer { const b: number[] = []; do { let d = n % 128; n = Math.floor(n / 128); if (n) d |= 0x80; b.push(d); } while (n); return Buffer.from(b); }
const packet = (kind: number, value: Buffer) => Buffer.concat([Buffer.from([kind]), varint(value.length), value]);
const field = (number: number, value: Buffer) => Buffer.concat([varint(number << 3 | 2), varint(value.length), value]);
const operation = (entity: string, actions: string[]) =>
  field(3, Buffer.concat([field(1, Buffer.from(entity)), ...actions.map(action => field(2, Buffer.from(action)))]));
function macaroon(operations: Buffer[]): Buffer {
  const identifier = Buffer.concat([Buffer.from([3]), field(1, randomBytes(16)), field(2, Buffer.from('0')), ...operations]);
  return Buffer.concat([Buffer.from([2]), packet(1, Buffer.from('lnd')), packet(2, identifier), Buffer.from([0]), Buffer.from([0]),
    packet(6, randomBytes(32))]);
}
const stage = (bytes: Buffer) => { try { decodeMacaroon(new Secret(bytes)); return 'decoded'; } catch (error) { return (error as DecodeError).stage; } };

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const scratch = () => { const dir = mkdtempSync(join(tmpdir(), 'mw-redteam-')); dirs.push(dir); return dir; };

it('RED-TEAM/amplification a small identifier that would expand to megabytes of permissions stays bounded and fails closed', async () => {
  // The audit's file: a 16,000-byte entity times 15,000 one-byte actions (~240 MB of text).
  // LND honours such a macaroon, so it is decoded (parser review 2026-10-08, MEDIUM-2), but
  // only what fits the bounds is expanded and the grade fails closed.
  const bomb = macaroon([operation('e'.repeat(16_000), Array.from({ length: 15_000 }, () => 'r'))]);
  expect(bomb.length).toBeLessThan(70_000);
  // Cost against a macaroon of about the same size that expands to nothing large (the same
  // actions on a 16-byte entity, padded with ordinary operations), timed alternately in this
  // process: expanding the bomb (~240 MB of text) would cost thousands of times more, a
  // bounded decoder about the same. No fixed time limit, which would measure the runner.
  const plain = macaroon([operation('e'.repeat(16), Array.from({ length: 15_000 }, () => 'r')),
    ...Array.from({ length: 64 }, (_, i) => operation('pad', [String(i).padEnd(250, 'p')]))]);
  expect(Math.abs(plain.length - bomb.length)).toBeLessThan(bomb.length / 4);
  const timing = await compare(() => decodeMacaroon(new Secret(plain)), () => decodeMacaroon(new Secret(bomb)));
  expect(timing.ratio, timing.summary).toBeLessThan(LINEAR_4X);
  const facts = decodeMacaroon(new Secret(bomb));
  expect(facts.permissions).toEqual([]);
  expect(facts.warnings).toContain('identifier-exceeds-bounds');
  expect(gradeFacts(facts).grade).toBe('UNASSESSED');
  const bounded = (bytes: Buffer) => {
    const decoded = decodeMacaroon(new Secret(bytes));
    expect(decoded.permissions.length).toBeLessThanOrEqual(1024);
    expect(decoded.permissions.reduce((total, permission) => total + Buffer.byteLength(permission), 0)).toBeLessThanOrEqual(65_536);
    return [decoded.warnings.includes('identifier-exceeds-bounds'), decoded.permissions.length, gradeFacts(decoded).grade];
  };
  // Each bound on its own: an entity over 16 bytes or an action over 256 bytes is left out,
  // and so is everything past 1,024 permissions; the grade then fails closed.
  expect(bounded(macaroon([operation('e'.repeat(17), ['read'])]))).toEqual([true, 0, 'UNASSESSED']);
  expect(bounded(macaroon([operation('uri', ['/' + 'a'.repeat(256)])]))).toEqual([true, 0, 'UNASSESSED']);
  expect(bounded(macaroon(Array.from({ length: 3 }, () => operation('invoices', Array.from({ length: 400 }, (_, i) => `a${i}`))))))
    .toEqual([true, 1024, 'UNASSESSED']);
  // Operation and action counts are not memory bounds: within the totals they decode as LND does.
  expect(bounded(macaroon([operation('invoices', Array.from({ length: 513 }, (_, i) => `a${i}`))]))).toEqual([false, 513, 'UNASSESSED']);
  expect(bounded(macaroon(Array.from({ length: 257 }, () => operation('info', ['read']))))).toEqual([false, 257, 'READ']);
  expect(stage(macaroon([operation('info', ['read'])]))).toBe('decoded');
  // Real macaroons stay far below: every LND v0.21.4 RPC method as a URI permission still decodes.
  const allUris = Array.from({ length: 164 }, (_, i) => `/lnrpc.Lightning/Method${i}WithALongerName`);
  expect(stage(macaroon([operation('uri', allUris), operation('macaroon', ['generate', 'read', 'write'])]))).toBe('decoded');
});

it('RED-TEAM/amplification many worst-case accepted copies in one 4 MB file scan in linear time', async () => {
  const dir = scratch();
  // At the caps: a 16-byte entity with 512 one-byte actions, as base64 lines, about 4 MB for 1,800.
  // Before the fix a comparable file took about a minute. Cost is measured as growth, not against a
  // fixed limit: four times the copies must cost about four times as much.
  const file = (copies: number) => {
    const path = join(dir, `config-${copies}.env`);
    const lines: string[] = [];
    for (let i = 0; i < copies; i++)
      lines.push(`TOKEN=${macaroon([operation('e'.repeat(16), Array.from({ length: 512 }, () => 'r'))]).toString('base64')}`);
    writeFileSync(path, `${lines.join('\n')}\n`);
    return async () => {
      const result = await scanCommand([path, '--fail-on', 'READ', '--json']);
      expect(result.exitCode).toBe(1);
      expect((result.result as { summary: { findings: number } }).summary.findings).toBe(copies);
    };
  };
  const timing = await compare(file(450), file(1_800), 2);
  console.log(`RED-TEAM/amplification 450 and 1,800 copies: ${timing.summary}`);
  expect(timing.ratio, timing.summary).toBeLessThan(LINEAR_4X);
}, 180_000);

// Every platform: the renderer itself. The same names as real scanned files are the POSIX variant
// test/redteam-file-names.posix.test.ts (Windows file names cannot contain ':' or bidi controls).
it('RED-TEAM/forging a rendered path cannot start a text line with a GitHub workflow command or reorder the terminal', () => {
  const finding = { path: '::stop-commands::x', line: 1, column: 1, kind: 'macaroon-hex', fingerprint: 'fp:0123456789abcdef',
    grade: 'READ', rootKeyId: '0', permissions: [], caveats: [], warnings: [] };
  const text = render({ command: 'scan', ok: true, warnings: [], error: null, result: { findings: [finding,
    { ...finding, path: 'safe‮gnp.exe' }], skipped: [],
    summary: { findings: 2, distinct: 1, filesScanned: 1, filesSkipped: 0, ignored: 0 }, failOn: null } } as never, 'text');
  for (const line of text.split('\n')) expect(line.startsWith('::')).toBe(false);
  expect(text).toContain('./::stop-commands::x');
  expect(text).not.toContain('‮');
  expect(text).toContain('\\u202e');
});

it('RED-TEAM/nwc-linear the scan matcher returns exactly the published regex matches', () => {
  const global = new RegExp(nwc.source, `${nwc.flags}g`);
  const hex = (n: number) => randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
  const pieces = () => ['nostr+walletconnect:', 'NOSTRWALLETCONNECT:', 'nostrwalletconnect://', hex(64), hex(64).toUpperCase(),
    '?', '/?', '&', 'relay=wss%3A%2F%2Fr', 'secret=', 'SECRET=', ' ', '"', '<', 'g', 'a', '\n', ' ', hex(3)];
  for (let round = 0; round < 3_000; round++) {
    const choices = pieces();
    let text = '';
    for (let n = 0; n < 4 + (round % 40); n++) text += choices[Math.floor(Math.random() * choices.length)];
    const expected = [...text.matchAll(global)].map(match => ({ index: match.index, text: match[0] }));
    expect(nwcMatches(text), JSON.stringify(text)).toEqual(expected);
  }
});

it('RED-TEAM/nwc-linear a window of repeated prefixes without a secret is scanned in linear time', () => {
  const unit = `nostr+walletconnect:${'a'.repeat(64)}?`;
  const window = unit.repeat(Math.ceil(65_536 / unit.length)).slice(0, 65_536);
  const line = window.repeat(80); // about 5 MB
  const started = performance.now();
  expect(nwcMatches(line)).toEqual([]);
  // The backtracking regex needs about 15 ms per 64 K window and grows with the square of
  // the run; the linear matcher handles 5 MB in well under a second.
  expect(performance.now() - started).toBeLessThan(3_000);
});

it('RED-TEAM/sarif hostile file names stay valid, percent-encoded URIs inside valid JSON', async () => {
  const dir = scratch();
  const admin = macaroon([operation('info', ['read'])]).toString('hex');
  const names = ['100% #1 é.txt', 'a b&c=d;e.txt', process.platform === 'win32' ? 'x[1]{2}.txt' : 'q?x:y.txt'];
  for (const name of names) writeFileSync(join(dir, name), `${admin}\n`);
  const previous = process.cwd();
  process.chdir(dir);
  let rendered: string;
  try {
    const result = await scanCommand(['.', '--format', 'sarif']);
    rendered = render(result, 'text');
  } finally { process.chdir(previous); }
  const log = JSON.parse(rendered) as { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
  const uris = log.runs[0].results.map(result => result.locations[0].physicalLocation.artifactLocation.uri).sort();
  expect(uris).toHaveLength(names.length);
  for (const uri of uris) {
    // Only unreserved characters and percent escapes; decoding gives back a scanned name.
    expect(uri).toMatch(/^[A-Za-z0-9._~%-]+$/);
    expect(names).toContain(decodeURIComponent(uri));
  }
});
