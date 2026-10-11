import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { LOCK_FILE_LIMIT } from '../src/bounded-file.js';
import { TRACK_LIMIT } from '../src/commands/reconcile.js';
import { acquireLock, type Deps } from '../src/commands/watch.js';
import { decodeNwc } from '../src/decode/index.js';
import { decodeRuneText, RUNE_ALTERNATIVE_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_TEXT_LIMIT } from '../src/decode/rune.js';
import { MAX_GRPC_MESSAGE } from '../src/lnd/grpc.js';
import { decodeMiddlewareRequest, MAX_MACAROON_BYTES, MAX_METHOD_BYTES, MAX_PAYLOAD_BYTES,
  UNKNOWN_METHOD } from '../src/lnd/middleware-proto.js';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { SARIF_MAX_RESULTS } from '../src/output/scan-formats.js';
import { Secret } from '../src/secret.js';
import { rune } from './support/runes.js';

// Audit 1.4.0 (mutation probe): these bounds survived a change of their value because every
// test derived its input from the exported constant. Each constant is pinned to the literal
// docs/spec.md states, and where an input is cheap the exact boundary is exercised with
// literal sizes: n is accepted, n + 1 is refused.

describe('TESTS-AUDIT/bounds the constants equal the spec literals', () => {
  it.each([
    // spec.md "Lock owner records ... at most 64 KiB"
    ['LOCK_FILE_LIMIT', LOCK_FILE_LIMIT, 65_536],
    // spec.md rune bounds: 8,192 characters, 256 restrictions, 1,024 alternatives
    ['RUNE_TEXT_LIMIT', RUNE_TEXT_LIMIT, 8_192],
    ['RUNE_RESTRICTION_LIMIT', RUNE_RESTRICTION_LIMIT, 256],
    ['RUNE_ALTERNATIVE_LIMIT', RUNE_ALTERNATIVE_LIMIT, 1_024],
    // spec.md watch: a macaroon above 64 KiB, a method name above 256 bytes, a payload above 64 KiB
    ['MAX_MACAROON_BYTES', MAX_MACAROON_BYTES, 65_536],
    ['MAX_METHOD_BYTES', MAX_METHOD_BYTES, 256],
    ['MAX_PAYLOAD_BYTES', MAX_PAYLOAD_BYTES, 65_536],
    // spec.md SARIF: at most 25,000 results, GitHub's limit per run
    ['SARIF_MAX_RESULTS', SARIF_MAX_RESULTS, 25_000],
    // spec.md reconcile: TrackPaymentV2 lookups, at most 1,000
    ['TRACK_LIMIT', TRACK_LIMIT, 1_000],
    // spec.md watch: gRPC carries up to LND's 200 MiB limit
    ['MAX_GRPC_MESSAGE', MAX_GRPC_MESSAGE, 209_715_200],
  ] as const)('TESTS-AUDIT/bounds %s is the spec value', (_name, actual, literal) => {
    expect(actual).toBe(literal);
  });
});

// --- watch middleware stream fields ---------------------------------------------------------

function varint(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do { let byte = rest & 0x7f; rest = Math.floor(rest / 128); if (rest) byte |= 0x80; bytes.push(byte); } while (rest);
  return Buffer.from(bytes);
}
const field = (number: number, bytes: Buffer) => Buffer.concat([varint((number << 3) | 2), varint(bytes.length), bytes]);
/** RPCMiddlewareRequest{ request_id 1, raw_macaroon 2, request 5: RPCMessage{ method 1, serialized 4 }, msg_id 7 }. */
function interceptFrame(macaroon: Buffer, method: string, payload: Buffer): Buffer {
  const message = Buffer.concat([field(1, Buffer.from(method, 'utf8')), field(4, payload)]);
  return Buffer.concat([Buffer.from([0x08, 0x01]), field(2, macaroon), field(5, message), Buffer.from([0x38, 0x02])]);
}
const PAY = '/routerrpc.Router/SendPaymentV2';

describe('TESTS-AUDIT/bounds middleware fields at n and n + 1 bytes', () => {
  it('TESTS-AUDIT/bounds a 65,536-byte macaroon is kept and a 65,537-byte one keeps only its 4 KiB prefix', () => {
    const kept = decodeMiddlewareRequest(interceptFrame(Buffer.alloc(65_536, 0x61), PAY, Buffer.alloc(1)));
    expect({ length: kept.rawMacaroon.length, oversized: kept.oversizedMacaroon }).toEqual({ length: 65_536, oversized: false });
    // An oversized macaroon keeps a bounded prefix so the journal can still derive its identity from the header.
    const dropped = decodeMiddlewareRequest(interceptFrame(Buffer.alloc(65_537, 0x61), PAY, Buffer.alloc(1)));
    expect({ length: dropped.rawMacaroon.length, oversized: dropped.oversizedMacaroon }).toEqual({ length: 4 * 1024, oversized: true });
  });

  it('TESTS-AUDIT/bounds a 256-byte method name is kept and a 257-byte one is recorded as unknown', () => {
    const at = `/${'m'.repeat(255)}`, over = `/${'m'.repeat(256)}`;
    expect(Buffer.byteLength(at)).toBe(256);
    expect(decodeMiddlewareRequest(interceptFrame(Buffer.alloc(1), at, Buffer.alloc(0))).method).toBe(at);
    expect(decodeMiddlewareRequest(interceptFrame(Buffer.alloc(1), over, Buffer.alloc(0))).method).toBe(UNKNOWN_METHOD);
  });

  it('TESTS-AUDIT/bounds a 65,536-byte payload of a journaled method is passed on and a 65,537-byte one is not', () => {
    const methods = new Set([PAY]);
    const kept = decodeMiddlewareRequest(interceptFrame(Buffer.alloc(1), PAY, Buffer.alloc(65_536, 0x01)), methods);
    expect({ length: kept.payload.length, oversized: kept.oversizedPayload }).toEqual({ length: 65_536, oversized: false });
    const dropped = decodeMiddlewareRequest(interceptFrame(Buffer.alloc(1), PAY, Buffer.alloc(65_537, 0x01)), methods);
    expect({ length: dropped.payload.length, oversized: dropped.oversizedPayload }).toEqual({ length: 0, oversized: true });
  });
});

// --- NWC relays ----------------------------------------------------------------------------

// Synthetic NIP-47 connection: a random key per run, never a real one.
function nwc(relays: number): Secret {
  const secret = randomBytes(32).toString('hex'), wallet = randomBytes(32).toString('hex');
  const query = Array.from({ length: relays }, (_, index) => `relay=wss%3A%2F%2Fr${index}.example.com`).join('&');
  return new Secret(Buffer.from(`nostr+walletconnect://${wallet}?${query}&secret=${secret}`, 'utf8'));
}

it('TESTS-AUDIT/bounds an NWC URI with 64 relays decodes and one with 65 is refused at nwc-relay', () => {
  expect(decodeNwc(nwc(64)).relays).toHaveLength(64);
  let refused: unknown;
  try { decodeNwc(nwc(65)); } catch (error) { refused = error; }
  expect(refused).toMatchObject({ name: 'DecodeError', code: 3, stage: 'nwc-relay', message: 'invalid NWC URI nwc-relay' });
});

// --- runes ---------------------------------------------------------------------------------

describe('TESTS-AUDIT/bounds rune limits at n and n + 1', () => {
  it('TESTS-AUDIT/bounds rune text of exactly 8,192 characters parses and 8,193 characters is exceeds-bounds', () => {
    // 8,192 base64 characters are 6,144 bytes: the 32-byte authenticator and 6,112 bytes of restriction text.
    const text = rune(`=1&f=${'a'.repeat(6_112 - 5)}`);
    expect(text.length).toBe(8_192);
    expect(decodeRuneText(text)).toMatchObject({ ok: true });
    expect(decodeRuneText(`${text}A`)).toEqual({ ok: false, reason: 'exceeds-bounds' });
  });

  it('TESTS-AUDIT/bounds 256 restrictions parse and 257 are exceeds-bounds', () => {
    const restrictions = (count: number) => rune(Array.from({ length: count }, (_, index) => `f=${index}`).join('&'));
    expect(decodeRuneText(restrictions(256))).toMatchObject({ ok: true });
    expect(decodeRuneText(restrictions(257))).toEqual({ ok: false, reason: 'exceeds-bounds' });
  });

  it('TESTS-AUDIT/bounds 1,024 alternatives parse and 1,025 are exceeds-bounds', () => {
    const alternatives = (count: number) => rune(Array.from({ length: count }, () => 'f=1').join('|'));
    expect(decodeRuneText(alternatives(1_024))).toMatchObject({ ok: true });
    expect(decodeRuneText(alternatives(1_025))).toEqual({ ok: false, reason: 'exceeds-bounds' });
  });
});

// --- lock owner records ----------------------------------------------------------------------

const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function scratch(): string {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'tests-audit-bounds-'));
  dirs.push(dir);
  return dir;
}
const watchDeps = { fs, env: {}, clock: () => new Date(), emit: () => undefined, hostname: () => 'this-host.example',
  pid: 1_000_001, processDomain: async () => null } as unknown as Deps;

it('TESTS-AUDIT/bounds a watch lock record of 65,536 bytes is read and one of 65,537 bytes is refused unread', async () => {
  // Another host's record: never stale, so a record that is read is reported as held (EEXIST).
  const record = `${JSON.stringify({ pid: 4242, hostname: 'other-host.example' })}\n`;
  const padded = (size: number) => record + ' '.repeat(size - Buffer.byteLength(record));
  const atLimit = join(scratch(), 'registry.json.watch.lock');
  writeFileSync(atLimit, padded(65_536));
  await expect(acquireLock(atLimit, watchDeps)).rejects.toMatchObject({ code: 'EEXIST', message: 'watch lock held' });
  const overLimit = join(scratch(), 'registry.json.watch.lock');
  writeFileSync(overLimit, padded(65_537));
  await expect(acquireLock(overLimit, watchDeps)).rejects.toThrow('watch lock without owner record');
});

// --- SARIF ---------------------------------------------------------------------------------

function sarifLog(count: number) {
  const findings = Array.from({ length: count }, (_, index) => ({ path: join('/r', `f${index}.env`), line: 1, column: 1,
    kind: 'macaroon-hex', fingerprint: `fp:${index.toString(16).padStart(16, '0')}`, grade: 'READ', rootKeyId: '0',
    location: 'lnd', permissions: [], caveats: [], warnings: [] }));
  const output = { command: 'scan', ok: true, warnings: [], error: null, result: { findings, skipped: [],
    summary: { findings: count, distinct: count, filesScanned: count, filesSkipped: 0, ignored: 0 }, failOn: null },
    display: { format: 'sarif', scanRoot: '/r', toolVersion: '1.0.0' } } as unknown as OutputResult;
  return JSON.parse([...renderChunks(output, 'text')].join('')) as { runs: { results: unknown[];
    invocations: { properties: { omittedResults?: number } }[] }[] };
}

it('TESTS-AUDIT/bounds SARIF writes all of 25,000 findings and omits one of 25,001', () => {
  const full = sarifLog(25_000);
  expect(full.runs[0].results).toHaveLength(25_000);
  expect(full.runs[0].invocations[0].properties.omittedResults).toBeUndefined();
  const over = sarifLog(25_001);
  expect(over.runs[0].results).toHaveLength(25_000);
  expect(over.runs[0].invocations[0].properties.omittedResults).toBe(1);
}, 120_000);
