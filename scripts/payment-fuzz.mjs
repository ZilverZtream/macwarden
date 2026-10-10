// Property fuzzing of macwarden's payment side: what watch reads from an intercepted payment
// request (paymentFacts, deletionFacts), the payment journal writer and reader (PaymentJournal,
// readJournal, journalCoverage) and reconcile (run, with a fake LND adapter). Offline and seeded:
// every case is generated from (seed, target, case index) by a xorshift generator, so a failure is
// reproduced by its seed and index (journal cases also depend on disk timing, so a journal case
// reproduces its input exactly and its timing as closely as the machine allows).
//
//   npm run fuzz:payments                                  every target, default case counts
//   npm run fuzz:payments -- --target facts --cases 1000000 --seed 123 --jobs 8
//   node scripts/payment-fuzz.mjs --target journal --seed 123 --start 517 --cases 1 --verbose
//
// Default counts: facts 200,000, journal 2,000, reconcile 20,000. The CLI prints the seed first,
// the totals and timings as JSON, every failing case (seed, index, property, input, output), and
// exits 1 on any violation. test/payment-fuzz.test.ts runs a fixed seed with small counts on the
// TypeScript sources on every test run.
//
// Targets and properties:
//   facts      mutated SendPaymentV2 / SendToRouteV2 / DeletePayment / DeleteAllPayments payloads
//              (bit flips, truncation, duplicated fields, wire-type changes, huge varints, nested
//              routes and hops at the 64 KiB cap, BOLT11 invoices with random HRP amounts and tags,
//              invalid UTF-8, keysend custom records holding a sentinel preimage). paymentFacts and
//              deletionFacts never throw and stay within a time bound; every field has the journal's
//              documented form; the sentinel preimage, the invoice's payment secret and the invoice
//              text never reach the facts in any encoding; an unmutated request gives exactly the
//              facts the specification (docs/spec.md, Commands > 8, Payment journal) describes.
//   journal    random writer operations on a real PaymentJournal over a temporary file (captures from
//              the regtest vectors, registration markers, clock steps, bursts past the intake, slow,
//              short, failing or blocked writes, a pre-filled file that reaches the size limit), then
//              optionally a crash (truncation at a random byte) and a new run that repairs it.
//   reconcile  random journals (several runs, nodes, credentials, shared hashes, deletions, drops,
//              gaps, torn tails) against a fake LND with random listings and lookups, under random
//              --since/--until; the output is checked against the shipped schema, the exit-code
//              rule and the attribution invariants.
import { createHash, randomInt } from 'node:crypto';
import { fork } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, truncateSync, writeFileSync } from 'node:fs';
import * as nodeFs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import Ajv2020Module from 'ajv/dist/2020.js';

export const TARGETS = ['facts', 'journal', 'reconcile'];
export const DEFAULT_CASES = { facts: 200_000, journal: 2_000, reconcile: 20_000 };
const MAX_INT64 = (1n << 63n) - 1n;
const MAX_UINT64 = (1n << 64n) - 1n;
const INT64_SIGN = 1n << 63n;
const SEND = '/routerrpc.Router/SendPaymentV2';
const ROUTE = '/routerrpc.Router/SendToRouteV2';
const DELETE = '/lnrpc.Lightning/DeletePayment';
const DELETE_ALL = '/lnrpc.Lightning/DeleteAllPayments';
const METHODS = [SEND, ROUTE, DELETE, DELETE_ALL];
const EXTRACTIONS = ['complete', 'no-hash', 'amp', 'payload-too-large', 'malformed', 'invoice-invalid', 'invoice-too-long'];
const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_INVOICE_CHARS = 8 * 1024;
const KEYSEND_RECORD = 5_482_373_484n;
/** Known secrets placed in every request: the keysend preimage and the invoice's payment secret. */
export const SENTINEL_PREIMAGE = createHash('sha256').update('macwarden payment-fuzz sentinel preimage').digest();
export const SENTINEL_SECRET = createHash('sha256').update('macwarden payment-fuzz sentinel payment secret').digest();
export const NODE = `02${'ab'.repeat(32)}`;
export const OTHER_NODE = `03${'cd'.repeat(32)}`;
const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const REPO = resolve();

// ---------------------------------------------------------------------------------------------
// Generator.

/** xorshift128 seeded through splitmix32: fast and deterministic, good enough for test generation. */
export function xorshift(seed) {
  let s = seed >>> 0;
  const split = () => {
    s = (s + 0x9e3779b9) >>> 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    return (z ^ (z >>> 16)) >>> 0;
  };
  let x = split() || 1, y = split(), z = split(), w = split();
  const u32 = () => {
    const t = (x ^ (x << 11)) >>> 0;
    x = y; y = z; z = w;
    w = (w ^ (w >>> 19) ^ (t ^ (t >>> 8))) >>> 0;
    return w;
  };
  const next = () => u32() / 4294967296;
  const int = (low, high) => low + Math.floor(next() * (high - low + 1));
  const pick = items => items[Math.floor(next() * items.length)];
  const chance = p => next() < p;
  const bytes = length => { const out = Buffer.allocUnsafe(length); for (let i = 0; i < length; i++) out[i] = u32() & 0xff; return out; };
  const big = bits => { let value = 0n; for (let i = 0; i < bits; i += 32) value = (value << 32n) | BigInt(u32()); return value & ((1n << BigInt(bits)) - 1n); };
  /** One of the [value, weight] pairs; the values are given eagerly, so the stream stays aligned. */
  const weighted = table => {
    let total = 0;
    for (const [, weight] of table) total += weight;
    let point = next() * total;
    for (const [value, weight] of table) if ((point -= weight) < 0) return value;
    return table[table.length - 1][0];
  };
  return { next, int, pick, chance, bytes, big, weighted, u32 };
}

/** The per-case seed: a case is reproduced from the campaign seed, its target and its index. */
export function caseSeed(seed, target, index) {
  return createHash('sha256').update(`payment-fuzz:${target}:${seed}:${index}`).digest().readUInt32LE(0);
}

// ---------------------------------------------------------------------------------------------
// Protobuf and BOLT11 encoders, written from the field numbers of LND v0.21.4-beta
// (lnrpc/routerrpc/router.proto, lnrpc/lightning.proto) and BOLT 11, not from macwarden's decoder.

export function varint(value) {
  let rest = BigInt.asUintN(64, BigInt(value));
  const out = [];
  do {
    let byte = Number(rest & 0x7fn);
    rest >>= 7n;
    if (rest) byte |= 0x80;
    out.push(byte);
  } while (rest);
  return Buffer.from(out);
}
const tag = (field, wire) => varint((BigInt(field) << 3n) | BigInt(wire));
const uint = (field, value) => Buffer.concat([tag(field, 0), varint(value)]);
const len = (field, data) => {
  const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return Buffer.concat([tag(field, 2), varint(bytes.length), bytes]);
};
const cat = parts => Buffer.concat(parts);
/** A map<uint64, bytes> entry (custom records). */
const record = (field, key, value) => len(field, cat([uint(1, key), len(2, value)]));

/** Top-level fields of a message, lenient: stops at the first malformed field. */
function walk(data) {
  const fields = [];
  let position = 0;
  const read = () => {
    let value = 0n, shift = 0n;
    for (;;) {
      if (position >= data.length || shift > 63n) return null;
      const byte = data[position++];
      value |= BigInt(byte & 0x7f) << shift;
      if (!(byte & 0x80)) break;
      shift += 7n;
    }
    return value > MAX_UINT64 ? null : value;
  };
  while (position < data.length) {
    const start = position;
    const key = read();
    if (key === null) return { fields, complete: false };
    const number = Number(key >> 3n), wire = Number(key & 7n), tagEnd = position;
    if (number < 1 || number > 536_870_911) return { fields, complete: false };
    let valueStart = position, lengthStart = position;
    if (wire === 0) { if (read() === null) return { fields, complete: false }; }
    else if (wire === 2) {
      const length = read();
      if (length === null || length > BigInt(data.length - position)) return { fields, complete: false };
      valueStart = position;
      position += Number(length);
    } else if (wire === 1 || wire === 5) {
      const size = wire === 1 ? 8 : 4;
      if (position + size > data.length) return { fields, complete: false };
      position += size;
    } else return { fields, complete: false };
    fields.push({ number, wire, start, tagEnd, lengthStart, valueStart, end: position });
  }
  return { fields, complete: true };
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function polymod(values) {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = (((checksum & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let bit = 0; bit < 5; bit++) if ((top >>> bit) & 1) checksum = (checksum ^ GENERATORS[bit]) >>> 0;
  }
  return checksum;
}
const hrpExpand = hrp => [...[...hrp].map(char => char.charCodeAt(0) >> 5), 0, ...[...hrp].map(char => char.charCodeAt(0) & 31)];
function toGroups(data) {
  const out = [];
  let accumulator = 0, bits = 0;
  for (const byte of data) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; out.push((accumulator >> bits) & 31); }
    accumulator &= (1 << bits) - 1;
  }
  if (bits) out.push((accumulator << (5 - bits)) & 31);
  return out;
}
function bech32(hrp, groups) {
  const value = polymod([...hrpExpand(hrp), ...groups, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, index) => (value >> (5 * (5 - index))) & 31);
  return `${hrp}1${[...groups, ...checksum].map(group => CHARSET[group]).join('')}`;
}
/** Whether an all-lower-case ASCII bech32 text has a valid checksum (reference for the checksum defect). */
function bech32Valid(text) {
  const separator = text.lastIndexOf('1');
  if (separator < 1) return false;
  const groups = [];
  for (const char of text.slice(separator + 1)) { const index = CHARSET.indexOf(char); if (index < 0) return false; groups.push(index); }
  return polymod([...hrpExpand(text.slice(0, separator)), ...groups]) === 1;
}
const field = (type, groups) => [type, groups.length >> 5, groups.length & 31, ...groups];

/** A random int64 or uint64 wire value biased to the boundaries the decoder must respect. */
function wireAmount(r) {
  return r.weighted([
    [0n, 3], [BigInt(r.int(1, 1_000_000)), 6], [BigInt(r.int(1, 2 ** 31)) * BigInt(r.int(1, 2 ** 20)), 3],
    [MAX_INT64 - BigInt(r.int(0, 1000)), 2], [MAX_INT64 / 1000n + BigInt(r.int(-2, 2)), 2], [INT64_SIGN + BigInt(r.int(0, 1000)), 1],
    [MAX_UINT64 - BigInt(r.int(0, 1000)), 1], [r.big(64), 1], [MAX_INT64 / BigInt(r.int(2, 100_000)), 1]]);
}

/**
 * A BOLT11 invoice and what the specification says the journal reads from it: `valid` (hash and
 * amount), `invalid`, `too-long` or `unknown` (a defect whose outcome this generator does not model).
 */
function genInvoice(r) {
  const network = r.pick(['bc', 'tb', 'bcrt', 'sb', 'tbs', 'xyz']);
  let amountText = '', amount = null;
  if (r.chance(0.7)) {
    const multiplier = r.pick(['', 'm', 'u', 'n', 'p']);
    const digits = r.weighted([[r.int(1, 6), 6], [r.int(7, 15), 3], [r.int(16, 20), 2]]);
    let text = String(r.int(1, 9));
    for (let i = 1; i < digits; i++) text += String(r.int(0, 9));
    // A pico-bitcoin amount must be a whole number of millisatoshi: a multiple of 10.
    if (multiplier === 'p') text = text.length < 20 ? `${text}0` : `${text.slice(0, -1)}0`;
    amountText = text + multiplier;
    const value = BigInt(text);
    amount = { '': value * 100_000_000_000n, m: value * 100_000_000n, u: value * 100_000n, n: value * 100n, p: value / 10n }[multiplier];
  }
  const hash = r.bytes(32);
  const tags = [];
  for (let i = r.int(0, 5); i > 0; i--) {
    tags.push(r.weighted([
      [field(13, toGroups(r.bytes(r.int(0, 80)))), 3], [field(16, toGroups(SENTINEL_SECRET)), 3], [field(6, [r.int(0, 31), r.int(0, 31)]), 1],
      [field(5, toGroups(r.bytes(r.int(1, 8)))), 1], [field(r.pick([0, 2, 3, 4, 7, 8, 9, 10, 11, 12, 14, 15, 17, 18, 19, 20, 24, 27, 30, 31]),
        Array.from({ length: r.int(0, 60) }, () => r.int(0, 31))), 2]]));
  }
  let defect = r.chance(0.35) ? r.pick(['checksum', 'mixed-case', 'no-ln', 'bad-amount', 'no-p', 'padding', 'overrun', 'short', 'non-ascii', 'homoglyph']) : null;
  const long = r.weighted([[null, 96], ['too-long', 2], ['near-limit', 2]]);
  if (long) {
    // Tagged fields of 1,023 groups (1,026 characters each): 8 make the text longer than 8,192 characters.
    for (let i = long === 'too-long' ? 8 : 7; i > 0; i--) tags.push(field(13, Array.from({ length: 1023 }, () => r.int(0, 31))));
    defect = null;
  }
  const pGroups = toGroups(hash);
  if (defect === 'padding') pGroups[51] |= r.int(1, 15);
  const pField = field(1, pGroups);
  const wrongP = r.chance(0.15) ? field(1, Array.from({ length: r.pick([0, 1, 51, 53, 60]) }, () => r.int(0, 31))) : null;
  const laterP = r.chance(0.1) && defect !== 'no-p' ? field(1, toGroups(r.bytes(32))) : null;
  const at = r.int(0, tags.length);
  const ordered = [...tags.slice(0, at), ...(wrongP ? [wrongP] : []), ...(defect === 'no-p' ? [] : [pField]), ...(laterP ? [laterP] : []), ...tags.slice(at)];
  if (defect === 'overrun') ordered.push([13, 0, r.int(20, 31), ...Array.from({ length: r.int(0, 10) }, () => r.int(0, 31))]);
  const timestamp = Array.from({ length: 7 }, () => r.int(0, 31));
  const signature = Array.from({ length: 104 }, () => r.int(0, 31));
  let groups = [...timestamp, ...ordered.flat(), ...signature];
  if (defect === 'short') groups = [...timestamp, ...Array.from({ length: r.int(0, 100) }, () => r.int(0, 31))];
  let prefix = 'ln';
  if (defect === 'no-ln') prefix = r.pick(['lx', 'n', 'l', 'ln1', 'xn']);
  if (defect === 'bad-amount') amountText = r.pick(['0', '00', '01', '0u', '15p', '1p', '123456789012345678901', '999999999999999999999m']);
  let text = bech32(`${prefix}${network}${amountText}`, groups);
  if (defect === 'checksum') {
    const separator = text.lastIndexOf('1');
    const position = r.int(separator + 1, text.length - 1);
    const replacement = CHARSET[(CHARSET.indexOf(text[position]) + r.int(1, 31)) % 32];
    text = text.slice(0, position) + replacement + text.slice(position + 1);
    if (bech32Valid(text)) defect = 'unknown';
  }
  const upper = r.chance(0.1);
  if (upper) text = text.toUpperCase();
  if (defect === 'mixed-case') {
    const letters = [...text].map((char, index) => (/[a-z]/i.test(char) ? index : -1)).filter(index => index >= 0);
    const position = r.pick(letters);
    const char = text[position];
    text = text.slice(0, position) + (upper ? char.toLowerCase() : char.toUpperCase()) + text.slice(position + 1);
  }
  if (defect === 'non-ascii') {
    // Characters outside US-ASCII. The Kelvin sign (U+212A) lower-cases to the ASCII 'k', a bech32
    // character, and U+0130 lower-cases to two characters: none is a valid invoice character.
    const char = r.pick(['é', 'ß', 'K', 'İ', 'ſ', ' ']);
    const position = r.int(0, text.length - 1);
    text = r.chance(0.5) ? text.slice(0, position) + char + text.slice(position + 1) : text.slice(0, position) + char + text.slice(position);
  }
  if (defect === 'homoglyph') {
    // A character whose case mapping is a bech32 character: the Kelvin sign (U+212A) for 'K' in an
    // upper-case invoice, U+017F (long s, upper-cases to 'S') for 's' in a lower-case one.
    const [from, to] = upper ? ['K', 'K'] : ['s', 'ſ'];
    const positions = [...text].map((char, index) => (char === from ? index : -1)).filter(index => index >= 0);
    if (positions.length) { const position = r.pick(positions); text = text.slice(0, position) + to + text.slice(position + 1); }
    else defect = 'unknown';
  }
  const expect = defect === 'unknown' ? { kind: 'unknown' }
    : text.length > MAX_INVOICE_CHARS ? { kind: 'too-long' }
      : defect ? { kind: 'invalid', defect }
        : { kind: 'valid', hash: hash.toString('hex'), amount };
  return { text, expect, defect };
}

/** An invalid UTF-8 byte sequence (lone continuation, overlong, surrogate, truncated, above U+10FFFF). */
function invalidUtf8(r) {
  return r.pick([Buffer.from([0x80]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from([0xe2, 0x82]),
    Buffer.from([0xf4, 0x90, 0x80, 0x80]), Buffer.from([0xff]), Buffer.from([0xfe, 0xff])]);
}

// A field the decoder must skip (route hints, outgoing channel IDs, custom records, destination features...).
function filler(r, numbers) {
  const number = r.pick(numbers);
  return r.weighted([[uint(number, wireAmount(r)), 3], [len(number, r.bytes(r.int(0, 40))), 3],
    [cat([tag(number, 1), r.bytes(8)]), 1], [cat([tag(number, 5), r.bytes(4)]), 1]]);
}

/** routerrpc.SendPaymentRequest with each read field at most once; `spec` is what was encoded. */
function genSend(r, capped) {
  const spec = {};
  const parts = [];
  if (r.chance(0.5)) parts.push(len(1, r.bytes(33)));
  if (r.chance(0.5)) { spec.amt = wireAmount(r); parts.push(uint(2, spec.amt)); }
  if (r.chance(0.5)) {
    spec.hash = r.weighted([[r.bytes(32), 8], [r.bytes(r.int(0, 31)), 1], [r.bytes(r.int(33, 64)), 1]]);
    parts.push(len(3, spec.hash));
  }
  if (r.chance(0.55)) {
    const kind = r.weighted([['invoice', 12], ['empty', 1], ['utf8', 1], ['huge', 0.2]]);
    if (kind === 'invoice') { spec.invoice = genInvoice(r); parts.push(len(5, spec.invoice.text)); }
    else if (kind === 'empty') { spec.invoice = { text: '', expect: { kind: 'absent' } }; parts.push(len(5, Buffer.alloc(0))); }
    else if (kind === 'utf8') {
      const invoice = genInvoice(r);
      const bytes = Buffer.from(invoice.text, 'utf8');
      const position = r.int(0, bytes.length);
      spec.invoice = { text: null, expect: { kind: 'malformed' } };
      parts.push(len(5, cat([bytes.subarray(0, position), invalidUtf8(r), bytes.subarray(position)])));
    } else {
      // More bytes than 8,192 four-byte characters: refused before it is decoded.
      spec.invoice = { text: null, expect: { kind: 'too-long' } };
      parts.push(len(5, Buffer.alloc(MAX_INVOICE_CHARS * 4 + r.int(1, 100), 0x71)));
    }
  }
  if (r.chance(0.5)) { spec.feeSat = wireAmount(r); parts.push(uint(7, spec.feeSat)); }
  for (let i = r.weighted([[0, 3], [1, 4], [2, 2], [3, 1]]); i > 0; i--)
    parts.push(record(11, r.chance(0.7) ? KEYSEND_RECORD : r.big(64), r.chance(0.7) ? SENTINEL_PREIMAGE : r.bytes(r.int(0, 40))));
  if (r.chance(0.5)) { spec.amtMsat = wireAmount(r); parts.push(uint(12, spec.amtMsat)); }
  if (r.chance(0.5)) { spec.feeMsat = wireAmount(r); parts.push(uint(13, spec.feeMsat)); }
  if (r.chance(0.2)) { spec.amp = r.weighted([[0n, 2], [1n, 5], [BigInt(r.int(2, 1000)), 1]]); parts.push(uint(22, spec.amp)); }
  if (r.chance(0.3)) parts.push(record(25, BigInt(r.int(65536, 2 ** 31)), SENTINEL_PREIMAGE));
  for (let i = r.int(0, 3); i > 0; i--) parts.push(filler(r, [4, 6, 8, 9, 10, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27, 30, 1000]));
  if (capped) {
    // Pad to the payload cap with outgoing_chan_ids (19, packed) and route hints (10).
    const target = MAX_PAYLOAD_BYTES + r.int(-200, 40);
    let size = parts.reduce((total, part) => total + part.length, 0);
    while (size < target - 80) { const part = r.chance(0.5) ? len(19, r.bytes(Math.min(2000, target - size - 8))) : len(10, cat([len(1, r.bytes(33)), uint(2, r.big(64))])); parts.push(part); size += part.length; }
  }
  for (let i = parts.length - 1; i > 0; i--) { const j = r.int(0, i); [parts[i], parts[j]] = [parts[j], parts[i]]; }
  return { payload: cat(parts), spec };
}

function genHop(r, spec) {
  const parts = [];
  if (r.chance(0.5)) parts.push(uint(1, r.big(64)));
  if (r.chance(0.3)) parts.push(uint(3, r.big(40)));
  if (r.chance(0.8)) { spec.amount = wireAmount(r); parts.push(uint(6, spec.amount)); }
  if (r.chance(0.5)) parts.push(uint(7, r.big(40)));
  if (r.chance(0.5)) parts.push(len(8, r.bytes(33).toString('hex')));
  if (r.chance(0.3)) parts.push(len(10, cat([len(11, SENTINEL_SECRET), uint(10, r.big(40))])));
  for (let i = r.weighted([[0, 3], [1, 3], [2, 1]]); i > 0; i--) parts.push(record(11, r.chance(0.7) ? KEYSEND_RECORD : r.big(64), SENTINEL_PREIMAGE));
  if (r.chance(0.1)) parts.push(len(13, r.bytes(r.int(0, 40))));
  for (let i = parts.length - 1; i > 0; i--) { const j = r.int(0, i); [parts[i], parts[j]] = [parts[j], parts[i]]; }
  return cat(parts);
}

/** routerrpc.SendToRouteRequest with one route; `spec` holds the hash, total_amt_msat and the hops' amounts. */
function genRoute(r, capped) {
  const spec = { hops: [] };
  const parts = [];
  if (r.chance(0.85)) {
    spec.hash = r.weighted([[r.bytes(32), 8], [r.bytes(r.int(0, 31)), 1], [r.bytes(r.int(33, 64)), 1]]);
    parts.push(len(1, spec.hash));
  }
  if (r.chance(0.9)) {
    spec.route = { hops: [] };
    const routeParts = [];
    if (r.chance(0.5)) routeParts.push(uint(1, r.int(0, 2 ** 31)));
    if (r.chance(0.8)) { spec.route.total = wireAmount(r); routeParts.push(uint(6, spec.route.total)); }
    if (r.chance(0.3)) routeParts.push(uint(5, r.big(40)));
    const hopCount = capped ? 0 : r.weighted([[0, 1], [r.int(1, 5), 8], [r.int(6, 27), 2], [r.int(28, 200), 0.5]]);
    for (let i = 0; i < hopCount; i++) { const hop = {}; routeParts.push(len(4, genHop(r, hop))); spec.route.hops.push(hop); }
    if (capped) {
      // Hops up to the payload cap: the nested decoder walks every one of them.
      const target = MAX_PAYLOAD_BYTES + r.int(-300, 40) - (spec.hash ? spec.hash.length + 2 : 0) - 8;
      let size = routeParts.reduce((total, part) => total + part.length, 0);
      while (size < target - 200) { const hop = {}; const part = len(4, genHop(r, hop)); routeParts.push(part); spec.route.hops.push(hop); size += part.length; }
    }
    if (r.chance(0.2)) routeParts.push(len(8, r.bytes(r.int(0, 30))));
    parts.push(len(2, cat(routeParts)));
  }
  if (r.chance(0.3)) parts.push(uint(3, r.int(0, 1)));
  if (r.chance(0.3)) parts.push(record(4, BigInt(r.int(65536, 2 ** 31)), SENTINEL_PREIMAGE));
  return { payload: cat(parts), spec };
}

function genDelete(r) {
  const spec = {};
  const parts = [];
  if (r.chance(0.8)) { spec.hash = r.weighted([[r.bytes(32), 8], [r.bytes(r.int(0, 31)), 1], [r.bytes(r.int(33, 64)), 1]]); parts.push(len(1, spec.hash)); }
  if (r.chance(0.5)) { spec.failedHtlcs = r.weighted([[0n, 1], [1n, 3], [BigInt(r.int(2, 300)), 1]]); parts.push(uint(2, spec.failedHtlcs)); }
  return { payload: cat(parts), spec };
}

function genDeleteAll(r) {
  const spec = {};
  const parts = [];
  for (const number of [1, 2, 3]) if (r.chance(0.5)) { spec[number] = r.weighted([[0n, 1], [1n, 4], [BigInt(r.int(2, 300)), 1]]); parts.push(uint(number, spec[number])); }
  for (let i = parts.length - 1; i > 0; i--) { const j = r.int(0, i); [parts[i], parts[j]] = [parts[j], parts[i]]; }
  return { payload: cat(parts), spec };
}

const int64 = value => (value === undefined ? 0n : value >= INT64_SIGN ? null : value);
const bounded = value => (value === null || value < 0n || value > MAX_INT64 ? null : value);

/** The facts the specification gives for an unmutated SendPaymentV2 request. */
function expectSend(spec) {
  const amt = int64(spec.amt), amtMsat = int64(spec.amtMsat), feeSat = int64(spec.feeSat), feeMsat = int64(spec.feeMsat);
  const requested = amt === null || amtMsat === null ? null : bounded(amtMsat > 0n ? amtMsat : amt > 0n ? amt * 1000n : null);
  const fee = feeSat === null || feeMsat === null ? null : bounded(feeMsat > 0n ? feeMsat : feeSat * 1000n);
  const amp = spec.amp !== undefined && spec.amp !== 0n;
  const invoice = spec.invoice && spec.invoice.expect.kind !== 'absent' ? spec.invoice.expect : null;
  if (invoice?.kind === 'malformed') return { paymentHash: null, amountMsat: null, amountSource: null, feeLimitMsat: null, amp: false, extraction: 'malformed' };
  if (invoice?.kind === 'unknown') return null;
  let paymentHash = null, amount = null, source = null, extraction;
  if (invoice) {
    if (invoice.kind === 'too-long') extraction = 'invoice-too-long';
    else if (invoice.kind === 'invalid') extraction = 'invoice-invalid';
    else {
      extraction = 'complete';
      paymentHash = invoice.hash;
      const value = bounded(invoice.amount);
      if (value !== null) { amount = value; source = 'invoice'; }
    }
  } else if (spec.hash) {
    paymentHash = spec.hash.length === 32 ? spec.hash.toString('hex') : null;
    extraction = paymentHash ? 'complete' : 'malformed';
  } else extraction = 'no-hash';
  if (source === null && requested !== null) { amount = requested; source = 'request'; }
  if (amp) { paymentHash = null; extraction = 'amp'; }
  return { paymentHash, amountMsat: amount === null ? null : amount.toString(), amountSource: source,
    feeLimitMsat: fee === null ? null : fee.toString(), amp, extraction };
}

function expectRoute(spec) {
  const paymentHash = spec.hash && spec.hash.length === 32 ? spec.hash.toString('hex') : null;
  const total = spec.route?.total === undefined ? null : int64(spec.route.total);
  const hops = spec.route?.hops ?? [];
  const last = hops.length ? int64(hops[hops.length - 1].amount) : null;
  const delivered = last !== null && last > 0n ? last : null;
  const fee = delivered !== null && total !== null && total >= delivered ? total - delivered : null;
  return { paymentHash, amountMsat: delivered === null ? null : delivered.toString(), amountSource: delivered === null ? null : 'route',
    feeLimitMsat: fee === null ? null : fee.toString(), amp: false, extraction: !spec.hash ? 'no-hash' : paymentHash ? 'complete' : 'malformed' };
}

function expectDeletion(method, spec) {
  if (method === DELETE) {
    const paymentHash = spec.hash && spec.hash.length === 32 ? spec.hash.toString('hex') : null;
    return { paymentHash, scope: spec.failedHtlcs ? 'failed-htlcs' : 'payment', extraction: spec.hash && !paymentHash ? 'malformed' : 'complete' };
  }
  const scope = spec[3] ? 'all-payments' : spec[1] ? 'failed-payments' : 'none';
  return { paymentHash: null, scope: spec[2] && scope !== 'none' ? 'failed-htlcs' : scope, extraction: 'complete' };
}

/** 1 to 3 mutations of a serialized message; returns the bytes and the mutation names. */
function mutate(r, data) {
  let out = Buffer.from(data);
  const ops = [];
  for (let i = r.int(1, 3); i > 0; i--) {
    const op = r.weighted([['flip', 4], ['truncate', 2], ['duplicate-field', 3], ['duplicate-slice', 1], ['wire-type', 3], ['huge-varint', 2],
      ['huge-length', 1], ['insert', 1], ['delete', 1], ['nested-flip', 2]]);
    const fields = walk(out).fields;
    const boundary = () => (fields.length ? r.pick([...fields.map(item => item.start), out.length]) : r.int(0, out.length));
    ops.push(op);
    if (op === 'flip' && out.length) { out[r.int(0, out.length - 1)] ^= 1 << r.int(0, 7); }
    else if (op === 'truncate') out = out.subarray(0, r.int(0, out.length));
    else if (op === 'duplicate-field' && fields.length) {
      const item = r.pick(fields);
      const at = boundary();
      out = cat([out.subarray(0, at), out.subarray(item.start, item.end), out.subarray(at)]);
    } else if (op === 'duplicate-slice' && out.length) {
      const from = r.int(0, out.length - 1), to = r.int(from, Math.min(out.length, from + 64));
      const at = r.int(0, out.length);
      out = cat([out.subarray(0, at), out.subarray(from, to), out.subarray(at)]);
    } else if (op === 'wire-type' && fields.length) {
      const item = r.pick(fields);
      out = cat([out.subarray(0, item.start), tag(item.number, r.int(0, 7)), out.subarray(item.tagEnd)]);
    } else if (op === 'huge-varint') {
      const at = boundary();
      const value = r.pick([
        Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]), // 2^64-1, ten bytes
        Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]), // above 2^64-1
        Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]), // eleven bytes
        Buffer.from([0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]), // 1, not minimal
        Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80])]); // never ends
      out = cat([out.subarray(0, at), tag(r.pick([2, 7, 12, 13, 22, 6, 1, 3]), 0), value, out.subarray(at)]);
    } else if (op === 'huge-length') {
      const lengthDelimited = fields.filter(item => item.wire === 2);
      if (lengthDelimited.length) {
        const item = r.pick(lengthDelimited);
        const length = r.pick([1n << 62n, MAX_UINT64, BigInt(item.end - item.valueStart + r.int(1, 5)), 0n]);
        out = cat([out.subarray(0, item.tagEnd), varint(length), out.subarray(item.valueStart)]);
      }
    } else if (op === 'insert') {
      const at = r.int(0, out.length);
      out = cat([out.subarray(0, at), r.bytes(r.int(1, 16)), out.subarray(at)]);
    } else if (op === 'delete' && out.length) {
      const from = r.int(0, out.length - 1);
      out = cat([out.subarray(0, from), out.subarray(Math.min(out.length, from + r.int(1, 16)))]);
    } else if (op === 'nested-flip') {
      const nested = fields.filter(item => item.wire === 2 && item.end > item.valueStart);
      if (nested.length) { const item = r.pick(nested); out[r.int(item.valueStart, item.end - 1)] ^= 1 << r.int(0, 7); }
    }
  }
  return { data: out, ops };
}

/**
 * One facts case: the method, the payload (null when oversized, as watch passes it), the facts
 * the specification gives (null when mutated or not modelled) and the secrets it must not reveal.
 */
export function factsCase(seed, index) {
  const r = xorshift(caseSeed(seed, 'facts', index));
  const kind = r.weighted([['send', 30], ['route', 15], ['delete', 5], ['delete-all', 5], ['mutated', 40], ['cross-method', 3], ['random', 2]]);
  const capped = r.chance(0.02);
  const build = method => (method === SEND ? genSend(r, capped) : method === ROUTE ? genRoute(r, capped) : method === DELETE ? genDelete(r) : genDeleteAll(r));
  let method = { send: SEND, route: ROUTE, delete: DELETE, 'delete-all': DELETE_ALL }[kind] ?? r.pick(METHODS);
  let { payload, spec } = kind === 'random' ? { payload: r.bytes(r.int(0, 200)), spec: null } : build(method);
  let ops = [];
  if (kind === 'mutated') ({ data: payload, ops } = mutate(r, payload));
  if (kind === 'cross-method') { method = r.pick(METHODS.filter(item => item !== method)); ops = ['cross-method']; }
  const oversized = payload.length > MAX_PAYLOAD_BYTES;
  let expect = null;
  if (oversized) expect = method === SEND || method === ROUTE
    ? { paymentHash: null, amountMsat: null, amountSource: null, feeLimitMsat: null, amp: false, extraction: 'payload-too-large' }
    : { paymentHash: null, scope: 'none', extraction: 'payload-too-large' };
  else if (!ops.length && spec) expect = method === SEND ? expectSend(spec) : method === ROUTE ? expectRoute(spec) : expectDeletion(method, spec);
  const invoice = spec?.invoice?.text || null;
  return { method, payload: oversized ? null : payload, size: payload.length, oversized, expect, kind, ops, invoice, defect: spec?.invoice?.defect ?? null };
}

const leakForms = buffer => [buffer.toString('hex'), buffer.toString('hex').toUpperCase(), buffer.toString('base64'), buffer.toString('base64url'),
  buffer.toString('latin1'), buffer.toString('base64').replace(/=+$/, '')];
const SENTINEL_FORMS = [...leakForms(SENTINEL_PREIMAGE).map(form => ['preimage', form]), ...leakForms(SENTINEL_SECRET).map(form => ['payment-secret', form])];

/** Form problems of one PaymentFacts value, as the journal documents them (empty when none). */
export function paymentFactsProblems(facts, method) {
  const problems = [];
  const keys = ['paymentHash', 'amountMsat', 'amountSource', 'feeLimitMsat', 'amp', 'extraction'];
  if (!facts || typeof facts !== 'object' || Object.keys(facts).length !== keys.length || !keys.every(key => Object.hasOwn(facts, key))) return ['keys'];
  if (facts.paymentHash !== null && !(typeof facts.paymentHash === 'string' && HASH.test(facts.paymentHash))) problems.push('paymentHash form');
  for (const key of ['amountMsat', 'feeLimitMsat']) {
    const value = facts[key];
    if (value !== null && !(typeof value === 'string' && DECIMAL.test(value) && value.length <= 20 && BigInt(value) <= MAX_INT64)) problems.push(`${key} form`);
  }
  if (![null, 'request', 'invoice', 'route'].includes(facts.amountSource)) problems.push('amountSource value');
  if ((facts.amountSource === null) !== (facts.amountMsat === null)) problems.push('amountSource null iff amountMsat null');
  if (facts.amountSource === 'route' && method !== ROUTE) problems.push('route amount from another method');
  if ((facts.amountSource === 'request' || facts.amountSource === 'invoice') && method !== SEND) problems.push('request amount from another method');
  if (typeof facts.amp !== 'boolean') problems.push('amp type');
  if (!EXTRACTIONS.includes(facts.extraction)) problems.push('extraction value');
  if ((facts.extraction === 'complete') !== (facts.paymentHash !== null)) problems.push('hash non-null iff extraction complete');
  if (facts.amp !== (facts.extraction === 'amp')) problems.push('amp iff extraction amp');
  return problems;
}

export function deletionFactsProblems(facts, method) {
  const problems = [];
  const keys = ['paymentHash', 'scope', 'extraction'];
  if (!facts || typeof facts !== 'object' || Object.keys(facts).length !== keys.length || !keys.every(key => Object.hasOwn(facts, key))) return ['keys'];
  if (facts.paymentHash !== null && !(typeof facts.paymentHash === 'string' && HASH.test(facts.paymentHash))) problems.push('paymentHash form');
  if (!['payment', 'failed-htlcs', 'all-payments', 'failed-payments', 'none'].includes(facts.scope)) problems.push('scope value');
  if (!['complete', 'payload-too-large', 'malformed'].includes(facts.extraction)) problems.push('extraction value');
  if (facts.paymentHash !== null && facts.extraction !== 'complete') problems.push('hash without complete extraction');
  if (method === DELETE_ALL && facts.paymentHash !== null) problems.push('DeleteAllPayments with a hash');
  if (method === DELETE && facts.extraction === 'complete' && !['payment', 'failed-htlcs'].includes(facts.scope)) problems.push('DeletePayment scope');
  return problems;
}

/** Whether the payload itself names the sentinel as its payment hash (a mutation can move it there). */
function sentinelIsTheHash(method, payload) {
  if (!payload) return false;
  const number = method === SEND ? 3 : 1;
  return walk(payload).fields.some(item => item.number === number && item.wire === 2 && item.end - item.valueStart === 32
    && payload.subarray(item.valueStart, item.end).equals(SENTINEL_PREIMAGE));
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const preview = (buffer, limit = 2048) => (buffer === null ? 'null' : buffer.length > limit
  ? `${buffer.subarray(0, limit).toString('hex')}... (${buffer.length} bytes; regenerate with --verbose)` : buffer.toString('hex'));

/**
 * Records a failure: one a known open defect explains is counted in `stats.known` (with up to
 * three examples, marked `known`), so the failure limit applies to new findings only.
 */
function recorder(stats, failures, maxFailures) {
  stats.known ??= {};
  let fresh = 0;
  return failure => {
    const id = knownDefect(failure);
    if (id) {
      stats.known[id] = (stats.known[id] ?? 0) + 1;
      if (stats.known[id] <= 3) failures.push({ ...failure, known: id });
      return;
    }
    if (fresh++ < maxFailures) failures.push(failure);
  };
}

/**
 * Runs the facts target. `api` = { paymentFacts, deletionFacts, parseRecord }. Returns the stats,
 * the timing (the slowest decode, confirmed by repeating it) and the failures.
 */
/**
 * @param {Record<string, any>} api
 * @param {{ seed: number, cases: number, start?: number, maxFailures?: number, timeLimitMs?: number, verbose?: boolean,
 *   onProgress?: (done: number, failures: number) => void }} options
 */
export function factsCampaign(api, { seed, cases, start = 0, maxFailures = 20, timeLimitMs = 100, verbose = false, onProgress }) {
  const stats = { cases: 0, mutated: 0, oversized: 0, capped: 0, expected: 0, invoices: 0, sentinelAsHash: 0,
    byExtraction: /** @type {Record<string, number>} */ ({}), byKind: /** @type {Record<string, number>} */ ({}),
    byMethod: /** @type {Record<string, number>} */ ({}) };
  const timing = { maxMs: 0, maxIndex: -1, totalMs: 0, maxBytes: 0 };
  const failures = [];
  const record = recorder(stats, failures, maxFailures);
  const fail = (index, kind, message, item, output) => {
    record({ target: 'facts', seed, index, kind, message,
      input: { method: item.method, kind: item.kind, mutations: item.ops, invoiceDefect: item.defect, oversized: item.oversized, size: item.size,
        payload: verbose ? (item.payload?.toString('hex') ?? null) : preview(item.payload) },
      output: output === undefined ? undefined : JSON.stringify(output) });
  };
  const RUN = '00000000-0000-4000-8000-000000000000';
  for (let index = start; index < start + cases; index++) {
    const item = factsCase(seed, index);
    stats.cases++;
    stats.byKind[item.kind] = (stats.byKind[item.kind] ?? 0) + 1;
    stats.byMethod[item.method] = (stats.byMethod[item.method] ?? 0) + 1;
    if (item.ops.length) stats.mutated++;
    if (item.oversized) stats.oversized++;
    if (item.size > MAX_PAYLOAD_BYTES - 1024) stats.capped++;
    if (item.invoice) stats.invoices++;
    const payment = item.method === SEND || item.method === ROUTE;
    // The decoder zeroes nothing itself, but give it its own copy, as the journal does.
    const decode = () => (payment ? api.paymentFacts(item.method, item.payload && Buffer.from(item.payload), item.oversized)
      : api.deletionFacts(item.method, item.payload && Buffer.from(item.payload), item.oversized));
    let facts;
    const began = performance.now();
    try { facts = decode(); }
    catch (error) { fail(index, 'threw', `${payment ? 'paymentFacts' : 'deletionFacts'} threw ${error?.name}: ${error?.message}`, item); continue; }
    let elapsed = performance.now() - began;
    if (elapsed > timeLimitMs) {
      // A garbage collection can stop any call: count it only if repeating the call is slow too.
      for (let again = 0; again < 3 && elapsed > timeLimitMs; again++) { const t = performance.now(); decode(); elapsed = Math.min(elapsed, performance.now() - t); }
      if (elapsed > timeLimitMs) fail(index, 'slow', `decoding took ${elapsed.toFixed(1)} ms (limit ${timeLimitMs} ms)`, item);
    }
    timing.totalMs += elapsed;
    if (elapsed > timing.maxMs) { timing.maxMs = elapsed; timing.maxIndex = index; timing.maxBytes = item.size; }
    stats.byExtraction[facts?.extraction] = (stats.byExtraction[facts?.extraction] ?? 0) + 1;
    const problems = payment ? paymentFactsProblems(facts, item.method) : deletionFactsProblems(facts, item.method);
    if (problems.length) fail(index, 'form', problems.join('; '), item, facts);
    // The journal's reader takes the record these facts make.
    const who = { requestId: '1', credential: 'id:0123456789abcdef', rootKeyId: '0' };
    const recordLine = JSON.stringify(payment
      ? { v: 1, type: 'payment', time: '2026-10-09T10:00:00.000Z', run: RUN, ...who, method: item.method, ...facts }
      : { v: 1, type: 'deletion', time: '2026-10-09T10:00:00.000Z', run: RUN, ...who, method: item.method, ...facts });
    if (!problems.length && api.parseRecord(recordLine) === null) fail(index, 'reader-refuses', 'parseRecord refuses the record these facts make', item, facts);
    // No secret and no invoice text in the facts, in any encoding.
    const text = JSON.stringify(facts);
    const values = Object.values(facts ?? {}).filter(value => typeof value === 'string').join('\u0000');
    for (const [name, form] of SENTINEL_FORMS) {
      if (!text.includes(form) && !values.includes(form)) continue;
      if (name === 'preimage' && facts.paymentHash === SENTINEL_PREIMAGE.toString('hex') && sentinelIsTheHash(item.method, item.payload)) { stats.sentinelAsHash++; continue; }
      fail(index, 'leak', `the ${name} sentinel appears in the facts`, item, facts);
    }
    if (item.invoice && item.invoice.length >= 16 && (text.includes(item.invoice) || text.toLowerCase().includes(item.invoice.toLowerCase().slice(0, 40))))
      fail(index, 'leak', 'invoice text appears in the facts', item, facts);
    if (item.expect) {
      stats.expected++;
      if (!same(facts, item.expect)) fail(index, 'specification', `facts differ from the specification: expected ${JSON.stringify(item.expect)}`, item, facts);
    }
    if (onProgress && (index - start + 1) % 20_000 === 0) onProgress(index - start + 1, failures.length);
  }
  return { stats, timing, failures };
}

// ---------------------------------------------------------------------------------------------
// Journal target.

/** The regtest vectors (throwaway credentials from a disposable node; never real credentials). */
export function loadVectors(root = REPO) {
  const dir = join(root, 'test/vectors');
  return readdirSync(dir).filter(name => name.endsWith('.macaroon')).sort().map(name => ({ name, bytes: readFileSync(join(dir, name)) }));
}

/** Independent credential ID: SHA-256 of the identifier packet (type 2 of the V2 header); null when not found. */
export function identityOf(bytes) {
  let at = 1;
  const read = () => {
    let value = 0, shift = 0;
    for (let i = 0; i < 8; i++) { if (at >= bytes.length) return null; const byte = bytes[at++]; value += (byte & 0x7f) * 2 ** shift; if (!(byte & 0x80)) return value; shift += 7; }
    return null;
  };
  if (bytes[0] !== 2) return null;
  for (let guard = 0; guard < 16; guard++) {
    const type = read();
    if (type === null || type === 0) return null;
    const length = read();
    if (length === null || at + length > bytes.length) return null;
    if (type === 2) return `id:${createHash('sha256').update(bytes.subarray(at, at + length)).digest('hex').slice(0, 16)}`;
    at += length;
  }
  return null;
}

const delay = ms => new Promise(done => setTimeout(done, ms));
const turns = async count => { for (let i = 0; i < count; i++) await new Promise(done => setImmediate(done)); };
const MAX_RECORD_TIME = 253_402_300_799_999;

/**
 * fs/promises whose file handles write as `control.mode` says: normally, slowly, a part per call,
 * a part and then an error, no progress, a failing fsync, or held until `control.release()`.
 */
function controlledFs(control) {
  const wrap = handle => new Proxy(handle, {
    get(target, property) {
      if (property === 'write') return async (buffer, offset = 0, length = buffer.length - offset) => {
        if (control.gate) await control.gate.promise;
        const mode = control.mode;
        if (mode === 'slow') await delay(control.delayMs);
        if (mode === 'short' && length > 1) return target.write(buffer, offset, Math.max(1, Math.floor(length * control.fraction)));
        if (mode === 'fail') {
          const part = Math.floor(length * control.fraction);
          if (part > 0) await target.write(buffer, offset, part);
          control.failedWrites++;
          throw Object.assign(new Error('injected write failure'), { code: 'EIO' });
        }
        // No progress: writeAll gives up, after any part an earlier short write left (a failed write).
        if (mode === 'zero') { control.failedWrites++; return { bytesWritten: 0, buffer }; }
        return target.write(buffer, offset, length);
      };
      if (property === 'sync') return async () => {
        if (control.syncFail) { control.failedWrites++; throw Object.assign(new Error('injected fsync failure'), { code: 'EIO' }); }
        return target.sync();
      };
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { ...nodeFs, open: async (...args) => wrap(await nodeFs.open(...args)) };
}

function gate() { let release; const promise = new Promise(done => { release = done; }); return { promise, release }; }

let prefillCache = null;
/** A valid journal run of `alive` records, `size` bytes or slightly fewer (whole lines). */
function prefill(size) {
  const run = 'f0f0f0f0-0000-4000-8000-00000000f111';
  const head = `${JSON.stringify({ v: 1, type: 'run-start', time: '2026-10-09T09:00:00.000Z', run, node: NODE, version: 'prefill', repairedTail: false })}\n`;
  const line = `${JSON.stringify({ v: 1, type: 'alive', time: '2026-10-09T09:00:00.000Z', run })}\n`;
  if (!prefillCache) prefillCache = Buffer.from(line.repeat(Math.ceil((64 * 1024 * 1024) / line.length)));
  const count = Math.max(0, Math.floor((size - head.length) / line.length));
  return Buffer.concat([Buffer.from(head), prefillCache.subarray(0, count * line.length)]);
}

/** A payload for a captured call: mostly small requests, sometimes at the cap, sometimes oversized. */
function capturePayload(r, method, big) {
  if (big) return { payload: r.bytes(MAX_PAYLOAD_BYTES - r.int(0, 64)), oversized: false };
  if (r.chance(0.03)) return { payload: null, oversized: true };
  if (r.chance(0.02)) return { payload: null, oversized: false };
  const built = method === SEND ? genSend(r, false) : method === ROUTE ? genRoute(r, false) : method === DELETE ? genDelete(r) : genDeleteAll(r);
  const payload = r.chance(0.2) ? mutate(r, built.payload).data : built.payload;
  return payload.length > MAX_PAYLOAD_BYTES ? { payload: null, oversized: true } : { payload, oversized: false };
}

function journalOps(r, fill) {
  const ops = [];
  const count = r.int(4, 40);
  for (let i = 0; i < count; i++) {
    const op = r.weighted([['capture', 30], ['burst', 2], ['big-burst', 1], ['registered', 8], ['unregistered', 6], ['clock', 6], ['yield', 18],
      ['sleep', 4], ['fs', 5], ['marker-flood', 0.3], ['pending-flood', 0.6]]);
    if (op === 'capture') ops.push({ op, count: r.int(1, 4) });
    else if (op === 'burst') ops.push({ op, count: r.int(1_025, 2_200) });
    else if (op === 'big-burst') ops.push({ op, count: r.int(100, 180) });
    else if (op === 'unregistered') ops.push({ op, reason: r.pick(['stream-lost', 'refresh', 'stopping']) });
    else if (op === 'clock') ops.push({ op, step: r.weighted([['forward', 6], ['far-forward', 1], ['back', 3], ['nan', 1], ['throw', 1], ['year-9999', 1],
      ['beyond-9999', 1], ['restore', 3]]), amount: r.int(1, 10_000), far: r.int(1, 400) * 86_400_000 });
    else if (op === 'yield') ops.push({ op, turns: r.int(1, 40) });
    else if (op === 'sleep') ops.push({ op, ms: r.int(1, 15) });
    else if (op === 'fs') ops.push({ op, mode: r.weighted([['normal', 8], ['slow', 4], ['short', 3], ['fail', 1], ['zero', 1], ['sync-fail', 1], ['hold', 2], ['release', 3]]),
      delayMs: r.int(1, 20), fraction: r.next() });
    else ops.push({ op });
  }
  if (fill) {
    // Registered when the file fills, so the full record ends a covered span (the journal-full gap).
    for (let i = 0; i < 8; i++) ops.splice(r.int(0, ops.length), 0, { op: 'fill-burst', count: 300 });
    // The registration lands before the first burst, so it is not among the lines lost at the limit.
    ops.unshift({ op: 'registered' }, { op: 'yield', turns: 10 }, { op: 'sleep', ms: 15 });
    return ops.filter(item => item.op !== 'unregistered' && item.op !== 'marker-flood');
  }
  return ops;
}

/**
 * One journal case. Returns nothing; reports failures through `ctx.fail(kind, message, detail)`.
 * `ctx` also carries the stats, the vectors and the trace (the operations as run).
 */
async function journalCase(api, seed, index, dir, ctx) {
  const r = xorshift(caseSeed(seed, 'journal', index));
  const path = join(dir, 'payments.journal');
  const fill = index % 25 === 3;
  const crash = index % 25 === 5 || r.chance(0.4);
  const { stats, vectors, fail, trace } = ctx;
  const noLock = async () => async () => undefined;
  let clockValue = Date.parse('2026-10-09T10:00:00.000Z') + r.int(0, 86_400) * 1_000;
  let clockMode = 'ok';
  const clock = () => {
    if (clockMode === 'throw') throw new Error('clock unavailable');
    return new Date(clockMode === 'nan' ? Number.NaN : clockValue);
  };
  const control = { mode: 'normal', delayMs: 0, fraction: 0.5, syncFail: false, gate: null, failedWrites: 0 };
  const fs = controlledFs(control);
  if (fill) {
    stats.fills++;
    const first = await api.PaymentJournal.open(path, NODE, 'fuzz', { fs: nodeFs, clock, lock: noLock });
    await first.close();
    const size = statSync(path).size;
    const target = api.JOURNAL_LIMIT_BYTES - api.JOURNAL_RESERVE_BYTES - api.JOURNAL_START_ROOM_BYTES - r.int(0, 50_000);
    appendFileSync(path, prefill(target - size));
    trace.push(`prefilled to ${statSync(path).size} bytes`);
  }
  const journal = await api.PaymentJournal.open(path, NODE, 'fuzz', { fs, clock, lock: noLock });
  const run = { journal, captured: 0, afterStop: 0, duringClose: 0, calls: new Map(), accepted: [], requestId: BigInt(r.int(1, 1_000_000)) };
  if (r.chance(0.05)) run.requestId = MAX_UINT64 - 100_000n;

  const capture = (big = false) => {
    const method = r.weighted([[SEND, 6], [ROUTE, 3], [DELETE, 1], [DELETE_ALL, 1]]);
    const { payload, oversized } = capturePayload(r, method, big);
    const macaroonKind = r.weighted([['vector', 80], ['none', 5], ['random', 5], ['oversized', 5], ['truncated', 5]]);
    const vector = r.pick(vectors);
    const macaroon = macaroonKind === 'vector' ? vector.bytes : macaroonKind === 'random' ? r.bytes(r.int(1, 300))
      : macaroonKind === 'truncated' ? vector.bytes.subarray(0, r.int(1, vector.bytes.length - 1)) : null;
    const requestId = run.requestId++;
    const call = { kind: 'request', requestId, method, isError: false, customCaveatCondition: '',
      macaroon: macaroon ? new api.Secret(Buffer.from(macaroon)) : null, payload: payload ? Buffer.from(payload) : null,
      payloadBytes: payload?.length ?? 0, macaroonBytes: macaroon?.length ?? 0,
      ...(macaroonKind === 'oversized' ? { oversizedMacaroon: true } : {}), ...(oversized ? { oversizedPayload: true } : {}) };
    run.calls.set(requestId.toString(), { method, payload, oversized, macaroonKind, macaroon });
    if (journal.stats.stopped) run.afterStop++;
    if (run.closing) run.duringClose++;
    run.captured++;
    const dropped = journal.stats.dropped;
    journal.capture(call);
    if (journal.stats.dropped === dropped && call.payload) run.accepted.push(call.payload);
  };

  const ops = journalOps(r, fill);
  for (const item of ops) {
    trace.push(JSON.stringify(item));
    switch (item.op) {
      case 'capture': for (let i = 0; i < item.count; i++) capture(); break;
      case 'burst': for (let i = 0; i < item.count; i++) capture(); stats.bursts++; break;
      case 'big-burst': for (let i = 0; i < item.count; i++) capture(true); stats.bursts++; break;
      case 'fill-burst': for (let i = 0; i < item.count; i++) { capture(); if (i % 50 === 49) { if (clockMode === 'ok') clockValue += 1_000; await turns(8); } } break;
      case 'registered': journal.registered(); break;
      case 'unregistered': journal.unregistered(item.reason); break;
      case 'clock':
        if (item.step === 'forward') { clockMode = 'ok'; clockValue += item.amount; }
        else if (item.step === 'far-forward') { clockMode = 'ok'; clockValue = Math.min(clockValue + item.far, MAX_RECORD_TIME - 1_000_000); }
        else if (item.step === 'back') { clockMode = 'ok'; clockValue -= item.amount * 1_000; }
        else if (item.step === 'nan') clockMode = 'nan';
        else if (item.step === 'throw') clockMode = 'throw';
        else if (item.step === 'year-9999') { clockMode = 'ok'; clockValue = MAX_RECORD_TIME - item.amount; }
        else if (item.step === 'beyond-9999') { clockMode = 'ok'; clockValue = MAX_RECORD_TIME + item.amount * 1_000; }
        else { clockMode = 'ok'; clockValue = Date.parse('2026-10-09T12:00:00.000Z') + item.amount * 1_000; }
        break;
      case 'yield': await turns(item.turns); break;
      case 'sleep': await delay(item.ms); break;
      case 'fs':
        if (item.mode === 'hold') { if (!control.gate) control.gate = gate(); }
        else if (item.mode === 'release') { control.gate?.release(); control.gate = null; }
        else if (item.mode === 'sync-fail') control.syncFail = true;
        else { control.mode = item.mode; control.delayMs = item.delayMs; control.fraction = item.fraction; }
        break;
      case 'marker-flood':
        // Markers are never dropped: more than 1 MiB of them waiting for a held disk stops the run ('stalled').
        if (!control.gate) control.gate = gate();
        for (let i = 0; i < 6_000; i++) { journal.registered(); journal.unregistered('refresh'); }
        await turns(60);
        stats.markerFloods++;
        break;
      case 'pending-flood':
        // Records wait for a held disk: past 1 MiB of lines they are dropped and counted.
        if (!control.gate) control.gate = gate();
        for (let i = 0; i < 3_200; i++) { capture(); if (i % 400 === 399) await turns(40); }
        await turns(40);
        stats.pendingFloods++;
        break;
      default: break;
    }
  }
  control.gate?.release();
  control.gate = null;
  const lateCaptures = r.chance(0.1) ? r.int(1, 5) : 0;
  const closing = journal.close();
  run.closing = true;
  for (let i = 0; i < lateCaptures; i++) capture();
  const final = await closing;
  stats.captured += run.captured;
  if (final.stopped) stats.stopped[final.stopped] = (stats.stopped[final.stopped] ?? 0) + 1;
  // The payload copies the journal decoded hold no request byte any more (the invoice text is not kept).
  if (run.accepted.some(payload => payload.some(byte => byte !== 0))) fail('payload-kept', 'a payload copy the journal accepted was not zeroed after close');
  await checkRun(api, path, run, ctx, { stopped: final.stopped, failedWrites: control.failedWrites, label: 'run 1' });
  if (!crash) return;

  // A crash: the file is cut at a random byte, then the next run repairs it.
  stats.truncated++;
  const before = readFileSync(path);
  const cut = r.weighted([[r.int(0, before.length), 2], [lineBoundary(r, before), 1], [lastLine(r, before), 1]]);
  truncateSync(path, cut);
  const left = before.subarray(0, cut);
  trace.push(`truncated ${before.length} -> ${cut} bytes`);
  try { await api.readJournal(path); }
  catch (error) { fail('truncated-refused', `readJournal refuses the file cut at byte ${cut}: ${error?.message}`); return; }
  const endsClean = cut === 0 || (left[left.length - 1] === 0x0a && api.parseRecord(left.subarray(left.lastIndexOf(0x0a, left.length - 2) + 1, left.length - 1).toString('utf8')) !== null);
  const refusedHead = cut > 0 && !left.subarray(0, 64).toString('latin1').startsWith('{"v":1,"type":"run-start"');
  const refusedFull = cut > api.JOURNAL_LIMIT_BYTES - api.JOURNAL_RESERVE_BYTES - api.JOURNAL_START_ROOM_BYTES;
  clockMode = 'ok';
  clockValue = Date.parse('2026-10-09T12:00:00.000Z') + r.int(0, 100_000);
  let second;
  try { second = await api.PaymentJournal.open(path, NODE, 'fuzz', { fs: nodeFs, clock, lock: noLock }); }
  catch (error) {
    if (refusedHead || refusedFull) { stats.refusedReopen++; return; }
    fail('reopen-refused', `reopening the file cut at byte ${cut} was refused: ${error?.message}`);
    return;
  }
  if (refusedHead || refusedFull) fail('reopen-accepted', `reopening a file cut at byte ${cut} was accepted (head or size should refuse it)`);
  const run2 = { journal: second, captured: 0, afterStop: 0, duringClose: 0, calls: new Map(), accepted: [], requestId: BigInt(r.int(1, 1_000_000)) };
  for (let i = r.int(0, 8); i > 0; i--) {
    const step = r.weighted([['capture', 4], ['registered', 2], ['unregistered', 1], ['yield', 2]]);
    trace.push(`run 2: ${step}`);
    if (step === 'capture') {
      const method = r.pick(METHODS);
      const { payload, oversized } = capturePayload(r, method, false);
      const vector = r.pick(vectors);
      const requestId = run2.requestId++;
      run2.calls.set(requestId.toString(), { method, payload, oversized, macaroonKind: 'vector', macaroon: vector.bytes });
      run2.captured++;
      second.capture({ kind: 'request', requestId, method, isError: false, customCaveatCondition: '', macaroon: new api.Secret(Buffer.from(vector.bytes)),
        payload: payload ? Buffer.from(payload) : null, payloadBytes: payload?.length ?? 0, macaroonBytes: vector.bytes.length, ...(oversized ? { oversizedPayload: true } : {}) });
    } else if (step === 'registered') second.registered();
    else if (step === 'unregistered') second.unregistered('stream-lost');
    else await turns(r.int(1, 20));
  }
  const final2 = await second.close();
  stats.captured += run2.captured;
  const contents = await checkRun(api, path, run2, ctx, { stopped: final2.stopped, failedWrites: 0, label: 'run 2' });
  if (!contents) return;
  const runStart = contents.records.find(item => item.type === 'run-start' && item.run === second.run);
  if (runStart && runStart.repairedTail !== !endsClean) fail('repaired-tail', `run 2 run-start says repairedTail ${runStart.repairedTail}; the file cut at byte ${cut} ${endsClean ? 'ended with a complete record' : 'ended with an incomplete or invalid line'}`);
  if (!endsClean) stats.repaired++;
}

function lineBoundary(r, bytes) {
  const ends = [];
  for (let i = bytes.indexOf(0x0a); i >= 0 && ends.length < 100_000; i = bytes.indexOf(0x0a, i + 1)) ends.push(i + 1);
  return ends.length ? r.pick(ends) : 0;
}
function lastLine(r, bytes) {
  const end = bytes.lastIndexOf(0x0a, bytes.length - 2);
  return r.int(Math.max(0, end + 1), bytes.length);
}

/**
 * Checks the file after a run closed: the reader accepts it, every complete line is a record,
 * times keep their order, the counts add up, the size bound holds and coverage is consistent.
 */
async function checkRun(api, path, run, ctx, { stopped, failedWrites, label }) {
  const { fail, stats } = ctx;
  const journal = run.journal;
  const size = statSync(path).size;
  if (size > api.JOURNAL_LIMIT_BYTES) fail('size', `${label}: the file is ${size} bytes, above ${api.JOURNAL_LIMIT_BYTES}`);
  let contents;
  try { contents = await api.readJournal(path); }
  catch (error) { fail('reader-refuses', `${label}: readJournal refuses the file: ${error?.message}`); return null; }
  if (contents.tornTail && !failedWrites) fail('torn-tail', `${label}: the file ends with an incomplete line though no write failed`);
  // Every complete line is a record the reader takes (a failed write may leave the last one partial).
  const text = readFileSync(path, 'utf8');
  const lines = text.split('\n');
  lines.pop();
  for (const [at, line] of lines.entries()) {
    if (api.parseRecord(line) === null && !(failedWrites && at === lines.length - 1) && !contents.repairedLines)
      { fail('line', `${label}: line ${at + 1} is not a valid record: ${line.slice(0, 200)}`); break; }
  }
  const records = contents.records.filter(item => item.run === journal.run);
  if (!records.length || records[0].type !== 'run-start') { fail('run-start', `${label}: the run's run-start is not in the file`); return contents; }
  let previous = -Infinity;
  for (const item of records) {
    const time = Date.parse(item.time);
    if (time < previous) { fail('time-order', `${label}: ${item.type} at ${item.time} comes after a later record`); break; }
    previous = time;
  }
  const s = journal.stats;
  if (s.payments + s.deletions + s.dropped !== run.captured)
    fail('stats', `${label}: payments ${s.payments} + deletions ${s.deletions} + dropped ${s.dropped} != ${run.captured} captured`);
  const payments = records.filter(item => item.type === 'payment');
  const deletions = records.filter(item => item.type === 'deletion');
  const dropped = records.filter(item => item.type === 'drop').reduce((total, item) => total + item.count, 0);
  const inFile = payments.length + deletions.length + dropped;
  stats.records += payments.length + deletions.length;
  stats.dropRecords += records.filter(item => item.type === 'drop').length;
  stats.droppedInFile += dropped;
  // Captures after close() began are counted as dropped and not journaled (documented): they are calls lost at stop.
  if (run.duringClose) { stats.shortfallClosing += run.duringClose; }
  if (stopped === null) {
    if (inFile !== run.captured - run.duringClose)
      fail('accounting', `${label}: records ${payments.length + deletions.length} + drop counts ${dropped} = ${inFile} != ${run.captured} captured - ${run.duringClose} while closing (journal not stopped)`);
  } else {
    // Calls lost because journaling stopped are counted in the statistics, not in the file.
    const shortfall = run.captured - inFile;
    if (shortfall < 0) fail('accounting', `${label}: the file accounts for ${inFile} calls, more than the ${run.captured} captured`);
    else if (shortfall > 0) {
      stats.shortfallCases++; stats.shortfall += shortfall;
      stats.shortfallAfterStop += Math.min(shortfall, run.afterStop);
      if (stopped === 'full' && shortfall > run.afterStop) stats.fullShortfallBeforeStop += shortfall - run.afterStop;
    }
  }
  const ends = records.filter(item => item.type === 'run-end');
  if (ends.length) {
    const end = ends[0];
    if (end.payments !== payments.length || end.deletions !== deletions.length)
      fail('run-end', `${label}: run-end counts ${end.payments}/${end.deletions} differ from the records in the file ${payments.length}/${deletions.length}`);
    // A failed fsync after the run-end landed counts the batch as dropped afterwards: compare only an unstopped run.
    if (stopped === null && end.dropped !== s.dropped - run.duringClose)
      fail('run-end', `${label}: run-end dropped ${end.dropped}, statistics ${s.dropped} (${run.duringClose} captured while closing)`);
  }
  if (stopped === null && !ends.length) fail('run-end', `${label}: the run closed without a stop but has no run-end`);
  // Each record names its call: the method, the caller and the facts of that request.
  const seen = new Set();
  for (const item of [...payments, ...deletions]) {
    if (seen.has(item.requestId)) fail('duplicate', `${label}: request ${item.requestId} recorded twice`);
    seen.add(item.requestId);
    const call = run.calls.get(item.requestId);
    if (!call) { fail('unknown-request', `${label}: request ${item.requestId} was never captured`); continue; }
    if (call.method !== item.method) fail('method', `${label}: request ${item.requestId} recorded as ${item.method}, captured as ${call.method}`);
    const expectedId = call.macaroonKind === 'none' ? 'id:none' : call.macaroonKind === 'oversized' ? 'id:undecodable' : null;
    if (expectedId && item.credential !== expectedId) fail('credential', `${label}: request ${item.requestId} credential ${item.credential}, expected ${expectedId}`);
    if (call.macaroonKind === 'vector') {
      const id = identityOf(call.macaroon);
      if (item.credential !== id && item.credential !== 'id:undecodable') fail('credential', `${label}: request ${item.requestId} credential ${item.credential}, expected ${id}`);
    }
    if (item.credential.length < 19 && item.rootKeyId !== 'none') fail('credential', `${label}: ${item.credential} with root key ID ${item.rootKeyId}`);
    const facts = item.type === 'payment' ? api.paymentFacts(call.method, call.payload && Buffer.from(call.payload), call.oversized)
      : api.deletionFacts(call.method, call.payload && Buffer.from(call.payload), call.oversized);
    const recorded = item.type === 'payment'
      ? { paymentHash: item.paymentHash, amountMsat: item.amountMsat, amountSource: item.amountSource, feeLimitMsat: item.feeLimitMsat, amp: item.amp, extraction: item.extraction }
      : { paymentHash: item.paymentHash, scope: item.scope, extraction: item.extraction };
    if (!same(recorded, facts)) {
      if (item.extraction === 'malformed' && item.paymentHash === null) stats.fallbacks++;
      else fail('facts', `${label}: request ${item.requestId} recorded ${JSON.stringify(recorded)}, the request's facts are ${JSON.stringify(facts)}`);
    }
  }
  checkCoverage(api, records, ctx, label, stopped);
  return contents;
}

function checkCoverage(api, records, ctx, label, stopped) {
  const { fail } = ctx;
  const from = Date.parse(records[0].time);
  const to = Math.max(...records.map(item => Date.parse(item.time))) + 1_000;
  let coverage;
  try { coverage = api.journalCoverage(records, NODE, from, to); }
  catch (error) { fail('coverage-threw', `${label}: journalCoverage threw ${error?.message}`); return; }
  const covered = coverage.covered;
  let sum = 0;
  for (const [index, [a, b]] of covered.entries()) {
    if (!(a < b) || a < from || b > to) fail('coverage', `${label}: covered span [${a}, ${b}] is empty or outside the window [${from}, ${to}]`);
    if (index && a <= covered[index - 1][1]) fail('coverage', `${label}: covered spans overlap or touch: [${covered[index - 1]}] and [${a}, ${b}]`);
    sum += b - a;
  }
  if (sum !== coverage.coveredMs) fail('coverage', `${label}: coveredMs ${coverage.coveredMs} != the sum of the spans ${sum}`);
  const overlap = (a, b, c, d) => Math.min(b, d) - Math.max(a, c);
  for (const gap of coverage.gaps) {
    if (gap.from < from || gap.to > to || gap.from > gap.to) fail('coverage', `${label}: gap ${JSON.stringify(gap)} outside the window [${from}, ${to}]`);
    for (const [a, b] of covered) if (overlap(a, b, gap.from, gap.to) > 0) { fail('coverage', `${label}: gap ${JSON.stringify(gap)} overlaps covered [${a}, ${b}]`); break; }
  }
  // Covered spans and gaps together are the window.
  const all = [...covered.map(([a, b]) => [a, b]), ...coverage.gaps.map(gap => [gap.from, gap.to])].sort((x, y) => x[0] - y[0]);
  let cursor = from;
  for (const [a, b] of all) { if (a > cursor) { fail('coverage', `${label}: [${cursor}, ${a}] is neither covered nor a gap`); break; } cursor = Math.max(cursor, b); }
  if (cursor < to) fail('coverage', `${label}: [${cursor}, ${to}] is neither covered nor a gap`);
  // No covered time inside a drop window; every drop count is listed.
  const drops = records.filter(item => item.type === 'drop');
  for (const drop of drops) {
    const first = Date.parse(drop.first), last = Date.parse(drop.last);
    for (const [a, b] of covered) if (overlap(a, b, first, last) > 0) { fail('coverage', `${label}: covered [${a}, ${b}] inside drop window [${drop.first}, ${drop.last}]`); break; }
  }
  const listedDrops = coverage.gaps.reduce((total, gap) => total + gap.dropped, 0);
  const recordedDrops = drops.reduce((total, item) => total + item.count, 0);
  if (listedDrops !== recordedDrops) fail('coverage', `${label}: gaps list ${listedDrops} dropped calls, drop records hold ${recordedDrops}`);
  // A full journal: the drop of what did not fit is listed, starting no later than the journal-full gap.
  const fullAt = records.findIndex(item => item.type === 'full');
  if (fullAt > 0 && records[fullAt - 1].type === 'drop') {
    ctx.stats.fullWithDrop++;
    const fullGap = coverage.gaps.find(gap => gap.reason === 'journal-full');
    if (fullGap) {
      ctx.stats.fullGaps++;
      const before = coverage.gaps.find(gap => gap.reason === 'dropped' && gap.dropped > 0 && gap.from <= fullGap.from);
      if (!before) fail('full', `${label}: no dropped gap precedes the journal-full gap ${JSON.stringify(fullGap)}: ${JSON.stringify(coverage.gaps.slice(-4))}`);
    }
  }
  if (stopped === 'full' && fullAt < 0 && !ctx.truncatedRun) ctx.stats.fullWithoutRecord++;
}

/**
 * Runs the journal target. `api` = { PaymentJournal, readJournal, parseRecord, journalCoverage,
 * paymentFacts, deletionFacts, Secret, JOURNAL_LIMIT_BYTES, JOURNAL_RESERVE_BYTES, JOURNAL_START_ROOM_BYTES }.
 */
/**
 * @param {Record<string, any>} api
 * @param {{ seed: number, cases: number, start?: number, scratchRoot?: string, maxFailures?: number, verbose?: boolean,
 *   onProgress?: (done: number, failures: number) => void, vectors?: { name: string, bytes: Buffer }[] }} options
 */
export async function journalCampaign(api, { seed, cases, start = 0, scratchRoot = tmpdir(), maxFailures = 20, verbose = false, onProgress, vectors = loadVectors() }) {
  const stats = { cases: 0, captured: 0, records: 0, dropRecords: 0, droppedInFile: 0, stopped: {}, truncated: 0, repaired: 0, refusedReopen: 0,
    shortfallCases: 0, shortfall: 0, shortfallAfterStop: 0, shortfallClosing: 0, fullShortfallBeforeStop: 0, fills: 0, fallbacks: 0, bursts: 0, markerFloods: 0,
    pendingFloods: 0, fullWithDrop: 0, fullGaps: 0, fullWithoutRecord: 0 };
  const timing = { maxMs: 0, maxIndex: -1, totalMs: 0 };
  const failures = [];
  const record = recorder(stats, failures, maxFailures);
  mkdirSync(scratchRoot, { recursive: true });
  const root = mkdtempSync(join(scratchRoot, 'payment-fuzz-journal-'));
  try {
    for (let index = start; index < start + cases; index++) {
      const dir = join(root, String(index));
      mkdirSync(dir);
      const trace = [];
      const ctx = { stats, vectors, trace, fail: (kind, message) => {
        let file;
        // With --verbose the journal's lines are part of the report (they hold no secret: identifiers, hashes, amounts, times).
        if (verbose) try { file = readFileSync(join(dir, 'payments.journal'), 'utf8').split('\n').filter(line => !line.includes('"type":"alive"') || line.length < 100).slice(-200); } catch { file = null; }
        record({ target: 'journal', seed, index, kind, message, input: verbose ? trace.slice() : trace.slice(0, 60), ...(file ? { file } : {}) });
      } };
      const began = performance.now();
      try { await journalCase(api, seed, index, dir, ctx); }
      catch (error) { ctx.fail('threw', `the case threw ${error?.name}: ${error?.message} ${error?.stack?.split('\n').slice(1, 4).join(' ')}`); }
      const elapsed = performance.now() - began;
      timing.totalMs += elapsed;
      if (elapsed > timing.maxMs) { timing.maxMs = elapsed; timing.maxIndex = index; }
      stats.cases++;
      rmSync(dir, { recursive: true, force: true });
      if (onProgress && stats.cases % 50 === 0) onProgress(stats.cases, failures.length);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
  return { stats, timing, failures };
}

// ---------------------------------------------------------------------------------------------
// Reconcile target.

const BASE = Date.parse('2026-10-09T10:00:00.000Z');
const iso = ms => new Date(ms).toISOString();
function uuid(r) {
  const hex = r.bytes(16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${'89ab'[r.int(0, 3)]}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}
function msat(r) {
  return r.weighted([[0n, 2], [BigInt(r.int(1, 1_000_000)), 6], [MAX_INT64 - BigInt(r.int(0, 1000)), 2], [MAX_INT64 / BigInt(r.int(2, 12)), 2],
    [r.big(62), 1], [MAX_INT64, 1]]);
}

/** A valid journal (the reader's rules) as text, and its records in file order. */
function genReconcileJournal(r) {
  const creds = Array.from({ length: r.int(1, 5) }, () => ({ credential: `id:${r.bytes(8).toString('hex')}`,
    rootKeyId: r.pick(['0', '4294967341', '18446744073709551615', String(r.int(1, 2 ** 31))]) }));
  if (r.chance(0.2)) creds.push({ credential: r.pick(['id:none', 'id:undecodable']), rootKeyId: 'none' });
  const hashes = Array.from({ length: r.int(1, 10) }, () => r.bytes(32).toString('hex'));
  const lines = [];
  const records = [];
  const push = item => { lines.push(JSON.stringify(item)); records.push(item); };
  let t = BASE + r.int(0, 3_600) * 1_000;
  let requestId = BigInt(r.int(1, 1000));
  for (let k = r.int(1, 4); k > 0; k--) {
    let repaired = false;
    if (lines.length && r.chance(0.15)) { lines.push(r.pick(['{"v":1,"type":"payment","ti', '{"v":1', 'xx', '{"v":1,"type":"alive","time":"2026-1'])); repaired = true; }
    t = Math.max(0, t + (r.chance(0.15) ? -r.int(1, 7_200) * 1_000 : r.int(0, 3_600) * 1_000));
    const run = uuid(r);
    const node = r.chance(0.85) ? NODE : OTHER_NODE;
    push({ v: 1, type: 'run-start', time: iso(t), run, node, version: '1.2.1', repairedTail: repaired || r.chance(0.05) });
    let session = 0, registered = false;
    for (let e = r.int(0, 30); e > 0; e--) {
      t += r.weighted([[0, 2], [r.int(1, 999), 2], [r.int(1, 60) * 1_000, 4], [r.int(1, 900) * 1_000, 2]]);
      const base = { v: 1, time: iso(t), run };
      const kind = r.weighted([['marker', 5], ['alive', 1], ['payment', 10], ['deletion', 2], ['drop', 1.5], ['full', 0.3], ['end', 0.7]]);
      if (kind === 'marker') {
        if (registered) push({ ...base, type: 'unregistered', session, reason: r.pick(['stream-lost', 'refresh', 'stopping']) });
        else push({ ...base, type: 'registered', session: ++session });
        registered = !registered;
      } else if (kind === 'alive') push({ ...base, type: 'alive' });
      else if (kind === 'payment') {
        const who = r.pick(creds);
        const method = r.chance(0.75) ? SEND : ROUTE;
        const paymentHash = r.chance(0.8) ? r.pick(hashes) : null;
        const extraction = paymentHash ? 'complete' : r.pick(['no-hash', 'amp', 'payload-too-large', 'malformed', 'invoice-invalid', 'invoice-too-long']);
        const amount = r.chance(0.8) ? msat(r).toString() : null;
        push({ ...base, type: 'payment', requestId: String(requestId++), method, credential: who.credential, rootKeyId: who.rootKeyId, paymentHash,
          amountMsat: amount, amountSource: amount === null ? null : method === ROUTE ? 'route' : r.pick(['request', 'invoice']),
          feeLimitMsat: r.chance(0.7) ? msat(r).toString() : null, amp: extraction === 'amp', extraction });
      } else if (kind === 'deletion') {
        const who = r.pick(creds);
        const all = r.chance(0.4);
        const malformed = r.chance(0.1);
        push({ ...base, type: 'deletion', requestId: String(requestId++), method: all ? DELETE_ALL : DELETE, credential: who.credential, rootKeyId: who.rootKeyId,
          paymentHash: all || malformed ? null : r.chance(0.8) ? r.pick(hashes) : r.bytes(32).toString('hex'),
          scope: malformed ? 'none' : all ? r.pick(['all-payments', 'failed-payments', 'failed-htlcs', 'none']) : r.pick(['payment', 'failed-htlcs']),
          extraction: malformed ? 'malformed' : 'complete' });
      } else if (kind === 'drop') {
        const last = Math.max(0, t - r.int(0, 5_000));
        push({ ...base, type: 'drop', count: r.int(1, 6), first: iso(Math.max(0, last - r.int(0, 30_000))), last: iso(last), reason: 'overload' });
      } else if (kind === 'full') { push({ ...base, type: 'full' }); break; }
      else {
        if (registered && r.chance(0.8)) push({ ...base, type: 'unregistered', session, reason: 'stopping' });
        push({ ...base, time: iso(t), type: 'run-end', payments: r.int(0, 9), deletions: r.int(0, 3), dropped: r.int(0, 3) });
        break;
      }
    }
  }
  const torn = r.chance(0.08);
  const text = `${lines.join('\n')}\n${torn ? '{"v":1,"type":"payment","time":"2026-10-09T1' : ''}`;
  return { text, records, creds, hashes, torn };
}

const FAILURE_REASONS = ['timeout', 'no-route', 'error', 'incorrect-payment-details', 'insufficient-balance', 'canceled'];
function lndPayment(r, hash, createdMs) {
  const status = r.pick(['succeeded', 'failed', 'in-flight', 'unknown']);
  const attempts = r.weighted([[0, 2], [r.int(1, 5), 5], [r.int(6, 1000), 1]]);
  const succeededAttempts = status === 'succeeded' && r.chance(0.8) ? r.int(0, attempts) : r.chance(0.2) ? r.int(0, attempts) : 0;
  // The adapter's contract (src/lnd/index.ts): every amount and sum within int64, times in four-digit years.
  const reason = status === 'failed' ? r.weighted([[r.pick(FAILURE_REASONS), 8], [null, 1],
    [Array.from({ length: r.int(1, 64) }, () => r.pick([...'ABCDEFGHIJKLMNOPQRSTUVWXYZ_'])).join('').toLowerCase().replaceAll('_', '-'), 1]]) : null;
  return { paymentHash: hash, status, createdAtNs: BigInt(Math.max(0, createdMs)) * 1_000_000n + BigInt(r.int(0, 999_999)),
    valueMsat: msat(r), feeMsat: msat(r), attempts, succeededAttempts, succeededMsat: succeededAttempts ? msat(r) : 0n,
    succeededFeesMsat: succeededAttempts ? msat(r) : 0n, inFlightMsat: r.chance(0.3) ? msat(r) : 0n, failureReason: reason, index: r.big(64) };
}

/** A fake LND: random pages (duplicates, non-advancing offsets, short pages) and lookups (records, none, errors). */
function genLnd(r, model, LndError) {
  const nodeRuns = new Set(model.records.filter(item => item.type === 'run-start' && item.node === NODE).map(item => item.run));
  const firstSeen = new Map();
  for (const item of model.records) if (item.type === 'payment' && item.paymentHash && nodeRuns.has(item.run) && !firstSeen.has(item.paymentHash)) firstSeen.set(item.paymentHash, Date.parse(item.time));
  const times = model.records.map(item => Date.parse(item.time));
  const low = Math.min(...times), high = Math.max(...times);
  const around = hash => firstSeen.get(hash) ?? r.int(low - 3_600_000, high + 3_600_000);
  const offset = () => r.weighted([[r.int(-60_000, 60_000), 3], [-r.int(61, 86_400) * 1_000, 2], [r.int(1, 3_600) * 1_000, 2], [-61_000, 0.5], [-60_000, 0.5],
    [-60_001, 0.3], [-r.int(1, 400) * 86_400_000, 0.3]]);
  const listing = [];
  const track = new Map();
  const hashes = [...model.hashes, ...Array.from({ length: r.int(0, 4) }, () => r.bytes(32).toString('hex'))];
  for (const hash of hashes) {
    const present = r.chance(0.7);
    if (present && r.chance(0.75)) {
      listing.push(lndPayment(r, hash, around(hash) + offset()));
      if (r.chance(0.1)) listing.push(lndPayment(r, hash, around(hash) + offset()));
    }
    const lookup = r.weighted([['record', present ? 6 : 0], ['none', present ? 1 : 6], ['error5', 2], ['error4', 0.15]]);
    track.set(hash, lookup === 'record' ? lndPayment(r, hash, around(hash) + offset()) : lookup === 'none' ? null
      : new LndError(lookup === 'error4' ? 4 : 5, 'track-payment', lookup === 'error4' ? 'LND unreachable' : 'LND request rejected'));
  }
  for (let i = listing.length - 1; i > 0; i--) { const j = r.int(0, i); [listing[i], listing[j]] = [listing[j], listing[i]]; }
  // Pages: one short page, or full pages of 100 padded with payments the journal never saw.
  const pages = [];
  let last = BigInt(r.int(0, 50));
  if (r.chance(0.15)) {
    const count = r.int(2, 3);
    for (let p = 0; p < count; p++) {
      const page = listing.splice(0, r.int(0, Math.min(listing.length, 100)));
      if (p < count - 1) while (page.length < 100) page.push(lndPayment(r, r.bytes(32).toString('hex'), r.int(low - 3_600_000, high + 3_600_000)));
      const advance = r.weighted([[BigInt(r.int(1, 500)), 8], [0n, 1], [-BigInt(r.int(1, 10)), 1]]);
      last = last + advance < 0n ? 0n : last + advance;
      pages.push({ payments: page, lastIndexOffset: last });
    }
  } else pages.push({ payments: listing.splice(0, 99), lastIndexOffset: last + BigInt(r.int(0, 100)) });
  const listFails = r.chance(0.01);
  return { pages, track, listFails };
}

const RECONCILE_LIST_PAGE = 100;
const CLOCK_TOLERANCE_MS = 60_000;

function windowArgs(r, model, now) {
  const times = model.records.map(item => Date.parse(item.time));
  const low = Math.min(...times), high = Math.max(...times);
  const instant = () => { const ms = r.int(low - 7_200_000, high + 7_200_000); const text = iso(ms); return r.chance(0.3) ? text.replace(/\.\d{3}Z$/, 'Z') : text; };
  const relative = () => r.weighted([[`${r.int(1, 3_000)}m`, 3], [`${r.int(1, 48)}h`, 3], [`${r.int(1, 3)}d`, 2], [`${r.int(1, 999_999)}${r.pick(['m', 'h', 'd'])}`, 1],
    [`999999${r.pick(['h', 'd'])}`, 0.5]]);
  const parse = value => { if (value === null) return null; const match = /^([1-9][0-9]{0,5})(m|h|d)$/.exec(value);
    return match ? now - Number(match[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2]] : Date.parse(value); };
  const since = r.weighted([[null, 4], [instant(), 4], [relative(), 2]]);
  const until = r.weighted([[null, 5], [instant(), 3.5], [relative(), 1.5]]);
  return { since, until, sinceMs: parse(since), untilMs: parse(until) };
}

/** What reconcile must do with a generated case, worked out from the specification (Commands > 12). */
function reconcileOracle(model, lnd, window, now) {
  const nodeOf = new Map();
  for (const item of model.records) if (item.type === 'run-start') nodeOf.set(item.run, item.node);
  const mine = model.records.filter(item => nodeOf.get(item.run) === NODE);
  if (window.sinceMs !== null && window.untilMs !== null && window.sinceMs > window.untilMs) return { exit: 2 };
  const until = window.untilMs ?? now;
  const since = window.sinceMs ?? Math.min(mine.length ? Date.parse(mine[0].time) : until, until);
  if (since > until) return { exit: 2 };
  const inWindow = ms => ms >= since && ms <= until;
  const payments = mine.filter(item => item.type === 'payment');
  const windowHashes = new Set(payments.filter(item => item.paymentHash && inWindow(Date.parse(item.time))).map(item => item.paymentHash));
  const requests = new Map();
  for (const item of payments) if (item.paymentHash && windowHashes.has(item.paymentHash)) {
    const list = requests.get(item.paymentHash) ?? [];
    list.push(item);
    requests.set(item.paymentHash, list);
  }
  if (lnd.listFails) return { exit: 5, since, until };
  const listed = new Map();
  let offset = 0n;
  for (let call = 0; ; call++) {
    const page = lnd.pages[call] ?? { payments: [], lastIndexOffset: offset };
    for (const item of page.payments) listed.set(item.paymentHash, item);
    if (page.payments.length < RECONCILE_LIST_PAGE || page.lastIndexOffset <= offset) break;
    offset = page.lastIndexOffset;
  }
  const settlementOf = new Map();
  for (const hash of windowHashes) {
    if (listed.has(hash)) { settlementOf.set(hash, listed.get(hash)); continue; }
    const tracked = lnd.track.get(hash) ?? null;
    if (tracked instanceof Error) { if (tracked.code === 4) return { exit: 4, since, until }; settlementOf.set(hash, 'unknown'); }
    else settlementOf.set(hash, tracked ?? 'not-found');
  }
  const attribution = new Map();
  const sums = new Map();
  for (const [hash, list] of requests) {
    const credentials = [...new Set(list.map(item => item.credential))].sort();
    const found = settlementOf.get(hash);
    const created = typeof found === 'object' ? Number(found.createdAtNs / 1_000_000n) : null;
    // As reconcile states it: the first journaled request for the hash, in file order.
    const firstInFile = Date.parse(list[0].time);
    const earliest = Math.min(...list.map(item => Date.parse(item.time)));
    const kind = credentials.length > 1 ? 'ambiguous' : created !== null && created < firstInFile - CLOCK_TOLERANCE_MS ? 'historical' : 'single';
    attribution.set(hash, { kind, credentials, created, earliest, firstInFile });
    if (kind === 'single' && typeof found === 'object') {
      const fromSummary = found.status === 'succeeded' && found.succeededAttempts === 0;
      const row = sums.get(credentials[0]) ?? { settled: 0n, fees: 0n, inFlight: 0n };
      row.settled += fromSummary ? found.valueMsat : found.succeededMsat;
      row.fees += fromSummary ? found.feeMsat : found.succeededFeesMsat;
      row.inFlight += found.inFlightMsat;
      sums.set(credentials[0], row);
    }
  }
  for (const row of sums.values()) if (row.settled > MAX_INT64 || row.fees > MAX_INT64 || row.inFlight > MAX_INT64) return { exit: 5, since, until };
  const journaled = new Set(payments.filter(item => item.paymentHash).map(item => item.paymentHash));
  const unattributed = [...listed.values()].filter(item => inWindow(Number(item.createdAtNs / 1_000_000n)) && !journaled.has(item.paymentHash)).length;
  return { exit: null, since, until, mine, inWindow, windowHashes, requests, attribution, unattributed,
    unmatched: payments.filter(item => !item.paymentHash && inWindow(Date.parse(item.time))),
    deletions: mine.filter(item => item.type === 'deletion' && inWindow(Date.parse(item.time))) };
}

/** Every `...Msat` string in a document (path and value). */
function amounts(value, path = '', out = []) {
  if (Array.isArray(value)) value.forEach((item, index) => amounts(item, `${path}/${index}`, out));
  else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) {
    if (/Msat$/.test(key) && typeof item === 'string') out.push([`${path}/${key}`, item]);
    else amounts(item, `${path}/${key}`, out);
  }
  return out;
}

const Ajv = Ajv2020Module.default ?? Ajv2020Module;
let reconcileValidator = null;
/** The ajv setup of test/helpers/output-schema.ts, on the shipped schema. */
export function reconcileSchema(root = REPO) {
  if (!reconcileValidator) {
    const ajv = new Ajv({ strict: false, allErrors: true });
    reconcileValidator = ajv.compile(JSON.parse(readFileSync(join(root, 'schemas/output/reconcile.schema.json'), 'utf8')));
  }
  return reconcileValidator;
}

/** Runs the reconcile target. `api` = { run, render, LndError }. */
/**
 * @param {Record<string, any>} api
 * @param {{ seed: number, cases: number, start?: number, scratchRoot?: string, maxFailures?: number, verbose?: boolean,
 *   onProgress?: (done: number, failures: number) => void, root?: string }} options
 */
export async function reconcileCampaign(api, { seed, cases, start = 0, scratchRoot = tmpdir(), maxFailures = 20, verbose = false, onProgress, root: repoRoot = REPO }) {
  const stats = { cases: 0, exits: /** @type {Record<string, number>} */ ({}), ambiguous: 0, historical: 0, single: 0, unattributed: 0, gaps: 0, tornTails: 0, multiPage: 0,
    historicalByFileOrder: 0, schemaChecked: 0 };
  const timing = { maxMs: 0, maxIndex: -1, totalMs: 0 };
  const failures = [];
  const record = recorder(stats, failures, maxFailures);
  const validate = reconcileSchema(repoRoot);
  const snapshot = JSON.parse(readFileSync(join(repoRoot, 'src/grade/lnd-permissions.json'), 'utf8'));
  mkdirSync(scratchRoot, { recursive: true });
  const dir = mkdtempSync(join(scratchRoot, 'payment-fuzz-reconcile-'));
  try {
    writeFileSync(join(dir, 'tls.cert'), 'not used by the fake adapter');
    writeFileSync(join(dir, 'own.macaroon'), readFileSync(join(repoRoot, 'test/vectors/default-readonly.macaroon')));
    const entry = (label, rootKeyId) => ({ nodePubkey: NODE, label, rootKeyId, permissions: ['offchain:write'], caveats: [], grade: 'SPEND',
      fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: true, status: 'active', revokedAt: null,
      revokeEvidence: null, replaces: null, replacedBy: null });
    writeFileSync(join(dir, 'registry.json'), JSON.stringify({ schema: 1, entries: [entry('shop', '4294967341'), entry('max', '18446744073709551615')] }));
    const path = join(dir, 'payments.journal');
    const baseArgs = ['--payment-journal', path, '--lnd-rest', 'localhost:8080', '--tls-cert', join(dir, 'tls.cert'), '--macaroon', join(dir, 'own.macaroon'),
      '--registry', join(dir, 'registry.json')];
    for (let index = start; index < start + cases; index++) {
      const r = xorshift(caseSeed(seed, 'reconcile', index));
      const model = genReconcileJournal(r);
      const lnd = genLnd(r, model, api.LndError);
      const times = model.records.map(item => Date.parse(item.time));
      const now = Math.max(...times) + r.int(-600, 7_200) * 1_000;
      const window = windowArgs(r, model, now);
      const args = [...baseArgs, ...(window.since ? ['--since', window.since] : []), ...(window.until ? ['--until', window.until] : [])];
      writeFileSync(path, model.text);
      const fail = (kind, message, output) => {
        record({ target: 'reconcile', seed, index, kind, message,
          input: { window: { since: window.since, until: window.until, now: iso(now) }, journal: verbose ? model.text : `${model.text.slice(0, 3000)}${model.text.length > 3000 ? '...' : ''}`,
            lnd: verbose ? JSON.stringify(lnd, (key, value) => (typeof value === 'bigint' ? value.toString() : value instanceof Error ? `LndError(${value.code})` : value))
              : `${lnd.pages.length} page(s), ${lnd.track.size} lookups${lnd.listFails ? ', listing fails' : ''}` },
          output: output === undefined ? undefined : verbose ? output : output.slice(0, 4000) });
      };
      let calls = 0;
      const adapter = {
        getInfo: async () => ({ pubkey: NODE, alias: 'fuzz', network: 'regtest', version: '0.21.4-beta' }),
        listPermissions: async () => snapshot.methods,
        listPayments: async ({ indexOffset }) => {
          if (lnd.listFails) throw new api.LndError(5, 'list-payments', 'invalid LND response');
          const page = lnd.pages[calls++];
          return page ?? { payments: [], lastIndexOffset: indexOffset };
        },
        trackPayment: async hash => { const found = lnd.track.get(hash); if (found instanceof Error) throw found; return found ?? null; },
      };
      for (const name of ['listMacaroonIds', 'bakeMacaroon', 'deleteMacaroonId', 'checkMacaroon']) adapter[name] = async () => { throw new Error('unexpected adapter call'); };
      const expected = reconcileOracle(model, lnd, window, now);
      const began = performance.now();
      let output;
      try { output = await api.run(args, { lnd: adapter, fs: nodeFs, env: {}, clock: () => new Date(now) }); }
      catch (error) { fail('threw', `reconcile threw ${error?.name}: ${error?.message}`); stats.cases++; continue; }
      const elapsed = performance.now() - began;
      timing.totalMs += elapsed;
      if (elapsed > timing.maxMs) { timing.maxMs = elapsed; timing.maxIndex = index; }
      stats.cases++;
      if (model.torn) stats.tornTails++;
      if (lnd.pages.length > 1) stats.multiPage++;
      const exit = output.ok ? output.exitCode ?? 0 : output.error.code;
      stats.exits[exit] = (stats.exits[exit] ?? 0) + 1;
      const rendered = api.render(output, 'json');
      const document = JSON.parse(rendered);
      stats.schemaChecked++;
      if (!validate(document)) fail('schema', `output does not validate against reconcile.schema.json: ${JSON.stringify(validate.errors.slice(0, 5))}`, rendered);
      for (const [where, value] of amounts(document)) if (!DECIMAL.test(value) || BigInt(value) > MAX_INT64) fail('amount', `${where} = ${value} is above 2^63-1`, rendered);
      if (!output.ok) {
        if (expected.exit !== exit) fail('exit', `exit ${exit} (${output.error.step}: ${output.error.message}), expected ${expected.exit ?? '0 or 1'}`, rendered);
        continue;
      }
      if (expected.exit !== null) { fail('exit', `exit ${exit}, expected ${expected.exit}`, rendered); continue; }
      checkReconcile(output.result, exit, expected, fail, stats, rendered);
      if (onProgress && stats.cases % 2_000 === 0) onProgress(stats.cases, failures.length);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
  return { stats, timing, failures };
}

function checkReconcile(result, exit, expected, fail, stats, rendered) {
  const say = (kind, message) => fail(kind, message, rendered);
  if (result.window.since !== iso(expected.since) || result.window.until !== iso(expected.until))
    say('window', `window ${result.window.since} .. ${result.window.until}, expected ${iso(expected.since)} .. ${iso(expected.until)}`);
  const final = result.payments.every(item => item.settlement.status === 'succeeded' || item.settlement.status === 'failed');
  const complete = result.coverage.complete && final && !result.unmatched.length && !result.unattributed.length
    && result.payments.every(item => item.attribution === 'single') && !result.deletions.length && !result.lookups.listTruncated && !result.lookups.trackLimited;
  if ((exit === 0) !== complete) say('exit', `exit ${exit} but the reconciliation is ${complete ? '' : 'not '}complete`);
  if (result.coverage.complete !== (result.coverage.gapCount === 0)) say('coverage', 'complete differs from gapCount 0');
  if (result.coverage.gapSeconds > result.coverage.windowSeconds - result.coverage.coveredSeconds + 1)
    say('coverage', `gapSeconds ${result.coverage.gapSeconds} > windowSeconds ${result.coverage.windowSeconds} - coveredSeconds ${result.coverage.coveredSeconds} + 1`);
  if (result.coverage.gaps.length) stats.gaps++;
  // The payments are exactly the hashes journaled in the window, attributed from every request.
  const hashes = new Set(result.payments.map(item => item.paymentHash));
  if (hashes.size !== result.payments.length) say('payments', 'a payment hash is listed twice');
  if (hashes.size !== expected.windowHashes.size || [...expected.windowHashes].some(hash => !hashes.has(hash)))
    say('payments', `payments ${hashes.size}, hashes journaled in the window ${expected.windowHashes.size}`);
  const credited = new Map();
  for (const item of result.payments) {
    const oracle = expected.attribution.get(item.paymentHash);
    if (!oracle) continue;
    stats[item.attribution] = (stats[item.attribution] ?? 0) + 1;
    if (!same(item.credentials, oracle.credentials)) say('attribution', `${item.paymentHash}: credentials ${item.credentials}, requested by ${oracle.credentials}`);
    if (oracle.credentials.length > 1 && item.attribution !== 'ambiguous') say('attribution', `${item.paymentHash} requested by ${oracle.credentials.length} credentials is ${item.attribution}`);
    if (oracle.credentials.length === 1 && item.attribution === 'ambiguous') say('attribution', `${item.paymentHash} requested by one credential is ambiguous`);
    const created = item.settlement.createdAt === null ? null : Date.parse(item.settlement.createdAt);
    if (oracle.credentials.length === 1 && created !== null && created < oracle.earliest - CLOCK_TOLERANCE_MS && item.attribution !== 'historical')
      say('attribution', `${item.paymentHash}: LND created it at ${item.settlement.createdAt}, before every journaled request (${iso(oracle.earliest)}), but it is ${item.attribution}`);
    if (item.attribution === 'historical' && !(created !== null && created < oracle.earliest - CLOCK_TOLERANCE_MS)) stats.historicalByFileOrder++;
    if (item.attribution !== oracle.kind) say('attribution', `${item.paymentHash} is ${item.attribution}, expected ${oracle.kind}`);
    if (item.attribution === 'single') {
      const credential = item.credentials[0];
      // Never credited to a credential when another one requested the hash, before or after it.
      const others = expected.requests.get(item.paymentHash).filter(request => request.credential !== credential);
      if (others.length) say('hostile', `${item.paymentHash} credited to ${credential} though ${others[0].credential} requested it at ${others[0].time}`);
      const list = credited.get(credential) ?? [];
      list.push(item);
      credited.set(credential, list);
    }
    if (item.observation.calls !== expected.requests.get(item.paymentHash).length) say('observation', `${item.paymentHash}: calls ${item.observation.calls}, journaled ${expected.requests.get(item.paymentHash).length}`);
  }
  for (const row of result.credentials) {
    const singles = credited.get(row.credential) ?? [];
    const total = key => singles.reduce((sum, item) => sum + BigInt(item.settlement[key] ?? '0'), 0n).toString();
    if (row.settledMsat !== total('settledMsat')) say('credential', `${row.credential}: settledMsat ${row.settledMsat}, its single payments settled ${total('settledMsat')}`);
    if (row.feesMsat !== total('feesMsat')) say('credential', `${row.credential}: feesMsat ${row.feesMsat}, its single payments ${total('feesMsat')}`);
    if (row.inFlightMsat !== total('inFlightMsat')) say('credential', `${row.credential}: inFlightMsat ${row.inFlightMsat}, its single payments ${total('inFlightMsat')}`);
    if (row.payments !== row.succeeded + row.failed + row.inFlight + row.notFound + row.unknown) say('credential', `${row.credential}: payments ${row.payments} != the sum of its outcomes`);
    if (row.payments !== singles.length) say('credential', `${row.credential}: payments ${row.payments}, single payments credited ${singles.length}`);
    const ambiguous = result.payments.filter(item => item.attribution === 'ambiguous' && item.credentials.includes(row.credential)).length;
    if (row.ambiguous !== ambiguous) say('credential', `${row.credential}: ambiguous ${row.ambiguous}, expected ${ambiguous}`);
    const historical = result.payments.filter(item => item.attribution === 'historical' && item.credentials[0] === row.credential).length;
    if (row.historical !== historical) say('credential', `${row.credential}: historical ${row.historical}, expected ${historical}`);
    const requested = singles.reduce((sum, item) => sum + BigInt(item.observation.requestedMsat ?? item.observation.routeAttemptsMsat ?? '0'), 0n);
    const capped = requested > MAX_INT64 ? MAX_INT64 : requested;
    if (row.requestedMsat !== capped.toString()) say('credential', `${row.credential}: requestedMsat ${row.requestedMsat}, expected ${capped}`);
    const unmatched = expected.unmatched.filter(item => item.credential === row.credential).length;
    if (row.unmatched !== unmatched) say('credential', `${row.credential}: unmatched ${row.unmatched}, journaled ${unmatched}`);
    const deletions = expected.deletions.filter(item => item.credential === row.credential).length;
    if (row.deletions !== deletions) say('credential', `${row.credential}: deletions ${row.deletions}, journaled ${deletions}`);
  }
  for (const credential of credited.keys()) if (!result.credentials.some(row => row.credential === credential)) say('credential', `${credential} has payments but no row`);
  if (result.unmatched.length !== expected.unmatched.length) say('unmatched', `unmatched ${result.unmatched.length}, journaled ${expected.unmatched.length}`);
  if (result.deletions.length !== expected.deletions.length) say('deletions', `deletions ${result.deletions.length}, journaled ${expected.deletions.length}`);
  if (result.unattributed.length !== expected.unattributed) say('unattributed', `unattributed ${result.unattributed.length}, expected ${expected.unattributed}`);
  stats.unattributed += result.unattributed.length;
}

// ---------------------------------------------------------------------------------------------
// Built package and command line.

export async function builtApi(distRoot = resolve('dist')) {
  const load = path => import(pathToFileURL(join(distRoot, path)).href);
  const [request, journal, reconcile, output, secret, errors] = await Promise.all([load('watch/payment-request.js'), load('watch/payment-journal.js'),
    load('commands/reconcile.js'), load('output/index.js'), load('secret.js'), load('errors.js')]);
  return { paymentFacts: request.paymentFacts, deletionFacts: request.deletionFacts, parseRecord: journal.parseRecord, readJournal: journal.readJournal,
    journalCoverage: journal.journalCoverage, PaymentJournal: journal.PaymentJournal, JOURNAL_LIMIT_BYTES: journal.JOURNAL_LIMIT_BYTES,
    JOURNAL_RESERVE_BYTES: journal.JOURNAL_RESERVE_BYTES, JOURNAL_START_ROOM_BYTES: journal.JOURNAL_START_ROOM_BYTES, Secret: secret.Secret,
    run: reconcile.run, render: output.render, LndError: errors.LndError };
}

// The earliest instant a four-digit year renders (0000-01-01T00:00:00.000Z).
const YEAR_ZERO = Date.parse('0000-01-01T00:00:00.000Z');
const relativeMs = (value, now) => {
  const match = typeof value === 'string' ? /^([1-9][0-9]{0,5})(m|h|d)$/.exec(value) : null;
  return match ? Date.parse(now) - Number(match[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2]] : null;
};
/**
 * Open defects this campaign found (see the campaign report); each is reproduced by the seeds it
 * lists there. A failure one of them explains is not a new finding; the command line still fails on it.
 */
export const KNOWN_DEFECTS = [
  // An upper-case invoice holding the Kelvin sign (U+212A) where a 'K' was: it lower-cases to the
  // bech32 'k' and decodes, though the specification (and LND's zpay32) refuse non-ASCII characters.
  { id: 'PF-1', target: 'facts', test: failure => failure.kind === 'specification' && failure.input?.invoiceDefect === 'homoglyph' },
  // --since or --until <n>d reaching before the year 0: the window is printed as a six-digit year
  // the reconcile schema refuses.
  { id: 'PF-2', target: 'reconcile', test: failure => failure.kind === 'schema'
    && [failure.input?.window?.since, failure.input?.window?.until].some(value => (relativeMs(value, failure.input.window.now) ?? Infinity) < YEAR_ZERO) },
];
export function knownDefect(failure) { return KNOWN_DEFECTS.find(item => item.target === failure.target && item.test(failure))?.id ?? null; }

export async function runTarget(api, target, options) {
  if (target === 'facts') return factsCampaign(api, options);
  if (target === 'journal') return journalCampaign(api, options);
  return reconcileCampaign(api, options);
}

function merge(into, from) {
  for (const [key, value] of Object.entries(from)) {
    if (typeof value === 'number') into[key] = (into[key] ?? 0) + value;
    else if (value && typeof value === 'object') merge(into[key] ??= {}, value);
  }
  return into;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const option = (name, fallback) => { const at = args.indexOf(name); return at < 0 ? fallback : args[at + 1]; };
  const number = (name, fallback) => {
    const value = option(name, undefined);
    if (value === undefined) return fallback;
    if (!/^[0-9]+$/.test(value)) throw new Error(`${name} must be a non-negative integer`);
    return Number(value);
  };
  const targets = option('--target', 'all') === 'all' ? TARGETS : [option('--target')];
  if (targets.some(target => !TARGETS.includes(target))) throw new Error(`--target must be one of ${TARGETS.join(', ')} or all`);
  const seed = number('--seed', randomInt(2 ** 31));
  const start = number('--start', 0);
  const jobs = Math.max(1, number('--jobs', 1));
  const verbose = args.includes('--verbose');
  const scratchRoot = option('--scratch', join(resolve(), 'test/.tmp'));
  if (args.includes('--child')) {
    const target = targets[0];
    const api = await builtApi();
    const result = await runTarget(api, target, { seed, cases: number('--cases', 0), start, scratchRoot, verbose, maxFailures: 50,
      onProgress: done => process.send?.({ progress: done }) });
    process.send?.({ result });
  } else {
    process.stdout.write(`payment fuzz: seed ${seed}, targets ${targets.join(', ')}, from index ${start}, ${jobs} job(s)\n`);
    let failed = false;
    const totals = {};
    for (const target of targets) {
      const cases = number('--cases', DEFAULT_CASES[target]);
      const began = performance.now();
      const parts = [];
      const share = Math.ceil(cases / jobs);
      const results = await Promise.all(Array.from({ length: Math.min(jobs, cases) }, (_, job) => new Promise((done, reject) => {
        const first = start + job * share, count = Math.min(share, start + cases - first);
        if (count <= 0) { done(null); return; }
        const child = fork(process.argv[1], ['--child', '--target', target, '--seed', String(seed), '--start', String(first), '--cases', String(count),
          '--scratch', scratchRoot, ...(verbose ? ['--verbose'] : [])], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
        let result = null;
        child.on('message', message => {
          if (message.result) result = message.result;
          else if (message.progress) { parts[job] = message.progress; const done = parts.reduce((total, item) => total + (item ?? 0), 0);
            process.stdout.write(`  ${target}: ${done}/${cases} cases, ${((performance.now() - began) / 1000).toFixed(0)} s\n`); }
        });
        child.on('exit', code => (result ? done(result) : reject(new Error(`${target} job ${job} exited ${code} without a result`))));
      })));
      const merged = { stats: {}, timing: { maxMs: 0, maxIndex: -1, totalMs: 0 }, failures: [] };
      for (const result of results.filter(Boolean)) {
        merge(merged.stats, result.stats);
        merged.timing.totalMs += result.timing.totalMs;
        if (result.timing.maxMs > merged.timing.maxMs) Object.assign(merged.timing, { maxMs: result.timing.maxMs, maxIndex: result.timing.maxIndex, ...(result.timing.maxBytes !== undefined ? { maxBytes: result.timing.maxBytes } : {}) });
        merged.failures.push(...result.failures);
      }
      merged.failures.sort((a, b) => a.index - b.index);
      const seconds = (performance.now() - began) / 1000;
      const summary = { target, seed, start, cases, seconds: Number(seconds.toFixed(1)), meanMsPerCase: Number((merged.timing.totalMs / Math.max(1, merged.stats.cases ?? 1)).toFixed(3)),
        worstMs: Number(merged.timing.maxMs.toFixed(2)), worstIndex: merged.timing.maxIndex, ...(merged.timing.maxBytes !== undefined ? { worstBytes: merged.timing.maxBytes } : {}),
        failures: merged.failures.length, stats: merged.stats };
      totals[target] = summary;
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      if (merged.failures.length) {
        failed = true;
        const first = merged.failures[0];
        process.stdout.write(`FIRST FAILURE ${target} seed=${first.seed} index=${first.index} ${first.kind}: ${first.message}\n`);
        process.stdout.write(`  reproduce: node scripts/payment-fuzz.mjs --target ${target} --seed ${first.seed} --start ${first.index} --cases 1 --verbose\n`);
        for (const failure of merged.failures) process.stdout.write(`FAIL ${failure.known ? `[known ${failure.known}] ` : ''}${JSON.stringify(failure)}\n`);
      }
    }
    if (option('--summary', null)) writeFileSync(option('--summary'), JSON.stringify(totals, null, 2));
    process.exitCode = failed ? 1 : 0;
  }
}
