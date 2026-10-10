// Property fuzzing of macwarden's Core Lightning rune support (decoder, assessment, scan context),
// offline and deterministic: every case is generated from (seed, case index), so a failure is
// reproduced by its seed and index alone. Shared by test/rune-fuzz.test.ts (a CI-sized profile on
// the TypeScript sources) and scripts/fuzz-runes.mjs (long runs on the built package).
//
// Two independent models live here, both written from Core Lightning v26.06.8 rather than from
// macwarden's code:
//   referenceDecode  ccan/ccan/base64 base64_decode_using_maps (URL-safe maps), rune_from_base64n,
//                    from_string, rune_restr_decode, rune_altern_decode and rune_add_restr.
//   concreteCheck    lightningd/runes.c check_condition and ccan rune_alt_single for one concrete
//                    request (method, time, peer, params, rate state, invoice contents).
// The runes carry random 32-byte authenticators (test-only): they have no authority on any node.
import { createHash } from 'node:crypto';

/** sfc32 seeded through splitmix32: fast, deterministic, good enough for test generation. */
export function prng(seed) {
  let s = seed >>> 0;
  const split = () => {
    s = (s + 0x9e3779b9) >>> 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    return (z ^ (z >>> 16)) >>> 0;
  };
  let a = split(), b = split(), c = split(), d = split();
  const next = () => {
    const t = (((a + b) >>> 0) + d) >>> 0;
    d = (d + 1) >>> 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) >>> 0;
    c = ((c << 21) | (c >>> 11)) >>> 0;
    c = (c + t) >>> 0;
    return t / 4294967296;
  };
  for (let i = 0; i < 12; i++) next();
  const int = (low, high) => low + Math.floor(next() * (high - low + 1));
  const pick = items => items[Math.floor(next() * items.length)];
  const chance = p => next() < p;
  const bytes = length => Buffer.from(Array.from({ length }, () => Math.floor(next() * 256)));
  return { next, int, pick, chance, bytes };
}

/** The per-case seed: a case is reproduced from the campaign seed and its index. */
export function caseSeed(seed, index) {
  return createHash('sha256').update(`${seed}:${index}`).digest().readUInt32LE(0);
}

// ---------------------------------------------------------------------------------------------
// Reference decoder (Core Lightning v26.06.8), unbounded.

const URLSAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const DECODE_MAP = new Int16Array(256).fill(-1);
for (let i = 0; i < 64; i++) DECODE_MAP[URLSAFE.charCodeAt(i)] = i;
const CONDITIONS = '!=/^$~<>{}#';

/** C ispunct() in the "C" locale. */
function ispunct(byte) {
  return byte > 0x20 && byte < 0x7f && !((byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a));
}

function quartet(src, at, dest) {
  const v = [0, 1, 2, 3].map(k => DECODE_MAP[src[at + k]]);
  if (v.some(x => x === -1)) return false;
  dest.push(((v[0] << 2) | (v[1] >> 4)) & 0xff, (((v[1] & 0xf) << 4) | (v[2] >> 2)) & 0xff, (((v[2] & 0x3) << 6) | v[3]) & 0xff);
  return true;
}

/** base64_decode_using_maps over the bytes Core Lightning receives; null on failure. */
export function referenceBase64(src) {
  const dest = [];
  let i = 0;
  for (; src.length - i > 4; i += 4) if (!quartet(src, i, dest)) return null;
  let insize = src.length - i;
  while (insize !== 0 && src[i + insize - 1] === 0x3d) insize--;
  if (insize === 0) return Buffer.from(dest);
  if (insize === 1) return null;
  const tail = Buffer.alloc(4, 0x41);
  src.copy(tail, 0, i, i + insize);
  const out = [];
  if (!quartet(tail, 0, out)) return null;
  dest.push(...out.slice(0, insize - 1));
  return Buffer.from(dest);
}

/**
 * rune_from_base64n on the UTF-8 bytes of `text`. Returns { ok: false, stage } or the parsed rune:
 * restrictions as arrays of { field, condition, value } (latin1 byte strings), unique ID and version.
 */
export function referenceDecode(text) {
  const raw = referenceBase64(Buffer.from(text, 'utf8'));
  if (raw === null) return { ok: false, stage: 'base64' };
  if (raw.length < 32) return { ok: false, stage: 'short' };
  const data = raw.subarray(32);
  if (data.includes(0)) return { ok: false, stage: 'nul' };
  const restrictions = [];
  let uniqueId = null, version = null, alternatives = 0;
  let p = 0;
  const len = data.length;
  while (p < len) {
    const alterns = [];
    let more;
    do {
      const start = p;
      while (p < len && !(ispunct(data[p]) && data[p] !== 0x5f)) p++;
      const field = data.toString('latin1', start, p);
      if (p >= len) return { ok: false, stage: 'syntax' };
      const condition = String.fromCharCode(data[p++]);
      if (!CONDITIONS.includes(condition)) return { ok: false, stage: 'syntax' };
      const value = [];
      more = false;
      while (p < len) {
        let c = data[p++];
        if (c === 0x7c) { more = true; break; }
        if (c === 0x26) break;
        if (c === 0x5c) {
          if (p >= len) return { ok: false, stage: 'syntax' };
          c = data[p++];
        }
        value.push(c);
      }
      alterns.push({ field, condition, value: Buffer.from(value).toString('latin1') });
      alternatives++;
    } while (more);
    for (const alt of alterns) {
      if (alt.field !== '') continue;
      if (alterns.length !== 1 || restrictions.length !== 0 || alt.condition !== '=') return { ok: false, stage: 'placement' };
      const dash = alt.value.indexOf('-');
      uniqueId = dash < 0 ? alt.value : alt.value.slice(0, dash);
      version = dash < 0 ? null : alt.value.slice(dash + 1);
    }
    restrictions.push(alterns);
  }
  return { ok: true, bytes: raw, uniqueId, version, restrictions: uniqueId === null ? restrictions : restrictions.slice(1),
    restrictionCount: restrictions.length, alternatives };
}

// ---------------------------------------------------------------------------------------------
// Encoding (rune_to_base64 with a test authenticator).

export function escapeValue(value) {
  return value.replace(/[\\|&]/g, match => `\\${match}`);
}

/** Restriction text as Core Lightning writes it; `ast` = { uniqueId, version, restrictions }. */
export function restrictionText(ast) {
  const all = [];
  if (ast.uniqueId !== null) all.push([{ field: '', condition: '=', value: ast.version === null ? ast.uniqueId : `${ast.uniqueId}-${ast.version}` }]);
  all.push(...ast.restrictions);
  return all.map(restriction => restriction.map(alt => alt.field + alt.condition + escapeValue(alt.value)).join('|')).join('&');
}

export function encodeRune(ast, authenticator) {
  const bytes = Buffer.concat([authenticator, Buffer.from(restrictionText(ast), 'latin1')]);
  const raw = bytes.toString('base64url');
  return { text: raw + '='.repeat((4 - raw.length % 4) % 4), bytes };
}

export function fingerprintOf(bytes) {
  return `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
}

// ---------------------------------------------------------------------------------------------
// Generators.

const FIELD_SAFE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
const SPECIAL_VALUE = ['&', '|', '\\', '-', '=', '!', '^', '$', '~', '<', '>', '{', '}', '#', '/', '"', "'", ' ', '\t', '%', '+'];
const UNICODE = ['é', '☕', '日本', '\u{1F600}', 'ÿ', '​', 'Ω'];

function latin1Of(text) {
  return Buffer.from(text, 'utf8').toString('latin1');
}

export function randomField(r, known) {
  if (known.length && r.chance(0.7)) return r.pick(known);
  const length = r.int(1, r.chance(0.9) ? 12 : 200);
  let field = '';
  for (let i = 0; i < length; i++) {
    const roll = r.next();
    if (roll < 0.85) field += r.pick(FIELD_SAFE);
    else if (roll < 0.9) field += ' ';
    else if (roll < 0.95) field += String.fromCharCode(r.int(0x80, 0xff));
    else field += String.fromCharCode(r.pick([r.int(1, 0x1f), 0x7f]));
  }
  return field;
}

export function randomValue(r, pool = []) {
  if (pool.length && r.chance(0.4)) return r.pick(pool);
  const length = r.chance(0.05) ? r.int(200, 3000) : r.int(0, 24);
  let value = '';
  while (value.length < length) {
    const roll = r.next();
    if (roll < 0.55) value += r.pick(FIELD_SAFE);
    else if (roll < 0.8) value += r.pick(SPECIAL_VALUE);
    else if (roll < 0.9) value += latin1Of(r.pick(UNICODE));
    else value += String.fromCharCode(r.int(1, 255));
  }
  return value;
}

// Integers at the edges of strtol and strtoul: signs, blanks, wrap-around, overflow, units.
const TRICKY_NUMBERS = [' +5', '	7', '-0', '0x10', '1e3', '4294967294', '4294967295', '18446744073709551615', '18446744073709551616',
  '-18446744073709551615', '-18446744073709551614', '-18446744069414584322', '-18446744073709551615sec', '-18446744073709551614nsec',
  ' -18446744073709551610min', '000000000000000000000001', '-9223372036854775808', '-9223372036854775809', '5 ', '5sec ', '+0', '3',
  '18446744073sec', '213503day', '213504day', '5constructor', '1__proto__', '3toString', '2valueOf', '9hasOwnProperty'];
const KNOWN_FIELDS = ['method', 'method', 'method', 'time', 'id', 'pnum', 'rate', 'per', 'pnameamount_msat', 'pnamelabel', 'pnamedestination',
  'parr0', 'parr1', 'pinvbolt11_amount', 'pinvbolt11_description', 'pinvbolt11_node', 'pinvbolt11_payee', 'colour', 'pname'];

/** A random AST within or (sometimes) beyond macwarden's bounds. */
export function randomAst(r, { large = false, methods = [] } = {}) {
  const uniqueId = r.chance(0.8) ? (r.chance(0.8) ? String(r.int(0, 10 ** r.int(1, 9))) : randomValue(r).replace(/-/g, '')) : null;
  const version = uniqueId !== null && r.chance(0.15) ? randomValue(r) : null;
  const count = large ? r.int(200, 320) : r.chance(0.1) ? 0 : r.int(1, 8);
  const restrictions = [];
  const valuePool = [...methods.slice(0, 40), '0', '1', '-1', '1600000000', '9223372036854775807', '9223372036854775808', ' 5', '+7',
    '10sec', '5min', '1day', '02' + 'ab'.repeat(32), '', ...TRICKY_NUMBERS];
  for (let i = 0; i < count; i++) {
    const alternatives = large ? r.int(1, 6) : r.chance(0.1) ? r.int(5, 40) : r.int(1, 4);
    const restriction = [];
    for (let j = 0; j < alternatives; j++)
      restriction.push({ field: randomField(r, KNOWN_FIELDS), condition: r.pick(CONDITIONS), value: randomValue(r, valuePool) });
    restrictions.push(restriction);
  }
  return { uniqueId, version, restrictions };
}

const MUTATION_CHARACTERS = [...URLSAFE, '=', '=', '+', '/', ' ', '\n', '\r', '\t', '.', '%', '\0', 'é', '☕', '\u{1F600}', ' '];
const BYTE_SPECIALS = [0, 0x26, 0x7c, 0x5c, 0x3d, 0x2d, 0x21, 0x23, 0x3c, 0x3e, 0x7b, 0x7d, 0x2e, 0x20, 0x80, 0xff];

/** One to three text-level or byte-level mutations of a rune text. */
export function mutate(r, text, bytes) {
  let current = text;
  const rounds = r.int(1, 3);
  for (let round = 0; round < rounds; round++) {
    const at = r.int(0, current.length);
    switch (r.int(0, 10)) {
      case 0: current = current.slice(0, at) + r.pick(MUTATION_CHARACTERS) + current.slice(at + 1); break;
      case 1: current = current.slice(0, at) + r.pick(MUTATION_CHARACTERS) + current.slice(at); break;
      case 2: current = current.slice(0, at) + current.slice(at + 1); break;
      case 3: current = current.slice(0, at); break;
      case 4: current += '='.repeat(r.int(1, 5)); break;
      case 5: current = current.replace(/=+$/, ''); break;
      case 6: { const end = r.int(at, Math.min(current.length, at + 40)); current = current.slice(0, end) + current.slice(at, end) + current.slice(end); break; }
      case 7: { const other = r.int(0, Math.max(0, current.length - 1)); const chars = [...current]; [chars[at], chars[other]] = [chars[other], chars[at]]; current = chars.join(''); break; }
      default: {
        // Byte level: edit the decoded bytes and re-encode, so the restriction parser sees the change.
        const decoded = Buffer.from(bytes);
        const where = r.int(r.chance(0.9) ? Math.min(32, decoded.length) : 0, decoded.length);
        const value = r.chance(0.7) ? r.pick(BYTE_SPECIALS) : r.int(0, 255);
        const edited = r.chance(0.5) ? Buffer.concat([decoded.subarray(0, where), Buffer.from([value]), decoded.subarray(where)])
          : Buffer.concat([decoded.subarray(0, where), Buffer.from([value]), decoded.subarray(where + 1)]);
        const raw = edited.toString('base64url');
        current = r.chance(0.5) ? raw + '='.repeat((4 - raw.length % 4) % 4) : raw;
        bytes = edited;
      }
    }
  }
  return current;
}

// ---------------------------------------------------------------------------------------------
// Concrete model of checkrune for one request (lightningd/runes.c, ccan rune.c).

const LONG_MIN = -(2n ** 63n), LONG_MAX = 2n ** 63n - 1n;
const ULONG_MAX = 2n ** 64n - 1n;
const UINT32_MAX = 2n ** 32n - 1n;

/** strtol(value, &p, 10) accepted only when it consumes everything without ERANGE. */
function strtolWhole(value) {
  const match = /^[ \t\n\v\f\r]*([+-]?)([0-9]+)$/.exec(value);
  if (!match) return null;
  const n = (match[1] === '-' ? -1n : 1n) * BigInt(match[2]);
  return n < LONG_MIN || n > LONG_MAX ? null : n;
}

/** strtoul(value, &end, 10): the value and the rest, or null when nothing was converted. */
function strtoul(value) {
  const match = /^[ \t\n\v\f\r]*([+-]?)([0-9]+)/.exec(value);
  if (!match) return null;
  const magnitude = BigInt(match[2]);
  let number;
  if (magnitude > ULONG_MAX) number = ULONG_MAX;
  else number = match[1] === '-' ? (magnitude === 0n ? 0n : (ULONG_MAX + 1n - magnitude)) : magnitude;
  return { number, rest: value.slice(match[0].length) };
}

function lexo(field, value) {
  // strncmp(field, value, strlen(field)), then "same but longer" is before.
  const a = Buffer.from(field, 'latin1'), b = Buffer.from(value, 'latin1');
  for (let i = 0; i < a.length; i++) {
    const x = a[i], y = i < b.length ? b[i] : 0;
    if (x !== y) return x - y;
  }
  return b.length > a.length ? -1 : 0;
}

/** rune_alt_single: field is null (missing), { int: bigint } or { str: latin1 string }. */
export function altSingle(alt, field) {
  const str = field === null ? null : 'int' in field ? field.int.toString() : field.str;
  const v = alt.value;
  switch (alt.condition) {
    case '!': return str === null;
    case '=': return str !== null && str === v;
    case '/': return str !== null && str !== v;
    case '^': return str !== null && str.startsWith(v);
    case '$': return str !== null && str.endsWith(v);
    case '~': return str !== null && str.includes(v);
    case '<': case '>': {
      if (field === null || !('int' in field)) return false;
      const bound = strtolWhole(v);
      if (bound === null) return false;
      return alt.condition === '<' ? field.int < bound : field.int > bound;
    }
    case '{': return str !== null && lexo(str, v) < 0;
    case '}': return str !== null && lexo(str, v) > 0;
    case '#': return true;
  }
  throw new Error(`condition ${alt.condition}`);
}

function rateValid(alt) {
  if (alt.condition !== '=') return false;
  const parsed = strtoul(alt.value);
  if (parsed === null || parsed.rest !== '' || parsed.number === 0n || parsed.number >= UINT32_MAX) return false;
  return true;
}

function perValid(alt) {
  if (alt.condition !== '=') return false;
  const parsed = strtoul(alt.value);
  if (parsed === null || parsed.number === 0n || parsed.number >= UINT32_MAX) return false;
  const units = { '': 1_000_000_000n, sec: 1_000_000_000n, nsec: 1n, usec: 1000n, msec: 1_000_000n, min: 60_000_000_000n,
    hour: 3_600_000_000_000n, day: 86_400_000_000_000n };
  if (!Object.hasOwn(units, parsed.rest)) return false;
  return parsed.number * units[parsed.rest] <= ULONG_MAX;
}

function stripPunct(name) {
  return [...Buffer.from(name, 'latin1')].filter(byte => !ispunct(byte)).map(byte => String.fromCharCode(byte)).join('');
}

/**
 * check_condition for a request: { method (latin1 string), time (bigint), peer (string|null),
 * params: null | { object: [[key, value]] } | { array: [value] } with value { int } | { str },
 * rateOk (bool: the rune's last use is long enough ago), invoices: map param → { amount?, description?, node } | 'invalid' }.
 */
export function checkCondition(alt, request) {
  const { field } = alt;
  if (field === 'time') return altSingle(alt, { int: request.time });
  if (field === 'id') return altSingle(alt, request.peer === null ? null : { str: request.peer });
  if (field === 'method') return altSingle(alt, request.method === null ? null : { str: request.method });
  if (field === 'pnum') {
    const size = request.params === null ? 0 : 'object' in request.params ? request.params.object.length : request.params.array.length;
    return altSingle(alt, { int: BigInt(size) });
  }
  if (field === 'rate') return rateValid(alt) && request.rateOk;
  if (field === 'per') return perValid(alt) && request.rateOk;
  const params = new Map();
  if (request.params !== null && 'object' in request.params)
    for (const [key, value] of request.params.object) {
      if (!params.has(`pname${key}`)) params.set(`pname${key}`, value);
      if (!params.has(`pname${stripPunct(key)}`)) params.set(`pname${stripPunct(key)}`, value);
    }
  else if (request.params !== null) request.params.array.forEach((value, index) => params.set(`parr${index}`, value));
  if (field.startsWith('pinv')) {
    const rest = field.slice(4);
    const suffix = ['_amount', '_description', '_node'].find(item => rest.endsWith(item));
    if (!suffix) return false;
    const param = rest.slice(0, rest.length - suffix.length);
    if (!params.has(`pname${param}`)) return false;
    const invoice = request.invoices.get(param);
    if (!invoice || invoice === 'invalid') return false;
    if (suffix === '_amount') return altSingle(alt, invoice.amount === undefined ? null : { int: invoice.amount });
    if (suffix === '_description') return altSingle(alt, invoice.description === undefined ? null : { str: invoice.description });
    return altSingle(alt, invoice.node === undefined ? null : { str: invoice.node });
  }
  const value = params.get(field);
  return altSingle(alt, value === undefined ? null : value);
}

/** Whether checkrune's rune_test passes the restrictions (unique ID already removed) for the request. */
export function concreteCheck(restrictions, request) {
  return restrictions.every(restriction => restriction.some(alt => checkCondition(alt, request)));
}

const INVOICE_NODES = ['02' + 'ab'.repeat(32), '03' + 'cd'.repeat(32)];

/** A random concrete request steered by the values the rune names, so boundaries are hit. */
export function randomRequest(r, restrictions, tableMethods, now) {
  const values = restrictions.flat();
  const named = values.filter(alt => alt.field === 'method').map(alt => alt.value);
  const ints = values.map(alt => strtolWhole(alt.value)).filter(value => value !== null);
  const roll = r.next();
  let method;
  if (roll < 0.45 && named.length) {
    const base = r.pick(named);
    method = r.chance(0.7) ? base : r.chance(0.5) ? base + r.pick(FIELD_SAFE) : base.slice(0, -1);
  } else if (roll < 0.9) method = r.pick(tableMethods);
  else method = randomValue(r).slice(0, 20);
  const anInt = () => {
    if (ints.length && r.chance(0.7)) return r.pick(ints) + BigInt(r.int(-1, 1));
    return BigInt(r.int(-5, 2_000_000_000));
  };
  const time = r.chance(0.5) ? now + BigInt(r.int(-5, 5)) : anInt();
  const peer = r.chance(0.3) ? null : r.chance(0.5)
    ? (values.find(alt => alt.field === 'id')?.value ?? INVOICE_NODES[0]) : r.pick(INVOICE_NODES);
  const paramValue = () => {
    if (r.chance(0.5)) return { int: anInt() };
    if (values.length && r.chance(0.6)) {
      const base = r.pick(values).value;
      return { str: r.chance(0.7) ? base : base + 'x' };
    }
    return { str: randomValue(r).slice(0, 12) };
  };
  let params = null;
  const fields = values.map(alt => alt.field);
  if (r.chance(0.8)) {
    if (r.chance(0.75)) {
      const keys = new Set();
      for (const field of fields) {
        if (field.startsWith('pname') && r.chance(0.7)) keys.add(field.slice(5));
        if (field.startsWith('pinv') && r.chance(0.7)) keys.add(field.slice(4).replace(/_(amount|description|node)$/, ''));
      }
      if (r.chance(0.3)) keys.add(randomField(r, []));
      params = { object: [...keys].map(key => [key, paramValue()]) };
    } else {
      const size = r.int(0, 4);
      params = { array: Array.from({ length: size }, paramValue) };
    }
  }
  const invoices = new Map();
  if (params !== null && 'object' in params)
    for (const [key] of params.object) {
      if (r.chance(0.2)) { invoices.set(key, 'invalid'); continue; }
      invoices.set(key, { amount: r.chance(0.8) ? anInt() : undefined,
        description: r.chance(0.7) ? (values.length && r.chance(0.5) ? r.pick(values).value : 'coffee') : undefined,
        node: r.pick(INVOICE_NODES) });
    }
  return { method, time, peer, params, rateOk: r.chance(0.7), invoices };
}

// ---------------------------------------------------------------------------------------------
// Campaign.

/** The alternatives that are false for every request (used to build contradictions). */
export const ALWAYS_FALSE = [
  { field: 'method', condition: '!', value: '' }, { field: 'method', condition: '<', value: '5' },
  { field: 'rate', condition: '#', value: 'x' }, { field: 'rate', condition: '<', value: '1' }, { field: 'per', condition: '=', value: '0' },
  { field: 'per', condition: '=', value: '5weeks' }, { field: 'pinvx_payee', condition: '=', value: '1' },
  { field: 'time', condition: '<', value: 'soon' }, { field: 'id', condition: '>', value: '1' }, { field: 'pnum', condition: '!', value: '' },
  { field: 'time', condition: '!', value: '' },
];

const LADDER = ['READ', 'RECEIVE', 'OPERATE', 'SPEND', 'ADMIN'];

/** A short, printable description of test data for failure messages (synthetic runes only). */
export function describe(value) {
  const text = JSON.stringify(value, (key, item) => typeof item === 'bigint' ? `${item}n` : item instanceof Map ? Object.fromEntries(item) : item);
  return text.length > 600 ? `${text.slice(0, 600)}…` : text;
}

function sameFacts(facts, reference) {
  return JSON.stringify([facts.uniqueId, facts.version, facts.restrictions])
    === JSON.stringify([reference.uniqueId, reference.version, reference.restrictions]);
}

function factsOf(restrictions) {
  return { fingerprint: 'fp:0000000000000000', uniqueId: '1', version: null, restrictions, nonCanonical: false };
}

/**
 * Runs `cases` cases from `seed` against `api`:
 *   { decodeRuneText, assessRune, methodMayPass, runeReport, runeFindings, CLN_METHODS,
 *     RUNE_TEXT_LIMIT, RUNE_RESTRICTION_LIMIT, RUNE_ALTERNATIVE_LIMIT }
 * Returns counts per check and the first failures (seed, index, message).
 */
/**
 * @param {Record<string, any>} api
 * @param {{ seed: number, cases: number, start?: number, maxFailures?: number,
 *   onProgress?: (done: number, stats: object, failures: object[]) => void }} options
 */
export function runCampaign(api, { seed, cases, start = 0, maxFailures = 20, onProgress }) {
  const tableMethods = Object.keys(api.CLN_METHODS);
  const now = 1_791_500_000n;
  const stats = { cases: 0, roundTrip: 0, overBounds: 0, mutations: 0, mutationsAccepted: 0, mutationsRefused: 0, semantic: 0,
    requests: 0, requestsPassed: 0, single: 0, contradictions: 0, truncation: 0, reasons: /** @type {Record<string, number>} */ ({}) };
  const failures = [];
  const fail = (index, kind, message) => { if (failures.length < maxFailures) failures.push({ seed, index, kind, message }); };
  const scanContext = {};

  const checkDecode = (index, text, label) => {
    let result;
    try { result = api.decodeRuneText(text); }
    catch (error) { fail(index, label, `decodeRuneText threw ${error?.message}`); return null; }
    const reference = referenceDecode(text);
    stats.reasons[result.ok ? 'ok' : result.reason] = (stats.reasons[result.ok ? 'ok' : result.reason] ?? 0) + 1;
    if (text.length > api.RUNE_TEXT_LIMIT) {
      if (result.ok || result.reason !== 'exceeds-bounds') fail(index, label, `over the text limit but ${result.ok ? 'decoded' : result.reason}`);
      return result;
    }
    if (!reference.ok) {
      const allowed = { base64: ['not-base64url'], short: ['too-short'], nul: ['nul-byte'],
        syntax: ['restriction-syntax', 'exceeds-bounds'], placement: ['unique-id-placement', 'exceeds-bounds'] }[reference.stage];
      if (result.ok) fail(index, label, `decoded a text Core Lightning refuses (${reference.stage})`);
      else if (!allowed.includes(result.reason)) fail(index, label, `reason ${result.reason} for reference stage ${reference.stage}`);
      return result;
    }
    const beyond = reference.restrictionCount > api.RUNE_RESTRICTION_LIMIT || reference.alternatives > api.RUNE_ALTERNATIVE_LIMIT;
    if (beyond) {
      if (result.ok || result.reason !== 'exceeds-bounds') fail(index, label, `beyond bounds but ${result.ok ? 'decoded' : result.reason}`);
      return result;
    }
    if (!result.ok) { fail(index, label, `refused (${result.reason}) a rune Core Lightning accepts`); return result; }
    if (!sameFacts(result.facts, reference)) fail(index, label, 'decoded facts differ from the reference');
    if (result.facts.fingerprint !== fingerprintOf(reference.bytes)) fail(index, label, 'fingerprint is not over the decoded bytes');
    try {
      const assessment = api.assessRune(result.facts, now);
      const report = api.runeReport(result.facts, now);
      const truncated = api.runeReport(result.facts, now, true);
      if (!['UNASSESSED', 'ADMIN'].includes(truncated.grade)) fail(index, label, `possibly truncated rune graded ${truncated.grade}`);
      if (report.grade !== assessment.grade) fail(index, label, 'report and assessment grades differ');
    } catch (error) { fail(index, label, `assessment threw ${error?.message}`); }
    return result;
  };

  const assessmentInvariants = (index, restrictions, r) => {
    const facts = factsOf(restrictions);
    const assessment = api.assessRune(facts, now);
    const may = new Map(tableMethods.map(method => [method, api.methodMayPass(facts, method)]));
    // Grade consistency.
    if (assessment.methods === 'none') {
      if (assessment.grade !== 'READ' || [...may.values()].some(Boolean)) fail(index, 'semantic', 'methods none but a method may pass');
    } else {
      const classes = assessment.capabilities;
      if (classes.includes('ADMIN') && assessment.grade !== 'ADMIN') fail(index, 'semantic', 'ADMIN capability below ADMIN grade');
      if (assessment.grade !== 'UNASSESSED' && assessment.grade !== classes.find(grade => grade !== 'UNASSESSED'))
        fail(index, 'semantic', `grade ${assessment.grade} is not the highest capability ${classes.join(',')}`);
      if (assessment.methods === 'broad' && assessment.grade !== 'UNASSESSED' && assessment.grade !== 'ADMIN')
        fail(index, 'semantic', 'broad rune graded below UNASSESSED');
    }
    // Concrete soundness: whatever a concrete request passes, the assessment allows.
    const deadline = assessment.expiry.deadline === null ? null : BigInt(assessment.expiry.deadline);
    for (let k = 0; k < 8; k++) {
      const request = randomRequest(r, restrictions, tableMethods, now);
      stats.requests++;
      if (!concreteCheck(restrictions, request)) continue;
      stats.requestsPassed++;
      const context = ` [restrictions ${describe(restrictions)}; request ${describe(request)}]`;
      const inTable = Object.hasOwn(api.CLN_METHODS, request.method);
      if (assessment.methods === 'none') fail(index, 'soundness', `methods none, but ${JSON.stringify(request.method)} passes` + context);
      else if (inTable && !may.get(request.method)) fail(index, 'soundness', `${request.method} passes but is reported impossible` + context);
      else if (inTable && assessment.methods === 'listed' && !assessment.allowedMethods.includes(request.method))
        fail(index, 'soundness', `${request.method} passes but is not in allowedMethods` + context);
      else if (!inTable && assessment.methods !== 'broad' && !assessment.unreviewedMethods.includes(request.method))
        fail(index, 'soundness', `unlisted method ${JSON.stringify(request.method)} passes but is neither broad nor unreviewed` + context);
      if (inTable && !assessment.capabilities.includes(api.CLN_METHODS[request.method]))
        fail(index, 'soundness', `${request.method} passes but its class is not in capabilities` + context);
      if (deadline !== null && request.time >= deadline) fail(index, 'expiry', `passes at ${request.time} after deadline ${deadline}` + context);
    }
    return { assessment, may };
  };

  for (let index = start; index < start + cases; index++) {
    const r = prng(caseSeed(seed, index));
    stats.cases++;
    const kind = index % 10;
    try {
      if (kind === 0 || kind === 1) {
        // Round trip: random AST → encode → decode, exactly.
        const ast = randomAst(r, { large: r.chance(0.04), methods: tableMethods.slice(r.int(0, 150)) });
        const { text, bytes } = encodeRune(ast, r.bytes(32));
        const result = checkDecode(index, text, 'round-trip');
        const reference = referenceDecode(text);
        const within = text.length <= api.RUNE_TEXT_LIMIT && reference.ok && reference.restrictionCount <= api.RUNE_RESTRICTION_LIMIT
          && reference.alternatives <= api.RUNE_ALTERNATIVE_LIMIT;
        if (!within) { stats.overBounds++; continue; }
        stats.roundTrip++;
        if (!result?.ok) continue;
        if (!sameFacts(result.facts, { uniqueId: ast.uniqueId, version: ast.version, restrictions: ast.restrictions }))
          fail(index, 'round-trip', 'decode(encode(ast)) differs from ast');
        if (result.facts.nonCanonical) fail(index, 'round-trip', 'canonical text reported non-canonical');
        if (result.facts.fingerprint !== fingerprintOf(bytes)) fail(index, 'round-trip', 'fingerprint differs');
        const unpadded = text.replace(/=+$/, '');
        const again = api.decodeRuneText(unpadded);
        if (!again.ok || !sameFacts(again.facts, result.facts) || again.facts.fingerprint !== result.facts.fingerprint
          || again.facts.nonCanonical !== (unpadded !== text)) fail(index, 'round-trip', 'unpadded copy decodes differently');
      } else if (kind === 2 || kind === 3) {
        // Mutations: refuse or decode exactly as Core Lightning does, never a partial result, never a throw.
        const ast = randomAst(r, { methods: tableMethods });
        const { text, bytes } = encodeRune(ast, r.bytes(32));
        const mutated = r.chance(0.05) ? [...Array(r.int(0, 120))].map(() => r.pick(MUTATION_CHARACTERS)).join('') : mutate(r, text, bytes);
        stats.mutations++;
        const result = checkDecode(index, mutated, 'mutation');
        if (result?.ok) stats.mutationsAccepted++; else stats.mutationsRefused++;
      } else if (kind === 4 || kind === 5) {
        // Assessment monotonicity and concrete soundness.
        stats.semantic++;
        const ast = randomAst(r, { methods: tableMethods });
        const base = assessmentInvariants(index, ast.restrictions, r);
        // Adding a restriction never adds a capability.
        const extra = randomAst(r, { methods: tableMethods }).restrictions[0] ?? [{ field: 'method', condition: '=', value: r.pick(tableMethods) }];
        const narrowed = [...ast.restrictions];
        narrowed.splice(r.int(0, narrowed.length), 0, extra);
        const narrow = assessmentInvariants(index, narrowed, r);
        for (const method of tableMethods)
          if (narrow.may.get(method) && !base.may.get(method)) fail(index, 'monotonic', `adding a restriction allowed ${method}`);
        if (narrow.assessment.capabilities.some(grade => !base.assessment.capabilities.includes(grade))) fail(index, 'monotonic', 'adding a restriction added a capability');
        if (narrow.assessment.methods === 'broad' && base.assessment.methods !== 'broad') fail(index, 'monotonic', 'adding a restriction made the rune broad');
        if (base.assessment.methods !== 'broad' && narrow.assessment.unreviewedMethods.some(name => !base.assessment.unreviewedMethods.includes(name)))
          fail(index, 'monotonic', 'adding a restriction added an unreviewed method');
        // Adding an alternative never removes one.
        if (ast.restrictions.length) {
          const widened = ast.restrictions.map(restriction => [...restriction]);
          const target = widened[r.int(0, widened.length - 1)];
          target.splice(r.int(0, target.length), 0, { field: randomField(r, KNOWN_FIELDS), condition: r.pick(CONDITIONS),
            value: randomValue(r, tableMethods) });
          const wide = assessmentInvariants(index, widened, r);
          for (const method of tableMethods)
            if (base.may.get(method) && !wide.may.get(method)) fail(index, 'monotonic', `adding an alternative removed ${method}`);
          if (base.assessment.capabilities.some(grade => !wide.assessment.capabilities.includes(grade))) fail(index, 'monotonic', 'adding an alternative removed a capability');
          if (base.assessment.methods === 'broad' && wide.assessment.methods !== 'broad') fail(index, 'monotonic', 'adding an alternative made a broad rune narrow');
          if (wide.assessment.methods !== 'broad' && base.assessment.methods !== 'none'
            && base.assessment.unreviewedMethods.some(name => !wide.assessment.unreviewedMethods.includes(name)))
            fail(index, 'monotonic', 'adding an alternative removed an unreviewed method');
          // Expiry: a widened rune is never more expired.
          const order = { none: 0, 'time-conditions': 0, 'deadline-ahead': 1, 'deadline-passed': 1 };
          if (order[wide.assessment.expiry.status] > order[base.assessment.expiry.status]) fail(index, 'expiry', 'adding an alternative closed the rune');
          if (base.assessment.expiry.deadline !== null && wide.assessment.expiry.deadline !== null
            && BigInt(wide.assessment.expiry.deadline) < BigInt(base.assessment.expiry.deadline)) fail(index, 'expiry', 'adding an alternative brought the deadline forward');
        }
      } else if (kind === 6) {
        // Contradictions: two different pinned methods, or a restriction of always-false alternatives.
        stats.contradictions++;
        const ast = randomAst(r, { methods: tableMethods });
        const restrictions = [...ast.restrictions];
        if (r.chance(0.5)) {
          const a = r.pick(tableMethods);
          let b = r.pick(tableMethods);
          if (b === a) b = `${a}x`;
          restrictions.splice(r.int(0, restrictions.length), 0, [{ field: 'method', condition: '=', value: a }]);
          restrictions.splice(r.int(0, restrictions.length), 0, [{ field: 'method', condition: '=', value: b }]);
        } else {
          restrictions.splice(r.int(0, restrictions.length), 0, Array.from({ length: r.int(1, 4) }, () => r.pick(ALWAYS_FALSE)));
        }
        const { assessment } = assessmentInvariants(index, restrictions, r);
        if (assessment.methods !== 'none' || assessment.grade !== 'READ' || assessment.capabilities.length)
          fail(index, 'contradiction', `contradiction assessed as ${assessment.methods} ${assessment.grade}`);
        // Expiry is claimed only when every path is closed by time.
        const timed = [...ast.restrictions, [{ field: 'time', condition: '<', value: String(now - 10n) }, ...(r.chance(0.5) ? [r.pick(ALWAYS_FALSE)] : [])]];
        const closed = api.assessRune(factsOf(timed), now).expiry;
        if (closed.status !== 'deadline-passed') fail(index, 'expiry', `a restriction closed by time is ${closed.status}`);
        const open = [...ast.restrictions, [{ field: 'time', condition: '<', value: String(now - 10n) },
          { field: r.pick(['method', 'id', 'pnamefoo', 'pnum', 'time']), condition: r.pick(['=', '/', '^', '#']), value: 'x' }]];
        const notClosed = api.assessRune(factsOf(open), now).expiry;
        if (notClosed.status === 'deadline-passed' && !ast.restrictions.some(restriction => restriction.every(alt =>
          alt.field === 'time' && alt.condition === '<'))) {
          // Only a closing restriction among the random ones may expire it; check with the concrete model.
          for (let k = 0; k < 4; k++) {
            const request = randomRequest(r, open, tableMethods, now);
            if (concreteCheck(open, request) && request.time >= BigInt(notClosed.deadline)) fail(index, 'expiry', 'expired but a later request passes');
          }
        }
      } else if (kind === 7 || kind === 8) {
        // One alternative at a time, with values at the edges of every field's parser: whatever a
        // concrete request passes, the assessment must allow.
        stats.single++;
        const field = r.pick(KNOWN_FIELDS);
        const condition = r.pick(CONDITIONS);
        const value = r.chance(0.6) ? r.pick([...TRICKY_NUMBERS, ...TRICKY_NUMBERS.map(item => `${item}sec`), r.pick(tableMethods)])
          : randomValue(r, tableMethods);
        const restrictions = [[{ field, condition, value }]];
        if (r.chance(0.5)) restrictions.push([{ field: 'method', condition: '=', value: r.pick(tableMethods) }]);
        assessmentInvariants(index, restrictions, r);
      } else {
        // Truncated or over-limit values in scan context are never graded below UNASSESSED.
        stats.truncation++;
        const ast = randomAst(r, { large: r.chance(0.3), methods: tableMethods });
        const { text } = encodeRune(ast, r.bytes(32));
        const cut = text.slice(0, r.int(43, Math.max(43, text.length - 1)));
        const variants = [`RUNE="${cut}`, `RUNE=${cut}.`, `RUNE=${text}${'A'.repeat(r.chance(0.5) ? api.RUNE_TEXT_LIMIT : 0)}`];
        for (const line of variants) {
          const findings = api.runeFindings(line, new Date(Number(now) * 1000), scanContext);
          for (const finding of findings) {
            const limited = finding.kind === 'rune-invalid' || finding.rune?.warnings?.includes('possibly-truncated');
            const over = line.length > api.RUNE_TEXT_LIMIT + 6;
            if ((limited || over) && !['UNASSESSED', 'ADMIN'].includes(finding.grade))
              fail(index, 'truncation', `${over ? 'over-limit' : 'truncated'} value graded ${finding.grade}`);
          }
          if (findings.length === 0) fail(index, 'truncation', 'a value in rune key context was not reported');
        }
      }
    } catch (error) {
      fail(index, 'exception', `${error?.stack ?? error}`);
    }
    if (onProgress && (index + 1) % 10000 === 0) onProgress(index + 1 - start, stats, failures);
  }
  return { stats, failures, ladder: LADDER };
}
