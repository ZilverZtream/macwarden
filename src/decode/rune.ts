// Core Lightning rune decoding (1.2.0), offline. The reference is Core Lightning v26.06.8:
// ccan/ccan/rune/coding.c (rune_from_base64n, rune_altern_decode, rune_restr_decode),
// ccan/ccan/rune/rune.c (rune_add_restr, extract_unique_id) and ccan/ccan/base64/base64.c
// (base64_decode_using_maps with the URL-safe maps). This module reproduces their acceptance
// exactly, byte for byte, instead of using Node's permissive base64 decoder or splitting the
// decoded text on delimiters. It never returns the 32-byte authenticator or the decoded
// string that contains it: only the fingerprint, the unique ID and version, and the parsed
// restrictions leave this module.
import { createHash } from 'node:crypto';

/** A rune longer than this many characters is not parsed at all (fail closed, never partially). */
export const RUNE_TEXT_LIMIT = 8192;
/** At most this many restrictions (unique ID included) are parsed; more → exceeds-bounds. */
export const RUNE_RESTRICTION_LIMIT = 256;
/** At most this many alternatives in all restrictions together; more → exceeds-bounds. */
export const RUNE_ALTERNATIVE_LIMIT = 1024;
/** The shortest rune: a 32-byte authenticator and no restriction is 43 base64url characters. */
export const RUNE_SHORTEST_TEXT = 43;

/** ccan/rune enum rune_condition: '!' missing, '=' equal, '/' not equal, '^' starts with, '$' ends with,
 * '~' contains, '<' '>' integer comparison, '{' '}' lexical comparison, '#' comment. */
export type RuneCondition = '!' | '=' | '/' | '^' | '$' | '~' | '<' | '>' | '{' | '}' | '#';
export const RUNE_CONDITIONS: readonly RuneCondition[] = ['!', '=', '/', '^', '$', '~', '<', '>', '{', '}', '#'];

/**
 * One alternative. `field` and `value` are byte strings (latin1, one character per byte), exactly
 * the bytes Core Lightning compares; escapes are already removed from `value`.
 */
export type RuneAlternative = { field: string; condition: RuneCondition; value: string };

export type RuneFacts = {
  fingerprint: string;
  /** The unique ID from the initial empty-field restriction `=ID[-VERSION]`, verbatim (a string). */
  uniqueId: string | null;
  version: string | null;
  /** Every restriction after the unique ID: an AND of restrictions, each an OR of alternatives. */
  restrictions: RuneAlternative[][];
  /** The text is not what Core Lightning would write for these restrictions (padding, escapes, trailing '&'). */
  nonCanonical: boolean;
};

export type RuneInvalidReason = 'exceeds-bounds' | 'not-base64url' | 'too-short' | 'nul-byte' | 'restriction-syntax'
  | 'unique-id-placement';

export type RuneDecodeResult = { ok: true; facts: RuneFacts } | { ok: false; reason: RuneInvalidReason };

const URLSAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const SIXBIT = new Int8Array(256).fill(-1);
for (let i = 0; i < 64; i++) SIXBIT[URLSAFE.charCodeAt(i)] = i;

/** The characters a rune can be written in: the URL-safe alphabet and '=' padding. */
export const RUNE_ALPHABET = /^[A-Za-z0-9_=-]+$/;

/**
 * base64_decode_using_maps with Core Lightning's URL-safe maps: every quartet but the last must
 * be four alphabet characters; the last group of 1–4 characters may end in any number of '='
 * (all are dropped), must keep at least two characters, and its unused bits are ignored. Any
 * other character, including '+', '/', whitespace and '=' before the end, fails.
 */
export function decodeRuneBase64(text: string): Buffer | null {
  const length = text.length;
  const out = Buffer.alloc(Math.floor((length + 3) / 4) * 3);
  let written = 0;
  let at = 0;
  const sixbit = (index: number): number => {
    const code = text.charCodeAt(index);
    return code > 255 ? -1 : SIXBIT[code];
  };
  for (; length - at > 4; at += 4) {
    const a = sixbit(at), b = sixbit(at + 1), c = sixbit(at + 2), d = sixbit(at + 3);
    if (a < 0 || b < 0 || c < 0 || d < 0) return null;
    out[written++] = ((a << 2) | (b >> 4)) & 0xff;
    out[written++] = (((b & 0xf) << 4) | (c >> 2)) & 0xff;
    out[written++] = (((c & 0x3) << 6) | d) & 0xff;
  }
  let size = length - at;
  while (size !== 0 && text[at + size - 1] === '=') size--;
  if (size === 1) return null;
  if (size > 1) {
    const value = [0, 1, 2, 3].map(offset => offset < size ? sixbit(at + offset) : 0);
    if (value.some(item => item < 0)) return null;
    const bytes = [((value[0] << 2) | (value[1] >> 4)) & 0xff, (((value[1] & 0xf) << 4) | (value[2] >> 2)) & 0xff,
      (((value[2] & 0x3) << 6) | value[3]) & 0xff];
    for (let i = 0; i < size - 1; i++) out[written++] = bytes[i];
  }
  return out.subarray(0, written);
}

// C ispunct() in the "C" locale; ccan's field name stops at punctuation other than '_'.
function isFieldTerminator(byte: number): boolean {
  const punctuation = (byte >= 0x21 && byte <= 0x2f) || (byte >= 0x3a && byte <= 0x40)
    || (byte >= 0x5b && byte <= 0x60) || (byte >= 0x7b && byte <= 0x7e);
  return punctuation && byte !== 0x5f;
}

const CONDITION_BYTES = new Set(RUNE_CONDITIONS.map(condition => condition.charCodeAt(0)));

type Parsed = { ok: true; restrictions: RuneAlternative[][]; uniqueId: string | null; version: string | null }
  | { ok: false; reason: RuneInvalidReason };

/** from_string: the restriction text after the authenticator, parsed as rune_restr_decode does. */
function parseRestrictions(bytes: Buffer): Parsed {
  const restrictions: RuneAlternative[][] = [];
  let uniqueId: string | null = null;
  let version: string | null = null;
  let alternatives = 0;
  let pos = 0;
  while (pos < bytes.length) {
    if (restrictions.length >= RUNE_RESTRICTION_LIMIT) return { ok: false, reason: 'exceeds-bounds' };
    const restriction: RuneAlternative[] = [];
    let more: boolean;
    do {
      if (++alternatives > RUNE_ALTERNATIVE_LIMIT) return { ok: false, reason: 'exceeds-bounds' };
      const start = pos;
      while (pos < bytes.length && !isFieldTerminator(bytes[pos])) pos++;
      const field = bytes.toString('latin1', start, pos);
      if (pos >= bytes.length || !CONDITION_BYTES.has(bytes[pos])) return { ok: false, reason: 'restriction-syntax' };
      const condition = String.fromCharCode(bytes[pos++]) as RuneCondition;
      const value: number[] = [];
      more = false;
      while (pos < bytes.length) {
        let byte = bytes[pos++];
        if (byte === 0x7c) { more = true; break; }
        if (byte === 0x26) break;
        if (byte === 0x5c) {
          if (pos >= bytes.length) return { ok: false, reason: 'restriction-syntax' };
          byte = bytes[pos++];
        }
        value.push(byte);
      }
      restriction.push({ field, condition, value: Buffer.from(value).toString('latin1') });
    } while (more);
    // rune_add_restr: an empty field name is the unique ID: the only alternative of the first
    // restriction, with condition '='. The version is everything after its first '-'.
    for (const alternative of restriction) {
      if (alternative.field !== '') continue;
      if (restriction.length !== 1 || restrictions.length !== 0 || alternative.condition !== '=')
        return { ok: false, reason: 'unique-id-placement' };
      const dash = alternative.value.indexOf('-');
      uniqueId = dash < 0 ? alternative.value : alternative.value.slice(0, dash);
      version = dash < 0 ? null : alternative.value.slice(dash + 1);
    }
    restrictions.push(restriction);
  }
  return { ok: true, restrictions, uniqueId, version };
}

/** rune_altern_encode: '\\', '|' and '&' in a value are escaped with a backslash. */
function encodeRestrictions(restrictions: RuneAlternative[][]): Buffer {
  const text = restrictions.map(restriction => restriction.map(alternative =>
    alternative.field + alternative.condition + alternative.value.replace(/[\\|&]/g, match => `\\${match}`)).join('|')).join('&');
  return Buffer.from(text, 'latin1');
}

function fingerprintOf(bytes: Buffer): string {
  return `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
}

/**
 * rune_from_base64n on `text`, with macwarden's bounds. A rune that exceeds a bound is never
 * parsed in part: the result is `exceeds-bounds`, so no assessment can come from a truncated policy.
 */
export function decodeRuneText(text: string): RuneDecodeResult {
  if (text.length > RUNE_TEXT_LIMIT) return { ok: false, reason: 'exceeds-bounds' };
  const bytes = decodeRuneBase64(text);
  if (bytes === null) return { ok: false, reason: 'not-base64url' };
  if (bytes.length < 32) return { ok: false, reason: 'too-short' };
  const restrictionBytes = bytes.subarray(32);
  if (restrictionBytes.includes(0)) return { ok: false, reason: 'nul-byte' };
  const parsed = parseRestrictions(restrictionBytes);
  if (!parsed.ok) return parsed;
  const canonical = Buffer.concat([bytes.subarray(0, 32), encodeRestrictions(parsed.restrictions)]).toString('base64url');
  const padded = canonical + '='.repeat((4 - canonical.length % 4) % 4);
  const uniqueFirst = parsed.uniqueId !== null;
  return { ok: true, facts: {
    // The whole credential: authenticator and restriction text. Padding and other encoding
    // differences of the same bytes give the same fingerprint.
    fingerprint: fingerprintOf(bytes),
    uniqueId: parsed.uniqueId, version: parsed.version,
    restrictions: uniqueFirst ? parsed.restrictions.slice(1) : parsed.restrictions,
    nonCanonical: padded !== text,
  } };
}
