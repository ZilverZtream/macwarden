import { redactEncodedCredentials } from '../credential-recognition.js';
import { nwcMatches, replaceNwc } from './nwc-match.js';
import { lndconnect } from './patterns.js';

const lndconnectAll = new RegExp(lndconnect.source, `${lndconnect.flags}g`);

// The published nwc regex backtracks quadratically on repeated prefixes; the linear matcher
// returns exactly its matches (src/scan/nwc-match.ts).
function redactStructured(text: string): string {
  lndconnectAll.lastIndex = 0;
  return replaceNwc(text.replace(lndconnectAll, '[redacted]'),
    match => `[redacted]${/[^0-9a-f]$/i.test(match) ? match.slice(-1) : ''}`);
}

// Same rule as the output renderer: a complete macaroon is at least 36 bytes and every
// encoding the recognizer reads needs at least one printable ASCII character per byte, so a
// shorter printable ASCII string holds no credential. Decoded facts repeat (one entity per
// permission, the same caveats on many findings), so results are memoised, with a cap.
const SHORTEST_MACAROON = 36;
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
const decodedMemo = new Map<string, string>();
const DECODED_MEMO_LIMIT = 50_000;
const DECODED_MEMO_MAX_LENGTH = 4096;

export function redactDecoded(text: string): string {
  if (text.length < SHORTEST_MACAROON && PRINTABLE_ASCII.test(text)) return text;
  const memo = text.length <= DECODED_MEMO_MAX_LENGTH ? decodedMemo.get(text) : undefined;
  if (memo !== undefined) return memo;
  const safe = redactStructured(redactEncodedCredentials(text));
  if (text.length <= DECODED_MEMO_MAX_LENGTH) {
    if (decodedMemo.size >= DECODED_MEMO_LIMIT) decodedMemo.clear();
    decodedMemo.set(text, safe);
  }
  return safe;
}

export function redactPath(text: string): string {
  return redactStructured(redactEncodedCredentials(text));
}

// A matched NWC URI confirms the identity of its 32-byte secret. Keep only
// those known identities for redaction; ordinary encoded-looking facts remain
// unchanged.
export function collectNwcSecrets(text: string, secrets: Set<string>): void {
  if (!/walletconnect:/i.test(text)) return;
  for (const match of nwcMatches(text)) {
    const parameter = /(?:[?&])secret=([0-9a-f]{64})(?=[^0-9a-f]|$)/i.exec(match.text);
    if (parameter) secrets.add(parameter[1].toLowerCase());
  }
}

/** Needles grouped by length, each group with the rolling hashes of its members. */
type NeedleSet = Map<number, { values: Set<string>; hashes: Set<number> }>;
const BASE = 131;

function rollingHash(text: string, start: number, length: number): number {
  let hash = 0;
  for (let i = start; i < start + length; i++) hash = (Math.imul(hash, BASE) + text.charCodeAt(i)) | 0;
  return hash;
}

function addNeedle(set: NeedleSet, value: string): void {
  let group = set.get(value.length);
  if (!group) set.set(value.length, group = { values: new Set(), hashes: new Set() });
  group.values.add(value);
  group.hashes.add(rollingHash(value, 0, value.length));
}

/** Reports every occurrence of every needle in one pass per needle length (Rabin-Karp). */
function findNeedles(text: string, needles: NeedleSet, onMatch: (start: number, length: number) => void): void {
  for (const [length, { values, hashes }] of needles) {
    if (text.length < length) continue;
    let power = 1;
    for (let i = 1; i < length; i++) power = Math.imul(power, BASE);
    let hash = rollingHash(text, 0, length);
    for (let start = 0; ; start++) {
      if (hashes.has(hash) && values.has(text.slice(start, start + length))) onMatch(start, length);
      if (start + length >= text.length) break;
      hash = (Math.imul((hash - Math.imul(text.charCodeAt(start), power)) | 0, BASE)
        + text.charCodeAt(start + length)) | 0;
    }
  }
}

function isHexOrSpace(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102)
    || code === 32 || code === 9 || code === 13 || code === 10;
}

/**
 * Builds a redactor for a fixed set of known NWC secrets (64 lowercase hex digits each).
 * It replaces, with `[redacted]`, exactly what the per-secret replacement passes did:
 * - the hex form in either case, with any spaces, tabs, CR or LF between its digits;
 * - the base64 and base64url forms, padded or not, with at most one LF or CRLF between
 *   any two characters (line wrapping);
 * - the latin1 form and, when the bytes are valid UTF-8, the UTF-8 form.
 * Work is linear in the text length times the small number of distinct needle lengths,
 * however many secrets there are.
 */
export function knownSecretRedactor(secrets: ReadonlySet<string>): (text: string) => string {
  if (!secrets.size) return text => text;
  const hexes: NeedleSet = new Map();
  const wrapped: NeedleSet = new Map();
  const exact: NeedleSet = new Map();
  let minimum = 64;
  for (const hex of secrets) {
    addNeedle(hexes, hex.toLowerCase());
    const bytes = Buffer.from(hex, 'hex');
    const variants = new Set([
      bytes.toString('base64'), bytes.toString('base64').replace(/=+$/, ''),
      bytes.toString('base64url'), bytes.toString('base64url').replace(/=+$/, ''),
      bytes.toString('latin1'),
    ]);
    const utf8 = bytes.toString('utf8');
    if (Buffer.from(utf8, 'utf8').equals(bytes)) variants.add(utf8);
    for (const variant of variants) {
      if (!variant || variant === hex) continue;
      // Variants of 40 or more characters may be line-wrapped; shorter ones match exactly.
      addNeedle(variant.length >= 40 ? wrapped : exact, variant);
      minimum = Math.min(minimum, variant.length);
    }
  }
  return text => {
    if (text.length < minimum) return text;
    const spans: [number, number][] = [];
    // Hex: digits of maximal hex-or-whitespace runs, compared lower-cased.
    for (let i = 0; i < text.length;) {
      if (!isHexOrSpace(text.charCodeAt(i))) { i++; continue; }
      let digits = '';
      const positions: number[] = [];
      for (; i < text.length && isHexOrSpace(text.charCodeAt(i)); i++) {
        const code = text.charCodeAt(i);
        if (code !== 32 && code !== 9 && code !== 13 && code !== 10) { digits += text[i].toLowerCase(); positions.push(i); }
      }
      if (digits.length >= 64)
        findNeedles(digits, hexes, (start, length) => spans.push([positions[start], positions[start + length - 1] + 1]));
    }
    // Wrapped base64 forms: search the text with LF and CRLF removed, then require
    // that each removed gap between matched characters was exactly one LF or CRLF.
    if (wrapped.size) {
      let view = '';
      const positions: number[] = [];
      for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        if (code === 10 || (code === 13 && text.charCodeAt(i + 1) === 10)) continue;
        view += text[i];
        positions.push(i);
      }
      findNeedles(view, wrapped, (start, length) => {
        for (let k = start; k < start + length - 1; k++) {
          const gap = text.slice(positions[k] + 1, positions[k + 1]);
          if (gap !== '' && gap !== '\n' && gap !== '\r\n') return;
        }
        spans.push([positions[start], positions[start + length - 1] + 1]);
      });
    }
    findNeedles(text, exact, (start, length) => spans.push([start, start + length]));
    if (!spans.length) return text;
    // Leftmost first, longest at a position, never overlapping, as global replacement does.
    spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    let output = '';
    let cursor = 0;
    for (const [start, end] of spans) {
      if (start < cursor) continue;
      output += `${text.slice(cursor, start)}[redacted]`;
      cursor = end;
    }
    return output + text.slice(cursor);
  };
}

const redactors = new WeakMap<ReadonlySet<string>, { size: number; redact: (text: string) => string }>();

/** Redacts every known NWC secret form; the matcher is built once per secret set. */
export function redactKnownSecrets(text: string, secrets: ReadonlySet<string>): string {
  if (!secrets.size) return text;
  let cached = redactors.get(secrets);
  if (!cached || cached.size !== secrets.size) redactors.set(secrets, cached = { size: secrets.size, redact: knownSecretRedactor(secrets) });
  return cached.redact(text);
}
