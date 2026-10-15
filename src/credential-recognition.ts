import { groupedBase64 } from './grouped-runs.js';
import { macaroonEnds } from './decode/recognition.js';

// Normalize only for recognition. Every character retains its end offset in
// the original string, so replacement leaves surrounding text untouched. With
// decode false only whitespace is compacted, so the literal text is inspected.
type NormalizedText = { value: string; starts: number[]; ends: number[]; escaped: boolean[] };
function normalized(text: string, compact = true, source?: NormalizedText, decode = true, backslashPairs = true): NormalizedText {
  let value = '';
  const starts: number[] = [];
  const ends: number[] = [];
  const escaped: boolean[] = [];
  for (let i = 0; i < text.length;) {
    // eslint-disable-next-line no-control-regex
    if (compact && /[\s\x00]/u.test(text[i])) { i++; continue; }
    const at = i;
    const percentByte = decode && text[i] === '%' && /^[0-9a-f]{2}$/i.test(text.slice(i + 1, i + 3));
    const encodedByte = !decode ? null : /^(?:%u([0-9a-f]{4})|&#(?:x([0-9a-f]{1,4})|([0-9]{1,5}));)/i.exec(text.slice(i, i + 12));
    const escape = decode && text[i] === '\\' ? (backslashPairs ? /^(?:u([0-9a-f]{4})|x([0-9a-f]{2})|([0-7]{1,3})|([\\"/bfnrt]))/i
      : /^(?:u([0-9a-f]{4})|x([0-9a-f]{2})|([0-7]{1,3})|(["/bfnrt]))/i).exec(text.slice(i + 1)) : null;
    let character: string;
    if (encodedByte && parseInt(encodedByte[1] ?? encodedByte[2] ?? encodedByte[3], encodedByte[3] ? 10 : 16) <= 255) {
      character = String.fromCharCode(parseInt(encodedByte[1] ?? encodedByte[2] ?? encodedByte[3], encodedByte[3] ? 10 : 16));
      i += encodedByte[0].length;
    } else if (percentByte) {
      character = String.fromCharCode(parseInt(text.slice(i + 1, i + 3), 16));
      i += 3;
    } else if (escape) {
      character = escape[4] ? ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[escape[4]] ?? escape[4])
        : String.fromCharCode(parseInt(escape[1] ?? escape[2] ?? escape[3], escape[3] ? 8 : 16));
      i += escape[0].length + 1;
    } else {
      character = text[i++];
    }
    // eslint-disable-next-line no-control-regex
    if (compact && /[\s\x00]/u.test(character)) continue;
    value += character;
    starts.push(source?.starts[at] ?? at);
    ends.push(source?.ends[i - 1] ?? i);
    escaped.push(source?.escaped[at] || percentByte || escape !== null || encodedByte !== null);
  }
  return { value, starts, ends, escaped };
}

// A macaroon starts with version 2 and a location (1) or identifier (2) packet kind. LND
// also accepts the kind as a non-minimal varint (0x81 0x00 ...), so a re-framed copy starts 0281/0282.
const MACAROON_HEX_STARTS = new Set(['0201', '0202', '0281', '0282']);

function isHexDigit(character: string | undefined): boolean {
  return character !== undefined && /^[0-9a-f]$/i.test(character);
}

function regularGroups(run: string): boolean {
  const lengths = run.replace(/=+$/, '').split(/[^A-Za-z0-9+/_-]/).map(group => group.length);
  const size = lengths[0];
  return size % 4 === 0 && lengths.slice(0, -1).every(length => length === size) && lengths.at(-1)! <= size;
}

/**
 * The regular groups of a grouped run. A word joined to the run by a separator (a key before
 * it, "mac:AgED:bG5k:...", or a suffix after it) is a group of another length, which made
 * the whole run irregular and left the credential in it unredacted (audit 1.3.2): the first
 * and last groups are each also tried without. Linear: at most four checks of the run.
 */
function regularRun(run: { index: number; value: string }): { index: number; value: string } | null {
  const body = run.value.replace(/=+$/, '');
  const padding = run.value.slice(body.length);
  let first = -1, last = -1;
  for (let at = 0; at < body.length; at++) {
    if (/[A-Za-z0-9+/_-]/.test(body[at])) continue;
    if (first < 0) first = at;
    last = at;
  }
  if (first < 0) return null;
  for (const [dropFirst, dropLast] of [[false, false], [true, false], [false, true], [true, true]]) {
    const start = dropFirst ? first + 1 : 0;
    const end = dropLast ? last : body.length;
    if (end <= start || (dropFirst && dropLast && first === last)) continue;
    const value = body.slice(start, end) + (dropLast ? '' : padding);
    if (/[^A-Za-z0-9+/_=-]/.test(value) && regularGroups(value)) return { index: run.index + start, value };
  }
  return null;
}

function isByteSeparator(character: string | undefined): boolean {
  return character !== undefined && character !== '\\' && /^[^0-9A-Za-z]$/u.test(character);
}

// Hex encodings, contiguous or with byte separators, in normalized text.
function hexSpans(value: string, starts: number[], ends: number[], found: [number, number][]): void {
  // A maximal run is decoded once. Repeated 02 prefixes in an ordinary hex
  // string do not cause a decode of every remaining suffix.
  const hexRuns = /(?:0x)?[0-9a-f]{8,}/gi;
  for (let run = hexRuns.exec(value); run; run = hexRuns.exec(value)) {
    const prefix = /^0x/i.test(run[0]) ? 2 : 0;
    const digits = run[0].slice(prefix);
    // Both phases matter when ordinary hex text touches a credential.
    const phases = [0, 1].map(phase => {
      const bytes = Buffer.from(digits.slice(phase), 'hex');
      return macaroonEnds(bytes);
    });
    for (let offset = 0; offset + 8 <= digits.length; offset++) {
      if (!MACAROON_HEX_STARTS.has(digits.slice(offset, offset + 4).toLowerCase())) continue;
      const length = phases[offset % 2](Math.floor(offset / 2));
      if (length === null) continue;
      const begin = run.index + prefix + offset;
      found.push([starts[begin], ends[begin + length * 2 - 1]]);
      offset += length * 2 - 1;
    }
  }
  // Compact each maximal run of hex digits separated by byte delimiters once.
  // Digit offsets still point into the original text, including any CR/LF or
  // percent escapes removed by normalization. Both phases permit an odd hex
  // character immediately before the credential without consuming it.
  for (let at = 0; at < value.length;) {
    if (!isHexDigit(value.charAt(at))) { at++; continue; }
    const digitPositions: number[] = [];
    let cursor = at;
    let hasSeparator = false;
    while (true) {
      while (isHexDigit(value.charAt(cursor))) digitPositions.push(cursor++);
      const separatorStart = cursor;
      while (isByteSeparator(value.charAt(cursor))) cursor++;
      if (cursor === separatorStart || !isHexDigit(value.charAt(cursor))) break;
      hasSeparator = true;
    }
    at = cursor;
    if (!hasSeparator || digitPositions.length < 8) continue;
    const digits = digitPositions.map(position => value.charAt(position)).join('');
    const phases = [0, 1].map(phase => macaroonEnds(Buffer.from(digits.slice(phase), 'hex')));
    for (let offset = 0; offset + 8 <= digits.length; offset++) {
      if (!MACAROON_HEX_STARTS.has(digits.slice(offset, offset + 4).toLowerCase())) continue;
      const length = phases[offset % 2](Math.floor(offset / 2));
      if (length === null) continue;
      const begin = digitPositions[offset];
      const last = digitPositions[offset + length * 2 - 1];
      found.push([starts[begin], ends[last]]);
      offset += length * 2 - 1;
    }
  }
}

// A backslash, "%" and "&" start the escapes the decoding layers interpret. An escape-like prefix
// ("\0201...", "%0201...", "%2AgEDb...", "\x2AIBQ...") must not hide a credential by being
// decoded together with its first character (a hex digit, as is the 'A' every base64 and base32
// macaroon starts with), so every form is also recognised in the literal text (audit 1.3.2;
// whitespace compacted only).
function literalSpans(text: string): [number, number][] {
  return /[\\%&]/.test(text) ? spans(text, undefined, true, false) : [];
}

// Raw bytes rendered as UTF-8 (Buffer#toString('utf8'), TextDecoder, Go's string printing)
// keep every byte below 0x80 and every valid sequence, but replace each ill-formed sequence
// of one to three bytes with U+FFFD. Lengths and offsets of a binary credential are lost, so
// it is recognised by the framing that survives instead. Every such rendering of a credential
// the structural decoder accepts starts with U+0002 and a header packet kind (1 or 2; a
// non-minimal varint kind renders as U+FFFD... U+0000), and holds, after an end-of-section
// U+0000, its signature packet header (kind 6, length 32, each minimal or as U+FFFD... U+0000)
// followed by 32 bytes. The span runs from the first such start to the end of the last
// signature that can follow it, counting each U+FFFD as at least one byte: never shorter than
// the credential's rendering. Bytes 0x80 and above never render as ASCII, so this is sound;
// it can only redact more, and only text that already holds these control characters.
const NON_ASCII = /[\u0080-￿]/;
const SIGNATURE_BYTES = 32;
const MAX_VARINT = 10;

/** End (exclusive) of a small varint at `at` rendered as UTF-8, or -1: `minimal` or U+FFFD{1,9} U+0000. */
function renderedVarint(text: string, at: number, minimal: string): number {
  if (text[at] === minimal) return at + 1;
  let cursor = at;
  while (cursor < text.length && cursor - at < MAX_VARINT - 1 && text[cursor] === '�') cursor++;
  return cursor > at && text[cursor] === '\u0000' ? cursor + 1 : -1;
}

/** Fewest and most UTF-8 bytes the code unit at `at` can stand for in a rendering. */
function renderedBytes(text: string, at: number): [number, number] {
  const unit = text.charCodeAt(at);
  if (unit < 0x80) return [1, 1];
  if (unit < 0x800) return [2, 2];
  if (unit === 0xfffd) return [1, 3];
  if (unit >= 0xdc00 && unit <= 0xdfff) return [0, 0];
  return unit >= 0xd800 && unit <= 0xdbff ? [4, 4] : [3, 3];
}

function utf8RenderingSpans(text: string, starts: number[], ends: number[], found: [number, number][]): void {
  let first = -1;
  for (let at = text.indexOf('\u0002'); at >= 0 && at + 1 < text.length; at = text.indexOf('\u0002', at + 1)) {
    if (text[at + 1] === '\u0001' || renderedVarint(text, at + 1, '\u0002') !== -1) { first = at; break; }
  }
  if (first < 0) return;
  // The last signature header after the start whose 32 bytes can still follow it.
  for (let at = text.length - 1; at > first; at--) {
    if (text[at] !== '\u0000') continue;
    const kind = renderedVarint(text, at + 1, '\u0006');
    const body = kind < 0 ? -1 : renderedVarint(text, kind, ' ');
    if (body < 0) continue;
    let fewest = 0, most = 0, end = body;
    while (end < text.length && fewest < SIGNATURE_BYTES) {
      const [low, high] = renderedBytes(text, end++);
      fewest += low; most += high;
    }
    if (most < SIGNATURE_BYTES) continue;
    // Keep a surrogate pair whole.
    if (end < text.length && renderedBytes(text, end)[1] === 0) end++;
    found.push([starts[first], ends[end - 1]]);
    return;
  }
}

function spans(text: string, source?: NormalizedText, backslashPairs = true, decode = true): [number, number][] {
  const { value, starts, ends } = normalized(text, true, source, decode, backslashPairs);
  const found: [number, number][] = [];
  const raw = normalized(text, false, source, decode, backslashPairs);
  // Decode each decimal byte array once, then redact only confirmed macaroon
  // spans. Ordinary arrays and any surrounding values retain their source text.
  const decimalArrays = /(?:0x[0-9a-f]{2}(?:[^0-9A-Za-z\\]{1,3}0x[0-9a-f]{2})+|\d{1,3}(?:[^0-9A-Za-z\\]{1,3}\d{1,3})+)/gi;
  for (let run = decimalArrays.exec(raw.value); run; run = decimalArrays.exec(raw.value)) {
    const tokens = [...run[0].matchAll(/0x[0-9a-f]{2}|\d+/gi)];
    const values = tokens.map(token => Number(token[0]));
    for (let segmentStart = 0; segmentStart < values.length;) {
      let segmentEnd = segmentStart;
      while (segmentEnd < values.length && values[segmentEnd] <= 255) segmentEnd++;
      if (segmentEnd > segmentStart) {
        const bytes = Buffer.from(values.slice(segmentStart, segmentEnd));
        const lengthAt = macaroonEnds(bytes);
        for (let pos = 0; pos < bytes.length; pos++) {
          if (bytes[pos] !== 2) continue;
          const length = lengthAt(pos);
          if (length === null) continue;
          const begin = run.index + tokens[segmentStart + pos].index;
          const last = tokens[segmentStart + pos + length - 1];
          const end = run.index + last.index + last[0].length;
          found.push([raw.starts[begin], raw.ends[end - 1]]);
          pos += length - 1;
        }
      }
      segmentStart = segmentEnd + 1;
    }
  }
  hexSpans(value, starts, ends, found);
  if (raw.value.includes(String.fromCharCode(2))) {
    // Raw latin1 and recovered escaped bytes use the same structured decoder.
    // Preserve offsets through JSON escapes and UTF-16 zero-byte padding.
    const binary = Buffer.allocUnsafe(raw.value.length);
    for (let i = 0; i < raw.value.length; i++) binary[i] = raw.value.charCodeAt(i) <= 255 ? raw.value.charCodeAt(i) : 255;
    const binaryLength = macaroonEnds(binary);
    for (let pos = 0; pos < binary.length; pos++) {
      if (binary[pos] !== 2) continue;
      const length = binaryLength(pos);
      if (length === null) continue;
      found.push([raw.starts[pos], raw.ends[pos + length - 1]]);
      pos += length - 1;
    }
    // A UTF-8 rendering differs from the latin1 one only when a character is not ASCII.
    if (NON_ASCII.test(raw.value)) utf8RenderingSpans(raw.value, raw.starts, raw.ends, found);
    // UTF-16 byte strings can carry raw credentials with zero-byte padding.
    for (const phase of [0, 1]) for (const order of [0, 1]) {
      const bytes = Buffer.allocUnsafe(Math.floor((raw.value.length - phase) / 2));
      for (let i = 0; i < bytes.length; i++) {
        const at = phase + i * 2;
        bytes[i] = raw.value.charCodeAt(at + 1 - order) === 0 && raw.value.charCodeAt(at + order) <= 255
          ? raw.value.charCodeAt(at + order) : 255;
      }
      const lengthAt = macaroonEnds(bytes);
      for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] !== 2) continue;
        const length = lengthAt(i);
        if (length === null) continue;
        found.push([raw.starts[phase + i * 2], raw.ends[phase + (i + length) * 2 - 1]]);
        i += length - 1;
      }
    }
  }
  const base64Sources = [{ text: value, starts, ends, grouped: false, delimiter: '' },
    { text: raw.value, starts: raw.starts, ends: raw.ends, grouped: true, delimiter: '-' },
    { text: raw.value, starts: raw.starts, ends: raw.ends, grouped: true, delimiter: '_' },
    { text: raw.value, starts: raw.starts, ends: raw.ends, grouped: true, delimiter: 'other' }];
  const contiguousBase64Starts = new Set<number>();
  for (const source of base64Sources) {
  // Grouped shapes use a linear scan: the equivalent X+(?:SX+)+ regular expressions
  // backtrack quadratically over long unseparated runs (see src/grouped-runs.ts).
  const base64Runs = !source.grouped
    ? [...source.text.matchAll(/[A-Za-z0-9+/_-]{12,}={0,2}/g)].map(match => ({ index: match.index, value: match[0] }))
    : source.delimiter === 'other' ? groupedBase64.other(source.text)
    : source.delimiter === '_' ? groupedBase64.underscore(source.text) : groupedBase64.dash(source.text);
  for (const matched of base64Runs) {
    const run = source.delimiter === 'other' ? regularRun(matched) : matched;
    if (!run) continue;
    const positions = [...run.value].flatMap((char, index) => source.grouped && (source.delimiter === 'other'
      ? !/[A-Za-z0-9+/_=-]/.test(char) : char === source.delimiter) ? [] : [run.index + index]);
    const data = positions.map(index => source.text[index]).join('');
    // A credential can begin after one or two bytes in the same encoded
    // stream; neither start has the standalone "Ag" characters. Decode each
    // possible character alignment once, then inspect its bytes in order.
    for (let phase = 0; phase < 4 && phase < data.length; phase++) {
      const bytes = Buffer.from(data.slice(phase), 'base64url');
      const lengthAt = macaroonEnds(bytes);
      for (let byteOffset = 0; byteOffset < bytes.length; byteOffset++) {
        if (bytes[byteOffset] !== 2) continue;
        const length = lengthAt(byteOffset);
        if (length === null) continue;
        // Include the whole starting group when its characters share prefix
        // bits. At the end, consume only characters needed for the last byte
        // and any padding, leaving adjacent ordinary text intact.
        const begin = phase + 4 * Math.floor(byteOffset / 3);
        const lastByte = byteOffset + length;
        const completeGroups = Math.floor(lastByte / 3);
        const trailingBytes = lastByte % 3;
        let end = Math.min(data.length, phase + 4 * completeGroups +
          (trailingBytes === 0 ? 0 : trailingBytes + 1));
        while (end < data.length && data[end] === '=') end++;
        const start = source.starts[positions[begin]];
        // A dash is also a base64url digit. Preserve a confirmed contiguous
        // credential's interval rather than reinterpret its signature with
        // dashes removed and consume neighboring ordinary characters.
        if (!source.grouped || !contiguousBase64Starts.has(start)) {
          found.push([start, source.ends[positions[end - 1]]]);
        }
        if (!source.grouped) contiguousBase64Starts.add(start);
        byteOffset += length - 1;
      }
    }
  }
  }
  const base32Runs = /[A-Z2-7]{16,}={0,6}/gi;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  for (let run = base32Runs.exec(raw.value); run; run = base32Runs.exec(raw.value)) {
    for (let phase = 0; phase < 8; phase++) {
      const digits = run[0].slice(phase).replace(/=+$/, '').toUpperCase();
      const decoded: number[] = [];
      let accumulator = 0, bits = 0;
      for (const char of digits) {
        accumulator = (accumulator << 5) | alphabet.indexOf(char); bits += 5;
        if (bits >= 8) { bits -= 8; decoded.push((accumulator >>> bits) & 255); }
      }
      const bytes = Buffer.from(decoded), lengthAt = macaroonEnds(bytes);
      for (let pos = 0; pos < bytes.length; pos++) {
        if (bytes[pos] !== 2) continue;
        const length = lengthAt(pos);
        if (length === null) continue;
        const begin = run.index + phase + 8 * Math.floor(pos / 5);
        let end = run.index + phase + Math.ceil((pos + length) * 8 / 5);
        while (raw.value[end] === '=') end++;
        found.push([raw.starts[begin], raw.ends[end - 1]]);
        pos += length - 1;
      }
    }
  }
  return found.sort((a, b) => a[0] - b[0]);
}

export function redactEncodedCredentials(text: string): string {
  const matches: [number, number][] = literalSpans(text);
  // A stray backslash before an escaped credential (a backslash, then \x02\x01...) pairs with
  // the first escape's backslash and hides its byte: text holding two adjacent backslashes is
  // read once more with every backslash starting an escape on its own.
  if (text.includes('\\\\')) matches.push(...spans(text, undefined, false));
  let source: NormalizedText | undefined;
  // A fixed number of escape layers keeps work bounded. Compose source offsets
  // on every pass and inspect each representation before further normalization.
  for (let layer = 0; layer < 4; layer++) {
    const value = source?.value ?? text;
    matches.push(...spans(value, source));
    const next = normalized(value, false, source);
    if (next.value === value) break;
    source = next;
  }
  matches.sort((a, b) => a[0] - b[0]);
  let output = '';
  let cursor = 0;
  for (let index = 0; index < matches.length;) {
    const start = matches[index][0];
    let end = matches[index++][1];
    while (index < matches.length && matches[index][0] <= end) {
      end = Math.max(end, matches[index++][1]);
    }
    output += `${text.slice(cursor, start)}[redacted]`;
    cursor = end;
  }
  return output + text.slice(cursor);
}
