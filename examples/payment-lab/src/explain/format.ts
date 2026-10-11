/**
 * What an explanation may print, and how.
 *
 * - A payment hash appears only as a fingerprint: its first 8 and last 4 hex characters.
 * - A preimage and a payment request are never read from the records, and `scrub` replaces anything
 *   that looks like one in a string that came from elsewhere (an LND error message, an event's
 *   detail). Invisible characters (the format characters and the others listed below) are skipped
 *   while matching, so none can split a secret in two; a match takes those inside it along. A BOLT 11
 *   string (`lnbc`, `lntb`, `lnbcrt` or `lnsb` and at least 20 more letters or digits, any case,
 *   anywhere in a word) becomes `[payment request]`. A run of exactly 64 hex characters that is a
 *   payment hash of the subject or the subject's own ID, or follows `=sha256-` (an outbox effect's
 *   hashed file name), becomes its fingerprint, any other `[redacted]`; a longer run, which may hold
 *   a secret at any offset, becomes `[redacted hex N chars]` whole. A standalone run of 43 or 44 base64 characters (the
 *   standard alphabet, with its `=` padding), which is how LND's REST API writes 32 bytes such as a preimage, becomes
 *   `[redacted base64]` unless it is the subject's own ID; a run of only hex digits is left to the hex rule.
 * - `capString` cuts any one string to 1,024 characters and says how many more there were.
 * - Text output escapes what a terminal or a CI runner would act on, as macwarden's text output does
 *   (docs/spec.md, Output): control characters (C0, DEL, C1) as `\xNN`; Unicode whitespace other than
 *   the space, the bidirectional controls and invisible characters as `\uNNNN` (`\u{N}` beyond
 *   U+FFFF); the legacy CI marker `##[` as `##\x5b`; and no line starts, after spaces, with `::`.
 */

export function fingerprint(paymentHash: string): string {
  return /^[0-9a-f]{64}$/i.test(paymentHash) ? `${paymentHash.slice(0, 8).toLowerCase()}…${paymentHash.slice(-4).toLowerCase()}` : '[not a hash]';
}

// eslint-disable-next-line no-misleading-character-class
const INVISIBLE = /[\p{Cf}\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u3164\ufe00-\ufe0f\uffa0\u{e0000}-\u{e0fff}]/u;
/** A BOLT 11 string (group 1); a hex run of 64 or more; a standalone base64 run of 43 or 44 characters (group 2), 32 bytes. */
const SECRET_SHAPED = /(ln(?:bcrt|bc|tb|sb)[0-9a-z]{20,})|[0-9a-f]{64,}|(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{43,44}={0,2})(?![A-Za-z0-9+/=])/gi;
const HASHED_NAME = '=sha256-';
/**
 * Whether `value` has a run of 24 or more of [A-Za-z0-9+/]: every SECRET_SHAPED match is one
 * (BOLT 11: 4 + 20; hex: 64; base64: 43). One pass, no backtracking.
 */
function hasSecretRun(value: string): boolean {
  let run = 0;
  for (let at = 0; at < value.length; at += 1) {
    const code = value.charCodeAt(at);
    if ((code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 43 || code === 47) {
      if (++run >= 24) return true;
    } else run = 0;
  }
  return false;
}

/** A string with every payment hash fingerprinted and anything else secret-shaped removed (see the header). */
export function scrub(value: string, known: ReadonlySet<string>): string {
  const replace = (text: string, invoice: string | undefined, base64: string | undefined, start: number, visible: string): string => (
    invoice !== undefined ? '[payment request]'
      : base64 !== undefined ? (known.has(text.toLowerCase()) || /^[0-9a-f]+$/i.test(text) ? text : '[redacted base64]')
    : text.length > 64 ? `[redacted hex ${text.length} chars]`
      : known.has(text.toLowerCase()) || visible.slice(Math.max(0, start - HASHED_NAME.length), start) === HASHED_NAME ? fingerprint(text)
        : '[redacted]');
  if (!INVISIBLE.test(value)) {
    // No run long enough for any secret shape: nothing to replace (most timeline details).
    if (!hasSecretRun(value)) return value;
    return value.replace(SECRET_SHAPED, (text: string, invoice: string | undefined, base64: string | undefined, start: number) =>
      replace(text, invoice, base64, start, value));
  }
  // The string without its invisible characters, and the offset in `value` of each of its UTF-16 units.
  let visible = '';
  const origin: number[] = [];
  let offset = 0;
  for (const character of value) {
    if (!INVISIBLE.test(character)) {
      visible += character;
      for (let unit = 0; unit < character.length; unit += 1) origin.push(offset + unit);
    }
    offset += character.length;
  }
  let result = '';
  let copied = 0;
  for (const match of visible.matchAll(SECRET_SHAPED)) {
    const text = match[0];
    const start = match.index;
    // Matched characters are ASCII, one unit each; the invisible characters between them go with the match.
    result += value.slice(copied, origin[start]) + replace(text, match[1], match[2], start, visible);
    copied = (origin[start + text.length - 1] as number) + 1;
  }
  return result + value.slice(copied);
}

export const MAX_STRING = 1024;

/** At most MAX_STRING characters (UTF-16 units, a surrogate pair never split), then `…(N more)`. */
export function capString(value: string): string {
  if (value.length <= MAX_STRING) return value;
  const cut = /[\ud800-\udbff]/.test(value.charAt(MAX_STRING - 1)) ? MAX_STRING - 1 : MAX_STRING;
  return `${value.slice(0, cut)}…(${value.length - cut} more)`;
}

// eslint-disable-next-line no-control-regex, no-misleading-character-class
const UNSAFE_TEXT = /[\x00-\x1f\x7f-\xa0\u034f\u115f\u1160\u1680\u17b4\u17b5\u180b-\u180f\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\u3164\ufe00-\ufe0f\uffa0\u{e0000}-\u{e0fff}\p{Cf}]/gu;

/** One text line's content, escaped (see the header). */
export function safeText(value: string): string {
  return value.replace(UNSAFE_TEXT, character => {
    const code = character.codePointAt(0) ?? 0;
    return code < 0x100 ? `\\x${code.toString(16).padStart(2, '0')}`
      : code <= 0xffff ? `\\u${code.toString(16).padStart(4, '0')}` : `\\u{${code.toString(16)}}`;
  }).replace(/##\[/g, '##\\x5b').replace(/^( *)::/, '$1\\x3a:');
}

export const MAX_LINE = 120;

/**
 * Lines of at most MAX_LINE characters: `first` starts the first line, `indent` every continuation.
 * Breaks at spaces; a word longer than a line is cut. The text is escaped before it is measured.
 */
export function wrap(first: string, text: string, indent: string): string[] {
  const words = safeText(text).split(' ');
  const lines: string[] = [];
  let line = safeText(first);
  let empty = true;
  for (let word of words) {
    for (;;) {
      const candidate = empty ? `${line}${word}` : `${line} ${word}`;
      if (candidate.length <= MAX_LINE) { line = candidate; empty = false; break; }
      if (empty) {
        // A word that does not fit on an empty line is cut.
        const room = MAX_LINE - line.length;
        lines.push(`${line}${word.slice(0, room)}`);
        word = word.slice(room);
        line = indent;
        continue;
      }
      lines.push(line);
      line = indent;
      empty = true;
    }
  }
  lines.push(line);
  return lines.map(item => item.replace(/^( *)::/, '$1\\x3a:'));
}
