/**
 * What an explanation may print, and how.
 *
 * - A payment hash appears only as a fingerprint: its first 8 and last 4 hex characters.
 * - A preimage and a payment request are never read from the records, and `scrub` replaces anything
 *   that looks like one in a string that came from elsewhere (an LND error message, an event's
 *   detail): a 64-hex run that is a payment hash of the subject becomes its fingerprint, any other
 *   becomes `[redacted]`, and a BOLT 11 string becomes `[payment request]`.
 * - Text output escapes what a terminal or a CI runner would act on, as macwarden's text output does
 *   (docs/spec.md, Output): control characters (C0, DEL, C1) as `\xNN`; Unicode whitespace other than
 *   the space, the bidirectional controls and invisible characters as `\uNNNN` (`\u{N}` beyond
 *   U+FFFF); the legacy CI marker `##[` as `##\x5b`; and no line starts, after spaces, with `::`.
 */

export function fingerprint(paymentHash: string): string {
  return /^[0-9a-f]{64}$/i.test(paymentHash) ? `${paymentHash.slice(0, 8).toLowerCase()}…${paymentHash.slice(-4).toLowerCase()}` : '[not a hash]';
}

const HEX64 = /(?<![0-9a-f])(?<!sha256-)[0-9a-f]{64}(?![0-9a-f])/gi;
const BOLT11 = /\bln(?:bcrt|bc|tbs|tb|sb)[0-9a-z]*1[0-9a-z]{20,}/gi;

/** A string with every payment hash fingerprinted and anything else secret-shaped removed (see the header). */
export function scrub(value: string, known: ReadonlySet<string>): string {
  return value.replace(BOLT11, '[payment request]')
    .replace(HEX64, hex => known.has(hex.toLowerCase()) ? fingerprint(hex) : '[redacted]');
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
