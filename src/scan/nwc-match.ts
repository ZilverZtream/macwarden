// Linear-time equivalent of the published `nwc` detector regex (src/scan/patterns.ts),
// used for scanning. The regex's lazy middle `[^\s"'<>]*?` makes a backtracking engine
// rescan the rest of a segment from every candidate start, which is quadratic when an
// attacker repeats the prefix without a secret. This matcher returns exactly the matches
// `text.matchAll(/nwc/gi)` would, in one pass:
//   prefix  (nostr+walletconnect|nostrwalletconnect):(//)?<64 hex>/??
//   middle  shortest run of characters other than whitespace, " ' < >
//   secret  secret=<64 hex> followed by a non-hex character (consumed) or the end.
const PREFIX = /(?:nostr\+walletconnect|nostrwalletconnect):(?:\/\/)?[0-9a-f]{64}\/?\?/gi;
const BOUNDARY = /[\s"'<>]/;
const HEX = /[0-9a-f]/i;
const SECRET = 'secret=';

export type NwcMatch = { index: number; text: string };

/**
 * `open`, when given and empty, receives the index of the first prefix (outside an earlier
 * match) whose middle runs to the end of `text` without a boundary or a valid secret: in a
 * window cut from a longer line, such a URI may continue past the window end.
 */
export function nwcMatches(text: string, open?: number[]): NwcMatch[] {
  const length = text.length;
  // nextValid[i]: smallest p >= i where "secret=" + 64 hex + (non-hex | end) starts.
  // nextBoundary[i]: smallest p >= i holding a boundary character. Both scanned right to left.
  const nextValid = new Int32Array(length + 1).fill(-1);
  const nextBoundary = new Int32Array(length + 1).fill(-1);
  // hexRun[i]: number of consecutive hex characters starting at i.
  const hexRun = new Int32Array(length + 1);
  for (let i = length - 1; i >= 0; i--) {
    hexRun[i] = HEX.test(text[i]) ? hexRun[i + 1] + 1 : 0;
    nextBoundary[i] = BOUNDARY.test(text[i]) ? i : nextBoundary[i + 1];
    let valid = false;
    if ((text[i] === 's' || text[i] === 'S') && i + SECRET.length + 64 <= length
      && text.slice(i, i + SECRET.length).toLowerCase() === SECRET
      && hexRun[i + SECRET.length] >= 64) {
      const after = i + SECRET.length + 64;
      valid = after === length || !HEX.test(text[after]);
    }
    nextValid[i] = valid ? i : nextValid[i + 1];
  }
  const matches: NwcMatch[] = [];
  let resume = 0;
  PREFIX.lastIndex = 0;
  for (let head = PREFIX.exec(text); head; head = PREFIX.exec(text)) {
    if (head.index < resume) continue;
    const middle = head.index + head[0].length;
    const secretAt = nextValid[middle];
    const boundaryAt = nextBoundary[middle];
    // Every later prefix lies in the same open run, so only the first is reported.
    if (secretAt === -1 && boundaryAt === -1 && open?.length === 0) open.push(head.index);
    if (secretAt === -1 || (boundaryAt !== -1 && boundaryAt < secretAt)) continue;
    const afterHex = secretAt + SECRET.length + 64;
    const end = afterHex < length ? afterHex + 1 : afterHex;
    matches.push({ index: head.index, text: text.slice(head.index, end) });
    resume = end;
    PREFIX.lastIndex = end;
  }
  return matches;
}

/**
 * Replaces every match of the published `nwc` regex exactly as `text.replace(/nwc/gi, replacer)`
 * would, in linear time. Used by output redaction and scan's secret collection.
 */
export function replaceNwc(text: string, replacer: (match: string) => string): string {
  if (!/walletconnect:/i.test(text)) return text;
  let output = '';
  let cursor = 0;
  for (const match of nwcMatches(text)) {
    output += text.slice(cursor, match.index) + replacer(match.text);
    cursor = match.index + match.text.length;
  }
  return cursor === 0 ? text : output + text.slice(cursor);
}

const NWC_ESCAPE_HINT = /\\\/|%[0-9a-f]{2}|nostr walletconnect/i;

/**
 * One normalised copy of a line, for NWC URIs written in common escaped forms: JSON-escaped
 * slashes ("\/" becomes "/"), one level of percent-encoding (ASCII bytes only) and a "+"
 * decoded to a space in the scheme ("nostr walletconnect"). `origin[i]` is the index in the
 * original code points of normalised code point i. Null when the line has none of these.
 * (An "&amp;" before secret= needs no unescaping: the matcher accepts it as it is.)
 */
export function nwcUnescaped(points: readonly string[], line: string): { points: string[]; origin: number[] } | null {
  if (!/walletconnect/i.test(line) || !NWC_ESCAPE_HINT.test(line)) return null;
  const out: string[] = [];
  const origin: number[] = [];
  for (let i = 0; i < points.length;) {
    if (points[i] === '\\' && points[i + 1] === '/') { out.push('/'); origin.push(i); i += 2; continue; }
    if (points[i] === '%' && /^[0-7][0-9a-f]$/i.test(`${points[i + 1] ?? ''}${points[i + 2] ?? ''}`)) {
      out.push(String.fromCharCode(parseInt(points[i + 1] + points[i + 2], 16))); origin.push(i); i += 3; continue;
    }
    out.push(points[i]); origin.push(i); i++;
  }
  for (let i = 5; i + 13 < out.length; i++) {
    if (out[i] === ' ' && out.slice(i - 5, i).join('').toLowerCase() === 'nostr'
      && out.slice(i + 1, i + 14).join('').toLowerCase() === 'walletconnect') out[i] = '+';
  }
  return { points: out, origin };
}
