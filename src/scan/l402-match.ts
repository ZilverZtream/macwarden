// L402 "<base64 macaroon>:<hex preimage>" pairs without a scheme (scan only; not in the rule
// packs). The equivalent regular expression,
//   (?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}:[0-9a-f]{64}(?![0-9A-Za-z_])   (case-insensitive hex)
// (a "=" before the run is allowed: KEY=<pair> in .env files and shell assignments)
// would retry every start of a long base64 run, which is quadratic. This matcher finds each ":"
// followed by exactly 64 hex digits and a boundary, then walks left over the base64 run once:
// colons are not base64 characters, so the runs walked for different colons never overlap and
// the work is linear in the text.

const MIN_RUN = 40;
const PREIMAGE_DIGITS = 64;

function isHex(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
}

function isWord(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95;
}

function isBase64(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
    || code === 43 || code === 47 || code === 95 || code === 45;
}

export type PairMatch = { index: number; text: string };

/**
 * Every pair in `text`. `previous`: the character before the window when the line starts
 * earlier; a run that reaches the window start and continues before it belongs to an earlier
 * window. `next`: the character after the window when the line continues past it.
 */
export function l402PairMatches(text: string, opts: { previous?: string | null; next?: string | null } = {}): PairMatch[] {
  const matches: PairMatch[] = [];
  for (let colon = text.indexOf(':'); colon >= 0; colon = text.indexOf(':', colon + 1)) {
    const end = colon + 1 + PREIMAGE_DIGITS;
    if (end > text.length) break;
    let digits = 0;
    while (digits < PREIMAGE_DIGITS && isHex(text.charCodeAt(colon + 1 + digits))) digits++;
    if (digits < PREIMAGE_DIGITS) continue;
    const after = end < text.length ? text.charCodeAt(end) : opts.next ? opts.next.charCodeAt(0) : NaN;
    if (!Number.isNaN(after) && isWord(after)) continue;
    let start = colon;
    let padding = 0;
    while (padding < 2 && start > 0 && text.charCodeAt(start - 1) === 61) { start--; padding++; }
    const runEnd = start;
    while (start > 0 && isBase64(text.charCodeAt(start - 1))) start--;
    if (runEnd - start < MIN_RUN) continue;
    if (start === 0 && opts.previous && isBase64(opts.previous.charCodeAt(0))) continue;
    matches.push({ index: start, text: text.slice(start, end) });
  }
  return matches;
}
