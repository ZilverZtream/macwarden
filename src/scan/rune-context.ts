// Rune candidates in explicit rune context (1.2.0). A Core Lightning rune is URL-safe base64 with
// no fixed prefix, and as few as 32 decoded bytes are a structurally valid rune, so arbitrary
// base64 is never taken for one. Two contexts are recognised.
//
// Key context (strong): a value assigned to a rune key.
//
//   rune=…  RUNE=…  CLN_RUNE=…  cln-rune: …  "rune": "…"  'rune': '…'  clnRune = "…"  --rune=…
//   Rune: …  (clnrest's HTTP header, any case, as in curl -H 'Rune: …')
//
// The key is "rune" (any case) on its own or after a separator ('_', '-', '.') or a lower-case
// letter or digit (camelCase); "prune", "runes" and "rune_id" are not rune keys. One optional
// quote may close the key; then optional blanks, '=' or ':' (not '==' or '=>'), optional
// blanks and one optional opening quote. The value is the following run of base64 characters
// (both alphabets and '=', so a standard-alphabet value is examined and refused rather than cut).
//
// Command context (weaker): a whole argument, after a command that takes a rune positionally,
// on the same line: `commando` (lightning-cli commando <peer> <method> <params> <rune>, the
// commando plugin's RPC), `checkrune`, `showrunes`, `createrune` and `invokerune`, and any
// argument after `lightning-cli`. An argument is a run of base64 characters with a blank, a
// quote or the line start or end on both sides. Peer IDs, hashes and other arguments share the
// alphabet, so the scan reports a command-context value only when it is a rune Core Lightning
// would check: it parses and carries a numeric unique ID (src/scan/runes.ts).
//
// Every step moves forward and a key inside an earlier value is skipped, so the work is linear.
import { RUNE_SHORTEST_TEXT, RUNE_TEXT_LIMIT, decodeRuneText } from '../decode/rune.js';

export type RuneCandidate = {
  /** UTF-16 offsets of the value run in the text. */
  start: number;
  end: number;
  /** The value, or its first RUNE_TEXT_LIMIT + 1 characters when it is longer. */
  text: string;
  /** The quote that opened the value, if any. */
  quote: string | null;
  /** key: assigned to a rune key; command: a positional argument of a rune-taking command. */
  context: 'key' | 'command';
};

const KEY = /rune/gi;
// Commands that take a rune as a positional argument, and lightning-cli itself.
const COMMAND = /(?:^|[^A-Za-z0-9_-])(?:commando|checkrune|showrunes|createrune|invokerune|lightning-cli)(?![A-Za-z0-9_-])/i;
const QUOTES = '"\'`';
const BLANK = ' \t';

function isAlnum(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isRunCharacter(code: number): boolean {
  return isAlnum(code) || code === 45 || code === 95 || code === 43 || code === 47 || code === 61;
}

function keyCandidates(text: string): RuneCandidate[] {
  const found: RuneCandidate[] = [];
  KEY.lastIndex = 0;
  for (let match = KEY.exec(text); match; match = KEY.exec(text)) {
    const at = match.index;
    if (at > 0) {
      const before = text.charCodeAt(at - 1);
      // camelCase: a lower-case letter or digit followed by a capital R (clnRune, cln2Rune).
      const camel = text[at] === 'R' && ((before >= 97 && before <= 122) || (before >= 48 && before <= 57));
      if (isAlnum(before) && !camel) continue;
    }
    let p = at + 4;
    if (p < text.length && QUOTES.includes(text[p])) p++;
    while (p < text.length && BLANK.includes(text[p])) p++;
    if (text[p] !== '=' && text[p] !== ':') continue;
    if (text[p] === '=' && (text[p + 1] === '=' || text[p + 1] === '>')) continue;
    p++;
    while (p < text.length && BLANK.includes(text[p])) p++;
    const quote = p < text.length && QUOTES.includes(text[p]) ? text[p] : null;
    if (quote) p++;
    const start = p;
    while (p < text.length && isRunCharacter(text.charCodeAt(p))) p++;
    // A key inside this value is part of the value.
    KEY.lastIndex = Math.max(KEY.lastIndex, p);
    if (p - start < RUNE_SHORTEST_TEXT) continue;
    found.push({ start, end: p, text: text.slice(start, Math.min(p, start + RUNE_TEXT_LIMIT + 1)), quote, context: 'key' });
  }
  return found;
}

function commandCandidates(line: string, taken: RuneCandidate[]): RuneCandidate[] {
  const command = COMMAND.exec(line);
  if (!command) return [];
  const found: RuneCandidate[] = [];
  let next = 0;
  for (let p = command.index + command[0].length; p < line.length;) {
    if (!isRunCharacter(line.charCodeAt(p))) { p++; continue; }
    const start = p;
    while (p < line.length && isRunCharacter(line.charCodeAt(p))) p++;
    const before = start === 0 ? ' ' : line[start - 1];
    const after = p === line.length ? ' ' : line[p];
    const bounded = (BLANK.includes(before) || QUOTES.includes(before)) && (BLANK.includes(after) || QUOTES.includes(after));
    while (next < taken.length && taken[next].end <= start) next++;
    const overlaps = next < taken.length && taken[next].start < p;
    if (!bounded || overlaps || p - start < RUNE_SHORTEST_TEXT || p - start > RUNE_TEXT_LIMIT) continue;
    found.push({ start, end: p, text: line.slice(start, p), quote: QUOTES.includes(before) ? before : null, context: 'command' });
  }
  return found;
}

/** Whether a command-context value is a rune Core Lightning would check: it parses and has a numeric unique ID. */
export function checkableRune(text: string): boolean {
  const decoded = decodeRuneText(text);
  return decoded.ok && decoded.facts.uniqueId !== null && /^[0-9]{1,18}$/.test(decoded.facts.uniqueId);
}

/** Candidates in key context and in command context on one line (or text), in text order. */
export function runeCandidates(text: string): RuneCandidate[] {
  const keyed = keyCandidates(text);
  const commands = commandCandidates(text, keyed);
  return commands.length ? [...keyed, ...commands].sort((a, b) => a.start - b.start) : keyed;
}

/**
 * The text with every rune-context value replaced by [redacted] (output redaction): every
 * key-context value, and every command-context value that is a checkable rune.
 */
export function redactRuneContexts(text: string): string {
  if (text.length < RUNE_SHORTEST_TEXT || !/rune|commando|lightning-cli/i.test(text)) return text;
  const candidates = text.split(/(\r\n|\n|\r)/).reduce<{ offset: number; found: RuneCandidate[] }>((state, part) => {
    for (const candidate of runeCandidates(part))
      if (candidate.context === 'key' || checkableRune(candidate.text))
        state.found.push({ ...candidate, start: candidate.start + state.offset, end: candidate.end + state.offset });
    state.offset += part.length;
    return state;
  }, { offset: 0, found: [] }).found;
  if (!candidates.length) return text;
  let output = '';
  let cursor = 0;
  for (const candidate of candidates) {
    output += `${text.slice(cursor, candidate.start)}[redacted]`;
    cursor = candidate.end;
  }
  return output + text.slice(cursor);
}
