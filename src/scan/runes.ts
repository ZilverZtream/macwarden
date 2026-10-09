// Core Lightning runes in scanned text (1.2.0): contextual, never context-free. A value assigned
// to a rune key (src/scan/rune-context.ts) must parse completely as Core Lightning parses runes.
// In that strong context a value that does not parse, or exceeds the parser's bounds, is
// still reported (kind rune-invalid, grade UNASSESSED) instead of disappearing. A positional
// argument of a rune-taking command is reported only when it is a checkable rune.
import { createHash } from 'node:crypto';
import { decodeRuneText, RUNE_ALPHABET, RUNE_TEXT_LIMIT, type RuneFacts } from '../decode/rune.js';
import { unixSeconds } from '../grade/rune.js';
import { runeReport, type RuneInvalidReport, type RuneReport } from '../rune-report.js';
import { checkableRune, runeCandidates, type RuneCandidate } from './rune-context.js';
import type { ScanFinding } from './index.js';

type Shared = Pick<ScanFinding, 'fingerprint' | 'grade' | 'unassessed'> & { rune: RuneReport | RuneInvalidReport };
// Per scan: one shared result per distinct value (and truncation state), like decoded macaroons.
const caches = new WeakMap<object, Map<string, Shared>>();
const NONE = Object.freeze([]) as unknown as string[];
// Every key context contains "rune"; every command context names commando or lightning-cli, or a
// command whose name contains "rune".
const RUNE_LINE = /rune|commando|lightning-cli/i;
// Characters that end a value without suggesting it continues: blanks, quotes and common
// punctuation after a value in configuration, code and prose.
const TERMINATORS = new Set([...' \t"\'`,;)]}>&#|'.split('')]);

function textFingerprint(text: string): string {
  return `fp:${createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 16)}`;
}

/**
 * Whether the value read may be the start of a longer one: a quoted value not closed by its
 * quote, an unquoted value followed by a character that does not end values, or one that ends
 * its line while the next line holds only base64 characters (a wrapped or folded value).
 */
function possiblyTruncated(line: string, candidate: RuneCandidate, next: string | undefined): boolean {
  const after = line[candidate.end];
  if (candidate.quote !== null) return after !== candidate.quote;
  if (after === undefined) return next !== undefined && /^[A-Za-z0-9+/_=-]+$/.test(next.trim());
  // A percent-encoded '=' is padding, which Core Lightning ignores anyway.
  if (after === '%' && /^%3d/i.test(line.slice(candidate.end, candidate.end + 3))) return false;
  return !TERMINATORS.has(after);
}

/** The rune whose text a standard base64 value encodes, when it encodes exactly one rune. */
function base64Rune(text: string): RuneFacts | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  const bytes = Buffer.from(text, 'base64');
  if (bytes.toString('base64') !== text) return null;
  const inner = bytes.toString('latin1').trim();
  if (!RUNE_ALPHABET.test(inner)) return null;
  const decoded = decodeRuneText(inner);
  return decoded.ok ? decoded.facts : null;
}

function shared(candidate: RuneCandidate, truncated: boolean, now: Date, cache: Map<string, Shared>): Shared {
  const key = `${truncated ? 1 : 0}${candidate.text}`;
  const known = cache.get(key);
  if (known) return known;
  let result: Shared;
  const invalid = (reason: RuneInvalidReport['reason']): Shared => ({ fingerprint: textFingerprint(candidate.text), grade: 'UNASSESSED',
    unassessed: NONE, rune: { recognition: 'invalid', reason, verification: 'unchecked' } });
  if (candidate.text.length > RUNE_TEXT_LIMIT) result = invalid('exceeds-bounds');
  else {
    // A Kubernetes Secret or Helm value holds the base64 of the rune text: decoded once, one level
    // deep. A value whose base64 decoding is itself rune text is that rune; rune text read
    // directly would also parse there, but only as a policy built from encoded characters.
    const decoded = decodeRuneText(candidate.text);
    const inner = candidate.context === 'key' ? base64Rune(candidate.text) : null;
    if (inner) {
      const assessed = runeReport(inner, unixSeconds(now), truncated);
      result = { fingerprint: inner.fingerprint, grade: assessed.grade,
        unassessed: assessed.unassessed.length ? assessed.unassessed : NONE, rune: assessed.report };
    } else if (!decoded.ok) result = invalid(decoded.reason);
    else {
      const assessed = runeReport(decoded.facts, unixSeconds(now), truncated);
      result = { fingerprint: decoded.facts.fingerprint, grade: assessed.grade,
        unassessed: assessed.unassessed.length ? assessed.unassessed : NONE, rune: assessed.report };
    }
  }
  cache.set(key, result);
  return result;
}

/** The rune findings of a scanned text; `context` identifies the scan (shared facts). */
export function runeFindings(text: string, now: Date, context: object): ScanFinding[] {
  if (!RUNE_LINE.test(text)) return [];
  let cache = caches.get(context);
  if (!cache) caches.set(context, cache = new Map());
  const findings: ScanFinding[] = [];
  const lines = text.split(/\r\n|\n|\r/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (!RUNE_LINE.test(line)) continue;
    // Columns count code points; advance one counter through the line.
    let unit = 0;
    let point = 0;
    for (const candidate of runeCandidates(line)) {
      // A positional argument is reported only when it is a rune Core Lightning would check.
      if (candidate.context === 'command' && !checkableRune(candidate.text)) continue;
      while (unit < candidate.start) { unit += line.codePointAt(unit)! > 0xffff ? 2 : 1; point++; }
      const truncated = possiblyTruncated(line, candidate, lines[index + 1]);
      const facts = shared(candidate, truncated, now, cache);
      findings.push({ path: '', line: index + 1, column: point + 1, kind: facts.rune.recognition === 'invalid' ? 'rune-invalid' : 'rune',
        fingerprint: facts.fingerprint, grade: facts.grade, rootKeyId: null, permissions: null, caveats: null,
        warnings: NONE, unassessed: facts.unassessed, rune: facts.rune });
    }
  }
  return findings;
}
