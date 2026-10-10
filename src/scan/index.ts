import { mcpServerStringSpans, withinSpans } from './mcp-context.js';
import { createHash } from 'node:crypto';
import { constants, type BigIntStats, type Stats } from 'node:fs';
import * as fs from 'node:fs/promises';
import { basename, dirname, join, parse, posix, relative, sep } from 'node:path';
import { decodeL402, decodeL402Macaroon, decodeL402Macaroons, decodeMacaroon, DecodeError, isL402Macaroon, L402_MAX_MACAROONS,
  l402RedactionSecret, parseTimeBefore,
  type Caveat, type L402Facts, type MacaroonFacts } from '../decode/index.js';
import { assessL402, type L402Report } from '../l402.js';
import { l402PairMatches } from './l402-match.js';
import { describe, gradeFacts, type Grade } from '../grade/index.js';
import { InputError } from '../input/index.js';
import { parseLndconnect } from '../input/lndconnect.js';
import { Secret } from '../secret.js';
import { isProtectedPath } from '../protected-path.js';
import { l402Challenge, l402Header, l402MacaroonBase64, l402MacaroonHex, lndconnect, macaroonBase64, macaroonHex, nwc } from './patterns.js';
import { collectNwcSecrets, knownSecretRedactor, redactDecoded, redactPath } from './redact.js';
import { nwcMatches, nwcUnescaped } from './nwc-match.js';
import { IgnoreFileError, parseIgnoreFile, type IgnoreEntry } from './ignore.js';
import { assertWorkTree, blobSizes, GitHistoryError, historyEntries, isShallowRepository, locateRepository, MODE_REGULAR, MODE_SYMLINK,
  readBlobs } from './git-history.js';
import { Cancelled, cancellable, checkCancellation } from '../cancellation.js';
import { readBounded } from '../bounded-file.js';
import { runeFindings } from './runes.js';
import type { RuneInvalidReport, RuneReport } from '../rune-report.js';

/** An unexpected exception while analysing a file's bytes: a bug, reported as exit 8 (internal). */
class ScanAnalysisFailure extends Error {
  constructor(cause: unknown) { super('internal error while analysing a scanned file', { cause }); }
}

export { IgnoreFileError } from './ignore.js';
export { GitHistoryError } from './git-history.js';

export type FindingKind = 'macaroon-file' | 'undecodable' | 'macaroon-hex' | 'macaroon-base64' | 'lndconnect' | 'nwc' | 'undecodable-candidate'
  | 'l402' | 'l402-file' | 'rune' | 'rune-invalid';
export type ScanFinding = {
  path: string;
  line: number | null;
  column: number | null;
  kind: FindingKind;
  fingerprint: string;
  grade: Grade | null;
  rootKeyId: string | null;
  permissions: string[] | null;
  caveats: Caveat[] | null;
  warnings: string[];
  unassessed: string[];
  /** Present only on a --git-history finding: the full hash of the oldest commit that added it. */
  commit?: string;
  /** Present only when the credential is a string value inside an MCP server entry of a JSON config. */
  context?: 'mcp-config';
  /** Present only on a Core Lightning rune finding (kind rune or rune-invalid): its sanitised facts. */
  rune?: RuneReport | RuneInvalidReport;
  /**
   * On a --git-history finding whose file content was also added at other paths, and on a
   * work-tree finding whose file has other hard-link names under the same path argument:
   * how many, and up to ALSO_AT_EXAMPLES of them. One finding stands for all of them.
   */
  alsoAt?: { count: number; paths: string[] };
  /** Present only on l402 and l402-file findings: the facts inspect reports (docs/spec.md, L402). */
  l402?: L402Report;
};
export type ScanResult = {
  findings: ScanFinding[];
  ignoredFingerprints?: string[];
  skipped: { path: string; reason: string }[];
  summary: {
    filesScanned: number;
    filesSkipped: number;
    dropped: number;
    ignored: number;
    findings: number;
    distinct: number;
    /** Present only with --git-history: distinct historical blobs read. */
    blobsScanned?: number;
    /** Present only with --git-history --allow-shallow on a shallow clone: history is incomplete. */
    shallowHistory?: true;
    /** Present only with --agent-configs: well-known agent and MCP client locations found and absent. */
    agentConfigs?: { found: { client: string; path: string }[]; absent: { client: string; path: string }[] };
    byGrade: Record<Grade | 'NWC' | 'UNDECODABLE' | 'L402', number>;
  };
  failOn: { threshold: 'ADMIN' | 'SPEND' | 'OPERATE' | 'RECEIVE' | 'READ'; count: number } | null;
};
export type ScanOptions = {
  fs?: Pick<typeof fs, 'realpath' | 'lstat' | 'stat' | 'open' | 'readdir'>;
  clock?: () => Date;
  includeDirs?: boolean;
  ignoreFile?: string;
  /** Also scan every blob added on any ref of the enclosing git work tree. */
  gitHistory?: boolean;
  /** Scan a shallow clone's fetched history instead of refusing it. */
  allowShallow?: boolean;
};

type FileStat = Stats | BigIntStats;

function exactIdentity(value: number | bigint): bigint | null {
  return typeof value === 'bigint' ? value : Number.isSafeInteger(value) ? BigInt(value) : null;
}

function sameFileIdentity(left: FileStat, right: FileStat): boolean {
  const samePart = (a: number | bigint, b: number | bigint): boolean => {
    const exactA = exactIdentity(a);
    const exactB = exactIdentity(b);
    return exactA !== null && exactB !== null && exactA === exactB;
  };
  return samePart(left.dev, right.dev) && samePart(left.ino, right.ino);
}

function fileIdentity(stat: FileStat, target: string): string {
  const dev = exactIdentity(stat.dev);
  const ino = exactIdentity(stat.ino);
  if (dev === null || ino === null || ino === 0n ||
      (typeof stat.ino === 'number' && stat.nlink === 1)) return target;
  return `${dev}:${ino}`;
}

/** `truncated`: the match was cut by its window's end and may continue in the line (fail closed). */
type HitKind = 'lndconnect' | 'nwc' | 'macaroon-hex' | 'macaroon-base64' | 'l402-header' | 'l402-challenge' | 'l402-pair' | 'l402-hex'
  | 'l402-base64';
type Hit = {
  start: number; text: string; kind: HitKind; truncated?: true;
  /** Code points the match covers in the line, when matched on an unescaped copy of it. */
  extent?: number;
};
const detectors = [
  { kind: 'lndconnect', pattern: lndconnect },
  { kind: 'l402-header', pattern: l402Header },
  // Scan only: a WWW-Authenticate challenge (L402 section 5.1): the scheme, an optional invoice
  // parameter, then macaroon= or token= with the base64 macaroon, quoted, JSON-escaped or bare.
  { kind: 'l402-challenge', pattern: l402Challenge },
  // Scan only: a scheme-less "<base64 macaroon>:<hex preimage>" pair, found by a linear matcher
  // (src/scan/l402-match.ts); this regex only names the shape.
  { kind: 'l402-pair', pattern: /[A-Za-z0-9+/_-]{40,}={0,2}:[0-9a-f]{64}/i },
  { kind: 'nwc', pattern: nwc },
  { kind: 'macaroon-hex', pattern: macaroonHex },
  { kind: 'macaroon-base64', pattern: macaroonBase64 },
  { kind: 'l402-hex', pattern: l402MacaroonHex },
  { kind: 'l402-base64', pattern: l402MacaroonBase64 },
  // RR-10, scan only (not part of the published patterns): hex with a separator between every
  // byte (colon hex, xxd -g1, spaced bytes) is decoded; the prefix of an xxd default dump
  // (two-byte groups, either alignment) is a candidate, since a dump spans several lines.
  { kind: 'macaroon-hex', pattern: /02[: -]01[: -]03[: -]6c[: -]6e[: -]64[: -]02(?:[: -][0-9a-f]{2}){20,}/i },
  { kind: 'macaroon-hex', pattern: /0201 036c 6e64 02(?:[0-9a-f]{2})?|02 0103 6c6e 6402/i },
] as const;
// RR-10: a prefix whose continuation is shorter than the published patterns need and that
// ends its line may be a credential wrapped narrower than 49 columns. It is joined with the
// following lines of the same alphabet and reported when the joined text decodes.
const NARROW_WRAP = [
  { kind: 'macaroon-base64', start: /AgEDbG5kA[A-Za-z0-9+/_-]{0,39}\s*$/, more: /^[A-Za-z0-9+/_-]+={0,2}$/ },
  { kind: 'macaroon-hex', start: /0201036c6e6402[0-9a-f]{0,39}\s*$/i, more: /^[0-9a-f]+$/i },
] as const;
const detectorRegexes = detectors.map(({ kind, pattern }) =>
  ({ kind, regex: new RegExp(pattern.source, `${pattern.flags.replace('g', '')}g`) }));
// Every detector match contains one of these (case-insensitive superset), so a line
// without any of them cannot produce a hit and is not split into code points.
// "walletconnect%3a" covers percent-encoded NWC URIs, which are matched on a normalised copy.
const PLAIN_MAY_MATCH = /lndconnect:\/\/|walletconnect:|walletconnect%3a|0201036c6e6402|AgEDbG5kA|02[: -]01[: -]03[: -]6c|0201 036c 6e64 02|02 0103 6c6e 6402|l402[ \t]|lsat[ \t]|0201046c73617402420000|AgEEbHNhdAJCAA|:[0-9a-f]{64}/i;

/**
 * The part of base64(prefix) that does not depend on the bytes before or after the prefix,
 * for each of the three byte alignments: text that holds the base64 of a text credential
 * (a Kubernetes Secret's data, Helm values) holds one of these.
 */
function encodedCores(prefix: string): string[] {
  return [0, 1, 2].map(lead => {
    const encode = (fill: number) => Buffer.concat([Buffer.alloc(lead, fill), Buffer.from(prefix), Buffer.alloc(3, fill)]).toString('base64');
    const [low, high] = [encode(0), encode(0xff)];
    let best = '';
    for (let at = 0, run = 0; at < low.length; at++) {
      run = low[at] === high[at] ? run + 1 : 0;
      if (run > best.length) best = low.slice(at - run + 1, at + 1);
    }
    return best;
  });
}
const ENCODED_PREFIXES = ['0201036c6e6402', '0201036C6E6402', 'AgEDbG5kA', 'lndconnect://',
  'L402 ', 'LSAT ', 'l402 ', 'lsat ', '0201046c73617402420000', 'AgEEbHNhdAJCAA'];
// Base64 that may hold a text credential. Case matters: it is matched on the encoded text.
const ENCODED_CANDIDATE = new RegExp(ENCODED_PREFIXES.flatMap(encodedCores)
  .map(core => core.replace(/[+/]/g, match => `\\${match}`)).join('|'));
// A line that cannot produce a hit, plain or encoded, is not split into code points.
const MAY_MATCH = { test: (text: string) => PLAIN_MAY_MATCH.test(text) || ENCODED_CANDIDATE.test(text) };
/**
 * Every detector match of up to this many code points is matched whole wherever it starts in
 * a line. It covers the largest supported credential encodings with room to spare: the hex of
 * a 64 KiB credential (131,072), its base64 or base64url (87,382) with lndconnect host and
 * certificate parameters, and NWC URIs. A match still cut by a window end is reported as an
 * undecodable-candidate, never dropped.
 */
export const CANDIDATE_LIMIT = 262_144;
// Windows start every CANDIDATE_LIMIT code points and are long enough that a match starting
// anywhere in the first CANDIDATE_LIMIT code points has CANDIDATE_LIMIT code points of room.
// Each code point is matched at most twice, so time and memory stay linear in the line.
const STEP = CANDIDATE_LIMIT;
const WINDOW = STEP + CANDIDATE_LIMIT - 1;

function fingerprint(data: Buffer | string): string {
  return `fp:${createHash('sha256').update(data).digest('hex').slice(0, 16)}`;
}

// Findings never mutate these arrays; sharing them keeps a large result small.
const NONE = Object.freeze([]) as unknown as string[];

function nullFinding(path: string, line: number | null, column: number | null, kind: FindingKind, hash: string): ScanFinding {
  return { path, line, column, kind, fingerprint: hash, grade: null, rootKeyId: null,
    permissions: null, caveats: null, warnings: NONE, unassessed: NONE };
}

type FactFields = Pick<ScanFinding, 'fingerprint' | 'grade' | 'rootKeyId' | 'permissions' | 'caveats' | 'warnings' | 'unassessed'>;
/** Per-scan state shared by every file and blob: known NWC secrets and decoded facts by fingerprint. */
type ScanContext = { secrets: Set<string>; facts: Map<string, FactFields>; l402: Map<string, L402Report> };

function redactL402(report: L402Report, redact: (text: string) => string): L402Report {
  const text = (value: string | null) => value === null ? null : redact(value);
  return { ...report, location: text(report.location),
    services: report.services.map(service => ({ ...service, name: redact(service.name) })),
    caveats: report.caveats.map(caveat => ({ ...caveat, condition: text(caveat.condition), value: text(caveat.value),
      ...(caveat.service === undefined ? {} : { service: redact(caveat.service) }) })) };
}

// An L402 credential's facts, shared like withFacts by fingerprint and form. Its preimage
// joins the known secrets, so no reported string can carry it.
function withL402Facts(path: string, line: number | null, column: number | null, kind: 'l402' | 'l402-file',
  facts: L402Facts, now: Date, ctx: ScanContext): ScanFinding {
  const key = `${facts.fingerprint}\0${facts.form}\0${facts.scheme ?? ''}`;
  let report = ctx.l402.get(key);
  if (!report) {
    const preimage = l402RedactionSecret(facts);
    if (preimage !== null) ctx.secrets.add(preimage);
    for (const value of [facts.location, ...facts.caveats.flatMap(caveat => [caveat.condition, caveat.value])])
      if (value !== null) collectNwcSecrets(value, ctx.secrets);
    report = redactL402(assessL402(facts, now), redactDecoded);
    ctx.l402.set(key, report);
  }
  return { ...nullFinding(path, line, column, kind, facts.fingerprint), l402: report };
}

// The same credential (same fingerprint, hence the same canonical bytes) has the same
// facts wherever it is found, so they are computed and redacted once per scan.
function withFacts(path: string, line: number | null, column: number | null, kind: FindingKind,
  facts: MacaroonFacts, now: Date, ctx: ScanContext): ScanFinding {
  let shared = ctx.facts.get(facts.fingerprint);
  if (!shared) {
    if (facts.location !== null) collectNwcSecrets(facts.location, ctx.secrets);
    for (const value of [...facts.permissions, ...facts.caveats.map(caveat => caveat.value)])
      collectNwcSecrets(value, ctx.secrets);
    const assessed = gradeFacts(facts);
    shared = {
      fingerprint: facts.fingerprint, grade: assessed.grade,
      rootKeyId: facts.rootKeyId.toString(), permissions: facts.permissions.map(redactDecoded),
      caveats: facts.caveats.map(caveat => {
        const safeCaveat = { ...caveat, value: redactDecoded(caveat.value) };
        if (caveat.type !== 'time-before') return safeCaveat;
        const instant = parseTimeBefore(caveat.value);
        return instant === undefined ? safeCaveat :
          { ...safeCaveat, expired: BigInt(now.getTime()) * 1_000_000n >= instant };
      }),
      warnings: [...new Set([...assessed.warnings, ...describe(facts)])].sort(byteCompare),
      unassessed: assessed.unassessed.map(redactDecoded),
    };
    ctx.facts.set(facts.fingerprint, shared);
  }
  return { path, line, column, kind, ...shared };
}

function byteCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function decodeBase64(value: string): Buffer | null {
  const standard = /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  const url = /^[A-Za-z0-9_-]+={0,2}$/.test(value);
  if ((!standard && !url) || value.length % 4 === 1) return null;
  const padding = value.length - value.replace(/=+$/, '').length;
  if (padding > 0 && value.length % 4 !== 0) return null;
  const encoding = standard ? 'base64' : 'base64url';
  const bytes = Buffer.from(value, encoding);
  if (!bytes.length || bytes.toString(encoding).replace(/=+$/, '') !== value.replace(/=+$/, '')) return null;
  return bytes;
}

function decoded(bytes: Buffer): MacaroonFacts | null {
  try {
    return decodeMacaroon(new Secret(bytes));
  } catch (error) {
    if (!(error instanceof DecodeError)) throw error;
    return null;
  }
}

function credentialBytes(hit: Hit): Buffer | null {
  if (hit.kind === 'macaroon-hex' || hit.kind === 'l402-hex') {
    // Byte separators (RR-10) carry no data.
    const digits = hit.text.replace(/[: -]/g, '');
    if (digits.length % 2 !== 0) return null;
    return Buffer.from(digits, 'hex');
  }
  if (hit.kind === 'macaroon-base64' || hit.kind === 'l402-base64') return decodeBase64(hit.text);
  return null;
}

/**
 * The credential an L402 Authorization, challenge or pair match carries: an L402 finding, the
 * LND macaroon it holds (reported as macaroon-base64 at the macaroon), or null when it does not
 * decode. Pairs are confirmed only with an L402 identifier: the shape alone is too common.
 */
function l402Credential(hit: Hit, path: string, line: number, column: (start: number) => number, now: Date,
  ctx: ScanContext): ScanFinding | null {
  let macaroons: string[];
  let preimage: Buffer | null = null;
  let offset: number;
  const scheme = /^(l402|lsat)[ \t]+/i.exec(hit.text);
  const schemeName = scheme ? scheme[1].toUpperCase() as 'L402' | 'LSAT' : null;
  if (hit.kind === 'l402-challenge') {
    const parameter = /(?:macaroon|token)[ \t]*=[ \t]*\\?"?/i.exec(hit.text)!;
    offset = parameter.index + parameter[0].length;
    macaroons = [hit.text.slice(offset)];
  } else {
    const body = scheme ? hit.text.slice(scheme[0].length) : hit.text;
    offset = scheme ? scheme[0].length : 0;
    const colon = body.lastIndexOf(':');
    macaroons = body.slice(0, colon).split(',');
    preimage = Buffer.from(body.slice(colon + 1), 'hex');
  }
  if (macaroons.length > L402_MAX_MACAROONS) return null;
  const bytes = macaroons.map(decodeBase64);
  if (bytes.some(item => item === null)) return null;
  const form = hit.kind === 'l402-challenge' ? 'challenge' : hit.kind === 'l402-header' ? 'authorization' : 'pair';
  try {
    const result = decodeL402Macaroons(bytes.map(item => new Secret(item!)), preimage && new Secret(preimage), form, schemeName);
    if ('lnd' in result) {
      return withFacts(path, line, column(hit.start + offset), 'macaroon-base64', decodeMacaroon(result.lnd), now, ctx);
    }
    if (form === 'pair' && result.l402.identifier === null) return null;
    return withL402Facts(path, line, column(hit.start), 'l402', result.l402, now, ctx);
  } catch (error) {
    if (!(error instanceof DecodeError)) throw error;
    return null;
  }
}

/** A bare L402 macaroon (hex or base64 with Aperture's location and identifier), or null. */
function l402Macaroon(bytes: Buffer | null): L402Facts | null {
  if (bytes === null) return null;
  try {
    const result = decodeL402Macaroon(new Secret(bytes), null, 'macaroon');
    return 'l402' in result && result.l402.identifier !== null ? result.l402 : null;
  } catch (error) {
    if (!(error instanceof DecodeError)) throw error;
    return null;
  }
}

/**
 * Whether a match that ends at its window's end would be longer in the whole line: the same
 * detector, anchored at the match, matches more of the match followed by the next code point.
 */
function continues(kind: Hit['kind'], text: string, next: string, regex: RegExp): boolean {
  if (kind === 'nwc' || kind === 'l402-pair') return false;
  const sticky = new RegExp(regex.source, `${regex.flags.replace('g', '')}y`);
  const longer = sticky.exec(text + next);
  return longer !== null && longer[0].length > text.length;
}

function collectHits(points: string[], only?: readonly Hit['kind'][]): Hit[] {
  const hits = new Map<string, Hit>();
  const truncated = new Map<string, Hit>();
  for (let offset = 0; offset < points.length; offset += STEP) {
    const window = points.slice(offset, offset + WINDOW).join('');
    // The line continues past this window: a match reaching its end may be cut.
    const cut = offset + WINDOW < points.length ? points[offset + WINDOW] : null;
    // This window has more room for any match starting in it than the earlier ones had, so
    // it decides again about every earlier cut match that starts here.
    for (const [key, hit] of truncated) {
      if (hit.start >= offset) { hits.delete(key); truncated.delete(key); }
    }
    for (const { kind, regex } of detectorRegexes) {
      if (only !== undefined && !only.includes(kind)) continue;
      regex.lastIndex = 0;
      let codeUnit = 0;
      let codePoint = 0;
      // NWC uses a linear matcher equivalent to the published regex (src/scan/nwc-match.ts).
      // A prefix whose URI runs to the window end without a secret may be cut by the window.
      const open: number[] = [];
      const found: { index: number; 0: string; truncated?: true }[] = kind === 'nwc'
        ? nwcMatches(window, cut === null ? undefined : open).map(item => ({ index: item.index, 0: item.text }))
        // L402 pairs use a linear matcher too (src/scan/l402-match.ts); a pair is never a candidate.
        : kind === 'l402-pair'
          ? l402PairMatches(window, { previous: offset > 0 ? points[offset - 1] : null, next: cut })
            .map(item => ({ index: item.index, 0: item.text }))
          : [...window.matchAll(regex)];
      for (const index of open) found.push({ index, 0: window.slice(index), truncated: true });
      found.sort((a, b) => a.index - b.index);
      for (const match of found) {
        // Regex offsets count UTF-16 code units; scan columns count code points.
        // Advance once through the window instead of recounting every prefix.
        while (codeUnit < match.index) {
          codeUnit += window.codePointAt(codeUnit)! > 0xffff ? 2 : 1;
          codePoint++;
        }
        const start = offset + codePoint;
        const key = `${kind}:${start}`;
        const cutHere = match.truncated ?? (cut !== null && match.index + match[0].length === window.length &&
          continues(kind, window.slice(match.index), cut, regex));
        const prior = hits.get(key);
        if (prior && match[0].length <= prior.text.length) continue;
        const hit: Hit = cutHere ? { kind, start, text: match[0], truncated: true } : { kind, start, text: match[0] };
        hits.set(key, hit);
        if (cutHere) truncated.set(key, hit); else truncated.delete(key);
      }
    }
    // This window reached the line end: a later one would only rescan its tail.
    if (cut === null) break;
  }
  return [...hits.values()].sort(byStartThenDetector);
}

/** The line's code points with every "\/" read as "/"; origin and escaped map back to the line. */
function slashUnescaped(points: readonly string[]): { points: string[]; origin: number[]; escaped: boolean[] } {
  const out: string[] = [];
  const origin: number[] = [];
  const escaped: boolean[] = [];
  for (let i = 0; i < points.length; i++) {
    const pair = points[i] === '\\' && points[i + 1] === '/';
    out.push(pair ? '/' : points[i]);
    origin.push(i);
    escaped.push(pair);
    if (pair) i++;
  }
  return { points: out, origin, escaped };
}

function byStartThenDetector(a: Hit, b: Hit): number {
  return a.start - b.start || detectors.findIndex(d => d.kind === a.kind) - detectors.findIndex(d => d.kind === b.kind);
}

// Punctuation that commonly follows a URI in text (markdown, prose, YAML flow, shell) but is
// matched by the lndconnect pattern. It is removed only when the URI as matched does not parse.
// Stripped by one backward scan: the anchored regex `[...]+$` this replaced backtracked
// quadratically on a match that ends in other characters (audit 1.2.1), so one hostile 262 KB
// line cost 35 s.
const TRAILING_PUNCTUATION = new Set('`)]}>.,;:!?\'"*');
function withoutTrailingPunctuation(text: string): string {
  let end = text.length;
  while (end > 0 && TRAILING_PUNCTUATION.has(text[end - 1])) end -= 1;
  return text.slice(0, end);
}

/** The credential an lndconnect match carries, and the match's length in code points once confirmed. */
function lndconnectCredential(text: string): { bytes: Buffer; length: number } | null {
  const bytes = parseLndconnect(text, { standardBase64: true });
  if (bytes) return { bytes, length: Array.from(text).length };
  const trimmed = withoutTrailingPunctuation(text);
  if (trimmed === text) return null;
  const retried = parseLndconnect(trimmed, { standardBase64: true });
  return retried ? { bytes: retried, length: Array.from(trimmed).length } : null;
}

/**
 * The findings of one line (or of one decoded text, see scanEncoded). `column` maps a code
 * point offset in `text` to the 1-based column reported.
 */
function scanLine(path: string, line: number, text: string, now: Date, ctx: ScanContext,
  column: (start: number) => number): { findings: ScanFinding[]; dropped: number } {
  const findings: ScanFinding[] = [];
  let dropped = 0;
  const points = Array.from(text);
  let hits = collectHits(points);
  // NWC URIs in common escaped forms (JSON-escaped slashes, percent-encoding, "+" as a
  // space) are matched on one normalised copy of the line; a URI the line already matched
  // at the same column is not reported twice (a whole match replaces one cut by a window).
  const unescaped = nwcUnescaped(points, text);
  if (unescaped) {
    const seen = new Map(hits.filter(hit => hit.kind === 'nwc').map(hit => [hit.start, hit]));
    const replaced = new Set<Hit>();
    for (const hit of collectHits(unescaped.points, ['nwc'])) {
      const start = unescaped.origin[hit.start];
      const prior = seen.get(start);
      if (prior && !(prior.truncated && !hit.truncated)) continue;
      if (prior) replaced.add(prior);
      const moved = { ...hit, start };
      seen.set(start, moved);
      hits.push(moved);
    }
    if (replaced.size) hits = hits.filter(hit => !replaced.has(hit));
    hits.sort((a, b) => a.start - b.start);
  }
  // JSON-escaped slashes ("\/", PHP json_encode by default and some Java and Go encoders) would
  // stop a base64 macaroon or an lndconnect URI at the backslash: both are also matched on a
  // copy of the line with "\/" read as "/". A match there replaces the one at the same column
  // only when it covers more of the line, so an unescaped line yields the same hits.
  const slashes = text.includes('\\/') ? slashUnescaped(points) : null;
  if (slashes) {
    const byKey = new Map(hits.map(hit => [`${hit.kind}:${hit.start}`, hit]));
    const replaced = new Set<Hit>();
    for (const hit of collectHits(slashes.points, ['lndconnect', 'macaroon-base64', 'l402-header', 'l402-challenge', 'l402-pair', 'l402-base64'])) {
      const start = slashes.origin[hit.start];
      const last = hit.start + Array.from(hit.text).length - 1;
      const extent = slashes.origin[last] + (slashes.escaped[last] ? 2 : 1) - start;
      const key = `${hit.kind}:${start}`;
      const prior = byKey.get(key);
      if (prior && extent <= (prior.extent ?? Array.from(prior.text).length)) continue;
      if (prior) replaced.add(prior);
      const moved = { ...hit, start, extent };
      byKey.set(key, moved);
      hits.push(moved);
    }
    if (replaced.size) hits = hits.filter(hit => !replaced.has(hit));
    hits.sort(byStartThenDetector);
  }
  // An lndconnect URI is confirmed first. Only a confirmed URI hides the matches inside it:
  // a URI that does not parse never hides the credential it carries (fail closed).
  const lineFindings: { hit: Hit; finding: ScanFinding }[] = [];
  const spans: { start: number; end: number }[] = [];
  for (const hit of hits) {
    if (hit.kind !== 'lndconnect' || hit.truncated) continue;
    const confirmed = lndconnectCredential(hit.text);
    const facts = confirmed && decoded(confirmed.bytes);
    if (!confirmed || !facts) { dropped++; continue; }
    const length = Array.from(hit.text).length;
    spans.push({ start: hit.start, end: hit.start + (hit.extent ?? length) - (length - confirmed.length) });
    lineFindings.push({ hit, finding: withFacts(path, line, column(hit.start), 'lndconnect', facts, now, ctx) });
  }
  // L402 Authorization credentials and pairs are confirmed next, in line order; a confirmed one
  // hides the matches inside it (its macaroon as a bare L402 or LND macaroon, a pair inside a
  // header). One that does not decode hides nothing.
  const confirmedL402 = new Set<Hit>();
  if (hits.some(hit => hit.kind === 'l402-header' || hit.kind === 'l402-challenge' || hit.kind === 'l402-pair')) {
    const l402Spans: { start: number; end: number }[] = [];
    let lndIndex = 0;
    let covered = 0;
    for (const hit of hits) {
      while (lndIndex < spans.length && spans[lndIndex].start <= hit.start) covered = Math.max(covered, spans[lndIndex++].end);
      if ((hit.kind !== 'l402-header' && hit.kind !== 'l402-challenge' && hit.kind !== 'l402-pair') || hit.truncated || hit.start < covered) continue;
      const finding = l402Credential(hit, path, line, column, now, ctx);
      if (!finding) continue;
      const end = hit.start + (hit.extent ?? Array.from(hit.text).length);
      l402Spans.push({ start: hit.start, end });
      covered = Math.max(covered, end);
      confirmedL402.add(hit);
      lineFindings.push({ hit, finding });
    }
    for (const span of l402Spans) spans.push(span);
    spans.sort((a, b) => a.start - b.start);
  }
  let spanIndex = 0;
  let coveredUntil = 0;
  for (const hit of hits) {
    while (spanIndex < spans.length && spans[spanIndex].start <= hit.start) {
      coveredUntil = Math.max(coveredUntil, spans[spanIndex].end);
      spanIndex++;
    }
    const at = column(hit.start);
    // A match cut by its window's end may continue past it: report it, never decode a part.
    if (hit.truncated) {
      lineFindings.push({ hit, finding: nullFinding(path, line, at, 'undecodable-candidate', fingerprint(hit.text)) });
      continue;
    }
    // A challenge carries no preimage: one that does not decode is not reported (the bare macaroon
    // detectors still see an L402 macaroon inside it). A pair shape alone is not reported.
    if (hit.kind === 'lndconnect' || hit.kind === 'l402-pair' || hit.kind === 'l402-challenge' || confirmedL402.has(hit)
      || hit.start < coveredUntil) continue;
    if (hit.kind === 'l402-header') {
      // An Authorization credential that does not decode fails closed, like a macaroon prefix.
      lineFindings.push({ hit, finding: nullFinding(path, line, at, 'undecodable-candidate', fingerprint(hit.text)) });
      continue;
    }
    if (hit.kind === 'l402-hex' || hit.kind === 'l402-base64') {
      const l402 = l402Macaroon(credentialBytes(hit));
      lineFindings.push({ hit, finding: l402 ? withL402Facts(path, line, at, 'l402', l402, now, ctx)
        : nullFinding(path, line, at, 'undecodable-candidate', fingerprint(hit.text)) });
      continue;
    }
    if (hit.kind === 'nwc') {
      // The matcher ends every match with secret=<64 hex> and at most one delimiter. Any
      // match is reported (fail closed): "&amp;secret=" and other separators included.
      const secret = /secret=([0-9a-f]{64})[^0-9a-f]?$/i.exec(hit.text)![1].toLowerCase();
      ctx.secrets.add(secret);
      lineFindings.push({ hit, finding: nullFinding(path, line, at, 'nwc', fingerprint(Buffer.from(secret, 'hex'))) });
      continue;
    }
    const bytes = credentialBytes(hit);
    const facts = bytes && decoded(bytes);
    lineFindings.push({ hit, finding: facts ? withFacts(path, line, at, hit.kind, facts, now, ctx)
      : nullFinding(path, line, at, 'undecodable-candidate', fingerprint(hit.text)) });
  }
  lineFindings.sort((a, b) => byStartThenDetector(a.hit, b.hit));
  for (const { finding } of lineFindings) findings.push(finding);
  return { findings, dropped };
}

/**
 * RR-02: credentials stored as the base64 of their text (Kubernetes Secret data, Helm values).
 * Each base64 run of the line holding an encoded prefix is decoded once at each of the four
 * character phases, and the decoded text is scanned as a line, one level deep: decoded text
 * is never decoded again. A finding is reported at the column of its first encoded character.
 */
function scanEncoded(path: string, line: number, text: string, now: Date, ctx: ScanContext): { findings: ScanFinding[]; dropped: number } {
  const findings: ScanFinding[] = [];
  const reported = new Set<string>();
  let dropped = 0;
  const runs = /[A-Za-z0-9+/]{16,}={0,2}/g;
  // Columns count code points; base64 is ASCII, so advance a code point counter once.
  let unit = 0;
  let point = 0;
  for (let run = runs.exec(text); run; run = runs.exec(text)) {
    while (unit < run.index) { unit += text.codePointAt(unit)! > 0xffff ? 2 : 1; point++; }
    if (!ENCODED_CANDIDATE.test(run[0])) continue;
    const runStart = point;
    for (let phase = 0; phase < 4 && phase < run[0].length; phase++) {
      const usable = run[0].slice(phase).replace(/=+$/, '');
      const decodedText = Buffer.from(usable.slice(0, usable.length - (usable.length % 4 === 1 ? 1 : 0)), 'base64').toString('latin1');
      if (!PLAIN_MAY_MATCH.test(decodedText)) continue;
      // Decoded byte b starts in encoded character floor(b * 4 / 3) of this phase.
      const result = scanLine(path, line, decodedText, now, ctx, start => runStart + phase + Math.floor(start * 4 / 3) + 1);
      dropped += result.dropped;
      for (const finding of result.findings) {
        const key = `${finding.column}:${finding.kind}:${finding.fingerprint}`;
        if (!reported.has(key)) { reported.add(key); findings.push(finding); }
      }
    }
  }
  return { findings, dropped };
}

/**
 * RR-10: a credential wrapped narrower than 49 columns. When line `index` ends with a prefix
 * too short for the published patterns, the following lines that hold only the same alphabet
 * (indentation and trailing whitespace aside, at most CANDIDATE_LIMIT characters in all) are
 * joined to it; the credential is reported only when the joined text decodes. Text after the
 * credential is ignored, as the decoder ignores trailing bytes.
 */
function narrowWrap(path: string, lines: string[], index: number, found: ScanFinding[], now: Date,
  ctx: ScanContext): { finding: ScanFinding | null; last: number } {
  let last = index;
  for (const { kind, start, more } of NARROW_WRAP) {
    const tail = start.exec(lines[index]);
    if (!tail) continue;
    const column = Array.from(lines[index].slice(0, tail.index)).length + 1;
    if (found.some(finding => finding.column === column)) continue;
    let joined = tail[0].trimEnd();
    for (let next = index + 1; next < lines.length && joined.length < CANDIDATE_LIMIT; next++) {
      const part = lines[next].trim();
      if (!more.test(part)) break;
      joined += part;
      last = Math.max(last, next);
      if (part.endsWith('=')) break;
    }
    const bytes = kind === 'macaroon-hex' ? Buffer.from(joined.slice(0, joined.length - joined.length % 2), 'hex')
      : Buffer.from(joined.slice(0, CANDIDATE_LIMIT), joined.includes('-') || joined.includes('_') ? 'base64url' : 'base64');
    const facts = decoded(bytes);
    if (facts) return { finding: withFacts(path, index + 1, column, kind, facts, now, ctx), last };
  }
  return { finding: null, last };
}

function scanText(path: string, text: string, now: Date, ctx: ScanContext): { findings: ScanFinding[]; dropped: number } {
  const findings: ScanFinding[] = [];
  let dropped = 0;
  if (!MAY_MATCH.test(text)) return { findings, dropped };
  const lines = text.split(/\r\n|\n|\r/);
  let joinedUntil = -1;
  for (let i = 0; i < lines.length; i++) {
    if (!MAY_MATCH.test(lines[i])) continue;
    const line = scanLine(path, i + 1, lines[i], now, ctx, start => start + 1);
    // Each line is joined into at most one wrap, so joining stays linear in the text.
    if (i > joinedUntil) {
      const wrapped = narrowWrap(path, lines, i, line.findings, now, ctx);
      joinedUntil = wrapped.last;
      if (wrapped.finding) line.findings.push(wrapped.finding);
    }
    const encoded = ENCODED_CANDIDATE.test(lines[i]) ? scanEncoded(path, i + 1, lines[i], now, ctx) : null;
    const lineFindings = encoded?.findings.length ? [...line.findings, ...encoded.findings].sort((a, b) => a.column! - b.column!)
      : line.findings;
    for (const finding of lineFindings) findings.push(finding);
    dropped += line.dropped + (encoded?.dropped ?? 0);
  }
  return { findings, dropped };
}

function decodeText(bytes: Buffer): string {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe)
    return bytes.subarray(2).toString('utf16le');
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    const swapped = Buffer.from(bytes.subarray(2));
    if (swapped.length % 2 !== 0) swapped.subarray(0, swapped.length - 1).swap16();
    else swapped.swap16();
    return swapped.toString('utf16le');
  }
  const start = bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  return bytes.subarray(start).toString('utf8');
}

function reportedPath(path: string): string {
  const root = parse(path).root;
  const trailingSeparators = sep === '\\' ? /[\\/]+$/ : /\/+$/;
  const trimmed = path.length > root.length ? path.replace(trailingSeparators, '') : path;
  // Only Windows uses '\' as a separator; elsewhere it is an ordinary file name character.
  return sep === '\\' ? trimmed.replace(/\\/g, '/') : trimmed;
}

// Windows and macOS file systems compare names case-insensitively by default, so '.GIT' there
// is the '.git' directory. Elsewhere names are case-sensitive and '.GIT' is an ordinary directory.
const CASE_INSENSITIVE_NAMES = process.platform === 'win32' || process.platform === 'darwin';
function namedAs(name: string, names: readonly string[]): boolean {
  return names.includes(CASE_INSENSITIVE_NAMES ? name.toLowerCase() : name);
}
const EXCLUDED_DIRS = ['.git', 'node_modules'] as const;

function isSystemDirectoryPath(path: string): boolean {
  if (!path.startsWith('/')) return false;
  const normalized = posix.normalize(path);
  return ['/proc', '/sys', '/dev'].some(dir => normalized === dir || normalized.startsWith(`${dir}/`));
}

const TEXT_LIMIT = 5_242_880;
/**
 * Hard cap on findings per scan, counted before ignore entries apply. Beyond it the scan
 * fails closed (exit 3, step findings-limit) instead of growing without bound: an
 * attacker who controls scanned content or history must not be able to exhaust memory.
 */
export const FINDINGS_LIMIT = 250_000;
/** Example extra paths kept on a history finding whose content was added at several paths. */
export const ALSO_AT_EXAMPLES = 5;

/** Bound on history deduplication checks (a pending credential tested at a further path). */
export const HISTORY_DEDUP_WORK_LIMIT = 100_000_000;

export class FindingsLimitError extends Error {
  constructor(message?: string) {
    super(message ?? `more than ${FINDINGS_LIMIT.toLocaleString('en-US')} findings; the scan stops rather than report a partial result. `
      + 'Narrow the scan paths, or remove the planted credentials');
    this.name = 'FindingsLimitError';
  }
}
const NOT_SCANNABLE = 'scan path is not a regular file or directory';
/** At most this many files are open and read at once during a directory walk. */
export const SCAN_CONCURRENCY = 16;
/** Bound on dispatched but not yet committed file results (memory bound). */
const SCAN_QUEUE = SCAN_CONCURRENCY * 4;
const MACAROON_LIMIT = 65_536;

/** Files read whole as one credential: *.macaroon, and the L402 token store files of Aperture-based clients. */
function isCredentialFileName(name: string): boolean {
  return /\.macaroon$/i.test(name) || /^(?:l402|lsat)\.token(?:\.pending)?$/i.test(name);
}

function fileCredential(bytes: Buffer): Buffer | null {
  if (bytes[0] === 0x02) return bytes;
  let text: string;
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    if ((bytes.length - 2) % 2 !== 0) return null;
    text = bytes.subarray(2).toString('utf16le');
  } else if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    if ((bytes.length - 2) % 2 !== 0) return null;
    const swapped = Buffer.from(bytes.subarray(2));
    swapped.swap16();
    text = swapped.toString('utf16le');
  } else {
    const start = bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])) ? 3 : 0;
    text = bytes.subarray(start).toString('utf8');
  }
  const value = text.replace(/\s/g, '');
  if (!value) return null;
  if (/^lndconnect:\/\//i.test(value)) {
    return parseLndconnect(value);
  }
  if (/^(?:0x)?[0-9a-f]+$/i.test(value)) {
    const digits = /^0x/i.test(value) ? value.slice(2) : value;
    return digits.length % 2 === 0 ? Buffer.from(digits, 'hex') : null;
  }
  return decodeBase64(value);
}

type BytesOutcome = { findings: ScanFinding[]; dropped: number } | { skip: 'size' | 'binary' };

/** Scans one file's or blob's bytes exactly as the file walk does. */
// `name` is the file's base name, used only to recognise MCP JSON configs; history blobs pass ''.
function scanBytes(safePath: string, bytes: Buffer, macaroonFile: boolean, now: Date, ctx: ScanContext, name = ''): BytesOutcome {
  if (macaroonFile) {
    // A credential file: *.macaroon, or an L402 token store file (l402.token, lsat.token and
    // their .pending forms). Its content decides the kind: Aperture's token store framing or
    // a bare L402 macaroon gives l402-file, an LND macaroon macaroon-file.
    const tokenStore = bytes.length <= MACAROON_LIMIT && bytes[0] === 0x00;
    const credential = bytes.length <= MACAROON_LIMIT && !tokenStore ? fileCredential(bytes) : null;
    if (tokenStore || credential) {
      try {
        const secret = new Secret(tokenStore ? bytes : credential!);
        const l402 = tokenStore ? decodeL402(secret) : isL402Macaroon(secret)
          ? decodeL402Macaroon(secret, null, 'macaroon') : null;
        if (l402 && 'l402' in l402) return { findings: [withL402Facts(safePath, null, null, 'l402-file', l402.l402, now, ctx)], dropped: 0 };
        return { findings: [withFacts(safePath, null, null, 'macaroon-file',
          decodeMacaroon(l402 && 'lnd' in l402 ? l402.lnd : secret), now, ctx)], dropped: 0 };
      } catch (error) {
        if (!(error instanceof DecodeError)) throw error;
      }
    }
    return { findings: [nullFinding(safePath, null, null, 'undecodable',
      fingerprint(bytes.subarray(0, MACAROON_LIMIT + 1)))], dropped: 0 };
  }
  if (bytes.length > TEXT_LIMIT) return { skip: 'size' };
  if (!(bytes[0] === 0xff && bytes[1] === 0xfe) &&
    !(bytes[0] === 0xfe && bytes[1] === 0xff) && bytes.subarray(0, 8192).includes(0)) return { skip: 'binary' };
  const text = decodeText(bytes);
  const outcome = scanText(safePath, text, now, ctx);
  for (const finding of runeFindings(text, now, ctx)) outcome.findings.push({ ...finding, path: safePath });
  if (outcome.findings.length && /\.jsonc?$/i.test(name)) tagMcpContext(name, text, outcome.findings);
  return outcome;
}

// A credential that is a string value inside an MCP server entry is configured for an
// AI agent. Tagging is best effort: malformed JSON leaves the findings unchanged.
function tagMcpContext(path: string, text: string, findings: ScanFinding[]): void {
  const spans = mcpServerStringSpans(text, /(?:^|[\\/])mcp\.json$/i.test(path));
  if (!spans.length) return;
  for (const finding of findings) {
    if (finding.line !== null && finding.column !== null
      && withinSpans({ line: finding.line, column: finding.column }, spans)) finding.context = 'mcp-config';
  }
}

export { readBounded };

type ScanFs = NonNullable<ScanOptions['fs']>;
type Handle = Awaited<ReturnType<typeof fs.open>>;

/**
 * Opens a file for scanning: read-only, no-follow where the platform has it, and non-blocking,
 * so a FIFO swapped in after the walk's lstat cannot block open(2) waiting for a writer; the
 * caller then fstats the descriptor and reads only a regular file.
 */
export const SCAN_OPEN_FLAGS = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0);

/**
 * The scan's file system with every operation raced against the interrupt (SIGINT, SIGTERM,
 * SIGHUP): an operation still pending when the scan is interrupted rejects with Cancelled at
 * once, so a slow or stuck file system call cannot hold the scan. A handle opened after the
 * interrupt is closed when its open completes; a close never waits for a stuck read.
 */
function cancellableFs(raw: ScanFs): ScanFs {
  const wrap = <A extends unknown[], R>(operation: (...args: A) => Promise<R>) =>
    (...args: A): Promise<R> => cancellable(() => operation(...args));
  const handle = (opened: Handle): Handle => {
    const close = () => { const closing = opened.close(); closing.catch(() => {}); return cancellable(() => closing); };
    // The scan uses only these three operations of a handle.
    return { stat: wrap(opened.stat.bind(opened)), read: wrap(opened.read.bind(opened) as (...args: unknown[]) => Promise<unknown>),
      close } as unknown as Handle;
  };
  const open = async (...args: Parameters<ScanFs['open']>): Promise<Handle> => {
    checkCancellation();
    const pending = raw.open(...args);
    try { return handle(await cancellable(() => pending)); }
    catch (error) {
      if (error instanceof Cancelled) pending.then(late => late.close()).catch(() => {});
      throw error;
    }
  };
  return { realpath: wrap(raw.realpath.bind(raw) as (...args: unknown[]) => Promise<unknown>),
    lstat: wrap(raw.lstat.bind(raw) as (...args: unknown[]) => Promise<unknown>),
    stat: wrap(raw.stat.bind(raw) as (...args: unknown[]) => Promise<unknown>),
    readdir: wrap(raw.readdir.bind(raw) as (...args: unknown[]) => Promise<unknown>),
    open } as unknown as ScanFs;
}

export async function scan(paths: string[], opts: ScanOptions = {}): Promise<ScanResult> {
  const io = cancellableFs(opts.fs ?? fs);
  const now = opts.clock?.() ?? new Date();
  const findings: ScanFinding[] = [];
  const skipped: ScanResult['skipped'] = [];
  const skippedPaths = new Set<string>();
  const scannedFiles = new Set<string>();
  // Files with findings by identity, with the index of the path argument that scanned them.
  const owners = new Map<string, { arg: number; findings: ScanFinding[] }>();
  let currentArg = -1;
  const secrets = new Set<string>();
  const ctx: ScanContext = { secrets, facts: new Map(), l402: new Map() };
  let filesScanned = 0;
  let dropped = 0;
  let ignored = 0;
  const ignoredFingerprints = new Set<string>();
  async function readIgnoreFile(path: string, optional: boolean): Promise<IgnoreEntry[]> {
    try {
      if (isProtectedPath(path) || isSystemDirectoryPath(path)) throw new InputError('input-read', 'cannot read ignore file');
      const stat = await io.lstat(path, { bigint: true });
      if (!stat.isFile() || stat.isSymbolicLink()) throw new InputError('input-read', 'cannot read ignore file');
      const target = await io.realpath(path);
      if (isProtectedPath(target) || isSystemDirectoryPath(target)) throw new InputError('input-read', 'cannot read ignore file');
      const handle = await io.open(target, SCAN_OPEN_FLAGS);
      let content: string;
      try {
        const openedStat = await handle.stat({ bigint: true });
        const openedPath = await io.realpath(target);
        const openedPathStat = await io.lstat(target, { bigint: true });
        if (!openedStat.isFile() || isProtectedPath(openedPath) || isSystemDirectoryPath(openedPath) ||
            openedPath !== target ||
            !openedPathStat.isFile() || openedPathStat.isSymbolicLink() ||
            !sameFileIdentity(openedPathStat, openedStat)) throw new InputError('input-read', 'cannot read ignore file');
        const bytes = await readBounded(handle, TEXT_LIMIT, openedStat.size);
        if (bytes.length > TEXT_LIMIT) throw new InputError('input-read', 'cannot read ignore file');
        // Same encodings as scanned text: UTF-8 with or without BOM, UTF-16 LE or BE with a BOM
        // (what Windows PowerShell 5.1 writes with '>' and Out-File).
        content = decodeText(bytes);
      } finally {
        await handle.close();
      }
      return parseIgnoreFile(content);
    } catch (error) {
      if (optional && (error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      if (error instanceof InputError || error instanceof IgnoreFileError || error instanceof Cancelled) throw error;
      throw new InputError('input-read', 'cannot read ignore file');
    }
  }
  const explicitIgnore = opts.ignoreFile === undefined ? null : await readIgnoreFile(opts.ignoreFile, false);
  const skip = (path: string, reason: string) => {
    const safePath = redactPath(reportedPath(path));
    if (!skippedPaths.has(safePath)) {
      skippedPaths.add(safePath);
      skipped.push({ path: safePath, reason });
    }
  };

  // A file scan runs concurrently, so it returns its outcome as an event. Events
  // are committed strictly in walk order, which keeps every observable result
  // (dedupe winner, skip reasons, counters) identical to a sequential walk.
  type FileEvent =
    | { type: 'skip'; path: string; reason: string; identity?: string }
    | { type: 'dup'; path: string; identity: string }
    | { type: 'file'; path: string; identity: string; findings: ScanFinding[]; dropped: number }
    | { type: 'error'; error: unknown };

  // The parent directory of a walked file: its resolved path and the identity the walk saw.
  type Parent = { real: string; stat: FileStat };

  // True when `real` still names the directory the walk listed. lstat resolves every component
  // of the path, so a component replaced by a symlink (whose own identity differs) or by any
  // other directory since then shows up as a different identity. One lstat costs O(path
  // length), never a resolution per component.
  async function unchanged(parent: Parent): Promise<boolean> {
    return sameFileIdentity(await io.lstat(parent.real, { bigint: true }), parent.stat);
  }

  /**
   * Scans one file. An explicit argument is resolved with realpath. A walked file is not: its
   * resolved path is its parent's resolved path joined with its name, because the walk never
   * follows a symlink. Instead its own lstat, and its parent's identity, are checked again just
   * before and after the open; only an entry that changed since the walk's lstat is resolved
   * (realpath), to tell a swapped-in link to a protected file (never-open) from other changes.
   */
  async function scanFileTask(path: string, sourceStat: FileStat, explicit: boolean, parent?: Parent): Promise<FileEvent> {
    let identity: string | undefined;
    try {
      let target: string;
      if (parent === undefined) {
        target = await io.realpath(path);
        if (isProtectedPath(target)) return { type: 'skip', path, reason: 'never-open' };
      } else {
        target = join(parent.real, basename(path));
        const current = await io.lstat(target, { bigint: true });
        if (current.isSymbolicLink() || !current.isFile()) {
          if (isProtectedPath(await io.realpath(target))) return { type: 'skip', path, reason: 'never-open' };
          return { type: 'skip', path, reason: current.isSymbolicLink() ? 'symlink' : 'not-regular' };
        }
        if (!await unchanged(parent)) throw new InputError('input-read');
      }
      const macaroonFile = isCredentialFileName(basename(path));
      if (!macaroonFile && BigInt(sourceStat.size) > BigInt(TEXT_LIMIT)) return { type: 'skip', path, reason: 'size' };
      let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
      let bytes: Buffer;
      try {
        handle = await io.open(target, SCAN_OPEN_FLAGS);
        const openedStat = await handle.stat({ bigint: true });
        if (!openedStat.isFile()) {
          if (explicit) return { type: 'error', error: new InputError('input-read', NOT_SCANNABLE) };
          return { type: 'skip', path, reason: 'not-regular' };
        }
        // Check the path again after open, including platforms without O_NOFOLLOW: it must
        // still be the regular file that was opened, under the same resolved path.
        const openedPathStat = await io.lstat(target, { bigint: true });
        const samePath = parent === undefined ? await io.realpath(target).then(openedPath =>
          !isProtectedPath(openedPath) && openedPath === target) : await unchanged(parent);
        if (!samePath || !openedPathStat.isFile() ||
            openedPathStat.isSymbolicLink() || !sameFileIdentity(openedPathStat, openedStat))
          throw new InputError('input-read');
        identity = fileIdentity(openedStat, target);
        if (scannedFiles.has(identity)) return { type: 'dup', path, identity };
        bytes = await readBounded(handle, macaroonFile ? MACAROON_LIMIT : TEXT_LIMIT, openedStat.size);
      } finally {
        if (handle) await handle.close();
      }
      // An exception from analysing bytes that were read is a bug, not an unreadable file: it must
      // stop the scan (exit 8) rather than look like a clean scan of a skipped file.
      let outcome: ReturnType<typeof scanBytes>;
      try { outcome = scanBytes('', bytes, macaroonFile, now, ctx, basename(path)); }
      catch (failure) { throw new ScanAnalysisFailure(failure); }
      if ('skip' in outcome) return { type: 'skip', path, reason: outcome.skip, identity };
      if (outcome.findings.length) {
        const safePath = redactPath(reportedPath(path));
        for (const finding of outcome.findings) finding.path = safePath;
      }
      return { type: 'file', path, identity, findings: outcome.findings, dropped: outcome.dropped };
    } catch (error) {
      if (error instanceof Cancelled || error instanceof ScanAnalysisFailure) throw error;
      if (explicit) return { type: 'error', error: new InputError('input-read', 'cannot read scan path') };
      return { type: 'skip', path, reason: 'unreadable', identity };
    }
  }

  function addFinding(finding: ScanFinding): void {
    if (findings.length >= FINDINGS_LIMIT) throw new FindingsLimitError();
    findings.push(finding);
  }

  // Another name of a file already scanned under the same path argument (a hard link) is
  // added to the alsoAt of that file's findings, so every path holding the credential is
  // reported. Names reached through a different argument stay silent (SPEC: several arguments).
  function alias(identity: string, path: string): void {
    const owner = owners.get(identity);
    if (!owner || owner.arg !== currentArg) return;
    const safePath = redactPath(reportedPath(path));
    for (const finding of owner.findings) {
      const also = finding.alsoAt ??= { count: 0, paths: [] };
      also.count++;
      if (also.paths.length < ALSO_AT_EXAMPLES) also.paths.push(safePath);
    }
  }

  // Applies one event. A file whose identity was already committed is a
  // duplicate, exactly as the sequential walk's check before reading.
  function commit(event: FileEvent): void {
    if (event.type === 'error') throw event.error;
    if (event.type === 'dup') { alias(event.identity, event.path); return; }
    if (event.identity !== undefined && scannedFiles.has(event.identity)) { alias(event.identity, event.path); return; }
    if (event.type === 'skip') { skip(event.path, event.reason); return; }
    for (const finding of event.findings) addFinding(finding);
    dropped += event.dropped;
    filesScanned++;
    scannedFiles.add(event.identity);
    if (event.findings.length) owners.set(event.identity, { arg: currentArg, findings: event.findings });
  }

  // Ordered, bounded dispatch: at most SCAN_CONCURRENCY file tasks run, and at
  // most SCAN_QUEUE results wait for earlier ones before being committed.
  const ready = new Map<number, FileEvent>();
  let dispatched = 0;
  let committed = 0;
  let running = 0;
  let wake: (() => void) | undefined;
  const signal = () => { const resume = wake; wake = undefined; resume?.(); };
  function drainReady(): void {
    while (ready.has(committed)) {
      const event = ready.get(committed)!;
      ready.delete(committed);
      committed++;
      commit(event);
    }
  }
  async function waitFor(condition: () => boolean): Promise<void> {
    drainReady();
    while (!condition()) {
      await new Promise<void>(resume => { wake = resume; });
      drainReady();
    }
  }
  async function emit(event: FileEvent): Promise<void> {
    ready.set(dispatched++, event);
    drainReady();
  }
  async function dispatch(path: string, stat: FileStat, parent: Parent): Promise<void> {
    checkCancellation();
    await waitFor(() => running < SCAN_CONCURRENCY && dispatched - committed < SCAN_QUEUE);
    const sequence = dispatched++;
    running++;
    void scanFileTask(path, stat, false, parent)
      .catch((error: unknown): FileEvent => ({ type: 'error', error }))
      .then(event => { running--; ready.set(sequence, event); signal(); });
  }
  async function settle(): Promise<void> {
    drainReady();
    await waitFor(() => committed === dispatched);
  }

  async function scanFile(path: string, sourceStat: FileStat, explicit: boolean): Promise<void> {
    await settle();
    commit(await scanFileTask(path, sourceStat, explicit));
  }

  // An interrupt ends the scan; it is never turned into an unreadable skip or exit 3.
  const rethrowCancelled = (error: unknown) => { if (error instanceof Cancelled) throw error; };

  type Entry = { stat: FileStat } | { error: true } | { protected: true } | { excluded: true };

  // `parent` is the walked directory that listed `path` (absent for a path argument). Resolved
  // paths are carried down the walk instead of calling realpath per entry: realpath resolves
  // every component, so per entry it made the walk's cost grow with the cube of its depth.
  async function walk(path: string, isRoot: boolean, rootStat?: FileStat, known?: Entry, parent?: Parent, rootReal?: string): Promise<void> {
    checkCancellation();
    const note = (target: string, reason: string) => emit({ type: 'skip', path: target, reason });
    if (isProtectedPath(path)) { await note(path, 'never-open'); return; }
    let entry: FileStat;
    if (known !== undefined) {
      if (!('stat' in known)) { await note(path, 'unreadable'); return; }
      entry = known.stat;
    } else {
      try {
        entry = await io.lstat(path, { bigint: true });
      } catch (error) {
        rethrowCancelled(error);
        if (isRoot) throw new InputError('input-read', 'cannot read scan path');
        await note(path, 'unreadable'); return;
      }
    }
    if (!isRoot && entry.isSymbolicLink()) { await note(path, 'symlink'); return; }
    const stat = rootStat ?? entry;
    if (stat.isDirectory()) {
      let target: string;
      if (rootReal !== undefined) target = rootReal;
      else if (parent === undefined) {
        try { target = await io.realpath(path); }
        catch (error) {
          rethrowCancelled(error);
          if (isRoot) throw new InputError('input-read', 'cannot read scan path');
          await note(path, 'unreadable'); return;
        }
      } else {
        // Not a symlink (refused above), so it resolves to its parent's resolved path plus its name.
        target = join(parent.real, basename(path));
      }
      if (isProtectedPath(target)) { await note(path, 'never-open'); return; }
      if (isSystemDirectoryPath(target)) { await note(path, 'excluded-dir'); return; }
      if (!opts.includeDirs && namedAs(basename(path), EXCLUDED_DIRS)) {
        await note(path, 'excluded-dir'); return;
      }
      let names: string[];
      try { names = await io.readdir(path); }
      catch (error) {
        rethrowCancelled(error);
        if (isRoot) throw new InputError('input-read', 'cannot read scan path');
        await note(path, 'unreadable'); return;
      }
      const rootListing = isRoot && reportedPath(path) === '/';
      const self: Parent = { real: target, stat };
      // Stat children in bounded batches, then visit them in listing order.
      // Protected and excluded names are never stat'ed, as before.
      for (let offset = 0; offset < names.length; offset += SCAN_CONCURRENCY) {
        const batch = names.slice(offset, offset + SCAN_CONCURRENCY).map(child => join(path, child));
        const entries = await Promise.all(batch.map(async (child): Promise<Entry> => {
          if (rootListing && namedAs(basename(child), ['proc', 'sys', 'dev'])) return { excluded: true };
          if (isProtectedPath(child)) return { protected: true };
          try { return { stat: await io.lstat(child, { bigint: true }) }; }
          catch (error) { rethrowCancelled(error); return { error: true }; }
        }));
        // The children's stats count only if this directory is still the one listed: a path
        // component swapped for a symlink would otherwise lead the walk outside the tree.
        let same: boolean;
        try { same = await unchanged(self); }
        catch (error) { rethrowCancelled(error); same = false; }
        if (!same) {
          if (isRoot) throw new InputError('input-read', 'cannot read scan path');
          await note(path, 'unreadable'); return;
        }
        for (let i = 0; i < batch.length; i++) {
          const known = entries[i];
          if ('excluded' in known) await note(batch[i], 'excluded-dir');
          else await walk(batch[i], false, undefined, known, self);
        }
      }
    } else if (stat.isFile()) {
      if (isRoot || parent === undefined) await scanFile(path, stat, true);
      else await dispatch(path, stat, parent);
    } else {
      await note(path, 'not-regular');
    }
  }

  const git = 'git';
  let blobsScanned = 0;
  let shallowHistory = false;
  // Only with several path arguments can a later history scan meet the same blob again;
  // then outcomes are remembered by blob name and use. Empty outcomes are only marked seen.
  const crossCall = paths.length > 1;
  const historySeen = new Set<string>();
  const historyOutcomes = new Map<string, BytesOutcome>();
  const EMPTY_OUTCOME: BytesOutcome = { findings: [], dropped: 0 };
  const SIZE_SKIP: BytesOutcome = { skip: 'size' };
  async function scanHistory(arg: string, stat: FileStat): Promise<void> {
    const directory = stat.isDirectory() ? arg : dirname(arg);
    const pathspec = stat.isDirectory() ? [] : [basename(arg)];
    // Validate every location git would read before any git process starts.
    const repository = await locateRepository(directory);
    await assertWorkTree(git, directory, repository);
    if (await isShallowRepository(git, directory, repository)) {
      if (!opts.allowShallow) throw new GitHistoryError('git history is shallow, so older commits cannot be scanned; '
        + 'fetch the full history first (for example actions/checkout with fetch-depth: 0) or pass --allow-shallow');
      shallowHistory = true;
    }
    // A credential still present in the work tree is already reported by the walk.
    // That includes a work-tree file's other hard-link names (its alsoAt).
    const workTree = new Set(findings.flatMap(finding =>
      [finding.path, ...(finding.commit === undefined ? finding.alsoAt?.paths ?? [] : [])]
        .map(path => `${path}\0${finding.fingerprint}`)));
    const table = await historyEntries(git, directory, repository, pathspec);
    // Per distinct path: CLASSIFIED, MACAROON (*.macaroon), EXCLUDED (protected or in an
    // excluded directory), and whether a skip was already reported for it (skips are
    // de-duplicated by path anyway; this only avoids repeating the work).
    const CLASSIFIED = 1, MACAROON = 2, EXCLUDED = 4, MODE_SKIPPED = 8, OUTCOME_SKIPPED = 16;
    const pathState = new Uint8Array(table.paths.length);
    const joined = (index: number) => join(directory, table.paths[index]);
    const usage = new Uint8Array(table.blobs.length); // bit 1: as text, bit 2: as *.macaroon
    const wanted = new Uint32Array(table.length);
    let wantedCount = 0;
    for (let at = 0; at < table.length; at++) {
      if ((at & 4095) === 0) checkCancellation();
      const p = table.path[at];
      if (!(pathState[p] & CLASSIFIED)) {
        pathState[p] |= CLASSIFIED;
        const relativePath = table.paths[p];
        const parents = relativePath.split('/').slice(0, -1);
        // Same comparison as the file walk, so history and work tree agree.
        const excluded = parents.findIndex(segment => namedAs(segment, EXCLUDED_DIRS));
        if (isProtectedPath(joined(p))) { skip(joined(p), 'never-open'); pathState[p] |= EXCLUDED; }
        else if (!opts.includeDirs && excluded !== -1) {
          skip(join(directory, ...parents.slice(0, excluded + 1)), 'excluded-dir'); pathState[p] |= EXCLUDED;
        } else if (isCredentialFileName(basename(relativePath))) pathState[p] |= MACAROON;
      }
      if (pathState[p] & EXCLUDED) continue;
      if (table.mode[at] !== MODE_REGULAR) {
        if (!(pathState[p] & MODE_SKIPPED)) {
          pathState[p] |= MODE_SKIPPED;
          skip(joined(p), table.mode[at] === MODE_SYMLINK ? 'symlink' : 'not-regular');
        }
        continue;
      }
      usage[table.blob[at]] |= pathState[p] & MACAROON ? 2 : 1;
      wanted[wantedCount++] = at;
    }
    // Which uses of each blob already have an outcome from an earlier path argument.
    const done = new Uint8Array(table.blobs.length);
    const outcomes = new Map<number, BytesOutcome>();
    const reading: number[] = [];
    for (let b = 0; b < usage.length; b++) {
      if (!usage[b]) continue;
      if (crossCall) for (const bit of [1, 2]) {
        const key = `${table.blobs[b]}:${bit === 2}`;
        if (usage[b] & bit && historySeen.has(key)) {
          done[b] |= bit;
          const prior = historyOutcomes.get(key);
          if (prior) outcomes.set(b * 2 + (bit === 2 ? 1 : 0), prior);
        }
      }
      if (usage[b] & ~done[b]) reading.push(b);
    }
    const names = reading.map(b => table.blobs[b]);
    const sizes = await blobSizes(git, directory, repository, names);
    const needs = (i: number) => usage[reading[i]] & ~done[reading[i]];
    // Like the walk: text is read up to TEXT_LIMIT; a larger *.macaroon blob keeps only its
    // first MACAROON_LIMIT + 1 bytes and is reported undecodable with that fingerprint.
    const keep = (i: number) => sizes[i] <= TEXT_LIMIT ? sizes[i] : needs(i) & 2 ? MACAROON_LIMIT + 1 : 0;
    const readable: number[] = [];
    for (let i = 0; i < reading.length; i++) if (keep(i) > 0) readable.push(i);
    await readBlobs(git, directory, repository, readable.map(i => names[i]), j => keep(readable[j]), (j, bytes) => {
      checkCancellation();
      const i = readable[j];
      const b = reading[i];
      blobsScanned++;
      for (const bit of [1, 2]) {
        if (!(needs(i) & bit)) continue;
        const macaroonFile = bit === 2;
        const outcome = !macaroonFile && sizes[i] > TEXT_LIMIT ? SIZE_SKIP : scanBytes('', bytes, macaroonFile, now, ctx);
        const empty = !('skip' in outcome) && outcome.findings.length === 0;
        done[b] |= bit;
        if (!empty) outcomes.set(b * 2 + (macaroonFile ? 1 : 0), outcome);
        if (crossCall) {
          const key = `${table.blobs[b]}:${macaroonFile}`;
          historySeen.add(key);
          if (!empty) historyOutcomes.set(key, outcome);
        }
      }
    });
    // Oldest first. A credential is reported at the oldest commit and path where that exact
    // (path, fingerprint) pair is new; it is skipped only where that pair was already reported
    // (by the work tree or an older blob). Per (blob, use) a record keeps the blob's
    // credentials still waiting for such a path, so a credential already reported at the
    // blob's first path is reported at its next new path instead of being lost.
    // Every later path that added the same content is counted in that finding's alsoAt.
    // Work per extra path is O(1) once nothing is pending: a shared visit counter, and each
    // finding records the visit index it was reported at. Memory grows with distinct blob
    // findings, never with paths x findings.
    type BlobRecord = { visits: number; keepUntil: number; paths: { index: number; path: string }[];
      reported: { finding: ScanFinding; index: number }[]; pending: ScanFinding[] };
    const emittedAt = new Set<string>();
    const seenPairs = new Set<number>();
    const records = new Map<number, BlobRecord>();
    const pathCount = table.paths.length;
    const safePaths = new Map<number, string>();
    let dedupWork = 0;
    for (let w = 0; w < wantedCount; w++) {
      if ((w & 4095) === 0) checkCancellation();
      const at = wanted[w];
      const b = table.blob[at];
      const p = table.path[at];
      const bit = pathState[p] & MACAROON ? 2 : 1;
      // A blob never read (a text blob over the size limit) is skipped for size, as before.
      const outcome = outcomes.get(b * 2 + (bit === 2 ? 1 : 0)) ?? (done[b] & bit ? EMPTY_OUTCOME : SIZE_SKIP);
      if ('skip' in outcome) {
        if (!(pathState[p] & OUTCOME_SKIPPED)) { pathState[p] |= OUTCOME_SKIPPED; skip(joined(p), outcome.skip); }
        continue;
      }
      if (!outcome.findings.length) continue;
      // The same blob at the same path again (re-added later) adds nothing new.
      const pair = b * pathCount + p;
      if (seenPairs.has(pair)) continue;
      seenPairs.add(pair);
      let safePath = safePaths.get(p);
      if (safePath === undefined) safePaths.set(p, safePath = redactPath(reportedPath(joined(p))));
      // Keyed by blob and use: the same blob read as text and as a *.macaroon file gives
      // different findings, and neither may be folded into the other.
      const use = b * 2 + (bit === 2 ? 1 : 0);
      let record = records.get(use);
      if (!record) {
        // A credential repeated inside one blob is one credential.
        const unique: ScanFinding[] = [];
        const inBlob = new Set<string>();
        for (const finding of outcome.findings) {
          if (inBlob.has(finding.fingerprint)) continue;
          inBlob.add(finding.fingerprint);
          unique.push(finding);
        }
        record = { visits: 0, keepUntil: ALSO_AT_EXAMPLES, paths: [], reported: [], pending: unique };
        records.set(use, record);
      }
      const index = record.visits++;
      // Example paths are kept only near the visits where something was reported.
      if (index > 0 && index <= record.keepUntil) record.paths.push({ index, path: safePath });
      if (!record.pending.length) continue;
      const still: ScanFinding[] = [];
      for (const finding of record.pending) {
        if (++dedupWork > HISTORY_DEDUP_WORK_LIMIT)
          throw new FindingsLimitError('git history deduplication exceeded its work limit; the scan stops rather than report a partial result. '
            + 'Narrow the scan paths');
        const atPath = `${safePath}\0${finding.fingerprint}`;
        if (workTree.has(atPath) || emittedAt.has(atPath)) { still.push(finding); continue; }
        const reported: ScanFinding = { ...finding, path: safePath, commit: table.commits[table.commit[at]] };
        addFinding(reported);
        emittedAt.add(atPath);
        record.reported.push({ finding: reported, index });
        record.keepUntil = Math.max(record.keepUntil, index + ALSO_AT_EXAMPLES);
      }
      record.pending = still;
    }
    for (const record of records.values()) {
      for (const { finding, index } of record.reported) {
        const count = record.visits - 1 - index;
        if (count <= 0) continue;
        const paths = record.paths.filter(item => item.index > index).slice(0, ALSO_AT_EXAMPLES).map(item => item.path);
        finding.alsoAt = { count, paths };
      }
    }
  }

  for (const arg of paths) {
    currentArg++;
    if (isProtectedPath(arg)) { skip(arg, 'never-open'); continue; }
    let stat: FileStat;
    let target: string;
    try {
      target = await io.realpath(arg);
      if (isProtectedPath(target)) { skip(arg, 'never-open'); continue; }
      if (isSystemDirectoryPath(target)) { skip(arg, 'excluded-dir'); continue; }
      stat = await io.stat(arg, { bigint: true });
    }
    catch (error) {
      if (error instanceof Cancelled) throw error;
      throw new InputError('input-read', 'cannot read scan path');
    }
    // A named FIFO, device or socket cannot be scanned. Skipping it would let a CI gate pass
    // having scanned nothing, so it fails like an unreadable path.
    if (!stat.isFile() && !stat.isDirectory()) throw new InputError('input-read', NOT_SCANNABLE);
    const entries = explicitIgnore ?? (stat.isDirectory() ? await readIgnoreFile(join(arg, '.macwardenignore'), true) : []);
    const firstFinding = findings.length;
    // The argument was resolved above; the walk starts from that resolved path.
    await walk(arg, true, stat, undefined, undefined, target);
    await settle();
    if (opts.gitHistory) await scanHistory(arg, stat);
    if (entries.length) {
      const byFingerprint = new Map<string, IgnoreEntry[]>();
      for (const entry of entries) {
        const list = byFingerprint.get(entry.fingerprint);
        if (list) list.push(entry); else byFingerprint.set(entry.fingerprint, [entry]);
      }
      // Findings in one file share a path, so each (fingerprint, path) is matched once.
      const decided = new Map<string, boolean>();
      let kept = firstFinding;
      for (let i = firstFinding; i < findings.length; i++) {
        const finding = findings[i];
        const candidates = byFingerprint.get(finding.fingerprint);
        let drop = false;
        if (candidates) {
          const ignoredAt = (path: string): boolean => {
            const matchPath = explicitIgnore === null ? relative(arg, path).split(sep).join('/') : path;
            const key = `${finding.fingerprint}\0${matchPath}`;
            const known = decided.get(key);
            const result = known ?? candidates.some(entry => entry.matches(matchPath));
            if (known === undefined) decided.set(key, result);
            return result;
          };
          const also = finding.alsoAt;
          drop = ignoredAt(finding.path) && (!also || (also.count === also.paths.length && also.paths.every(ignoredAt)));
        }
        if (drop) { ignoredFingerprints.add(finding.fingerprint); ignored++; }
        else findings[kept++] = finding;
      }
      findings.length = kept;
    }
  }
  if (secrets.size) {
    // One matcher for every known secret; strings are rewritten only when they change.
    const redact = knownSecretRedactor(secrets);
    const array = (values: string[]) => {
      const safe = values.map(redact);
      return safe.every((value, i) => value === values[i]) ? values : safe;
    };
    for (const finding of findings) {
      finding.path = redact(finding.path);
      if (finding.alsoAt) finding.alsoAt.paths = finding.alsoAt.paths.map(redact);
      if (finding.permissions) finding.permissions = array(finding.permissions);
      if (finding.caveats) {
        const caveats = finding.caveats.map(caveat => {
          const value = redact(caveat.value);
          return value === caveat.value ? caveat : { ...caveat, value };
        });
        finding.caveats = caveats.every((caveat, i) => caveat === finding.caveats![i]) ? finding.caveats : caveats;
      }
      finding.unassessed = array(finding.unassessed);
      if (finding.l402) finding.l402 = redactL402(finding.l402, redact);
    }
    for (const item of skipped) item.path = redact(item.path);
  }
  findings.sort((a, b) => byteCompare(a.path, b.path) || (a.line ?? -1) - (b.line ?? -1) ||
    (a.column ?? -1) - (b.column ?? -1) || byteCompare(a.commit ?? '', b.commit ?? ''));
  skipped.sort((a, b) => byteCompare(a.path, b.path));
  const byGrade: ScanResult['summary']['byGrade'] = {
    ADMIN: 0, SPEND: 0, OPERATE: 0, RECEIVE: 0, READ: 0, UNASSESSED: 0, NWC: 0, UNDECODABLE: 0, L402: 0,
  };
  for (const finding of findings) {
    const key = finding.grade ?? (finding.kind === 'nwc' ? 'NWC' : finding.kind === 'l402' || finding.kind === 'l402-file'
      ? 'L402' : 'UNDECODABLE');
    byGrade[key]++;
  }
  const filesSkipped = skipped.length;
  return { findings, skipped,
    ...(ignoredFingerprints.size ? { ignoredFingerprints: [...ignoredFingerprints].sort(byteCompare) } : {}),
    summary: {
    filesScanned, filesSkipped, dropped, ignored,
    findings: findings.length, distinct: new Set(findings.map(finding => finding.fingerprint)).size,
    ...(opts.gitHistory ? { blobsScanned } : {}), ...(shallowHistory ? { shallowHistory: true as const } : {}), byGrade,
  }, failOn: null };
}
