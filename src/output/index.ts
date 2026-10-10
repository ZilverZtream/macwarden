import { githubLines, sarifPieces } from './scan-formats.js';
import { parseLndconnect } from '../input/lndconnect.js';
import { macaroonEnds } from '../decode/recognition.js';
import { types } from 'node:util';
import { lndconnect } from '../scan/patterns.js';
import { replaceNwc } from '../scan/nwc-match.js';
import { redactEncodedCredentials } from '../credential-recognition.js';
import { collectNwcSecrets, redactKnownSecrets, redactL402Text } from '../scan/redact.js';
import { redactRuneContexts } from '../scan/rune-context.js';
import type { RegistryEntry } from '../registry/index.js';
import { shellQuote } from '../online.js';
import { dirname, join } from 'node:path';

export type Mode = 'text' | 'json';
export type OutputWarning = string | { code: string; message: string };

export type InspectResult = {
  fingerprint: string; location: string | null; rootKeyId: string; permissions: string[];
  caveats: import('../decode/index.js').Caveat[]; grade: string; reasons: string[];
  warnings: string[]; unassessed: string[]; snapshot: string;
};
// Core Lightning rune facts (1.2.0); the authenticator and the decoded string are never part of it.
export type RuneInspectResult = {
  kind: 'rune'; fingerprint: string; grade: string; reasons: string[]; unassessed: string[];
  rune: import('../rune-report.js').RuneReport;
};
// NIP-47 connection facts; the connection secret is never part of the result.
export type NwcInspectResult = {
  kind: 'nwc'; fingerprint: string; walletPubkey: string; clientPubkey: string; relays: string[];
  lud16: string | null; grade: 'SPEND'; reasons: string[]; warnings: string[];
};
/** L402 credential facts; neither the preimage nor the macaroon bytes are part of the result. */
export type L402InspectResult = { kind: 'l402'; fingerprint: string } & import('../l402.js').L402Report;
export type InventoryResult = {
  node: { pubkey: string; alias: string; network: string; version: string };
  rootKeys: { rootKeyId: string; flags: string[]; verify: string;
    /** Earliest time-before of an active entry LND holds (RFC 3339 UTC), else null. */
    expires?: string | null;
    entry: Pick<RegistryEntry, 'label' | 'grade' | 'permissions' | 'caveats' | 'createdAt' | 'status' | 'fingerprint' | 'outPath' | 'replaces' | 'replacedBy'> | null;
    usage?: { calls: number; errors: number; lastUsed: string; methods: string[] };
    /** Present only when watch's canary guard denied uses of this root key ID. */
    canary?: { uses: number; firstUse: string; lastUse: string } }[];
  /** Present only with --expiring-within: the window and how many active credentials fall in it. */
  expiring?: { within: string; count: number };
  report?: { format: import('../report/access-review.js').ReportFormat; path: string | null;
    review: import('../report/access-review.js').AccessReview };
};
/** verify: the offline facts inspect reports, plus LND's answer for this one credential. */
export type VerifyResult = InspectResult & {
  node: { pubkey: string; alias: string; network: string };
  status: 'accepted' | 'rejected';
  /** Why LND rejected it; null when accepted. 'expired': rejected while a time-before caveat has passed. */
  rejection: 'root-key-missing' | 'signature-mismatch' | 'expired' | 'other' | null;
  /** false when a rejection may depend on the caller (IP lock, custom caveat): treat the credential as live. */
  conclusive: boolean;
  /** Whether ListMacaroonIDs lists the root key ID; null when the own credential cannot call it. */
  rootKeyListed: boolean | null;
  /** The credential shares the root key ID of macwarden's own credential. */
  ownCredential: boolean;
  /** macaroon:generate, the BakeMacaroon URI, or authority not fully assessed: a holder can or may bake further credentials (not the ADMIN grade alone). */
  canBake: boolean;
  registry: { label: string | null; status: 'active' | 'revoked'; match: 'fingerprint' | 'root-key-id' } | null;
  guidance: string[];
};
export type AttenuateResult = InspectResult & { dryRun: boolean; out: string | null;
  parentFingerprint: string; added: string[] };
export type BakePlan = { dryRun: true; label: string; permissions: string[]; grade: string;
  caveats: { type: string; value: string }[]; canary?: true };
export type WatchEvent =
  | { event: 'call' | 'error'; time: string; method: string; rootKeyId: string; credential: string; label: string | null }
  | { event: 'canary'; time: string; method: string; rootKeyId: string; credential: string; label: string | null; denied: true;
      /** Further denied uses folded into this alert since the previous one for the same canary. */
      repeats?: number }
  | { event: 'status'; time: string; status: 'registered' | 'reconnecting'; canaries: number; readOnly: true }
  | { event: 'status'; time: string; status: 'output-dropped'; dropped: number }
  | { event: 'status'; time: string; status: 'alert-failed'; rootKeyId: string; label: string | null }
  /** The payment journal stopped before the run ended; payments after this are not journaled. */
  | { event: 'status'; time: string; status: 'payment-journal-stopped'; reason: 'full' | 'write-failed' | 'stalled' };
export type WatchResult = { node: string; startedAt: string; endedAt: string; calls: number; errors: number;
  credentials: number; canaryAlerts: number; canaryUses: number; alertFailures: number; reconnects: number; canaries: number; usageFile: string;
  droppedUsageRecords: number;
  /** Usage records evicted (least recently seen first) to stay within the store limit. */
  evictedUsageRecords: number; droppedEvents: number 
  /** Calls whose attribution was dropped because callers outpaced it (the RPCs themselves were answered). */
  droppedAttributions?: number;
  /** Present with --payment-journal: records written this run, calls not journaled, and why journaling stopped early. */
  paymentJournal?: { path: string; payments: number; deletions: number; dropped: number; stopped: 'full' | 'write-failed' | 'stalled' | null } };
/** One journaled payment request, as reconcile reports it (observation evidence). */
export type ReconcileObservation = { time: string; run: string; requestId: string; method: string; credential: string; rootKeyId: string;
  label: string | null; amountMsat: string | null; amountSource: 'request' | 'invoice' | 'route' | null; feeLimitMsat: string | null;
  extraction: string };
/** What LND reports for one payment hash (settlement evidence); amounts in millisatoshi as decimal strings. */
export type ReconcileSettlement = { status: 'succeeded' | 'failed' | 'in-flight' | 'not-found' | 'unknown';
  source: 'list-payments' | 'track-payment' | null; createdAt: string | null; settledMsat: string | null; feesMsat: string | null;
  inFlightMsat: string | null; attempts: number | null; failureReason: string | null; predatesObservation: boolean };
export type ReconcilePayment = { paymentHash: string; attribution: 'single' | 'ambiguous' | 'historical'; credentials: string[];
  observation: { first: string; last: string; calls: number; requestedMsat: string | null; routeAttemptsMsat: string | null;
    feeLimitMsat: string | null; observations: ReconcileObservation[] };
  settlement: ReconcileSettlement; deletedBy: string[] };
export type ReconcileCredential = { credential: string; rootKeyIds: string[]; label: string | null; payments: number; succeeded: number;
  failed: number; inFlight: number; notFound: number; unknown: number; ambiguous: number; historical: number; unmatched: number;
  deletions: number; requestedMsat: string; settledMsat: string; feesMsat: string; inFlightMsat: string };
export type ReconcileUnattributed = { paymentHash: string; createdAt: string; status: 'succeeded' | 'failed' | 'in-flight' | 'unknown';
  settledMsat: string; feesMsat: string; inFlightMsat: string; attempts: number; failureReason: string | null;
  coverage: 'covered' | 'boundary' | 'gap' };
export type ReconcileResult = {
  node: { pubkey: string; alias: string; network: string };
  journal: { path: string; size: number; runs: number; records: number; firstRecord: string | null; lastRecord: string | null;
    otherNodeRecords: number; tornTail: boolean; repairedLines: number };
  window: { since: string; until: string };
  coverage: { windowSeconds: number; coveredSeconds: number; complete: boolean; gapCount: number; gapSeconds: number;
    gaps: { from: string; to: string; reason: string; dropped: number }[] };
  credentials: ReconcileCredential[];
  payments: ReconcilePayment[];
  unmatched: ReconcileObservation[];
  unattributed: ReconcileUnattributed[];
  deletions: { time: string; run: string; requestId: string; method: string; credential: string; rootKeyId: string; label: string | null;
    scope: string; paymentHash: string | null; extraction: string }[];
  lookups: { listed: number; listTruncated: boolean; tracked: number; trackFailed: number; trackLimited: number; attributedOutsideWindow: number };
};
export type RecommendResult = { node: string; selector: string; label: string | null; rootKeyId: string | null;
  credentials: string[]; observed: { method: string; calls: number; lastUsed: string; permissions: string[] }[];
  unmapped: string[]; recommended: string[]; recommendedUris: string[]; current: string[] | null; unneeded: string[];
  /** How long watch observed the node (seconds null: unknown); short below the 7-day threshold. */
  observation: { seconds: number | null; since: string | null; until: string | null; sessions: number; short: boolean; accepted: boolean };
  commands: string[] };
type Display = { now?: number; report?: string; alreadyAbsent?: boolean; finish?: { next: RegistryEntry; repaired: boolean };
  /** scan only: a CI format chosen with --format, the directory paths are relative to, and the tool version. */
  format?: 'sarif' | 'github'; scanRoot?: string; toolVersion?: string };
type Envelope = { schema?: 1; exitCode?: number; warnings: OutputWarning[]; display?: Display };
type Success<C extends string | null, R> = Envelope & { command: C; ok: true; result: R; error: null };
export type OutputResult =
  | (Envelope & { command: string | null; ok: false; result: null;
      error: { code: number; step: string | null; message: string } })
  | Success<'inspect', InspectResult | NwcInspectResult | L402InspectResult | RuneInspectResult>
  | Success<'scan', import('../scan/index.js').ScanResult>
  | (Success<'inventory', InventoryResult> & { display: { now: number } })
  | Success<'attenuate', AttenuateResult>
  | Success<'bake', BakePlan | RegistryEntry>
  | Success<'revoke', RevokePlan | RevokeResult>
  | Success<'rotate', RotatePlan | RotateStagedResult | RotateFinishedResult>
  | Success<'watch', WatchResult>
  | Success<'recommend', RecommendResult>
  | Success<'respond', RespondResult>
  | Success<'verify', VerifyResult>
  | Success<'reconcile', ReconcileResult>
  | Success<null, { text: string }>;

import type { RevokePlan, RevokeResult, RotatePlan, RotateStagedResult, RotateFinishedResult, RespondResult } from '../command-result.js';
export type { RevokePlan, RevokeResult, RotatePlan, RotateStagedResult, RotateFinishedResult, RespondResult } from '../command-result.js';

export function rotatePlanResult(plan: RotatePlan, next: RegistryEntry, warnings: OutputWarning[], repaired: boolean): OutputResult & { schema: 1 } {
  return { schema: 1, command: 'rotate', ok: true, warnings, result: plan, error: null, display: { finish: { next, repaired } } };
}

// Display-only context keeps the prescribed dry-run JSON result unchanged.
export function revokePlanResult(plan: RevokePlan, warnings: OutputWarning[], alreadyAbsent: boolean): OutputResult & { schema: 1 } {
  const result: OutputResult & { schema: 1 } = {
    schema: 1, command: 'revoke', ok: true, warnings, result: plan, error: null,
  };
  result.display = { alreadyAbsent };
  return result;
}

const lndconnectAll = new RegExp(lndconnect.source, `${lndconnect.flags}g`);

function hasCredentialInLndconnect(value: string): boolean {
  const bytes = parseLndconnect(value);
  return bytes !== null && macaroonEnds(bytes)(0) !== null;
}

// A complete macaroon is at least SHORTEST_MACAROON bytes: a version byte, an identifier
// packet, the section ends and a 32-byte signature packet (34 bytes on its own). Every
// encoding the recognizer reads (hex, base64, percent and backslash escapes, decimal
// arrays, raw bytes) needs at least one printable ASCII character per byte, and URI
// credentials are longer still, so a printable ASCII string shorter than that can hold
// no credential and is returned unchanged without running recognition.
const SHORTEST_MACAROON = 36;
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;
// Rendering visits the same strings (paths, kinds, permissions) many times.
const redacted = new Map<string, string>();
const MEMO_LIMIT = 50_000;
const MEMO_MAX_LENGTH = 4096;

function redact(text: string): string {
  if (text.length < SHORTEST_MACAROON && PRINTABLE_ASCII.test(text)) return text;
  const memo = text.length <= MEMO_MAX_LENGTH ? redacted.get(text) : undefined;
  if (memo !== undefined) return memo;
  const safe = redactUncached(text);
  if (text.length <= MEMO_MAX_LENGTH) {
    if (redacted.size >= MEMO_LIMIT) redacted.clear();
    redacted.set(text, safe);
  }
  return safe;
}

function redactUncached(text: string): string {
  lndconnectAll.lastIndex = 0;
  const withLndconnectRedacted = redactRuneContexts(text).replace(lndconnectAll, match => hasCredentialInLndconnect(match) ? '[redacted]' : match);
  // NWC URIs through the linear matcher: the published regex backtracks quadratically on
  // repeated prefixes. The match consumes one delimiter after the secret, which is kept.
  const withUrisRedacted = replaceNwc(withLndconnectRedacted,
    match => `[redacted]${/[^0-9a-f]$/i.test(match) ? match.slice(-1) : ''}`);
  // L402 Authorization credentials and macaroon:preimage pairs, which carry a preimage.
  return redactEncodedCredentials(redactL402Text(withUrisRedacted));
}

function assertPlain(value: unknown, seen = new WeakSet<object>()): void {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return;
  if (typeof value !== 'object' || types.isProxy(value) || seen.has(value)) {
    throw new Error('internal output value');
  }
  seen.add(value);
  const prototype: unknown = Object.getPrototypeOf(value);
  if (Array.isArray(value) ? prototype !== Array.prototype
    : prototype !== Object.prototype && prototype !== null) {
    throw new Error('internal output value');
  }
  // Symbol-keyed values are omitted by JSON.stringify and Object.values.
  // Reject them before rendering so hidden bytes cannot bypass validation.
  if (Object.getOwnPropertySymbols(value).length) throw new Error('internal output value');
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!('value' in descriptor)) throw new Error('internal output value');
    assertPlain(descriptor.value, seen);
  }
  seen.delete(value);
}

function jsonRedactor(): (key: string, value: unknown) => unknown {
  const renamed = new WeakSet<object>();
  return (_key, value) => {
    if (typeof value === 'string') return redact(value);
    if (!value || typeof value !== 'object' || Array.isArray(value) || renamed.has(value)) {
      return value;
    }
    // JSON.stringify visits values through the replacer, but not object keys.
    // Rename keys before it serializes the object; subsequent visits redact values.
    const safe = Object.fromEntries(Object.entries(value).map(([key, item]) => [redact(key), item]));
    renamed.add(safe);
    return safe;
  };
}

// eslint-disable-next-line no-control-regex, no-misleading-character-class
const UNSAFE_TEXT = /[\x00-\x1f\x7f-\xa0\u034f\u115f\u1160\u1680\u17b4\u17b5\u180b-\u180f\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\u3164\ufe00-\ufe0f\uffa0\u{e0000}-\u{e0fff}\p{Cf}]/gu;
function safeText(value: string): string {
  // Control characters, the Unicode bidirectional controls that can make a terminal show
  // text in a different order than it is stored (Trojan Source), and Unicode whitespace
  // other than the plain space are escaped. A CI runner trims Unicode whitespace before it
  // looks for a '::' workflow command, so none may reach a line start unescaped. The
  // legacy '##[' command marker is recognised anywhere in a line, so it is escaped too.
  // Invisible characters are escaped as well, so a name cannot look like a different file:
  // every format character (Unicode Cf: soft hyphen, zero-width characters, word joiner,
  // tags), the Hangul fillers, the combining grapheme joiner and the variation selectors.
  return redact(value).replace(UNSAFE_TEXT, character => {
    const code = character.codePointAt(0)!;
    return code < 0x100 ? `\\x${code.toString(16).padStart(2, '0')}`
      : code <= 0xffff ? `\\u${code.toString(16).padStart(4, '0')}` : `\\u{${code.toString(16)}}`;
  }).replace(/##\[/g, '##\\x5b');
}

/**
 * Text output is often read by CI runners. No line may start, after spaces, with '::'
 * (a GitHub Actions workflow command such as ::stop-commands:: or ::add-mask::), whatever
 * value reaches the line start. The colon is shown escaped; the rest of the line is kept.
 */
function guardLines(text: string): string {
  return text.replace(/^( *)::/gm, '$1\\x3a:');
}

export function error(stage: string, message: string): string {
  return `error: ${safeText(stage)}${message ? `: ${safeText(message)}` : ''}\n`;
}

const warningMessages: Record<string, string> = {
  'unsafe-arg': 'literal credentials can appear in shell history and process listings',
  'own-root-key-0': 'own credential uses root key ID 0',
  'snapshot-drift': 'LND method permissions differ from the bundled snapshot',
  'acl-best-effort': "the volume stores no Windows permissions (FAT or exFAT): anyone with access to the volume can read the file",
  'usage-unreadable': 'the watch usage file could not be read; last-used data is omitted',
  'usage-write-failed': 'the watch usage file could not be written; usage since the last save is lost',
  'canary-requires-watch': 'LND accepts this canary only while macwarden watch runs; a running watch picks it up within 60 seconds (or at its next reconnect), then denies and alerts on every use its permissions allow',
  'shallow-history': 'git history is shallow; commits before the shallow boundary were not scanned',
};

export function warning(value: OutputWarning): string {
  const code = typeof value === 'string' ? value : value.code;
  const message = typeof value === 'string' ? warningMessages[code] ?? code : value.message;
  return `warning: ${safeText(code)}: ${safeText(message)}\n`;
}

// One line per finding, so a large scan never becomes a single string.
function* scanTextLines(result: import('../scan/index.js').ScanResult): Generator<string> {
  const { findings } = result;
  for (const finding of findings) {
    // A scanned file name is attacker input. A text line that starts with '::' is a
    // GitHub Actions workflow command (::add-mask::, ::stop-commands::), so such a
    // relative path is printed as ./path; it names the same file.
    const path = /^[\s\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*:/.test(finding.path)
      ? `./${finding.path}` : finding.path;
    const others = finding.alsoAt ? `${finding.alsoAt.count} other path${finding.alsoAt.count === 1 ? '' : 's'}` : '';
    // A work-tree finding's alsoAt lists the file's other hard-link names: they are named, since
    // removing the credential from one name leaves it readable under the others.
    const also = !finding.alsoAt ? '' : finding.commit !== undefined ? ` (same content also added at ${others})`
      : ` (same file also at ${others}: ${finding.alsoAt.paths.map(safeText).join(', ')}`
        + `${finding.alsoAt.count > finding.alsoAt.paths.length ? ', ...' : ''})`;
    const location = `${finding.commit === undefined ? '' : `${finding.commit.slice(0, 7)}:`}${path}` +
      (finding.line === null ? '' : `:${finding.line}:${finding.column}`);
    const counted = finding.kind === 'nwc' ? ' (counted as SPEND)'
      : finding.kind === 'undecodable' || finding.kind === 'undecodable-candidate'
        ? ' (counted as ADMIN)'
        : finding.l402 ? ` ${safeText(finding.l402.status)} ${finding.l402.countedAs ? `(counted as ${finding.l402.countedAs})` : '(not counted)'}` : '';
    const grade = finding.grade ? ` ${finding.grade === 'UNASSESSED'
      ? 'UNASSESSED (treat as SPEND or worse)' : finding.grade}` : '';
    const root = finding.rootKeyId === null ? '' : ` root key ${finding.rootKeyId}`;
    // Like inspect: a time-before caveat already in the past makes the credential unusable.
    const expired = finding.caveats?.some(caveat => caveat.type === 'time-before' && caveat.expired === true) ? ' (expired)' : '';
    const rune = finding.rune ? runeLineFacts(finding.rune) : '';
    yield `${safeText(location)}  ${safeText(finding.kind)}  ${safeText(finding.fingerprint)}${grade}${root}${expired}${counted}${rune}${finding.context === 'mcp-config' ? ' (MCP server config)' : ''}${also}\n`;
  }
  yield* scanSummaryLines(result);
}

type RuneFacts = NonNullable<import('../scan/index.js').ScanFinding['rune']>;
const runeInvalidText: Record<string, string> = {
  'exceeds-bounds': 'longer than macwarden parses', 'not-base64url': 'not URL-safe base64', 'too-short': 'shorter than a rune',
  'nul-byte': 'NUL byte in its restrictions', 'restriction-syntax': 'restriction syntax error',
  'unique-id-placement': 'misplaced unique ID',
  'no-unique-id': 'no unique ID, which checkrune requires', 'unique-id-not-numeric': 'unique ID is not a number checkrune accepts',
};

/** A scan text line's rune facts: unique ID, possible capabilities, method access, expiry; never node acceptance. */
function runeLineFacts(rune: RuneFacts): string {
  if (rune.recognition === 'invalid')
    return ` (in rune context, does not parse as a rune: ${safeText(runeInvalidText[rune.reason] ?? rune.reason)})`;
  const parts: string[] = [];
  parts.push(rune.uniqueId === null ? 'no unique ID' : `unique ID ${safeText(rune.uniqueId)}`);
  if (rune.methods === 'none') parts.push('no method can pass');
  else parts.push(`may allow ${rune.capabilities.map(safeText).join(', ') || 'unreviewed methods'}`);
  if (rune.methods === 'broad') parts.push('broad method access');
  if (rune.warnings.includes('possibly-truncated')) parts.push('value may be cut');
  if (rune.expiry.status === 'deadline-passed') parts.push('deadline passed according to local clock');
  parts.push('not checked against the node');
  return ` (${parts.join('; ')})`;
}

function* scanSummaryLines(result: import('../scan/index.js').ScanResult): Generator<string> {
  const { summary, failOn } = result;
  if (result.ignoredFingerprints?.length)
    yield `ignored-fingerprints  ${result.ignoredFingerprints.map(safeText).join(' ')}\n`;
  yield (`${summary.findings} findings (${summary.distinct} distinct) in ${summary.filesScanned} files` +
    (summary.blobsScanned === undefined ? '' : ` and ${summary.blobsScanned} history blobs`) +
    `; ${summary.filesSkipped} skipped; ${summary.ignored} ignored` +
    (failOn ? `; ${failOn.count} at or above ${failOn.threshold}` : '')) + '\n';
}

function inspectText(result: InspectResult): string {
  const { fingerprint, location, rootKeyId, grade, reasons, permissions, caveats, warnings, unassessed, snapshot } = result;
  const lines = [
    `fingerprint  ${safeText(fingerprint)}`,
    ...(location === null ? [] : [`location     ${safeText(location)}`]),
    `root key ID  ${safeText(rootKeyId)}`,
    `grade        ${safeText(grade === 'UNASSESSED' ? 'UNASSESSED (treat as SPEND or worse)' : grade)}` +
      (reasons.length ? `   (${reasons.map(safeText).join(', ')})` : ''),
    `permissions  ${permissions.map(safeText).join(' ')}`,
    ...caveats.map(caveat => {
      const label = caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`;
      const state = caveat.type === 'time-before' && typeof caveat.expired === 'boolean'
        ? (caveat.expired ? ' (expired)' : ' (valid)') : '';
      const address = caveat.type === 'ipaddr' || caveat.type === 'iprange'
        ? ' (enforced against the address LND sees; REST clients appear as the REST proxy)' : '';
      return `caveats      ${safeText(label ?? 'unregistered')}${state}${address}`;
    }),
    ...unassessed.map(value => `unassessed   ${safeText(value)}`),
    ...warnings.map(code => `warning      ${safeText(code)}` +
      (code === 'root-key-0' ? ' (cannot be individually revoked)' : '')),
    `snapshot     LND ${safeText(snapshot)}`,
  ];
  return `${lines.join('\n')}\n`;
}

function runeTime(seconds: string): string {
  const value = BigInt(seconds);
  return value >= -8_640_000_000_000n && value <= 8_640_000_000_000n
    ? `${seconds} (${new Date(Number(value) * 1000).toISOString().replace('.000Z', 'Z')})` : seconds;
}

const runeExpiryText: Record<string, (deadline: string | null) => string> = {
  none: () => 'no time restriction',
  'time-conditions': () => 'time restrictions present; they do not close every request',
  'deadline-ahead': deadline => `every request is refused from ${runeTime(deadline ?? '0')} according to its restrictions`,
  'deadline-passed': deadline => `deadline passed according to local clock (${runeTime(deadline ?? '0')}); node acceptance is not checked`,
};

function runeInspectText(result: RuneInspectResult): string {
  const { rune } = result;
  const grade = result.grade === 'UNASSESSED' ? 'UNASSESSED (treat as SPEND or worse)' : result.grade;
  const lines = [
    'kind         rune (Core Lightning)',
    `fingerprint  ${safeText(result.fingerprint)}`,
    `unique ID    ${rune.uniqueId === null ? 'none' : safeText(rune.uniqueId)}${rune.version === null ? '' : `  version ${safeText(rune.version)}`}`,
    `grade        ${safeText(grade)}` + (result.reasons.length ? `   (${result.reasons.map(safeText).join(', ')})` : ''),
    `methods      ${rune.methods === 'listed' ? `listed: ${rune.allowedMethods.map(safeText).join(' ')}`
      : rune.methods === 'broad' ? 'broad: not limited to a list of exact method names' : 'none: no method can pass these restrictions'}`,
    ...(rune.capabilities.length ? [`may allow    ${rune.capabilities.map(safeText).join(', ')}`] : []),
    ...rune.restrictions.map((restriction, index) => `${index === 0 ? 'restriction ' : 'and         '} ${restriction
      .map(alternative => `${safeText(alternative.field)}${safeText(alternative.condition)}${safeText(alternative.value)}`).join(' OR ')}`),
    ...(rune.omittedAlternatives ? [`omitted      ${rune.omittedAlternatives} further alternatives`] : []),
    ...(rune.conditions.length ? [`conditions   ${rune.conditions.map(safeText).join(', ')} (described, not assessed)`] : []),
    `expiry       ${safeText(runeExpiryText[rune.expiry.status]?.(rune.expiry.deadline) ?? rune.expiry.status)}`,
    ...result.unassessed.map(value => `unassessed   ${safeText(value)}`),
    ...rune.sensitiveMethods.map(value => `sensitive    ${safeText(value)}`),
    ...rune.warnings.map(code => `warning      ${safeText(code)}`),
    'verified     no: authenticity, issuing node, blacklist and rate-limit state are not checked offline',
    `methods from ${safeText(rune.methodTable)}`,
  ];
  return `${lines.join('\n')}\n`;
}

function stringList(items: unknown): boolean {
  return Array.isArray(items) && items.every(item => typeof item === 'string');
}

function isRuneInspectResult(value: unknown): value is RuneInspectResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const fields = value as Record<string, unknown>;
  if (fields.kind !== 'rune' || typeof fields.fingerprint !== 'string' || typeof fields.grade !== 'string'
    || !stringList(fields.reasons) || !stringList(fields.unassessed)) return false;
  const rune = fields.rune as Record<string, unknown> | null | undefined;
  if (!rune || typeof rune !== 'object' || rune.recognition !== 'rune-syntax') return false;
  const expiry = rune.expiry as Record<string, unknown> | null | undefined;
  return Array.isArray(rune.restrictions) && rune.restrictions.every(restriction => Array.isArray(restriction)
      && restriction.every((alternative: unknown) => !!alternative && typeof alternative === 'object'
        && ['field', 'condition', 'value'].every(key => typeof (alternative as Record<string, unknown>)[key] === 'string')))
    && [rune.allowedMethods, rune.capabilities, rune.sensitiveMethods, rune.conditions, rune.warnings].every(stringList)
    && (rune.uniqueId === null || typeof rune.uniqueId === 'string') && (rune.version === null || typeof rune.version === 'string')
    && typeof rune.methods === 'string' && typeof rune.methodTable === 'string' && typeof rune.omittedAlternatives === 'number'
    && !!expiry && typeof expiry === 'object' && typeof expiry.status === 'string'
    && (expiry.deadline === null || (typeof expiry.deadline === 'string' && /^-?[0-9]+$/.test(expiry.deadline)));
}

function nwcInspectText(result: NwcInspectResult): string {
  const lines = [
    'kind         nwc (Nostr Wallet Connect, NIP-47)',
    `fingerprint  ${safeText(result.fingerprint)}`,
    `wallet       ${safeText(result.walletPubkey)}`,
    `client       ${safeText(result.clientPubkey)}`,
    ...result.relays.map(relay => `relay        ${safeText(relay)}`),
    ...(result.lud16 === null ? [] : [`lud16        ${safeText(result.lud16)}`]),
    'grade        SPEND   (counted: permissions and budget are set by the wallet service and not visible)',
    ...result.warnings.map(code => `warning      ${safeText(code)}` +
      (code === 'relay-details-removed' ? ' (relay userinfo, query or fragment not shown)' : '')),
    'revocation   in the wallet service; NIP-47 defines no call to create or revoke a connection',
  ];
  return `${lines.join('\n')}\n`;
}

const L402_PREIMAGE_TEXT: Record<L402InspectResult['preimage'], string> = {
  matches: 'present; hashes to the payment hash (proof of payment)',
  mismatch: 'present; does NOT hash to the payment hash (the server rejects it)',
  unverifiable: 'present; cannot be checked (identifier not recognised)',
  absent: 'absent; the macaroon alone grants nothing until its invoice is paid and the preimage added',
};

function l402CaveatText(caveat: import('../l402.js').L402ReportCaveat): string {
  if (caveat.type === 'withheld') return '(withheld: it carries the preimage)';
  if (caveat.type === 'preimage') return 'preimage=(not shown)';
  if (caveat.type === 'third-party') return `third-party ${safeText(caveat.value ?? '')}`;
  const text = caveat.condition === null ? caveat.value ?? '' : `${caveat.condition}=${caveat.value ?? ''}`;
  const state = typeof caveat.expired === 'boolean'
    ? ` (${caveat.until ? `${caveat.until}, ` : ''}${caveat.expired ? 'expired' : 'valid'})` : '';
  return `${safeText(text)}${state}`;
}

function l402InspectText(result: L402InspectResult): string {
  const form = (result.form === 'authorization' || result.form === 'challenge' ? `${result.form} (${result.scheme ?? 'L402'} scheme)` : result.form)
    + (result.macaroons > 1 ? `, ${result.macaroons} macaroons (facts of the primary one)` : '');
  const lines = [
    'kind         l402 (paid API access token; formerly LSAT)',
    `fingerprint  ${safeText(result.fingerprint)}`,
    ...(result.macaroonFingerprint === result.fingerprint ? [] : [`macaroon     ${safeText(result.macaroonFingerprint)}`]),
    `form         ${safeText(form)}`,
    ...(result.location === null ? [] : [`location     ${safeText(result.location)}`]),
    ...(result.identifier === null ? ['identifier   not an L402 version 0 identifier'] : [
      `version      ${result.identifier.version}`,
      `payment hash ${safeText(result.identifier.paymentHash)}`,
      `token ID     ${safeText(result.identifier.tokenId)}`]),
    ...(result.services.length ? [`services     ${result.services.map(service =>
      `${safeText(service.name)} (tier ${safeText(service.tier)})`).join(', ')}`] : []),
    ...result.caveats.map(caveat => `caveats      ${l402CaveatText(caveat)}`),
    `preimage     ${L402_PREIMAGE_TEXT[result.preimage]}${result.preimageSource === 'caveat' ? ' (from a preimage caveat)' : ''}`,
    `status       ${safeText(result.status)}`,
    'access       service-access: pays for access to a service; it gives no control of a Lightning node',
    `counted as   ${result.countedAs === null ? 'not counted by scan --fail-on' : `${result.countedAs} by scan --fail-on`}`,
    ...result.warnings.map(code => `warning      ${safeText(code)}`),
    'revocation   by the service that issued it; the holder cannot revoke it',
  ];
  return `${lines.join('\n')}\n`;
}

function attenuateText(result: AttenuateResult): string {
  const head = result.dryRun ? 'dry run      nothing written' : `written      ${safeText(result.out ?? '')}`;
  return `${head}
parent       ${safeText(result.parentFingerprint)}
` +
    result.added.map(caveat => `added        ${safeText(caveat)}
`).join('') + inspectText(result);
}

function verifyText(result: VerifyResult): string {
  const why = result.rejection === null ? '' : ` (${safeText(result.rejection)})`;
  const status = result.status === 'accepted' ? 'ACCEPTED by LND: this credential is live'
    : result.conclusive ? `rejected by LND${why}`
      : `REJECTED BY THIS CHECK ONLY${why}: it may still be accepted from another caller`;
  const registry = result.registry === null ? 'not in this registry'
    : `${safeText(result.registry.label ?? 'unlabelled')} (${safeText(result.registry.status)}${
      result.registry.match === 'fingerprint' ? ', same credential' : ', same root key ID, different credential'})`;
  const lines = [
    `node         ${safeText(result.node.pubkey)} (${safeText(result.node.alias)}) ${safeText(result.node.network)}`,
    `status       ${status}`,
    `root key     ${result.rootKeyListed === null ? 'not checked (own credential cannot call ListMacaroonIDs)'
      : result.rootKeyListed ? 'listed in LND' : 'not listed in LND'}${result.ownCredential ? "; macwarden's own root key ID" : ''}`,
    `registry     ${registry}`,
    ...result.guidance.map(line => `next         ${safeText(line)}`),
  ];
  return inspectText(result) + `${lines.join('\n')}\n`;
}

function respondText(result: RespondResult): string {
  const lines = [`respond ${result.mode}${result.dryRun ? ' (dry run: nothing changed)' : ''}  node ${safeText(result.node.pubkey)} (${safeText(result.node.alias)}) ${safeText(result.node.network)}`];
  if (result.outDir) lines.push(`replacements  ${safeText(result.outDir)}`);
  const table: string[][] = [['ROOT KEY ID', 'LABEL', 'GRADE', 'ACTION', 'STATUS']];
  for (const item of result.items) {
    const replacement = item.replacementRootKeyId ? ` -> ${safeText(item.replacementRootKeyId)}` : '';
    const detail = item.error ? `; ${safeText(item.error.step ?? 'usage')}: ${safeText(item.error.message)}` : item.note ? `; ${safeText(item.note)}` : '';
    const fingerprint = item.replacementFingerprint ? ` (${safeText(item.replacementFingerprint)})` : '';
    table.push([safeText(item.rootKeyId), safeText(item.label ?? '—'), safeText(item.grade), safeText(item.action),
      `${safeText(item.status)}${replacement}${fingerprint}${detail}`]);
  }
  lines.push(...alignedRows(table));
  for (const item of result.items) {
    const proof = item.proof;
    if (!proof || proof.proven === undefined) continue;
    lines.push(`proof  ${safeText(item.label ?? item.rootKeyId)}: old root key ID ${safeText(item.rootKeyId)} ` +
      `${proof.oldRootKeyIdAbsent === true ? 'absent from LND' : proof.oldRootKeyIdAbsent === false ? 'STILL LISTED' : 'not checked'}, ` +
      `old credential ${safeText(proof.oldCredential ?? 'not-tested')}; new root key ID ${safeText(item.replacementRootKeyId ?? '—')} ` +
      `credential ${safeText(proof.newCredential ?? 'not-tested')}: ${proof.proven ? `PROVEN (${safeText(proof.strength ?? '')})` : 'NOT PROVEN'}`);
  }
  if (result.unknown.rootKeyIds.length) {
    lines.push(`unknown root key IDs  ${result.unknown.rootKeyIds.map(safeText).join(' ')}`);
    lines.push(`  ${safeText(result.unknown.guidance)}`);
  }
  if (result.revokedButPresent.rootKeyIds.length) {
    lines.push(`REVOKED BUT STILL IN LND  ${result.revokedButPresent.rootKeyIds.map(safeText).join(' ')}`);
    lines.push(`  ${safeText(result.revokedButPresent.guidance)}`);
  }
  if (result.bakingRisk.guidance.length) {
    lines.push(`credentials that can bake  ${result.bakingRisk.rootKeyIds.map(safeText).join(' ') || '—'}`);
    for (const line of result.bakingRisk.guidance) lines.push(`  ${safeText(line)}`);
  }
  if (result.rootKey0.present) {
    lines.push('root key ID 0');
    for (const line of result.rootKey0.guidance) lines.push(`  ${safeText(line)}`);
  }
  for (const item of result.unproven)
    lines.push(`not proven  ${safeText(item.label ?? item.rootKeyId)} (root key ID ${safeText(item.rootKeyId)}): ${safeText(item.reason)}`);
  return `${lines.join('\n')}\n`;
}

/** Pads each column to its widest cell; the last column is not padded. */
function alignedRows(table: string[][]): string[] {
  const widths = table[0].map((_, column) => Math.max(...table.map(cells => [...(cells[column] ?? '')].length)));
  return table.map(cells => cells.map((cell, column) => column === cells.length - 1 ? cell
    : cell + ' '.repeat(widths[column] - [...cell].length)).join('  ').trimEnd());
}

type InventoryRow = InventoryResult['rootKeys'][number];

/**
 * The argument `revoke` resolves to this row's credential (RL-05): its label only when that label
 * names exactly one active entry on the node (as revoke V6 requires), otherwise its root key ID.
 * Null when revoke refuses the row (root key ID 0, macwarden's own credential).
 */
function revokeTarget(rows: InventoryRow[], row: InventoryRow): string | null {
  if (row.rootKeyId === '0' || row.flags.includes('default-root-key') || row.flags.includes('own-credential')) return null;
  const label = row.entry?.label ?? null;
  return label !== null && rows.filter(other => other.entry?.status === 'active' && other.entry.label === label).length === 1
    ? label : row.rootKeyId;
}

/**
 * The rotate command for this row, or null when rotate would refuse it (RL-05): no label, root
 * key ID 0, macwarden's own credential, a staged replacement or an original that already has one,
 * an invalid link, a custom caveat (a canary) or unassessed permissions. `--out` defaults to
 * `<label>-<YYYY-MM-DD>.macaroon` next to the recorded file (or in the current directory when no
 * file is recorded); ADMIN adds `--allow-admin`, which rotate requires.
 */
function rotateCommand(row: InventoryRow, now: number): string | null {
  const entry = row.entry;
  if (!entry || entry.status !== 'active' || entry.label === null || row.rootKeyId === '0') return null;
  if (['own-credential', 'default-root-key', 'replacement', 'pending-replacement', 'invalid-replacement']
    .some(flag => row.flags.includes(flag))) return null;
  if (entry.caveats.some(caveat => caveat.type === 'lnd-custom') || entry.grade === 'UNASSESSED') return null;
  const name = `${entry.label}-${new Date(now).toISOString().slice(0, 10)}.macaroon`;
  const out = entry.outPath ? join(dirname(entry.outPath), name) : name;
  return ['macwarden', 'rotate', entry.label, '--out', out, ...(entry.grade === 'ADMIN' ? ['--allow-admin'] : [])]
    .map(value => shellQuote(value)).join(' ');
}

function inventoryText(result: InventoryResult, now: number): string {
  const { node, rootKeys: rows } = result;
  const lines = [`node ${safeText(node.pubkey)} (${safeText(node.alias)}) ${safeText(node.network)}`];
  // Columns are padded to their widest cell so the table lines up; STATUS is last and unpadded.
  const table: string[][] = [['ROOT KEY ID', 'LABEL', 'GRADE', 'AGE', 'EXPIRES', 'STATUS']];
  for (const row of rows) {
    const entry = row.entry;
    const age = entry ? `${Math.max(0, Math.floor((now - Date.parse(entry.createdAt)) / 86_400_000))}d` : '—';
    const expires = row.expires ? row.expires.slice(0, 10) : '—';
    const status: string[] = [];
    // First, so it cannot be missed among ordinary status notes.
    if (row.canary) status.push(`CANARY TRIGGERED ${row.canary.uses} time${row.canary.uses === 1 ? '' : 's'}, last ${row.canary.lastUse}: `
      + "assume this credential's location is compromised");
    if (row.flags.includes('default-root-key')) status.push('default root key: cannot be individually revoked');
    else if (row.flags.includes('own-credential') && !entry) status.push("macwarden's own credential");
    else if (row.flags.includes('unknown')) status.push('unknown — not in this registry (another tool or operator may own it)');
    else if (row.flags.includes('missing-in-lnd')) status.push('missing in LND (registry says active)');
    else if (row.flags.includes('revoked-but-present')) status.push('revoked but present in LND');
    else if (row.flags.includes('replacement')) status.push('replacement');
    else status.push(entry?.status ?? 'unknown');
    // A separate note, not a base status: it must never replace or repeat the one above.
    if (row.flags.includes('invalid-replacement'))
      status.push('invalid replacement link (registry tampering?): restore the registry from a trusted copy');
    if (row.verify === 'canary') status.push('canary: verifiable only while watch runs');
    else if (row.verify !== 'not-checked') status.push(row.verify);
    // Every printed command runs as printed with the same connection and --registry flags (RL-05).
    if (row.flags.includes('expired')) {
      const target = revokeTarget(rows, row);
      status.push(target === null ? 'expired' : `expired; revoke with: macwarden revoke ${shellQuote(target)}`);
    } else if (row.flags.includes('expiring') && row.expires) {
      const left = Date.parse(row.expires) - now;
      const span = left >= 86_400_000 ? `${Math.floor(left / 86_400_000)}d` : `${Math.max(1, Math.ceil(left / 3_600_000))}h`;
      const command = rotateCommand(row, now);
      status.push(command === null ? `expires in ${span}` : `expires in ${span}; rotate with: ${command}`);
    }
    if (row.flags.includes('pending-replacement')) {
      const replacement = rows.find(candidate => candidate.entry?.status === 'active'
        && candidate.entry.replaces === row.rootKeyId);
      if (replacement) status.push(`rotation staged -> ${replacement.rootKeyId}`);
    }
    if (row.usage) status.push(`last used ${row.usage.lastUsed} (${row.usage.calls} calls${row.usage.errors ? `, ${row.usage.errors} errors` : ''})`);
    table.push([safeText(row.rootKeyId), safeText(entry?.label ?? '—'), safeText(entry?.grade ?? '—'),
      safeText(age), safeText(expires), status.map(safeText).join('; ')]);
  }
  const widths = table[0].map((_, column) => Math.max(...table.map(cells => [...cells[column]].length)));
  for (const cells of table)
    lines.push(cells.map((cell, column) => column === cells.length - 1 ? cell
      : cell + ' '.repeat(widths[column] - [...cell].length)).join('  ').trimEnd());
  if (result.expiring) lines.push(`${result.expiring.count} active credential(s) expired or expiring within ${safeText(result.expiring.within)}`);
  const triggered = rows.filter(row => row.canary);
  if (triggered.length) lines.push(`CANARY TRIGGERED: ${triggered.map(row => safeText(row.entry?.label ?? row.rootKeyId)).join(', ')}; `
    + 'someone has read where each was stored: treat that place as compromised and rotate every credential kept there');
  return `${lines.join('\n')}\n`;
}

/** One watch event: a text line, or one JSON object per line with --json. */
export function renderWatchEvent(event: WatchEvent, mode: Mode): string {
  if (mode === 'json') return `${JSON.stringify({ schema: 1, ...event }, jsonRedactor())}\n`;
  if (event.event === 'status' && event.status === 'output-dropped')
    return `${safeText(event.time)}  output fell behind: ${event.dropped} event lines dropped (counts and usage are unaffected)\n`;
  if (event.event === 'status' && event.status === 'payment-journal-stopped')
    return `${safeText(event.time)}  PAYMENT JOURNAL STOPPED (${safeText(event.reason)}): later payments are not journaled; reconcile reports the rest of this run as a gap\n`;
  if (event.event === 'status' && event.status === 'alert-failed')
    return `${safeText(event.time)}  ALERT COMMAND FAILED for canary ${safeText(event.label ?? 'unknown')} (root key ${safeText(event.rootKeyId)})\n`;
  if (event.event === 'status') return `${safeText(event.time)}  ${event.status === 'registered'
    ? `watching (read-only middleware registered${event.canaries ? `; guarding ${event.canaries} canar${event.canaries === 1 ? 'y' : 'ies'}` : ''})`
    : 'stream lost; reconnecting'}\n`;
  const who = `root key ${safeText(event.rootKeyId)}  ${safeText(event.credential)}  ${safeText(event.label ?? 'unregistered')}`;
  if (event.event === 'canary') return `${safeText(event.time)}  ALERT canary ${safeText(event.label ?? 'unknown')} used: ` +
    `${safeText(event.method)}  ${who}  request denied${event.repeats ? ` (+${event.repeats} more denied uses since the last alert)` : ''}\n`;
  return `${safeText(event.time)}  ${event.event === 'error' ? 'error ' : ''}${safeText(event.method)}  ${who}\n`;
}

function watchText(result: WatchResult): string {
  return `watched ${result.calls} calls (${result.errors} errors) from ${result.credentials} credentials; ` +
    `${result.canaryAlerts} canary alerts${result.alertFailures ? ` (${result.alertFailures} alert command failures)` : ''}; ` +
    `${result.reconnects} reconnects; usage saved to ${safeText(result.usageFile)}` +
    `${result.droppedUsageRecords ? `; ${result.droppedUsageRecords} usage records dropped` : ''}` +
    `${result.evictedUsageRecords ? `; ${result.evictedUsageRecords} usage records evicted at the limit` : ''}` +
    `${result.droppedEvents ? `; ${result.droppedEvents} event lines dropped because output fell behind` : ''}\n`
    + (result.paymentJournal ? `payment journal ${safeText(result.paymentJournal.path)}: ${result.paymentJournal.payments} payments, `
      + `${result.paymentJournal.deletions} deletions journaled${result.paymentJournal.dropped ? `; ${result.paymentJournal.dropped} not journaled` : ''}`
      + `${result.paymentJournal.stopped ? `; stopped early (${safeText(result.paymentJournal.stopped)})` : ''}\n` : '');
}

/** "1500 msat", or "unknown" for evidence that is not there. */
function msat(value: string | null): string { return value === null ? 'unknown' : `${safeText(value)} msat`; }

function reconcileText(result: ReconcileResult): string {
  const who = (credential: string, rootKeyId: string | null, label: string | null) =>
    `${safeText(credential)}${rootKeyId ? ` root key ${safeText(rootKeyId)}` : ''}${label ? ` (${safeText(label)})` : ''}`;
  const lines = [
    `node         ${safeText(result.node.pubkey)} (${safeText(result.node.alias)}, ${safeText(result.node.network)})`,
    `journal      ${safeText(result.journal.path)}: ${result.journal.records} records in ${result.journal.runs} watch runs`
      + (result.journal.firstRecord ? `, ${safeText(result.journal.firstRecord)} to ${safeText(result.journal.lastRecord ?? '')}` : ''),
    `window       ${safeText(result.window.since)} to ${safeText(result.window.until)}; covered ${formatDuration(result.coverage.coveredSeconds)} `
      + `of ${formatDuration(result.coverage.windowSeconds)}${result.coverage.complete ? '' : ` (${result.coverage.gapCount} gaps)`}`,
    ...result.coverage.gaps.slice(0, 20).map(gap => `gap          ${safeText(gap.from)} to ${safeText(gap.to)}  ${safeText(gap.reason)}`
      + (gap.dropped ? `  ${gap.dropped} payment calls not journaled` : '')),
    ...(result.coverage.gapCount > 20 ? [`gap          ... ${result.coverage.gapCount - 20} more (see --json)`] : []),
    ...result.credentials.map(row => `credential   ${who(row.credential, row.rootKeyIds.join(',') || null, row.label)}: ${row.payments} payments `
      + `(${row.succeeded} succeeded, ${row.failed} failed, ${row.inFlight + row.notFound + row.unknown} without a final outcome)`
      + `; requested ${msat(row.requestedMsat)}; settled ${msat(row.settledMsat)}; fees ${msat(row.feesMsat)}`
      + `${row.inFlightMsat !== '0' ? `; in flight ${msat(row.inFlightMsat)}` : ''}`
      + `${row.ambiguous ? `; ${row.ambiguous} shared with other credentials` : ''}${row.historical ? `; ${row.historical} with an LND record older than any journaled request` : ''}${row.unmatched ? `; ${row.unmatched} without a hash` : ''}`
      + `${row.deletions ? `; ${row.deletions} payment record deletions` : ''}`),
    ...result.payments.map(item => {
      const observed = item.attribution === 'single' ? safeText(item.credentials[0])
        : item.attribution === 'historical' ? `${safeText(item.credentials[0])} (historical: LND's record is older than every journaled request)`
          : `ambiguous (${item.credentials.map(safeText).join(', ')})`;
      const settled = item.settlement;
      return `payment      ${safeText(item.paymentHash)}  observed: ${observed}, ${item.observation.calls} request${item.observation.calls === 1 ? '' : 's'}, `
        + `requested ${msat(item.observation.requestedMsat ?? item.observation.routeAttemptsMsat)}, fee limit ${msat(item.observation.feeLimitMsat)}`
        + `  |  LND: ${safeText(settled.status)}${settled.source ? `, settled ${msat(settled.settledMsat)}, fees ${msat(settled.feesMsat)}, `
          + `${settled.attempts} attempt${settled.attempts === 1 ? '' : 's'}` : ''}`
        + `${settled.failureReason ? `, ${safeText(settled.failureReason)}` : ''}`
        + `${settled.predatesObservation ? '; LND record predates the observed request' : ''}`
        + `${item.deletedBy.length ? `; deletions by ${item.deletedBy.map(safeText).join(', ')}` : ''}`;
    }),
    ...result.unmatched.map(item => `unmatched    ${safeText(item.time)}  ${who(item.credential, item.rootKeyId, item.label)}  `
      + `${safeText(item.method)}  no payment hash (${safeText(item.extraction)})`),
    ...result.unattributed.map(item => `unattributed ${safeText(item.paymentHash)}  created ${safeText(item.createdAt)}  ${safeText(item.status)}, `
      + `settled ${msat(item.settledMsat)}, fees ${msat(item.feesMsat)}  (${item.coverage === 'covered' ? 'while watch was registered'
        : item.coverage === 'boundary' ? 'at the edge of watch coverage' : 'in a journal gap'})`),
    ...result.deletions.map(item => `deletion     ${safeText(item.time)}  ${who(item.credential, item.rootKeyId, item.label)}  `
      + `${safeText(item.method)}  ${safeText(item.scope)}${item.paymentHash ? ` ${safeText(item.paymentHash)}` : ''}`),
    'evidence     observed requests (journal) and settlement (LND) are separate; a request is not a payment, and a payment missing '
      + 'from either is no proof that none was made',
  ];
  return `${lines.join('\n')}\n`;
}

/** "3d 4h", "2h 5m", "1m 30s", "45s". */
export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86_400), hours = Math.floor(seconds % 86_400 / 3_600);
  const minutes = Math.floor(seconds % 3_600 / 60), rest = seconds % 60;
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${rest}s`;
  return `${rest}s`;
}

function observationLine(observation: RecommendResult['observation']): string {
  // seconds null with a coverage record: the record's times could not be evaluated.
  if (observation.seconds === null && observation.since !== null)
    return 'window       observation window cannot be computed (invalid watch coverage record); narrowing command withheld';
  const span = observation.seconds === null ? 'observed for an unknown time (no watch coverage recorded)'
    : `observed for ${formatDuration(observation.seconds)} (${observation.sessions} watch session${observation.sessions === 1 ? '' : 's'} since ${safeText(observation.since ?? '')})`;
  if (!observation.short) return `window       ${span}`;
  return `window       ${span}; SHORT OBSERVATION: rarely used methods (such as payments) may be missing`
    + (observation.accepted ? '' : '; narrowing command withheld (--accept-short-observation prints it)');
}

function recommendText(result: RecommendResult): string {
  const name = result.label ?? (result.rootKeyId === null ? result.selector : `root key ${result.rootKeyId}`);
  if (!result.observed.length) return `no observed calls for ${safeText(name)}; run macwarden watch while the app is in use, then retry\n`;
  return [
    `${safeText(name)}: ${result.observed.length} methods observed`,
    observationLine(result.observation),
    ...result.observed.map(item => `observed     ${safeText(item.method)}  ${item.calls} calls  last ${safeText(item.lastUsed)}`),
    `recommended  ${result.recommended.map(safeText).join(' ') || '(none)'}`,
    ...(result.current ? [`current      ${result.current.map(safeText).join(' ')}`] : []),
    ...(result.unneeded.length ? [`unneeded     ${result.unneeded.map(safeText).join(' ')}`] : []),
    ...(result.unmapped.length ? [`unmapped     ${result.unmapped.map(safeText).join(' ')} (not in LND's permission list; check before narrowing)`] : []),
    ...result.commands.map(command => `next         ${safeText(command)}`),
    'recommendation only: nothing was changed; usage covers only calls seen while watch ran',
  ].join('\n') + '\n';
}

function bakeText(result: BakePlan | RegistryEntry, warnings: OutputWarning[]): string {
  const aclBestEffort = warnings.some(item => (typeof item === "string" ? item : item.code) === "acl-best-effort");
  // Printed only after reserveOut verified the result: mode 0600 read back from the open
  // descriptor, or the owner-only Windows ACL read back while the exclusive handle was held.
  const protection = process.platform !== "win32" ? "0600, verified"
    : aclBestEffort ? "no Windows permissions on this volume" : "owner-only Windows ACL, verified";
  const { label, permissions, grade, caveats } = result;
  if (!('dryRun' in result)) return [
    `baked  ${safeText(label ?? 'unregistered')}  root key ID ${safeText(result.rootKeyId)}  ` +
      `${safeText(grade)}  ${safeText(result.fingerprint ?? 'unknown fingerprint')}`,
    ...caveats.map(item => `caveats  ${safeText(item.type)} ${safeText(item.value)}`),
    `wrote ${safeText(result.outPath ?? 'unknown path')} (${protection}); registry updated`,
  ].join('\n') + '\n';
  return [
    `dry-run  ${safeText(label ?? 'unregistered')}  ${safeText(grade)}`,
    `permissions  ${permissions.map(safeText).join(' ')}`,
    ...caveats.map(item => `caveats  ${safeText(item.type)} ${safeText(item.value)}`),
    'root key ID: allocated at bake time',
  ].join('\n') + '\n';
}

function revokeText(plan: RevokePlan, alreadyAbsent = false, terminal = plan.dryRun): string {
  return [
    `${plan.dryRun ? 'dry-run' : 'plan'}  ${safeText(plan.label ?? 'unregistered')}  ` +
      `root key ID ${safeText(plan.rootKeyId)}  grade ${safeText(plan.grade ?? 'unassessed')}`,
    `proof  ${plan.proof === 'rejected' ? 'ID absence and macaroon rejection planned (accepted baseline)'
      : 'by ID only (no accepted baseline)'}`,
    ...(alreadyAbsent ? ['Root key ID already absent; registry repair planned.'] : []),
    ...(terminal ? ['No revocation performed.'] : []),
  ].join('\n') + '\n';
}

export function revokeConfirmation(plan: RevokePlan, alreadyAbsent = false): string {
  return revokeText(plan, alreadyAbsent, false) + `Type ${safeText(plan.label ?? plan.rootKeyId)} to confirm: `;
}

export function writeRevokePrompt(question: string): void {
  process.stderr.write(question);
}

function revokedText(result: RevokeResult): string {
  return [
    `${result.repaired ? 'repaired (already absent)' : 'revoked'}  ${safeText(result.label ?? 'unregistered')}  ` +
      `root key ID ${safeText(result.rootKeyId)}  ${safeText(result.entry.fingerprint ?? 'unknown fingerprint')}`,
    `proof    ${result.evidence === 'rejected' ? 'ID absent from LND; macaroon rejected'
      : 'ID absent from LND (verified by ID only)'}`,
    'New requests with this macaroon are now rejected. Streams opened before the revoke stay open until they disconnect; if the credential may be compromised, restart LND.',
  ].join('\n') + '\n';
}

function finishPlanText(old: RegistryEntry, next: RegistryEntry, repaired: boolean): string {
  return [
    `old  ${safeText(old.rootKeyId)}  ${safeText(old.grade)}  ${old.permissions.map(safeText).join(' ')}`,
    `new  ${safeText(next.rootKeyId)}  ${safeText(next.grade)}  ${safeText(next.outPath ?? '')}`,
    repaired ? 'Old root key ID already absent; registry repair planned after replacement accepted.'
      : 'Finish plan: revoke the old root key ID; prove old rejected and new still accepted; update registry.',
  ].join('\n') + '\n';
}

export function writeRotateFinishPlan(old: RegistryEntry, next: RegistryEntry, repaired: boolean,
  stream: { write(text: string): unknown } = process.stderr): void {
  stream.write(finishPlanText(old, next, repaired));
}

export function rotateConfirmation(old: RegistryEntry, next: RegistryEntry): string {
  return `Finishing revokes root key ID ${safeText(old.rootKeyId)}. Continue only if every replica and config copy of ` +
    `${safeText(old.label ?? '')} now uses ${safeText(next.outPath ?? '')}. Type ${safeText(old.label ?? '')} to continue:`;
}

export function writeRotatePrompt(question: string): void {
  process.stderr.write(question);
}

function rotateText(result: RotatePlan | RotateStagedResult | RotateFinishedResult, context?: { next: RegistryEntry; repaired: boolean }): string {
  const old = result.old;
  const label = safeText(old.label ?? '');
  if (result.stage === 'stage') return [
    `dry-run stage  ${label}  old root key ID ${safeText(old.rootKeyId)}  ${safeText(result.grade)}`,
    `permissions  ${result.permissions.map(safeText).join(' ')}`,
    result.permissionsProven === false ? 'authority  unproven recorded permissions; old credential cannot prove them; typed approval required for stage' : 'authority  permissions proven by the old credential',
    ...old.caveats.map(caveat => `caveats  ${safeText(caveat.type)} ${safeText(caveat.value)}${caveat.requested === undefined ? '' : ` requested ${safeText(caveat.requested)}`}`),
    'stage plan  allocate a fresh root key ID; bake, verify, write and record a replacement',
    `finish plan  switch every replica and config copy, then macwarden rotate ${label} --finish`,
  ].join('\n') + '\n';
  if (result.stage === 'finish') {
    return `dry-run finish  ${label}  ${safeText(result.grade)}\n` +
      (context ? finishPlanText(old, context.next, context.repaired)
        : `old root key ID ${safeText(old.rootKeyId)}\npermissions  ${result.permissions.map(safeText).join(' ')}\n`) +
      'No revocation performed.\n';
  }
  const next = result.new;
  if (result.stage === 'finished') return [
    `${result.repaired ? 'repaired (already absent)' : 'revoked'}  ${safeText(old.rootKeyId)}; ` +
      `${result.evidence === 'rejected' ? 'old macaroon rejected' : 'old ID absent (verified by ID only)'}; ` +
      `new root key ID ${safeText(next.rootKeyId)} accepted; registry updated`,
    'New requests with this macaroon are now rejected. Streams opened before the revoke stay open until they disconnect; if the credential may be compromised, restart LND.',
  ].join('\n') + '\n';
  return [
    `staged  ${label}  root key ID ${safeText(next.rootKeyId)}  ${safeText(next.grade)}  ` +
      `${safeText(next.fingerprint ?? 'unknown fingerprint')}  -> ${safeText(next.outPath ?? '')}`,
    `permissions  ${next.permissions.map(safeText).join(' ')}; verified accepted by LND`,
    ...next.caveats.map(caveat => `caveats  ${safeText(caveat.type)} ${safeText(caveat.value)}`),
    `old root key ID ${safeText(old.rootKeyId)} is unchanged and still valid`,
    `next  switch every replica and config copy of ${label} to ${safeText(next.outPath ?? '')}, ` +
      `then macwarden rotate ${label} --finish`,
    `abandon  macwarden revoke ${safeText(next.rootKeyId)}`,
  ].join('\n') + '\n';
}

function isNwcInspectResult(value: unknown): value is NwcInspectResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const fields = value as Record<string, unknown>;
  return fields.kind === 'nwc' && fields.grade === 'SPEND'
    && ['fingerprint', 'walletPubkey', 'clientPubkey'].every(key => typeof fields[key] === 'string')
    && (fields.lud16 === null || typeof fields.lud16 === 'string')
    && [fields.relays, fields.reasons, fields.warnings]
      .every(items => Array.isArray(items) && items.every(item => typeof item === 'string'));
}

function isL402InspectResult(value: unknown): value is L402InspectResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const fields = value as Record<string, unknown>;
  return fields.kind === 'l402' && ['fingerprint', 'macaroonFingerprint', 'form', 'preimage', 'status'].every(key => typeof fields[key] === 'string')
    && typeof fields.macaroons === 'number'
    && Array.isArray(fields.caveats) && Array.isArray(fields.services) && Array.isArray(fields.warnings)
    && fields.caveats.every(caveat => caveat !== null && typeof caveat === 'object' && typeof caveat.type === 'string')
    && fields.services.every(service => service !== null && typeof service === 'object'
      && typeof service.name === 'string' && typeof service.tier === 'string')
    && (fields.identifier === null || (typeof fields.identifier === 'object' && fields.identifier !== null
      && typeof (fields.identifier as Record<string, unknown>).paymentHash === 'string'
      && typeof (fields.identifier as Record<string, unknown>).tokenId === 'string'));
}

function isInspectResult(value: unknown): value is InspectResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const fields = value as Record<string, unknown>;
  return typeof fields.fingerprint === 'string'
    && (fields.location === null || typeof fields.location === 'string')
    && typeof fields.rootKeyId === 'string'
    && typeof fields.grade === 'string'
    && typeof fields.snapshot === 'string'
    && [fields.reasons, fields.permissions, fields.warnings, fields.unassessed]
      .every(items => Array.isArray(items) && items.every(item => typeof item === 'string'))
    && Array.isArray(fields.caveats)
    && fields.caveats.every(caveat => caveat !== null && typeof caveat === 'object'
      && typeof caveat.type === 'string' && typeof caveat.value === 'string'
      && (caveat.expired === undefined || typeof caveat.expired === 'boolean'));
}

// assertPlain has already refused executable hooks, proxies and cycles.
// Runtime callers can still supply ordinary values outside the production union.
function textValues(value: unknown): string[] {
  if (typeof value === 'string') return [safeText(value)];
  if (typeof value === 'number' || typeof value === 'boolean') return [String(value)];
  if (!value || typeof value !== 'object') return [];
  return Object.values(value).flatMap(textValues);
}

function genericText(result: OutputResult): string {
  const lines = textValues(result.result);
  return `${(lines.length ? lines : Object.values(result)
    .filter((value): value is string => typeof value === 'string').map(safeText)).join('\n')}\n`;
}

function isTextResult(result: OutputResult): result is Success<null, { text: string }> {
  return result.ok && result.command === null && result.result !== null
    && typeof result.result === 'object' && "text" in result.result
    && typeof result.result.text === 'string';
}

// Pieces are concatenated into chunks of about this many UTF-16 code units.
const CHUNK_SIZE = 1 << 16;

function* batched(pieces: Iterable<string>): Generator<string> {
  let buffer = '';
  for (const piece of pieces) {
    buffer += piece;
    if (buffer.length >= CHUNK_SIZE) { yield buffer; buffer = ''; }
  }
  if (buffer) yield buffer;
}

// Byte-identical to JSON.stringify(value, replacer) for the plain values assertPlain
// admits. Arrays are serialized element by element, so no single string holds a
// large result and memory stays proportional to one element.
function* jsonPieces(value: unknown, replacer: (key: string, value: unknown) => unknown): Generator<string> {
  const omitted = (item: unknown) => item === undefined || typeof item === 'function' || typeof item === 'symbol';
  function* emit(item: unknown): Generator<string> {
    if (Array.isArray(item)) {
      yield '[';
      for (let index = 0; index < item.length; index++) {
        if (index) yield ',';
        yield JSON.stringify(item[index], replacer) ?? 'null';
      }
      yield ']';
    } else if (item !== null && typeof item === 'object') {
      yield '{';
      let first = true;
      for (const [key, child] of Object.entries(item)) {
        const replaced = replacer(key, child);
        if (omitted(replaced)) continue;
        yield `${first ? '' : ','}${JSON.stringify(key)}:`;
        first = false;
        yield* emit(replaced);
      }
      yield '}';
    } else yield JSON.stringify(item) ?? 'null';
  }
  const root = replacer('', value);
  if (!omitted(root)) yield* emit(root);
}

export function render(result: OutputResult, mode: Mode): string {
  return [...renderChunks(result, mode)].join('');
}

/** The rendered output in bounded chunks; their concatenation equals render(). */
export function* renderChunks(result: OutputResult, mode: Mode): Generator<string> {
  assertPlain(result);
  const secrets = new Set<string>();
  const collect = (value: unknown): void => {
    if (typeof value === 'string') collectNwcSecrets(value, secrets);
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) {
      collectNwcSecrets(key, secrets);
      collect(item);
    }
  };
  collect(result);
  const sanitize = (value: unknown): unknown => {
    if (typeof value === 'string') return redactKnownSecrets(redact(value), secrets);
    if (Array.isArray(value)) return value.map(sanitize);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
      .map(([key, item]) => [redactKnownSecrets(redact(key), secrets), sanitize(item)]));
    return value;
  };
  if (secrets.size) result = sanitize(result) as OutputResult;
  const { display: _display, exitCode: _exitCode, ...document } = result;
  void _display;
  void _exitCode;
  if (mode === 'json') {
    const pieces = batched(jsonPieces({ schema: 1, ...document }, jsonRedactor()));
    // Known NWC secrets in the output are rare; redact them across the whole text then.
    if (secrets.size) yield `${redactKnownSecrets([...pieces].join(''), secrets)}\n`;
    else { yield* pieces; yield '\n'; }
    return;
  }
  if (result.ok && result.command === 'scan' && !isTextResult(result)) {
    const format = result.display?.format;
    const root = result.display?.scanRoot ?? process.cwd();
    const lines = batched(format === 'sarif'
      ? sarifPieces(result.result, root, result.display?.toolVersion ?? '0.0.0', jsonRedactor())
      : format === 'github'
        ? githubLines(result.result, root, safeText, [...scanSummaryLines(result.result)].join(''), redact)
        : scanTextLines(result.result));
    // Text and annotation output both go through the line guard; a github annotation's
    // own '::' starts its line on purpose and is produced only by githubLines.
    const guard = format === 'sarif' || format === 'github' ? (text: string) => text : guardLines;
    if (secrets.size) yield guard(redactKnownSecrets([...lines].join(''), secrets));
    else for (const chunk of lines) yield guard(chunk);
    return;
  }
  let rendered: string;
  if (!result.ok) rendered = result.error && typeof result.error.message === 'string'
    && (result.error.step === null || typeof result.error.step === 'string')
    ? error(result.error.step ?? 'usage', result.error.message) : genericText(result);
  else if (isTextResult(result)) rendered = `${result.result.text.split('\n').map(safeText).join('\n')}\n`;
  else switch (result.command) {
    case 'inspect': rendered = isInspectResult(result.result)
      ? inspectText(result.result) : isNwcInspectResult(result.result)
        ? nwcInspectText(result.result) : isL402InspectResult(result.result)
          ? l402InspectText(result.result) : isRuneInspectResult(result.result)
            ? runeInspectText(result.result) : genericText(result); break;
    case 'inventory': rendered = typeof result.display?.report === 'string' ? result.display.report
      : typeof result.display?.now === 'number' && Number.isFinite(result.display.now)
        ? inventoryText(result.result, result.display.now) + (result.result.report?.path
          ? `access review (${safeText(result.result.report.format)}) written to ${safeText(result.result.report.path)}\n` : '')
        : genericText(result); break;
    case 'attenuate': rendered = attenuateText(result.result); break;
    case 'watch': rendered = watchText(result.result); break;
    case 'recommend': rendered = recommendText(result.result); break;
    case 'bake': rendered = bakeText(result.result, result.warnings); break;
    case 'revoke': rendered = 'evidence' in result.result ? revokedText(result.result)
      : revokeText(result.result, result.display?.alreadyAbsent ?? false); break;
    case 'rotate': rendered = rotateText(result.result, result.display?.finish); break;
    case 'respond': rendered = respondText(result.result); break;
    case 'verify': rendered = isInspectResult(result.result) ? verifyText(result.result) : genericText(result); break;
    case 'reconcile': rendered = reconcileText(result.result); break;
    default: rendered = genericText(result); break;
  }
  yield guardLines(redactKnownSecrets(rendered, secrets));
}

export function inventoryResult(result: InventoryResult, warnings: OutputWarning[], now: Date): OutputResult & { schema: 1 } {
  return { schema: 1, command: "inventory", ok: true, warnings, result, error: null, display: { now: now.getTime() } };
}

export function writeRotateStagePlan(old: RegistryEntry, permissions: string[], grade: string,
  stream: { write(text: string): unknown } = process.stderr): void {
  stream.write(`stage ${safeText(old.label ?? '')}  old root key ID ${safeText(old.rootKeyId)}  ${safeText(grade)}\n`
    + `permissions  ${permissions.map(safeText).join(' ')}\n`
    + 'stage plan  allocate a fresh root key ID; bake, verify, write and record a replacement\n');
}
