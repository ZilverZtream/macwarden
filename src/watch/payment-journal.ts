// The payment journal written by `watch --payment-journal <path>` and read by `reconcile`:
// an append-only, owner-only file of JSON lines that attributes each payment-initiating RPC
// (and each deletion of LND payment records) to the credential that made it, with explicit
// markers for every moment watch was not registered, so coverage is recorded, never implied.
//
// It holds credential IDs (identifier hashes), root key IDs, method names, payment hashes,
// requested amounts and fee limits, request IDs and times: never macaroon bytes, invoice
// text, preimages, custom records or any other request field.
import * as nodeFs from 'node:fs/promises';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { macaroonId } from '../decode/index.js';
import { PrivateFileError, reserveOwnerOnly, verifyOwnerOnly } from '../private-file.js';
import type { MiddlewareCall } from '../lnd/index.js';
import { isInstant } from '../instant.js';
import { isProtectedPath, outputNameProblem, resolveUnprotectedPath } from '../protected-path.js';
import { isRootKeyId } from '../root-key-id.js';
import type { Secret } from '../secret.js';
import { DELETION_METHODS, PAYMENT_METHODS, deletionFacts, paymentFacts, type DeletionFacts, type PaymentFacts } from './payment-request.js';

/** Journal format version (`v` in every record). A change older readers must understand takes a new number. */
export const JOURNAL_VERSION = 1;
/**
 * Largest journal: watch stops journaling (with a `full` record) when it is reached and refuses
 * to start on a file with less than JOURNAL_START_ROOM_BYTES left; reconcile refuses a larger
 * file. About 150,000 payment records. Rotation is manual: stop watch, move the file aside,
 * start watch again.
 */
export const JOURNAL_LIMIT_BYTES = 64 * 1024 * 1024;
/**
 * Room kept for the records that end a full journal: the `drop` record naming what did not fit
 * and the `full` record (each at most JOURNAL_LINE_LIMIT, about 300 bytes together in practice),
 * so the file never exceeds JOURNAL_LIMIT_BYTES.
 */
export const JOURNAL_RESERVE_BYTES = 4 * 1024;
/** watch starts on an existing journal only while at least this much room is left before the reserve. */
export const JOURNAL_START_ROOM_BYTES = 64 * 1024;
/** Longest record line accepted by the reader; watch writes at most about 500 bytes. */
export const JOURNAL_LINE_LIMIT = 2 * 1024;
/** Intercepted payment calls waiting to be decoded and attributed: items and bytes (payload plus macaroon). */
export const JOURNAL_INTAKE_ITEMS = 1_024;
export const JOURNAL_INTAKE_BYTES = 8 * 1024 * 1024;
/** Record lines waiting for the disk; payment and deletion records beyond this are dropped and counted. */
export const JOURNAL_PENDING_BYTES = 1024 * 1024;
/**
 * Markers (registration, drops, run end) are never dropped; if this many bytes of them wait
 * for a disk that does not take them, journaling stops for the run (no record is written
 * after that, so the reader sees coverage end at the last written record).
 */
export const JOURNAL_MARKER_BYTES = 1024 * 1024;
/** While registered, an `alive` record is written when nothing else was written for this long. */
export const JOURNAL_ALIVE_MS = 5 * 60_000;
/** Intake items decoded per event-loop turn (each at most 64 KiB of payload). */
const INTAKE_BATCH = 64;
// Decoding may use at most this share of wall time (a token bucket refilled as time passes, at
// most JOURNAL_BURST_MS banked), as attribution does (audit 1.2.1): one 64 KiB route payload
// costs up to 8 ms to decode and a holder of a pay credential chooses the rate, so a count per
// turn alone let a flood block the loop for 93-98 % of the time. When the budget is spent the
// next batch waits on a short timer; meanwhile the intake fills and further calls are dropped
// and counted.
export const JOURNAL_SHARE = 0.2;
export const JOURNAL_BURST_MS = 5;
const JOURNAL_RETRY_MS = 5;
// Consecutive unreadable lines a reader tolerates: each crash leaves at most one partial line and
// one partial repair, so a longer run is not a journal watch wrote (audit 1.2.1), wherever it lies.
export const JOURNAL_MAX_INVALID_RUN = 64;

export type UnregisterReason = 'stream-lost' | 'stopping' | 'refresh';
type Base = { v: 1; time: string; run: string };
export type RunStartRecord = Base & { type: 'run-start'; node: string; version: string; repairedTail: boolean };
export type RegisteredRecord = Base & { type: 'registered'; session: number };
export type UnregisteredRecord = Base & { type: 'unregistered'; session: number; reason: UnregisterReason };
export type AliveRecord = Base & { type: 'alive' };
export type Who = { requestId: string; credential: string; rootKeyId: string };
export type PaymentRecord = Base & Who & { type: 'payment'; method: typeof PAYMENT_METHODS[number] }
  & Pick<PaymentFacts, 'paymentHash' | 'amountMsat' | 'amountSource' | 'feeLimitMsat' | 'amp' | 'extraction'>;
export type DeletionRecord = Base & Who & { type: 'deletion'; method: typeof DELETION_METHODS[number] }
  & Pick<DeletionFacts, 'paymentHash' | 'scope' | 'extraction'>;
export type DropRecord = Base & { type: 'drop'; count: number; first: string; last: string; reason: 'overload' };
export type FullRecord = Base & { type: 'full' };
export type RunEndRecord = Base & { type: 'run-end'; payments: number; deletions: number; dropped: number };
export type JournalRecord = RunStartRecord | RegisteredRecord | UnregisteredRecord | AliveRecord | PaymentRecord | DeletionRecord
  | DropRecord | FullRecord | RunEndRecord;

export class JournalError extends Error {
  readonly code = 3;
  constructor(message: string) { super(message); this.name = 'JournalError'; }
}

// Strict record validation: exact keys per type, every value in its documented form.
const RUN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NODE = /^0[23][0-9a-f]{64}$/;
const HASH = /^[0-9a-f]{64}$/;
const MSAT = /^(?:0|[1-9][0-9]{0,19})$/;
const CREDENTIAL = /^id:(?:[0-9a-f]{16}|none|undecodable)$/;
const MS_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PRINTABLE = /^[\x20-\x7e]{1,64}$/;
// The last instant the reader accepts (MS_TIME: a four-digit year).
const MAX_RECORD_TIME = 253_402_300_799_999;
const time = (value: unknown): value is string => typeof value === 'string' && MS_TIME.test(value) && isInstant(value);
const count = (value: unknown, min = 0): value is number => Number.isSafeInteger(value) && (value as number) >= min;
const nullable = (value: unknown, pattern: RegExp) => value === null || (typeof value === 'string' && pattern.test(value));
const oneOf = (value: unknown, values: readonly unknown[]) => values.includes(value);
const msat = (value: unknown) => value === null || (typeof value === 'string' && MSAT.test(value) && BigInt(value) <= (1n << 63n) - 1n);
const who = (record: Record<string, unknown>) => typeof record.requestId === 'string' && MSAT.test(record.requestId)
  && BigInt(record.requestId) <= (1n << 64n) - 1n
  && typeof record.credential === 'string' && CREDENTIAL.test(record.credential)
  && (record.rootKeyId === 'none' || isRootKeyId(record.rootKeyId));
const KEYS: Record<JournalRecord['type'], string[]> = {
  'run-start': ['node', 'version', 'repairedTail'],
  registered: ['session'],
  unregistered: ['session', 'reason'],
  alive: [],
  payment: ['requestId', 'method', 'credential', 'rootKeyId', 'paymentHash', 'amountMsat', 'amountSource', 'feeLimitMsat', 'amp', 'extraction'],
  deletion: ['requestId', 'method', 'credential', 'rootKeyId', 'paymentHash', 'scope', 'extraction'],
  drop: ['count', 'first', 'last', 'reason'],
  full: [],
  'run-end': ['payments', 'deletions', 'dropped'],
};
const EXTRACTIONS = ['complete', 'no-hash', 'amp', 'payload-too-large', 'malformed', 'invoice-invalid', 'invoice-too-long'];

/** One record line (without its newline), or null when it is not a valid version 1 record. */
export function parseRecord(line: string): JournalRecord | null {
  if (line.length > JOURNAL_LINE_LIMIT) return null;
  let value: unknown;
  try { value = JSON.parse(line); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record.v !== JOURNAL_VERSION || typeof record.type !== 'string' || !Object.hasOwn(KEYS, record.type)) return null;
  const type = record.type as JournalRecord['type'];
  const expected = ['v', 'type', 'time', 'run', ...KEYS[type]];
  const keys = Object.keys(record);
  if (keys.length !== expected.length || !keys.every(key => expected.includes(key))) return null;
  if (!time(record.time) || typeof record.run !== 'string' || !RUN.test(record.run)) return null;
  let valid: boolean;
  switch (type) {
    case 'run-start': valid = typeof record.node === 'string' && NODE.test(record.node) && typeof record.version === 'string'
      && PRINTABLE.test(record.version) && typeof record.repairedTail === 'boolean'; break;
    case 'registered': valid = count(record.session, 1); break;
    case 'unregistered': valid = count(record.session, 1) && oneOf(record.reason, ['stream-lost', 'stopping', 'refresh']); break;
    case 'alive': case 'full': valid = true; break;
    case 'payment': valid = who(record) && oneOf(record.method, PAYMENT_METHODS) && nullable(record.paymentHash, HASH)
      && msat(record.amountMsat) && oneOf(record.amountSource, ['request', 'invoice', 'route', null])
      && (record.amountMsat === null) === (record.amountSource === null)
      && msat(record.feeLimitMsat) && typeof record.amp === 'boolean' && oneOf(record.extraction, EXTRACTIONS)
      && (record.extraction === 'complete') === (record.paymentHash !== null); break;
    case 'deletion': valid = who(record) && oneOf(record.method, DELETION_METHODS) && nullable(record.paymentHash, HASH)
      && oneOf(record.scope, ['payment', 'failed-htlcs', 'all-payments', 'failed-payments', 'none'])
      && oneOf(record.extraction, ['complete', 'payload-too-large', 'malformed']); break;
    case 'drop': valid = count(record.count, 1) && time(record.first) && time(record.last) && oneOf(record.reason, ['overload'])
      && Date.parse(record.first as string) <= Date.parse(record.last as string)
      && Date.parse(record.last as string) <= Date.parse(record.time as string); break;
    case 'run-end': valid = count(record.payments) && count(record.deletions) && count(record.dropped); break;
  }
  return valid ? record as JournalRecord : null;
}

export type JournalContents = {
  records: JournalRecord[];
  /**
   * The file ends with an incomplete or invalid line (watch was writing it, or crashed while
   * writing it, and no later run has repaired it yet); it was ignored.
   */
  tornTail: boolean;
  /** Incomplete lines from earlier crashes, each repaired by the next run (`repairedTail`). */
  repairedLines: number;
  size: number;
};

type ReadIO = Pick<typeof nodeFs, 'realpath' | 'stat' | 'open'>;

/**
 * Reads and validates a payment journal. The path and its resolved target must carry no
 * protected name (SAFE-02) and be a regular file of at most JOURNAL_LIMIT_BYTES, checked
 * before it is opened; the opened file must be that file. Only the bytes present when it was
 * opened are read (watch may be appending), in blocks, one line at a time (at most
 * JOURNAL_LINE_LIMIT each). Invalid lines are accepted only where a crash leaves them: at the
 * end of the file (ignored, `tornTail`; an unterminated last line always counts as one), or
 * directly before a `run-start` with `repairedTail: true` (the next run found them). Any other
 * invalid line, a record of a run that has not started or has ended, a time earlier than the
 * run's previous record, or an unmatched registration marker makes the whole journal invalid:
 * it is never partly used.
 */
export async function readJournal(path: string, fs: ReadIO = nodeFs): Promise<JournalContents> {
  if (isProtectedPath(path)) throw new JournalError('protected payment journal path');
  let resolved: string;
  try { resolved = await fs.realpath(path); }
  catch (error) {
    throw new JournalError((error as NodeJS.ErrnoException).code === 'ENOENT' ? 'payment journal not found' : 'cannot read payment journal');
  }
  if (isProtectedPath(resolved)) throw new JournalError('protected payment journal path');
  const before = await fs.stat(resolved, { bigint: true }).catch(() => { throw new JournalError('cannot read payment journal'); });
  if (!before.isFile()) throw new JournalError('payment journal is not a regular file');
  if (before.size > BigInt(JOURNAL_LIMIT_BYTES)) throw new JournalError('payment journal too large');
  let handle: nodeFs.FileHandle;
  try { handle = await fs.open(resolved, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0)); }
  catch { throw new JournalError('cannot read payment journal'); }
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) throw new JournalError('payment journal changed while opened');
    if (opened.size > BigInt(JOURNAL_LIMIT_BYTES)) throw new JournalError('payment journal too large');
    const size = Number(opened.size);
    const validation = new Validation();
    const block = Buffer.allocUnsafe(1024 * 1024);
    let carry = Buffer.alloc(0);
    let position = 0;
    while (position < size) {
      const { bytesRead } = await handle.read(block, 0, Math.min(block.length, size - position), position);
      if (bytesRead === 0) break;
      position += bytesRead;
      const chunk = carry.length ? Buffer.concat([carry, block.subarray(0, bytesRead)]) : block.subarray(0, bytesRead);
      let start = 0;
      for (let newline = chunk.indexOf(0x0a, start); newline >= 0; newline = chunk.indexOf(0x0a, start)) {
        // An over-long line is kept as a marker of its length only; it can never be valid.
        validation.line(newline - start > JOURNAL_LINE_LIMIT ? '\u0000'.repeat(JOURNAL_LINE_LIMIT + 1) : chunk.toString('utf8', start, newline));
        start = newline + 1;
      }
      carry = Buffer.from(chunk.subarray(start));
      // A line without a newline that is already longer than any record cannot become valid.
      if (carry.length > JOURNAL_LINE_LIMIT) carry = Buffer.from('\u0000'.repeat(JOURNAL_LINE_LIMIT + 1));
    }
    if (position < size) throw new JournalError('payment journal changed while read');
    return { ...validation.finish(carry.length > 0), size };
  } finally { await handle.close(); }
}

// Validates records one line at a time, as the reader produces them, keeping only the records
// (audit 1.2.1: every line of a 64 MiB file was once held before validation began).
class Validation {
  private readonly records: JournalRecord[] = [];
  private repairedLines = 0;
  private invalidRun = 0;
  private index = -1;
  private run: { id: string; last: number; ended: boolean; registered: number | null } | null = null;

  private invalid(index: number): never { throw new JournalError(`invalid payment journal (line ${index + 1})`); }

  line(text: string): void {
    const index = ++this.index;
    const record = parseRecord(text);
    if (!record) { if (++this.invalidRun > JOURNAL_MAX_INVALID_RUN) this.invalid(index); return; }
    if (this.invalidRun) {
      // Lines a crash left are tolerated only once the next run marked them repaired.
      if (record.type !== 'run-start' || !record.repairedTail) this.invalid(index - 1);
      this.repairedLines += this.invalidRun;
      this.invalidRun = 0;
    }
    const at = Date.parse(record.time);
    if (record.type === 'run-start') {
      this.run = { id: record.run, last: at, ended: false, registered: null };
    } else {
      if (!this.run || this.run.id !== record.run || this.run.ended || at < this.run.last) this.invalid(index);
      const current = this.run!;
      current.last = at;
      if (record.type === 'registered') {
        if (current.registered !== null) this.invalid(index);
        current.registered = record.session;
      } else if (record.type === 'unregistered') {
        if (current.registered !== record.session) this.invalid(index);
        current.registered = null;
      } else if (record.type === 'full' || record.type === 'run-end') current.ended = true;
    }
    this.records.push(record);
  }

  /** Invalid lines at the end, or an unterminated last line: a write a crash cut short (or one in progress), not yet repaired by a later run. They are ignored. */
  finish(unterminated: boolean): Omit<JournalContents, 'size'> {
    return { records: this.records, repairedLines: this.repairedLines, tornTail: this.invalidRun > 0 || unterminated };
  }
}

export type GapReason = 'before-journal' | 'not-running' | 'not-registered' | 'unconfirmed' | 'journal-full' | 'dropped';
export type Gap = { from: number; to: number; reason: GapReason; dropped: number };
export type Coverage = { covered: [number, number][]; gaps: Gap[]; coveredMs: number };

/**
 * When the journal shows watch registered with `node`, within [from, to] (milliseconds):
 * covered intervals and the gaps between them, each with its reason. Coverage exists only
 * between a `registered` record and what ends it: `unregistered` (gap reason
 * `not-registered`, or `not-running` when watch was stopping), `full` (`journal-full`), or,
 * when a run has neither (watch still running, killed or crashed), its last record
 * (`unconfirmed`). A `drop` record removes [first, last] from coverage (`dropped`, with its
 * count; listed even when it lasted no measurable time). Before the node's first run the gap
 * is `before-journal`.
 */
export function journalCoverage(records: JournalRecord[], node: string, from: number, to: number): Coverage {
  type Span = { from: number; to: number; end: GapReason };
  const spans: Span[] = [];
  const drops: Gap[] = [];
  let current: string | null = null;
  let start: number | null = null;
  let last = 0;
  let firstRun: number | null = null;
  const close = (end: GapReason, at: number) => { if (start !== null) spans.push({ from: start, to: at, end }); start = null; };
  for (const record of records) {
    const at = Date.parse(record.time);
    if (record.type === 'run-start') {
      if (current !== null) close('unconfirmed', last);
      current = record.node === node ? record.run : null;
      if (current !== null && firstRun === null) firstRun = at;
      last = at;
      continue;
    }
    if (record.run !== current) continue;
    last = at;
    switch (record.type) {
      case 'registered': start = at; break;
      case 'unregistered': close(record.reason === 'stopping' ? 'not-running' : 'not-registered', at); break;
      case 'full': close('journal-full', at); current = null; break;
      case 'run-end': close('not-running', at); current = null; break;
      case 'drop': drops.push({ from: Date.parse(record.first), to: Date.parse(record.last), reason: 'dropped', dropped: record.count }); break;
      default: break;
    }
  }
  if (current !== null) close('unconfirmed', last);
  // Everything below is one sorted sweep each (1.2.1): a hostile journal holds hundreds of
  // thousands of spans and drops, so nothing may pair every drop with every span.
  // Merge touching spans so a gap is reported only where coverage really stops; a span that
  // extends the previous one gives the merged span its end reason.
  const merged: Span[] = [];
  for (const span of spans.filter(span => span.to >= span.from).sort((a, b) => a.from - b.from)) {
    const previous = merged.at(-1);
    // A later span ending at or after the previous one gives the merged span its end reason: a
    // registration with no recorded end makes what follows unconfirmed, however short it was.
    if (previous && span.from <= previous.to) { if (span.to >= previous.to) { previous.to = span.to; previous.end = span.end; } }
    else merged.push({ ...span });
  }
  // Merge the drop windows the same way (counts add up), so they are disjoint and sorted.
  const dropWindows: Gap[] = [];
  for (const drop of drops.sort((a, b) => a.from - b.from)) {
    const previous = dropWindows.at(-1);
    if (previous && drop.from <= previous.to) { previous.to = Math.max(previous.to, drop.to); previous.dropped += drop.dropped; }
    else dropWindows.push({ ...drop });
  }
  // Covered time: the merged spans, minus every drop window, in one pass over both.
  const covered: Span[] = [];
  let next = 0;
  for (const span of merged) {
    while (next < dropWindows.length && dropWindows[next].to < span.from) next += 1;
    const pieces = covered.length;
    let cursor = span.from;
    let touched = false;
    for (let index = next; index < dropWindows.length && dropWindows[index].from <= span.to; index += 1) {
      const drop = dropWindows[index];
      touched = true;
      if (drop.from > cursor) covered.push({ from: cursor, to: drop.from, end: 'dropped' });
      cursor = Math.max(cursor, drop.to);
    }
    if (!touched) covered.push({ ...span });
    else if (cursor < span.to) covered.push({ from: cursor, to: span.to, end: span.end });
    // A drop reaching the span's end leaves nothing covered after it (a full journal's last drop
    // ends where the `full` record is, 1.2.1): the gap that follows keeps the reason that ended
    // the span (`journal-full`), and the drop is listed as its own gap with its count below.
    else if (covered.length > pieces) covered[covered.length - 1].end = span.end;
  }
  const pieces = covered.map(span => ({ ...span, from: Math.max(span.from, from), to: Math.min(span.to, to) }))
    .filter(span => span.from < span.to);
  // Touching pieces merge back: a drop that lasted no measurable time split a span in two.
  const clipped: Span[] = [];
  for (const span of pieces) {
    const previous = clipped.at(-1);
    // A later span ending at or after the previous one gives the merged span its end reason: a
    // registration with no recorded end makes what follows unconfirmed, however short it was.
    if (previous && span.from <= previous.to) { if (span.to >= previous.to) { previous.to = span.to; previous.end = span.end; } }
    else clipped.push({ ...span });
  }
  const gaps: Gap[] = [];
  let cursor = from;
  let reason: GapReason = firstRun === null || from < firstRun ? 'before-journal' : 'not-registered';
  // The reason for a gap that starts the window: whatever ended the last span before it.
  let before: Span | undefined;
  for (const span of covered) if (span.to <= from && (!before || span.to >= before.to)) before = span;
  if (before) reason = before.end;
  for (const span of clipped) {
    if (span.from > cursor) gaps.push({ from: cursor, to: span.from, reason, dropped: 0 });
    cursor = Math.max(cursor, span.to);
    reason = span.end;
  }
  if (cursor < to) gaps.push({ from: cursor, to, reason, dropped: 0 });
  // Drop records inside the window are listed with their counts, merged with the gap they form:
  // each record's count is listed only when that record touches the window (a merged window
  // would carry counts from outside it). The records are sorted by start, the sweep's gaps are
  // sorted, and a record can only extend the last gap this listing added, so one pointer serves.
  let gapIndex = 0;
  const listed: Gap[] = [];
  for (const drop of drops) {
    if (drop.to < from || drop.from > to) continue;
    const window = { from: Math.max(drop.from, from), to: Math.min(drop.to, to) };
    while (gapIndex < gaps.length && gaps[gapIndex].to < window.from) gapIndex += 1;
    let existing: Gap | undefined;
    for (let index = gapIndex; index < gaps.length && gaps[index].from <= window.to; index += 1) {
      if (gaps[index].reason === 'dropped') { existing = gaps[index]; break; }
    }
    const last = listed.at(-1);
    if (!existing && last && last.from <= window.to && window.from <= last.to) existing = last;
    if (existing) { existing.dropped += drop.dropped; existing.from = Math.min(existing.from, window.from); existing.to = Math.max(existing.to, window.to); }
    else listed.push({ ...window, reason: 'dropped', dropped: drop.dropped });
  }
  for (const gap of listed) gaps.push(gap); // never spread: a hostile journal lists hundreds of thousands
  gaps.sort((a, b) => a.from - b.from || a.to - b.to);
  return { covered: clipped.map(span => [span.from, span.to]), gaps,
    coveredMs: clipped.reduce((total, span) => total + (span.to - span.from), 0) };
}

/**
 * Writes every byte of `text` through the descriptor (1.2.1). A write may complete partially
 * (a full disk, a signal); counting what was written is the only way to know the line landed.
 * A write that makes no progress fails, as a failed write does.
 */
export async function writeAll(handle: Pick<nodeFs.FileHandle, 'write'>, text: string): Promise<void> {
  const bytes = Buffer.from(text, 'utf8');
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset);
    if (bytesWritten <= 0) throw new Error('write made no progress');
    offset += bytesWritten;
  }
}

/** Owner-only regular file: POSIX mode and owner from the open descriptor. */
function ownerOnlyProblem(stat: { mode: number; uid: number }, platform: NodeJS.Platform, uid: number | undefined): string | null {
  if (platform === 'win32') return null;
  if (uid !== undefined && stat.uid !== uid) return 'payment journal is owned by another user';
  if ((stat.mode & 0o077) !== 0) return 'payment journal must be owner-only (mode 0600)';
  return null;
}

export type WriterDeps = {
  fs: typeof nodeFs;
  clock: () => Date;
  /** Takes `<journal>.lock` (one writer per journal); returns its release. */
  lock: (path: string) => Promise<() => Promise<void>>;
  platform?: NodeJS.Platform;
  uid?: number;
  /** Told once when journaling stops before the run ends (watch reports it as a status event). */
  onStop?: (reason: NonNullable<JournalStats['stopped']>) => void;
};

export type JournalStats = { path: string; payments: number; deletions: number; dropped: number;
  /** Why journaling stopped before the run ended: the size limit, a failed write, or markers the disk did not take. */
  stopped: 'full' | 'write-failed' | 'stalled' | null };

type Intake = { kind: 'call'; at: number; method: string; requestId: bigint; macaroon: Secret | null; oversizedMacaroon: boolean;
  payload: Buffer | null; oversizedPayload: boolean; bytes: number }
  | { kind: 'marker'; make: (time: string) => JournalRecord; bytes: number; at: number };
type Drops = { count: number; first: number; last: number };
/**
 * A line waiting for the disk, with what a `full` needs to report it if it never lands: its
 * record type and time, and the calls it stands for (1 for a payment or deletion, a `drop`
 * record's count, 0 for other markers) with the earliest capture time among them.
 */
type Line = { text: string; type: JournalRecord['type']; at: number; calls: number; first: number };

/**
 * The journal writer of one watch run. Intercepted calls are captured synchronously (a bounded
 * copy of the payload and the caller's macaroon) and decoded later, off the intercept path;
 * records and markers keep their order through one FIFO; lines are appended and fsync'd by one
 * write at a time, so a slow disk never delays an intercept answer: when it falls behind,
 * payment records are dropped and counted, and a `drop` record says how many and when.
 */
export class PaymentJournal {
  readonly run = randomUUID();
  /** True when the journal lies on a Windows volume that stores no permissions (FAT, exFAT). */
  aclWarning = false;
  private readonly intake: Intake[] = [];
  private intakeHead = 0;
  private intakeBytes = 0;
  private scheduled = false;
  private budget = JOURNAL_BURST_MS;
  private budgetAt = performance.now();
  private retry: ReturnType<typeof setTimeout> | null = null;
  private pending: Line[] = [];
  private pendingBytes = 0;
  private markerBytes = 0;
  private writing: Promise<void> | null = null;
  // Calls dropped at capture (intake full): reported by a drop record placed in the FIFO before
  // the next accepted item, so the file keeps capture order.
  private intakeDrop: Drops | null = null;
  // Records dropped because the line queue was full: reported by a drop record before the next line.
  private lineDrop: Drops | null = null;
  private lastTime = 0;
  private lastWrite = Date.now();
  private session = 0;
  private registeredSession: number | null = null;
  private aliveTimer: ReturnType<typeof setInterval> | undefined;
  private closing = false;
  readonly stats: JournalStats;

  private constructor(private readonly handle: nodeFs.FileHandle, private size: number, private readonly release: () => Promise<void>,
    private readonly clock: () => Date, path: string, private readonly onStop?: WriterDeps['onStop']) {
    this.stats = { path, payments: 0, deletions: 0, dropped: 0, stopped: null };
  }

  /**
   * Opens (or creates) the journal and appends this run's `run-start`, synced, before watch
   * registers. Refused (JournalError, nothing written): a protected path or target, a name
   * Windows would change, a symlink or anything but a regular file, another writer holding
   * `<journal>.lock`, a file that is not owner-only (POSIX), a file that does not start with a
   * journal record, or one with less than JOURNAL_START_ROOM_BYTES of room left. A last line
   * left incomplete or invalid by a crash is ended with a newline and the run-start says `repairedTail`.
   */
  static async open(path: string, node: string, version: string, deps: WriterDeps): Promise<PaymentJournal> {
    const fs = deps.fs;
    const platform = deps.platform ?? process.platform;
    if (isProtectedPath(path)) throw new JournalError('protected payment journal path');
    let target: string;
    try { target = await resolveUnprotectedPath(path, fs); }
    catch { throw new JournalError('protected or unresolvable payment journal path'); }
    const nameProblem = outputNameProblem(target, platform);
    if (nameProblem) throw new JournalError(`invalid payment journal path: ${nameProblem}`);
    let existing: Awaited<ReturnType<typeof fs.lstat>> | null = null;
    try { existing = await fs.lstat(target); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new JournalError('cannot read payment journal'); }
    if (existing && (!existing.isFile() || existing.isSymbolicLink())) throw new JournalError('payment journal is not a regular file');
    let release: () => Promise<void>;
    try { release = await deps.lock(`${target}.lock`); }
    catch { throw new JournalError(`another watch writes this payment journal (lock ${target}.lock)`); }
    let handle: nodeFs.FileHandle | null = null;
    let aclWarning = false;
    try {
      // Windows (1.2.1): mode bits mean nothing there, so a new journal is created owner-only by
      // the shared helper (owned by this user, a protected DACL granting only this user), and an
      // existing one must already be, as a POSIX journal must be 0600.
      let created: { dev: number; ino: number } | null = null;
      if (process.platform === 'win32') {
        if (existing) {
          const found = await verifyOwnerOnly(target);
          if (!found) throw new JournalError('cannot verify the payment journal permissions');
          if (found.noAcl) aclWarning = true;
          else if (!found.ownerOnly) throw new JournalError('payment journal must be owner-only: on Windows it must be owned by your account and grant '
            + 'only your account, with inheritance disabled (for example: icacls <journal> /inheritance:r /grant:r "%USERNAME%":F /setowner "%USERNAME%"), '
            + 'or start a new journal at another path');
        } else {
          let reserved: Awaited<ReturnType<typeof reserveOwnerOnly>>;
          try { reserved = await reserveOwnerOnly(target, fs); }
          catch (error) { throw new JournalError(`cannot create payment journal${error instanceof PrivateFileError ? `: ${error.message}` : ''}`); }
          aclWarning = reserved.aclWarning;
          const stat = await reserved.handle.stat();
          created = { dev: stat.dev, ino: stat.ino };
          await reserved.handle.close();
        }
      }
      try {
        handle = await fs.open(target, constants.O_RDWR | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0), 0o600);
      } catch { throw new JournalError('cannot open payment journal'); }
      const opened = await handle.stat();
      if (!opened.isFile()) throw new JournalError('payment journal is not a regular file');
      const before = existing ?? created;
      if (before && (opened.dev !== before.dev || opened.ino !== before.ino)) throw new JournalError('payment journal changed while opened');
      const problem = ownerOnlyProblem(opened, platform, deps.uid ?? process.getuid?.());
      if (problem) throw new JournalError(problem);
      const size = opened.size;
      if (size > JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - JOURNAL_START_ROOM_BYTES)
        throw new JournalError('payment journal is full (64 MiB); move it aside and start watch again');
      let repairedTail = false;
      let newline = false;
      if (size > 0) {
        const head = Buffer.alloc(Math.min(size, 64));
        await handle.read(head, 0, head.length, 0);
        if (!head.toString('latin1').startsWith('{"v":1,"type":"run-start"')) throw new JournalError('not a macwarden payment journal');
        // The file must end with a complete, valid record; anything else is what a crash left.
        const length = Math.min(size, JOURNAL_LINE_LIMIT + 2);
        const tail = Buffer.alloc(length);
        await handle.read(tail, 0, length, size - length);
        newline = tail[length - 1] !== 0x0a;
        const previous = tail.lastIndexOf(0x0a, length - 2);
        const line = previous < 0 && length < size ? null : tail.toString('utf8', previous + 1, length - 1);
        repairedTail = newline || line === null || parseRecord(line) === null;
      }
      const journal = new PaymentJournal(handle, size, release, deps.clock, target, deps.onStop);
      journal.aclWarning = aclWarning;
      // The run-start has no earlier record to fall back on: a clock the reader cannot take is refused.
      const startAt = journal.clockTime();
      if (startAt === null) throw new JournalError('cannot open payment journal: the system clock is invalid');
      const first: RunStartRecord = { v: 1, type: 'run-start', time: journal.stamp(startAt), run: journal.run, node, version, repairedTail };
      const text = `${newline ? '\n' : ''}${JSON.stringify(first)}\n`;
      try { await writeAll(handle, text); await handle.sync(); }
      catch { throw new JournalError('cannot write payment journal'); }
      journal.size += Buffer.byteLength(text);
      journal.aliveTimer = setInterval(() => journal.keepAlive(), Math.min(JOURNAL_ALIVE_MS, 60_000));
      journal.aliveTimer.unref?.();
      return journal;
    } catch (error) {
      await handle?.close().catch(() => undefined);
      await release().catch(() => undefined);
      throw error instanceof JournalError ? error : new JournalError('cannot open payment journal');
    }
  }

  /**
   * The clock in milliseconds, or null when it is not a time the reader accepts (audit 1.2.1:
   * NaN threw out of the decoding turn and crashed watch; past the year 9999 every later record
   * was one the reader refuses).
   */
  private clockTime(): number | null {
    let value: number;
    try { value = this.clock().getTime(); } catch { return null; }
    return Number.isFinite(value) && value <= MAX_RECORD_TIME ? value : null;
  }

  /** The record time: the clock, never earlier than this run's previous record; the previous time when the clock is invalid. */
  private now(): string {
    return this.stamp(this.clockTime() ?? this.lastTime);
  }

  private base(time: string): Base { return { v: 1, time, run: this.run }; }

  /**
   * Called synchronously from the observer for a journaled method's `request` intercept,
   * while the intercepted frame is still valid. Costs a counter when the intake is full.
   */
  capture(call: MiddlewareCall): void {
    const at = Math.max(this.lastTime, this.clockTime() ?? this.lastTime);
    if (this.closing || this.stats.stopped) { this.stats.dropped += 1; return; }
    const bytes = (call.payloadBytes ?? 0) + (call.macaroonBytes ?? 0) + 256;
    if (this.intake.length - this.intakeHead >= JOURNAL_INTAKE_ITEMS || this.intakeBytes + bytes > JOURNAL_INTAKE_BYTES) {
      this.intakeDrop = this.note(this.intakeDrop, at);
      return;
    }
    this.flushIntakeDrop();
    this.intake.push({ kind: 'call', at, method: call.method, requestId: call.requestId, macaroon: call.macaroon,
      oversizedMacaroon: call.oversizedMacaroon === true, payload: call.payload ?? null, oversizedPayload: call.oversizedPayload === true, bytes });
    this.intakeBytes += bytes;
    this.schedule();
  }

  /** The observer session registered: coverage begins. */
  registered(): void {
    if (this.registeredSession !== null) return;
    const session = ++this.session;
    this.registeredSession = session;
    this.marker(time => ({ ...this.base(time), type: 'registered', session }));
  }

  /** The observer session ended (or was closed): coverage ends. */
  unregistered(reason: UnregisterReason): void {
    const session = this.registeredSession;
    if (session === null) return;
    this.registeredSession = null;
    this.marker(time => ({ ...this.base(time), type: 'unregistered', session, reason }));
  }

  private keepAlive(): void {
    if (this.registeredSession === null || this.stats.stopped || this.closing) return;
    if (Date.now() - this.lastWrite < JOURNAL_ALIVE_MS) return;
    this.lastWrite = Date.now();
    this.marker(time => ({ ...this.base(time), type: 'alive' }));
  }

  private marker(make: (time: string) => JournalRecord, at = this.clockTime() ?? this.lastTime): void {
    if (this.stats.stopped) return;
    this.flushIntakeDrop();
    this.intake.push({ kind: 'marker', make, bytes: 0, at });
    this.schedule();
  }

  private note(drops: Drops | null, at: number): Drops {
    this.stats.dropped += 1;
    if (!drops) return { count: 1, first: at, last: at };
    drops.count += 1;
    drops.first = Math.min(drops.first, at);
    drops.last = Math.max(drops.last, at);
    return drops;
  }

  private dropRecord(drops: Drops, time: string): DropRecord {
    return { ...this.base(time), type: 'drop', count: drops.count, first: new Date(drops.first).toISOString(),
      last: new Date(Math.min(drops.last, Date.parse(time))).toISOString(), reason: 'overload' };
  }

  /** Puts the drops counted at capture into the FIFO, so their record follows what was captured before them. */
  private flushIntakeDrop(): void {
    const drops = this.intakeDrop;
    if (!drops) return;
    this.intakeDrop = null;
    this.intake.push({ kind: 'marker', make: time => this.dropRecord(drops, time), bytes: 0, at: drops.last });
  }

  private schedule(): void {
    if (this.scheduled || this.retry) return;
    this.scheduled = true;
    setImmediate(() => { this.scheduled = false; this.drain(); });
  }

  /** One budgeted decoding turn; when the budget is spent, the next waits on a short timer, never spins. */
  private drain(): void {
    const now = performance.now();
    this.budget = Math.min(JOURNAL_BURST_MS, this.budget + (now - this.budgetAt) * JOURNAL_SHARE);
    this.budgetAt = now;
    if (this.budget > 0) {
      this.process(INTAKE_BATCH, this.budget);
      const after = performance.now();
      this.budget -= after - now;
      this.budgetAt = after;
    }
    if (this.intakeHead < this.intake.length && !this.scheduled && !this.retry) {
      if (this.budget > 0) this.schedule();
      else {
        this.retry = setTimeout(() => { this.retry = null; this.schedule(); }, JOURNAL_RETRY_MS);
        this.retry.unref?.();
      }
    }
  }

  /** Decodes up to `limit` intake items (at least one, within `budgetMs`) into lines, in order, then starts a write. */
  private process(limit: number, budgetMs = Infinity): void {
    const started = performance.now();
    let done = 0;
    while (this.intakeHead < this.intake.length && done < limit && (done === 0 || performance.now() - started < budgetMs)) {
      const item = this.intake[this.intakeHead];
      this.intake[this.intakeHead++] = undefined as unknown as Intake;
      this.intakeBytes -= item.bytes;
      done += 1;
      try {
        // A marker's time is the moment it describes (a registration change, a drop's last call), never
        // before the run's previous record; not the moment the queue reached it (1.2.1: a backlog
        // once moved an unregistered and the next registered to the same instant, hiding the gap).
        if (item.kind === 'marker') this.append(item.make(this.stamp(item.at)), false);
        else this.append(this.record(item), true);
      } catch { if (item.kind === 'call') this.lineDrop = this.note(this.lineDrop, Date.parse(this.stamp(item.at))); }
    }
    if (this.intakeHead === this.intake.length) { this.intake.length = 0; this.intakeHead = 0; }
    else if (this.intakeHead > 4_096) { this.intake.splice(0, this.intakeHead); this.intakeHead = 0; }
    this.startWrite();
  }

  /** A record time for a call captured at `at`: never earlier than the run's previous record. */
  private stamp(at: number): string {
    if (Number.isFinite(at) && at <= MAX_RECORD_TIME) this.lastTime = Math.max(this.lastTime, at);
    return new Date(this.lastTime).toISOString();
  }

  private record(item: Extract<Intake, { kind: 'call' }>): PaymentRecord | DeletionRecord {
    let credential = item.oversizedMacaroon ? 'id:undecodable' : 'id:none';
    let rootKeyId = 'none';
    if (item.macaroon) {
      try { const identity = macaroonId(item.macaroon); credential = identity.id; rootKeyId = identity.rootKeyId.toString(); }
      catch { credential = 'id:undecodable'; }
    }
    const payload = item.payload;
    try {
      const time = this.stamp(item.at);
      const whoFields = { requestId: item.requestId.toString(), credential, rootKeyId };
      // Every record is checked with the reader's own rules before it is written (1.2.1): one the
      // reader would refuse makes the whole journal unreadable, so a value outside its documented
      // form is recorded as 'malformed' with no facts, and one whose identity fields cannot be
      // written at all is dropped (counted, like any other drop) rather than written.
      const valid = (record: PaymentRecord | DeletionRecord) => parseRecord(JSON.stringify(record)) !== null;
      const identities = [whoFields, { requestId: whoFields.requestId, credential: 'id:undecodable', rootKeyId: 'none' }];
      if ((PAYMENT_METHODS as readonly string[]).includes(item.method)) {
        const facts = paymentFacts(item.method, payload, item.oversizedPayload);
        const method = item.method as PaymentRecord['method'];
        const record: PaymentRecord = { ...this.base(time), type: 'payment', ...whoFields, method,
          paymentHash: facts.paymentHash, amountMsat: facts.amountMsat, amountSource: facts.amountSource,
          feeLimitMsat: facts.feeLimitMsat, amp: facts.amp, extraction: facts.extraction };
        if (valid(record)) return record;
        for (const who of identities) {
          const fallback: PaymentRecord = { ...this.base(time), type: 'payment', ...who, method, paymentHash: null, amountMsat: null,
            amountSource: null, feeLimitMsat: null, amp: false, extraction: 'malformed' };
          if (valid(fallback)) return fallback;
        }
        throw new Error('unwritable payment record');
      }
      const facts = deletionFacts(item.method, payload, item.oversizedPayload);
      const method = item.method as DeletionRecord['method'];
      const record: DeletionRecord = { ...this.base(time), type: 'deletion', ...whoFields, method,
        paymentHash: facts.paymentHash, scope: facts.scope, extraction: facts.extraction };
      if (valid(record)) return record;
      for (const who of identities) {
        const fallback: DeletionRecord = { ...this.base(time), type: 'deletion', ...who, method, paymentHash: null, scope: 'none', extraction: 'malformed' };
        if (valid(fallback)) return fallback;
      }
      throw new Error('unwritable deletion record');
    } finally {
      // The payload holds the invoice text; it is not kept past its decoding.
      payload?.fill(0);
    }
  }

  private append(record: JournalRecord, droppable: boolean): void {
    if (this.stats.stopped) { if (droppable) this.stats.dropped += 1; return; }
    const text = `${JSON.stringify(record)}\n`;
    const bytes = Buffer.byteLength(text);
    if (droppable && this.pendingBytes + bytes > JOURNAL_PENDING_BYTES) {
      this.lineDrop = this.note(this.lineDrop, Date.parse(record.time));
      return;
    }
    if (this.lineDrop) {
      // Records dropped for lack of room are reported before the next line. Their times were
      // already stamped, so the run's latest time covers them: the drop record takes it and
      // times never decrease along the file.
      const drops = this.lineDrop;
      this.lineDrop = null;
      const drop = this.dropRecord(drops, new Date(this.lastTime).toISOString());
      this.queue({ text: `${JSON.stringify(drop)}\n`, type: 'drop', at: Date.parse(drop.time), calls: drop.count, first: drops.first }, false);
    }
    const at = Date.parse(record.time);
    const calls = record.type === 'payment' || record.type === 'deletion' ? 1 : 0;
    this.queue({ text, type: record.type, at, calls, first: at }, droppable);
    if (record.type === 'payment') this.stats.payments += 1;
    else if (record.type === 'deletion') this.stats.deletions += 1;
  }

  /** Records that will never be written: counted as dropped instead of journaled. */
  private discard(lines: Line[]): void {
    for (const line of lines) {
      if (line.type === 'payment') { this.stats.payments -= 1; this.stats.dropped += 1; }
      else if (line.type === 'deletion') { this.stats.deletions -= 1; this.stats.dropped += 1; }
    }
  }

  private queue(line: Line, droppable: boolean): void {
    const bytes = Buffer.byteLength(line.text);
    if (!droppable) {
      this.markerBytes += bytes;
      if (this.markerBytes > JOURNAL_MARKER_BYTES) { this.stop('stalled'); return; }
    }
    this.pending.push(line);
    this.pendingBytes += bytes;
    this.lastWrite = Date.now();
  }

  private stop(reason: NonNullable<JournalStats['stopped']>): void {
    if (this.stats.stopped) return;
    this.stats.stopped = reason;
    this.discard(this.pending);
    this.pending = [];
    this.pendingBytes = 0;
    this.markerBytes = 0;
    this.registeredSession = null;
    try { this.onStop?.(reason); } catch { /* reporting never affects the journal */ }
  }

  private startWrite(): void {
    if (this.writing || !this.pending.length || this.stats.stopped) return;
    this.writing = this.writeLoop().finally(() => { this.writing = null; if (this.pending.length && !this.stats.stopped) this.startWrite(); });
  }

  private async writeLoop(): Promise<void> {
    while (this.pending.length && !this.stats.stopped) {
      const lines = this.pending;
      this.pending = [];
      this.pendingBytes = 0;
      this.markerBytes = 0;
      // The file never grows past the limit: what does not fit is dropped, and a `drop` and a
      // `full` record, written into the reserved room, say what was lost and end coverage.
      const room = JOURNAL_LIMIT_BYTES - JOURNAL_RESERVE_BYTES - this.size;
      let take = 0;
      let bytes = 0;
      while (take < lines.length && bytes + Buffer.byteLength(lines[take].text) <= room) bytes += Buffer.byteLength(lines[take++].text);
      let text = lines.slice(0, take).map(line => line.text).join('');
      const full = take < lines.length;
      if (full) {
        const lost = lines.slice(take);
        this.discard(lost);
        text += this.fullRecords(lost);
      }
      try {
        await writeAll(this.handle, text);
        await this.handle.sync();
        this.size += Buffer.byteLength(text);
      } catch {
        // A failed append may have left part of a line: nothing more is written in this run, so
        // the next run's `repairedTail` and the reader's rule account for it.
        this.discard(lines.slice(0, take));
        this.stop('write-failed');
        return;
      }
      if (full) { this.stop('full'); return; }
    }
  }

  /**
   * The lines that end a full journal, for the `lost` lines that did not fit (1.2.1: the `full`
   * record once took the time it was written, so coverage ran on over the payments it had just
   * discarded and they left no trace). Coverage must end where the loss began, and records must
   * not go back in time, so: a `drop` record counts the calls the lost lines stand for (payment
   * and deletion records, and the counts of lost `drop` records), together with the calls
   * dropped earlier and not yet reported, from the earliest capture time of any lost line,
   * marker or call, to the latest; the `full` record follows at that latest time. The drop
   * window starts at the first lost line even when that is a marker: a lost `unregistered` would
   * otherwise leave the time after it looking covered. When only markers were lost (no call),
   * there is no `drop` record (a drop counts at least one call) and the `full` record takes the
   * first lost line's time instead. Both times are at or after every written record (the queue
   * is in time order), and both lines fit in JOURNAL_RESERVE_BYTES. Drops are already counted
   * in the statistics (discard, note); nothing is counted here.
   */
  private fullRecords(lost: Line[]): string {
    let calls = 0;
    let first = lost[0].first;
    let last = lost[0].at;
    for (const line of lost) { calls += line.calls; first = Math.min(first, line.first); last = Math.max(last, line.at); }
    for (const drops of [this.lineDrop, this.intakeDrop]) {
      if (!drops) continue;
      calls += drops.count; first = Math.min(first, drops.first); last = Math.max(last, drops.last);
    }
    this.lineDrop = null;
    this.intakeDrop = null;
    const iso = (at: number) => new Date(at).toISOString();
    const end = `${JSON.stringify({ ...this.base(iso(calls ? last : lost[0].at)), type: 'full' } satisfies FullRecord)}\n`;
    if (!calls) return end;
    const drop: DropRecord = { ...this.base(iso(last)), type: 'drop', count: calls, first: iso(first), last: iso(last), reason: 'overload' };
    return `${JSON.stringify(drop)}\n${end}`;
  }

  /**
   * Ends the run: remaining intake is decoded, `unregistered` (if still registered) and
   * `run-end` are appended and synced, the file is closed and the lock released. Captures after
   * this are counted as dropped. Returns the run's statistics.
   */
  async close(): Promise<JournalStats> {
    if (this.closing) return this.stats;
    clearInterval(this.aliveTimer);
    this.unregistered('stopping');
    this.flushIntakeDrop();
    this.closing = true;
    if (this.retry) { clearTimeout(this.retry); this.retry = null; }
    this.process(Number.MAX_SAFE_INTEGER);
    if (!this.stats.stopped) {
      // Drops not yet reported are written (by append) before the end record.
      const { payments, deletions } = this.stats;
      this.append({ ...this.base(this.now()), type: 'run-end', payments, deletions, dropped: this.stats.dropped }, false);
    }
    this.startWrite();
    while (this.writing) await this.writing;
    await this.handle.close().catch(() => undefined);
    await this.release().catch(() => undefined);
    return this.stats;
  }
}
