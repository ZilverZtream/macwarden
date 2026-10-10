// Observed credential usage recorded by `macwarden watch`, kept next to the registry.
// It holds only credential IDs (identifier hashes), root key IDs, method names, counts and
// timestamps:
// never macaroon bytes, request or response payloads, or gRPC metadata.
import * as nodeFs from 'node:fs/promises';
import { reserveOwnerOnly } from '../private-file.js';
import { randomUUID } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import { BoundedFileError, readBoundedFile, type BoundedReadIO } from '../bounded-file.js';
import { isInstant } from '../instant.js';
import { isRootKeyId } from '../root-key-id.js';

// Callers choose how many distinct (credential, method) pairs exist, so the store is
// bounded. At capacity the least recently seen record is evicted (O(1): the Map keeps
// records in recency order), and the eviction is remembered so `recommend` can tell
// whether a credential's history may be incomplete. 20,000 records serialize in a few
// milliseconds, keeping each flush's event-loop stall small (watch answers LND from it).
export const USAGE_LIMIT = 20_000;

export type UsageRecord = {
  nodePubkey: string;
  credential: string;
  rootKeyId: string;
  method: string;
  calls: number;
  errors: number;
  firstSeen: string;
  lastSeen: string;
};

/**
 * Denied uses of one registered canary, counted by the guard. Kept apart from ordinary
 * usage: a canary in use means the place it was stored is compromised.
 */
export type CanaryUse = { nodePubkey: string; rootKeyId: string; uses: number; firstUse: string; lastUse: string };

/**
 * How long watch has observed one node: from the first registration to the last moment it
 * was known registered, the time actually covered (gaps between runs excluded) and how many
 * registrations there were. recommend uses it to tell how much usage it has seen.
 */
export type Coverage = { nodePubkey: string; firstStart: string; lastEnd: string; coveredSeconds: number; sessions: number };

// Both lists are bounded: canaries by the registry in practice, nodes by how many nodes
// one registry serves. At capacity the least recently updated record is dropped.
export const CANARY_LIMIT = 1_000;
export const COVERAGE_LIMIT = 64;

/**
 * Per node, the most recent registered spans (start, end), oldest first and disjoint. They
 * place the covered time on the clock, so recommend can count only the coverage after a
 * credential was created. At most this many per node: when more, the oldest is dropped,
 * which only ever undercounts. Written as the top-level `coverageSpans` (from 1.1.0), apart
 * from `coverage`, whose records 1.0.1 reads with exactly their original keys.
 */
export const SPAN_LIMIT = 256;
export type CoverageSpans = { nodePubkey: string; spans: [string, string][] };

/**
 * Largest usage file read, derived from the record caps: 1 KiB per usage record (watch
 * writes at most about 600 bytes: a method name over 256 bytes is recorded as
 * /unknown/Unknown), 512 bytes per canary use or coverage record (at most about 200), 64 bytes per
 * coverage span (55 written) and 4 KiB for the counters. A larger file is refused before it is parsed.
 */
export const USAGE_FILE_LIMIT = 4096 + USAGE_LIMIT * 1024 + (CANARY_LIMIT + COVERAGE_LIMIT) * 512
  + COVERAGE_LIMIT * SPAN_LIMIT * 64;

export class UsageFileError extends Error {
  readonly code = 3;
  constructor(message: string) { super(message); this.name = 'UsageFileError'; }
}

const fields = ['nodePubkey', 'credential', 'rootKeyId', 'method', 'calls', 'errors', 'firstSeen', 'lastSeen'];
// Timestamps must be real instants (isInstant) and each pair in order, compared as instants:
// evidence with an impossible or reversed time is refused, never used for time arithmetic.
const ordered = (first: unknown, last: unknown) => isInstant(first) && isInstant(last) && Date.parse(first) <= Date.parse(last);
/** The later of two instants (a clock stepping back never moves a "last" time before its "first"). */
const later = (current: string, now: string) => Date.parse(now) >= Date.parse(current) ? now : current;
const NODE = /^0[23][0-9a-f]{64}$/;
const exactKeys = (record: Record<string, unknown>, names: string[]) => {
  const keys = Object.keys(record);
  return keys.length === names.length && keys.every(key => names.includes(key));
};
const count = (value: unknown) => Number.isSafeInteger(value) && (value as number) >= 0;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

function validCanaryUse(value: unknown): value is CanaryUse {
  return object(value) && exactKeys(value, ['nodePubkey', 'rootKeyId', 'uses', 'firstUse', 'lastUse'])
    && typeof value.nodePubkey === 'string' && NODE.test(value.nodePubkey)
    && isRootKeyId(value.rootKeyId)
    && count(value.uses) && ordered(value.firstUse, value.lastUse);
}

function validCoverage(value: unknown): value is Coverage {
  return object(value) && exactKeys(value, ['nodePubkey', 'firstStart', 'lastEnd', 'coveredSeconds', 'sessions'])
    && typeof value.nodePubkey === 'string' && NODE.test(value.nodePubkey)
    && ordered(value.firstStart, value.lastEnd)
    && count(value.coveredSeconds) && count(value.sessions);
}

function validSpans(value: unknown): value is CoverageSpans {
  return object(value) && exactKeys(value, ['nodePubkey', 'spans'])
    && typeof value.nodePubkey === 'string' && NODE.test(value.nodePubkey)
    && Array.isArray(value.spans) && value.spans.length <= SPAN_LIMIT
    && value.spans.every(span => Array.isArray(span) && span.length === 2
      && ordered(span[0], span[1]));
}

/** The union of spans: overlapping or touching ones merged, so no time is counted twice. */
function union(spans: [number, number][]): [number, number][] {
  const merged: [number, number][] = [];
  for (const [from, to] of [...spans].sort((a, b) => a[0] - b[0])) {
    const last = merged.at(-1);
    if (last && from <= last[1]) last[1] = Math.max(last[1], to); else merged.push([from, to]);
  }
  return merged;
}

function validRecord(value: unknown): value is UsageRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === fields.length && keys.every(key => fields.includes(key))
    && typeof record.nodePubkey === 'string' && /^0[23][0-9a-f]{64}$/.test(record.nodePubkey)
    && typeof record.credential === 'string' && /^id:[0-9a-f]{16}$/.test(record.credential)
    && isRootKeyId(record.rootKeyId)
    && typeof record.method === 'string' && /^\/[A-Za-z0-9_.]+\/[A-Za-z0-9_]+$/.test(record.method)
    && Number.isSafeInteger(record.calls) && (record.calls as number) >= 0
    && Number.isSafeInteger(record.errors) && (record.errors as number) >= 0
    && ordered(record.firstSeen, record.lastSeen);
}

export class UsageStore {
  private readonly records = new Map<string, UsageRecord>();
  dropped = 0;
  /** Records evicted to make room, and when the last one was (ISO time), if ever. */
  evictions = 0;
  lastEviction: string | null = null;
  changed = false;
  /** Increments on every change; a write clears 'changed' only if nothing changed meanwhile. */
  version = 0;
  /** Calls refused because their identity was not a valid node, credential or root key ID. */
  refused = 0;
  /**
   * Calls watch could not attribute because it was overloaded (its attribution queue was
   * full), and when the last one was. Their credentials are unknown, so any of them may be
   * missing usage: recommend never narrows while this is non-zero.
   */
  droppedAttributions = 0;
  lastAttributionDrop: string | null = null;

  private readonly canaryUses = new Map<string, CanaryUse>();
  private readonly coverages = new Map<string, Coverage>();
  /** Per node: the instant up to which the current registration was already counted. */
  private readonly covering = new Map<string, number>();
  /** Per node with a coverage record: its registered spans in ms (see SPAN_LIMIT). */
  private readonly spans = new Map<string, [number, number][]>();

  constructor(readonly limit = USAGE_LIMIT) {}

  private touch(): void { this.changed = true; this.version += 1; }

  /** Counts denied uses of a registered canary. */
  recordCanary(nodePubkey: string, rootKeyId: string, uses: number, at: Date): void {
    if (!NODE.test(nodePubkey) || !isRootKeyId(rootKeyId) || !Number.isSafeInteger(uses) || uses < 1) return;
    const key = `${nodePubkey}\0${rootKeyId}`;
    const now = at.toISOString();
    const existing = this.canaryUses.get(key);
    this.canaryUses.delete(key);
    if (!existing && this.canaryUses.size >= CANARY_LIMIT) this.canaryUses.delete(this.canaryUses.keys().next().value as string);
    this.canaryUses.set(key, existing
      ? { ...existing, uses: Math.min(existing.uses + uses, Number.MAX_SAFE_INTEGER), lastUse: later(existing.lastUse, now) }
      : { nodePubkey, rootKeyId, uses, firstUse: now, lastUse: now });
    this.touch();
  }

  canaryUsesFor(nodePubkey: string, rootKeyId: string): CanaryUse | null {
    return this.canaryUses.get(`${nodePubkey.toLowerCase()}\0${rootKeyId}`) ?? null;
  }

  /** A registration with this node began: coverage counts from here. */
  beginCoverage(nodePubkey: string, at: Date): void {
    if (!NODE.test(nodePubkey)) return;
    this.extendCoverage(nodePubkey, at);
    const now = at.toISOString();
    const existing = this.coverages.get(nodePubkey);
    this.coverages.delete(nodePubkey);
    if (!existing && this.coverages.size >= COVERAGE_LIMIT) {
      const oldest = this.coverages.keys().next().value as string;
      this.coverages.delete(oldest);
      this.spans.delete(oldest);
    }
    this.coverages.set(nodePubkey, existing ? { ...existing, sessions: existing.sessions + 1, lastEnd: later(existing.lastEnd, now) }
      : { nodePubkey, firstStart: now, lastEnd: now, coveredSeconds: 0, sessions: 1 });
    // A new span, starting no earlier than the last one ended (a clock stepping back never
    // makes spans overlap); one starting exactly where the last ended continues it. The seconds
    // counter starts there too (1.2.1): it once started at the raw clock and, after a step back
    // and the correction, counted time the spans already held.
    const spans = existing ? this.spans.get(nodePubkey) ?? [] : [];
    const last = spans.at(-1);
    const from = Math.max(at.getTime(), last?.[1] ?? -Infinity);
    this.covering.set(nodePubkey, from);
    if (!last || from > last[1]) {
      spans.push([from, from]);
      if (spans.length > SPAN_LIMIT) spans.shift();
    }
    this.spans.set(nodePubkey, spans);
    this.touch();
  }

  /** Counts the time since the last call as covered, while a registration is current. */
  extendCoverage(nodePubkey: string, at: Date): void {
    const from = this.covering.get(nodePubkey);
    const record = this.coverages.get(nodePubkey);
    if (from === undefined || !record) return;
    const until = at.getTime();
    if (until <= from) return;
    // Whole seconds only; the remainder is carried to the next call.
    const seconds = Math.floor((until - from) / 1_000);
    if (seconds > 0) {
      record.coveredSeconds += seconds;
      this.covering.set(nodePubkey, from + seconds * 1_000);
    }
    const span = this.spans.get(nodePubkey)?.at(-1);
    if (span && until > span[1]) span[1] = until;
    record.lastEnd = later(record.lastEnd, at.toISOString());
    this.touch();
  }

  /** The registration ended (stream lost, run stopped). */
  endCoverage(nodePubkey: string, at: Date): void {
    this.extendCoverage(nodePubkey, at);
    this.covering.delete(nodePubkey);
  }

  coverageFor(nodePubkey: string): Coverage | null {
    const record = this.coverages.get(nodePubkey.toLowerCase());
    return record ? { ...record } : null;
  }

  /**
   * Whole seconds of recorded spans after the instant `since` (ms): a lower bound of the time
   * watch was registered with this node since then. Null when no spans were recorded (a file
   * written before 1.1.0, or rewritten by 1.0.1).
   */
  coveredSince(nodePubkey: string, since: number): number | null {
    const node = nodePubkey.toLowerCase();
    const spans = this.coverages.has(node) ? this.spans.get(node) : undefined;
    if (!spans?.length) return null;
    let ms = 0;
    for (const [from, to] of spans) ms += Math.max(0, to - Math.max(from, since));
    return Math.floor(ms / 1_000);
  }

  private key(nodePubkey: string, credential: string, rootKeyId: string, method: string): string {
    return `${nodePubkey}\0${credential}\0${rootKeyId}\0${method}`;
  }

  /**
   * Counts one call; a method name that is not a gRPC URI is recorded as "/unknown/Unknown".
   * Returns false, recording nothing, for an identity the file format would reject, so
   * one odd call can never make the usage file unreadable.
   */
  record(nodePubkey: string, credential: string, rootKeyId: string, method: string, at: Date, error = false): boolean {
    if (!/^0[23][0-9a-f]{64}$/.test(nodePubkey) || !/^id:[0-9a-f]{16}$/.test(credential)
      || !isRootKeyId(rootKeyId)) { this.refused += 1; return false; }
    const safeMethod = /^\/[A-Za-z0-9_.]+\/[A-Za-z0-9_]+$/.test(method) ? method : '/unknown/Unknown';
    const key = this.key(nodePubkey, credential, rootKeyId, safeMethod);
    const now = at.toISOString();
    this.byRoot = null;
    const existing = this.records.get(key);
    if (existing) {
      if (error) existing.errors += 1; else existing.calls += 1;
      existing.lastSeen = later(existing.lastSeen, now);
      // Move to the end: the first record in the Map is always the least recently seen.
      this.records.delete(key);
      this.records.set(key, existing);
    } else {
      if (this.records.size >= this.limit) {
        const oldest = this.records.keys().next().value as string;
        this.records.delete(oldest);
        this.evictions += 1;
        this.lastEviction = now;
      }
      this.records.set(key, { nodePubkey, credential, rootKeyId, method: safeMethod,
        calls: error ? 0 : 1, errors: error ? 1 : 0, firstSeen: now, lastSeen: now });
    }
    this.changed = true;
    this.version += 1;
    return true;
  }

  /**
   * Notes one call that was not attributed (see droppedAttributions). Called once per drop
   * under overload, so it only counts and keeps a number; the time is formatted when the
   * store is written. A clock stepped back never moves the time before the one recorded.
   */
  noteDroppedAttribution(atMs: number): void {
    this.droppedAttributions += 1;
    const recorded = this.lastAttributionDropMs ?? (this.lastAttributionDrop === null ? null : Date.parse(this.lastAttributionDrop));
    this.lastAttributionDropMs = recorded === null || atMs > recorded ? atMs : recorded;
    this.changed = true;
    this.version += 1;
  }
  private lastAttributionDropMs: number | null = null;

  get size(): number { return this.records.size; }

  /** Records in a stable order (ordinal comparison, no locale work). */
  entries(): UsageRecord[] { return sortRecords([...this.records.values()]); }

  // Records by node and root key ID, built on first use and dropped on every change (audit
  // 1.2.1: inventory asked for each of 95,000 root key IDs, scanning every record each time).
  private byRoot: Map<string, UsageRecord[]> | null = null;
  private rootIndex(): Map<string, UsageRecord[]> {
    if (this.byRoot) return this.byRoot;
    const index = new Map<string, UsageRecord[]>();
    for (const record of this.records.values()) {
      const key = `${record.nodePubkey}\n${record.rootKeyId}`;
      const list = index.get(key);
      if (list) list.push(record); else index.set(key, [record]);
    }
    return this.byRoot = index;
  }

  forCredential(nodePubkey: string, select: { rootKeyId?: string; credential?: string }): UsageRecord[] {
    const node = nodePubkey.toLowerCase();
    const candidates = select.rootKeyId === undefined ? [...this.records.values()] : this.rootIndex().get(`${node}\n${select.rootKeyId}`) ?? [];
    return sortRecords(candidates.filter(record => record.nodePubkey === node
      && (select.rootKeyId === undefined || record.rootKeyId === select.rootKeyId)
      && (select.credential === undefined || record.credential === select.credential)));
  }

  /**
   * True when any credential's records may be missing. Conservative on purpose: an evicted
   * record or an unattributed call can belong to any credential, including one whose
   * remaining records were all first seen later (the lost call came first), so no time
   * window can prove a credential unaffected. Start a fresh observation to clear it.
   */
  maybeIncomplete(): boolean {
    return this.dropped > 0 || this.evictions > 0 || this.droppedAttributions > 0;
  }

  /** Compact, unsorted (recency order): serialization stays linear and fast. */
  toText(): string {
    return `${JSON.stringify({ schema: 1, dropped: this.dropped, evictions: this.evictions,
      lastEviction: this.lastEviction, droppedAttributions: this.droppedAttributions,
      lastAttributionDrop: this.lastAttributionDropMs === null ? this.lastAttributionDrop
        : new Date(this.lastAttributionDropMs).toISOString(), canaryUses: [...this.canaryUses.values()],
      coverage: [...this.coverages.values()], coverageSpans: [...this.spans].map(([nodePubkey, spans]) => ({ nodePubkey,
        spans: spans.map(([from, to]) => [new Date(from).toISOString(), new Date(to).toISOString()]) })),
      entries: [...this.records.values()] })}\n`;
  }

  static parse(text: string, limit = USAGE_LIMIT): UsageStore {
    let data: unknown;
    try { data = JSON.parse(text); } catch { throw new UsageFileError('invalid usage file'); }
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new UsageFileError('invalid usage file');
    const value = data as Record<string, unknown>;
    // Format version 1 (schema: 1). Fields are only ever added: schema, dropped and entries
    // are required; known later fields are validated when present; unknown fields are
    // ignored, so a newer file stays readable by this version.
    const count = (field: unknown) => field === undefined || (Number.isSafeInteger(field) && (field as number) >= 0);
    const instant = (field: unknown) => field === undefined || field === null || isInstant(field);
    if (value.schema !== 1 || !Number.isSafeInteger(value.dropped) || (value.dropped as number) < 0
      || !count(value.evictions) || !instant(value.lastEviction)
      || !count(value.droppedAttributions) || !instant(value.lastAttributionDrop)
      || !Array.isArray(value.entries) || !value.entries.every(validRecord)
      || (value.canaryUses !== undefined && (!Array.isArray(value.canaryUses) || !value.canaryUses.every(validCanaryUse)))
      || (value.coverage !== undefined && (!Array.isArray(value.coverage) || !value.coverage.every(validCoverage)))
      || (value.coverageSpans !== undefined && (!Array.isArray(value.coverageSpans) || !value.coverageSpans.every(validSpans))))
      throw new UsageFileError('invalid usage file');
    const store = new UsageStore(limit);
    store.dropped = value.dropped as number;
    store.evictions = (value.evictions as number | undefined) ?? 0;
    store.lastEviction = (value.lastEviction as string | null | undefined) ?? null;
    store.droppedAttributions = (value.droppedAttributions as number | undefined) ?? 0;
    store.lastAttributionDrop = (value.lastAttributionDrop as string | null | undefined) ?? null;
    // Files written before 1.0.1 have neither list. Oldest first, so a list longer than the
    // bound keeps its most recent records.
    const recent = <T>(items: T[], at: (item: T) => string) => [...items].sort((a, b) => at(a) < at(b) ? -1 : at(a) > at(b) ? 1 : 0);
    for (const item of recent((value.canaryUses as CanaryUse[] | undefined) ?? [], item => item.lastUse)) {
      const key = `${item.nodePubkey}\0${item.rootKeyId}`;
      if (store.canaryUses.has(key)) throw new UsageFileError('invalid usage file');
      if (store.canaryUses.size >= CANARY_LIMIT) store.canaryUses.delete(store.canaryUses.keys().next().value as string);
      store.canaryUses.set(key, { ...item });
    }
    for (const item of recent((value.coverage as Coverage[] | undefined) ?? [], item => item.lastEnd)) {
      if (store.coverages.has(item.nodePubkey)) throw new UsageFileError('invalid usage file');
      if (store.coverages.size >= COVERAGE_LIMIT) store.coverages.delete(store.coverages.keys().next().value as string);
      store.coverages.set(item.nodePubkey, { ...item });
    }
    // Spans are kept only for nodes that kept a coverage record, so they share its bound.
    for (const item of (value.coverageSpans as CoverageSpans[] | undefined) ?? []) {
      if (store.spans.has(item.nodePubkey)) throw new UsageFileError('invalid usage file');
      if (!store.coverages.has(item.nodePubkey)) continue;
      store.spans.set(item.nodePubkey, union(item.spans.map(([from, to]) => [Date.parse(from), Date.parse(to)])));
    }
    // Oldest first, so the most recently seen records are kept when a file holds more
    // than this store's limit (for example one written before the limit was lowered).
    const ordered = [...(value.entries as UsageRecord[])].sort((a, b) => a.lastSeen < b.lastSeen ? -1 : a.lastSeen > b.lastSeen ? 1 : 0);
    for (const record of ordered) {
      const key = store.key(record.nodePubkey, record.credential, record.rootKeyId, record.method);
      if (store.records.has(key)) throw new UsageFileError('invalid usage file');
      if (store.records.size >= limit) {
        store.records.delete(store.records.keys().next().value as string);
        store.evictions += 1;
        store.lastEviction = record.lastSeen;
      }
      store.records.set(key, { ...record });
    }
    return store;
  }
}

function sortRecords(records: UsageRecord[]): UsageRecord[] {
  const order = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
  return records.sort((a, b) => order(a.nodePubkey, b.nodePubkey) || order(a.rootKeyId, b.rootKeyId)
    || order(a.credential, b.credential) || order(a.method, b.method));
}

export function usagePath(registryPath: string): string { return `${registryPath}.usage.json`; }

/**
 * Reads the usage file through the bounded regular-file reader: a path or target with a
 * protected name (SAFE-02), anything but a regular file, or a file over USAGE_FILE_LIMIT is
 * refused before its content is read or parsed. A missing file is an empty store.
 */
export async function readUsage(path: string, fs: BoundedReadIO = nodeFs): Promise<UsageStore> {
  let text: string;
  try { text = (await readBoundedFile(path, fs, USAGE_FILE_LIMIT)).toString('utf8'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new UsageStore();
    if (error instanceof BoundedFileError && error.message === 'file too large') throw new UsageFileError('usage file too large');
    throw new UsageFileError('cannot read usage file');
  }
  return UsageStore.parse(text);
}

/** Atomic owner-only replacement: exclusive temp file, sync, rename. Returns the bytes written. */
export async function writeUsage(path: string, store: UsageStore,
  fs: Pick<typeof nodeFs, 'open' | 'rename' | 'unlink'> = nodeFs): Promise<number> {
  const temp = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  // Snapshot first: records arriving during the write keep 'changed' set for the next flush.
  const version = store.version;
  const text = store.toText();
  // Owner-only from creation on every platform (1.2.1); the rename keeps that.
  const { handle } = await reserveOwnerOnly(temp, fs);
  let renamed = false;
  try {
    await handle.writeFile(text, 'utf8');
    await handle.sync();
    await handle.close();
    await fs.rename(temp, path);
    renamed = true;
    if (store.version === version) store.changed = false;
    return Buffer.byteLength(text, 'utf8');
  } finally {
    if (!renamed) {
      await handle.close().catch(() => undefined);
      await fs.unlink(temp).catch(() => undefined);
    }
  }
}
