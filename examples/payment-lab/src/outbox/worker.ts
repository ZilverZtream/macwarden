import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import type { DatabaseSync } from 'node:sqlite';
import { text } from '../store/sqlite.ts';
import { EffectError, effectFields, publish, type EffectHooks, type EffectTarget } from './effects.ts';
import { acknowledge, claim, notDoneCount, retryLater, type OutboxRow } from './outbox.ts';

/**
 * The outbox worker. One pass claims due rows one at a time, lowest outbox ID first, and for each:
 *
 *   claim (BEGIN IMMEDIATE: pending and due, or a lease that ran out -> leased to this worker, attempts + 1)
 *   check (the row's ledger entry exists and is its own; otherwise the row fails and nothing is written)
 *   effect (publish: an existing file with a valid HMAC over the same fields counts as performed;
 *           any other existing file is a named failure, never overwritten)
 *   ack (BEGIN IMMEDIATE: leased to this worker -> done, acknowledged_at, lease cleared, in one statement)
 *
 * A failed effect puts the row back to pending, due after 1 s, 2 s, 4 s, … capped at 5 minutes,
 * with the same idempotency key; a row in backoff does not hold up the rows after it. A worker
 * that dies holding a lease leaves the row leased until the lease expires (60 s by default), then
 * any worker claims it again and the HMAC check finds whatever the dead worker published.
 */

export type Emit = (event: Record<string, unknown>) => void;

/** Crash-point hooks for the restart tests; each is called synchronously at its point. */
export interface WorkerHooks extends EffectHooks {
  afterClaim?(row: OutboxRow): void;
  afterEffect?(row: OutboxRow): void;
  afterAck?(row: OutboxRow): void;
}

export interface WorkerOptions {
  emit: Emit;
  /** This worker's lease identity; default host:pid:random. */
  owner?: string;
  leaseMs?: number;
  clock?: () => number;
  /** Rows claimed per pass at most (default 1000), so one pass is bounded. */
  maxRows?: number;
  hooks?: WorkerHooks;
}

export const DEFAULT_LEASE_MS = 60_000;

export interface PassResult {
  performed: number;
  alreadyPresent: number;
  failed: number;
  leaseLost: number;
  /** Rows not done after the pass (in backoff, leased elsewhere, or beyond maxRows). */
  remaining: number;
}

export function workerId(): string {
  return `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
}

/** The journal entry a row's effect cites, by kind: the settlement of the order, or the success of the operation's payment. */
const ENTRY_EVENT = { 'fulfill-order': 'invoice-settled', 'confirm-operation': 'payment-succeeded' } as const;

/**
 * The consistency check before an effect: the row's ledgerEntryId must name a journal entry of this
 * database, and that entry must be the row's own (the settlement or success for its payment hash).
 * A row that fails it is not performed and no file is written; it stays pending with a named error
 * (ledger-entry-missing or ledger-entry-mismatch), visible in outbox-status.
 */
function checkLedgerEntry(db: DatabaseSync, row: OutboxRow): void {
  const id = row.payload.ledgerEntryId;
  if (typeof id !== 'number' || !Number.isSafeInteger(id)) {
    throw new EffectError('ledger-entry-missing', `the row names no ledger entry (ledgerEntryId ${JSON.stringify(id ?? null)})`);
  }
  const entry = db.prepare('SELECT event, reference FROM journal_entries WHERE entry_id = ?').get(id);
  if (entry === undefined) throw new EffectError('ledger-entry-missing', `ledger entry ${id} does not exist in the journal`);
  const expected = ENTRY_EVENT[row.kind];
  const event = text(entry, 'event');
  const reference = text(entry, 'reference');
  if (event !== expected || reference !== row.payload.paymentHash) {
    throw new EffectError('ledger-entry-mismatch', `ledger entry ${id} is ${event} for ${reference}, not ${expected} for ${String(row.payload.paymentHash)}`);
  }
}

/** One pass over the due rows. Synchronous: every step is a local transaction or a local file operation. */
export function runPass(db: DatabaseSync, target: EffectTarget, options: WorkerOptions): PassResult {
  const owner = options.owner ?? workerId();
  const clock = options.clock ?? Date.now;
  const leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
  const hooks = options.hooks ?? {};
  const result: PassResult = { performed: 0, alreadyPresent: 0, failed: 0, leaseLost: 0, remaining: 0 };
  for (let index = 0; index < (options.maxRows ?? 1000); index += 1) {
    const row = claim(db, owner, clock(), leaseMs);
    if (row === undefined) break;
    hooks.afterClaim?.(row);
    let outcome: 'written' | 'already-present';
    try {
      checkLedgerEntry(db, row);
      outcome = publish(target, row.subject, effectFields(row), hooks,
        { owner, expiresAtMs: Date.parse(row.leaseExpiresAt ?? ''), nowMs: clock() });
    } catch (error) {
      const reason = error instanceof EffectError ? error.reason : 'error';
      const message = `${reason}: ${error instanceof Error ? error.message : String(error)}`;
      const rescheduled = retryLater(db, row.outboxId, owner, message, clock());
      result.failed += 1;
      options.emit({ event: 'outbox-failed', outboxId: row.outboxId, kind: row.kind, idempotencyKey: row.idempotencyKey,
        attempts: row.attempts, reason, conflict: reason === 'conflict', error: message, rescheduled });
      continue;
    }
    hooks.afterEffect?.(row);
    const acknowledged = acknowledge(db, row.outboxId, owner, clock());
    if (!acknowledged) result.leaseLost += 1;
    else if (outcome === 'already-present') result.alreadyPresent += 1;
    else result.performed += 1;
    options.emit({ event: acknowledged ? 'outbox-done' : 'outbox-lease-lost', outboxId: row.outboxId, kind: row.kind,
      idempotencyKey: row.idempotencyKey, effect: outcome, attempts: row.attempts });
    if (acknowledged) hooks.afterAck?.(row);
  }
  result.remaining = notDoneCount(db);
  return result;
}

/** Passes until `signal` aborts, one every intervalMs (or once). */
export async function runOutbox(db: DatabaseSync, target: EffectTarget, options: WorkerOptions & { once: boolean; intervalMs: number;
  signal: AbortSignal }): Promise<PassResult> {
  const owner = options.owner ?? workerId();
  let last = runPass(db, target, { ...options, owner });
  options.emit({ event: 'outbox-pass', ...last });
  while (!options.once && !options.signal.aborted) {
    await new Promise<void>(resolve => {
      const timer = setTimeout(done, options.intervalMs);
      function done(): void { clearTimeout(timer); options.signal.removeEventListener('abort', done); resolve(); }
      options.signal.addEventListener('abort', done, { once: true });
    });
    if (options.signal.aborted) break;
    last = runPass(db, target, { ...options, owner });
    options.emit({ event: 'outbox-pass', ...last });
  }
  return last;
}
