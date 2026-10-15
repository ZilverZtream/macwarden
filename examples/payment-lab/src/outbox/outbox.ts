import type { DatabaseSync } from 'node:sqlite';
import { changes, immediate, int, optionalText, text, type Row } from '../store/sqlite.ts';

/**
 * The transactional outbox both stores keep (each in its own database file): the business effect
 * of a settlement or a completed operation, recorded as an intent in the same BEGIN IMMEDIATE
 * transaction as the state change and its journal entry, and performed later by a worker
 * (src/outbox/worker.ts) that retries with the same idempotency key until the effect is
 * acknowledged.
 *
 * - kind             fulfill-order (receiver: an order was paid) or confirm-operation (payer: an
 *                    order payment, refund or payout succeeded)
 * - idempotency_key  order_id:payment_hash or operation_id:payment_hash; unique, so a repeated
 *                    settlement or update enqueues nothing
 * - subject          the order or operation ID, which names the effect's file
 * - payload          the fields the effect carries, as JSON text (amounts as decimal strings)
 * - state            pending (to perform), leased (a worker claimed it until lease_expires_at),
 *                    done (performed and acknowledged at acknowledged_at)
 * - attempts         claims so far; next_attempt_at is when the row is due again after a failure
 *
 * A row moves pending -> leased (claim) -> done (ack) or back to pending (retry later, or a lease
 * that expired is claimed again). The ack clears the lease in the same statement that marks the
 * row done, so there is no committed state "acknowledged but still leased".
 */

export const OUTBOX_SCHEMA = `
CREATE TABLE IF NOT EXISTS outbox (
  outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK (kind IN ('fulfill-order', 'confirm-operation')),
  idempotency_key TEXT NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 1 AND 256),
  subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 128),
  payload TEXT NOT NULL CHECK (json_valid(payload) AND length(payload) <= 4096),
  state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'done')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  acknowledged_at TEXT,
  CHECK ((state = 'done') = (acknowledged_at IS NOT NULL)),
  CHECK ((state = 'leased') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (state, next_attempt_at, outbox_id);
`;

export type OutboxKind = 'fulfill-order' | 'confirm-operation';
export type OutboxState = 'pending' | 'leased' | 'done';
/** A payload field: text (amounts as decimal strings), a number, or null. */
export type PayloadValue = string | number | null;

export interface OutboxItem {
  kind: OutboxKind;
  idempotencyKey: string;
  subject: string;
  payload: Record<string, PayloadValue>;
}

export interface OutboxRow extends OutboxItem {
  outboxId: number;
  state: OutboxState;
  attempts: number;
  nextAttemptAt: string;
  leaseOwner: string | undefined;
  leaseExpiresAt: string | undefined;
  lastError: string | undefined;
  createdAt: string;
  acknowledgedAt: string | undefined;
}

/** Retries back off exponentially from 1 s, capped at 5 minutes. */
export const BACKOFF_BASE_MS = 1000;
export const BACKOFF_CAP_MS = 5 * 60 * 1000;

export function backoffMs(attempts: number): number {
  return Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, Math.min(attempts - 1, 20)), BACKOFF_CAP_MS);
}

/** Receiver: a settlement fulfilled an order. */
export function fulfillOrder(input: { orderId: string; paymentHash: string; amountMsat: bigint; settleIndex: bigint;
  ledgerEntryId: number | undefined }): OutboxItem {
  return { kind: 'fulfill-order', idempotencyKey: `${input.orderId}:${input.paymentHash}`, subject: input.orderId, payload: {
    orderId: input.orderId, paymentHash: input.paymentHash, amountMsat: input.amountMsat.toString(),
    settleIndex: input.settleIndex.toString(), ledgerEntryId: input.ledgerEntryId ?? null } };
}

/** Payer: an operation completed (LND reported its payment succeeded): order payment confirmed, refund issued, payout confirmed. */
export function confirmOperation(input: { operationId: string; operationKind: string; paymentHash: string; valueMsat: bigint;
  feeMsat: bigint; ledgerEntryId: number | undefined }): OutboxItem {
  return { kind: 'confirm-operation', idempotencyKey: `${input.operationId}:${input.paymentHash}`, subject: input.operationId, payload: {
    operationId: input.operationId, operationKind: input.operationKind, paymentHash: input.paymentHash,
    valueMsat: input.valueMsat.toString(), feeMsat: input.feeMsat.toString(), ledgerEntryId: input.ledgerEntryId ?? null } };
}

/**
 * Records the effect as pending, in the caller's transaction (the one that makes the state change).
 * Returns the outbox ID, or undefined when the idempotency key was already enqueued (nothing changes).
 */
export function enqueue(db: DatabaseSync, item: OutboxItem, now: string): number | undefined {
  if (!db.isTransaction) throw new Error('an outbox row is enqueued only inside the transaction of the state change that causes it');
  const result = db.prepare(`INSERT INTO outbox (kind, idempotency_key, subject, payload, state, attempts, next_attempt_at, created_at)
    VALUES (?, ?, ?, ?, 'pending', 0, ?, ?) ON CONFLICT (idempotency_key) DO NOTHING`)
    .run(item.kind, item.idempotencyKey, item.subject, JSON.stringify(item.payload), now, now);
  return changes(result) === 1 ? Number(result.lastInsertRowid) : undefined;
}

function rowFrom(row: Row): OutboxRow {
  return {
    outboxId: Number(int(row, 'outbox_id')),
    kind: text(row, 'kind') as OutboxKind,
    idempotencyKey: text(row, 'idempotency_key'),
    subject: text(row, 'subject'),
    payload: JSON.parse(text(row, 'payload')) as Record<string, PayloadValue>,
    state: text(row, 'state') as OutboxState,
    attempts: Number(int(row, 'attempts')),
    nextAttemptAt: text(row, 'next_attempt_at'),
    leaseOwner: optionalText(row, 'lease_owner'),
    leaseExpiresAt: optionalText(row, 'lease_expires_at'),
    lastError: optionalText(row, 'last_error'),
    createdAt: text(row, 'created_at'),
    acknowledgedAt: optionalText(row, 'acknowledged_at'),
  };
}

const iso = (ms: number): string => new Date(ms).toISOString();

/**
 * Claims the due row that has been due longest (earliest next_attempt_at, then lowest outbox ID,
 * among the rows pending and due, or leased with an expired lease) for `owner` until now +
 * leaseMs, in one BEGIN IMMEDIATE transaction: two workers on one file serialise on SQLite's
 * write lock, and the second never sees the first's row as claimable while the lease runs. Each
 * claim counts an attempt. The order is by due time, not by ID: a row that failed is due again
 * only after its backoff, so rows enqueued after it come first, and 1,000 or more older rows
 * that keep failing (capped at 5 minutes between attempts) cannot take every claim of every pass
 * from a healthy row behind them (the outbox_due index serves this order).
 */
export function claim(db: DatabaseSync, owner: string, nowMs: number, leaseMs: number): OutboxRow | undefined {
  return immediate(db, () => {
    const now = iso(nowMs);
    const row = db.prepare(`SELECT outbox_id FROM outbox WHERE (state = 'pending' AND next_attempt_at <= ?)
      OR (state = 'leased' AND lease_expires_at <= ?) ORDER BY next_attempt_at, outbox_id LIMIT 1`).get(now, now);
    if (row === undefined) return undefined;
    const id = int(row, 'outbox_id');
    db.prepare(`UPDATE outbox SET state = 'leased', lease_owner = ?, lease_expires_at = ?, attempts = attempts + 1 WHERE outbox_id = ?`)
      .run(owner, iso(nowMs + leaseMs), id);
    return rowFrom(db.prepare('SELECT * FROM outbox WHERE outbox_id = ?').get(id) ?? {});
  });
}

/**
 * The effect is performed: done, acknowledged, lease cleared, in one statement. False when `owner` no longer holds the lease.
 * acknowledged_at is the later of now and created_at: a clock that stepped back since the row was
 * enqueued cannot record an acknowledgement before the row existed (both are ISO-8601 UTC text of
 * one format, so SQLite's MAX compares them in time order).
 */
export function acknowledge(db: DatabaseSync, outboxId: number, owner: string, nowMs: number): boolean {
  return immediate(db, () => changes(db.prepare(`UPDATE outbox SET state = 'done', acknowledged_at = MAX(?, created_at), lease_owner = NULL,
    lease_expires_at = NULL, last_error = NULL WHERE outbox_id = ? AND state = 'leased' AND lease_owner = ?`)
    .run(iso(nowMs), outboxId, owner)) === 1);
}

/** The effect failed: back to pending, due again after the backoff for its attempts. False when `owner` no longer holds the lease. */
export function retryLater(db: DatabaseSync, outboxId: number, owner: string, error: string, nowMs: number): boolean {
  return immediate(db, () => {
    const row = db.prepare(`SELECT attempts FROM outbox WHERE outbox_id = ? AND state = 'leased' AND lease_owner = ?`).get(outboxId, owner);
    if (row === undefined) return false;
    db.prepare(`UPDATE outbox SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL, last_error = ?, next_attempt_at = ?
      WHERE outbox_id = ?`).run(error.slice(0, 1000), iso(nowMs + backoffMs(Number(int(row, 'attempts')))), outboxId);
    return true;
  });
}

export function outboxRows(db: DatabaseSync, subject?: string): OutboxRow[] {
  return db.prepare('SELECT * FROM outbox WHERE (? IS NULL OR subject = ?) ORDER BY outbox_id').all(subject ?? null, subject ?? null).map(rowFrom);
}

/** Rows not yet done (pending or leased). */
export function notDoneCount(db: DatabaseSync): number {
  return Number(int(db.prepare(`SELECT COUNT(*) AS n FROM outbox WHERE state <> 'done'`).get() ?? {}, 'n'));
}

export interface OutboxStatus {
  pending: number;
  leased: number;
  done: number;
  /** Leased rows whose lease has run out (their worker died or stalled); the next claim takes them. */
  expiredLeases: number;
  /** Seconds since the oldest row not yet done was enqueued; null when every row is done. */
  oldestPendingAgeS: number | null;
  deadlineS: number;
  /** Rows not done more than deadlineS after they were enqueued, at most 20, oldest first. */
  overdue: { outboxId: number; kind: OutboxKind; idempotencyKey: string; state: OutboxState; attempts: number; createdAt: string;
    nextAttemptAt: string; lastError: string | undefined }[];
  overdueCount: number;
}

/**
 * The status from one snapshot: its queries run in one read transaction (BEGIN, deferred, so it works on the
 * read-only connection outbox-status opens), as explain reads its records. In autocommit each query saw the file as
 * it was then, and a worker's claim or ack committed between two of them could count a row in no state or in two,
 * or list an overdue row the counts call done (audit 1.3.2). A caller already in a transaction keeps its own.
 */
export function outboxStatus(db: DatabaseSync, nowMs: number, deadlineS: number): OutboxStatus {
  const own = !db.isTransaction;
  if (own) db.exec('BEGIN');
  try {
    return statusIn(db, nowMs, deadlineS);
  } finally {
    if (own && db.isTransaction) db.exec('COMMIT');
  }
}

function statusIn(db: DatabaseSync, nowMs: number, deadlineS: number): OutboxStatus {
  const counts = { pending: 0, leased: 0, done: 0 };
  for (const row of db.prepare('SELECT state, COUNT(*) AS n FROM outbox GROUP BY state').all()) {
    counts[text(row, 'state') as OutboxState] = Number(int(row, 'n'));
  }
  const now = iso(nowMs);
  const expired = db.prepare(`SELECT COUNT(*) AS n FROM outbox WHERE state = 'leased' AND lease_expires_at <= ?`).get(now) ?? {};
  const oldest = db.prepare(`SELECT MIN(created_at) AS t FROM outbox WHERE state <> 'done'`).get() ?? {};
  const oldestAt = optionalText(oldest, 't');
  const cutoff = iso(nowMs - deadlineS * 1000);
  const overdueCount = Number(int(db.prepare(`SELECT COUNT(*) AS n FROM outbox WHERE state <> 'done' AND created_at <= ?`).get(cutoff) ?? {}, 'n'));
  const overdue = db.prepare(`SELECT * FROM outbox WHERE state <> 'done' AND created_at <= ? ORDER BY outbox_id LIMIT 20`).all(cutoff)
    .map(rowFrom).map(row => ({ outboxId: row.outboxId, kind: row.kind, idempotencyKey: row.idempotencyKey, state: row.state,
      attempts: row.attempts, createdAt: row.createdAt, nextAttemptAt: row.nextAttemptAt, lastError: row.lastError }));
  return { ...counts, expiredLeases: Number(int(expired, 'n')),
    oldestPendingAgeS: oldestAt === undefined ? null : Math.max(0, Math.floor((nowMs - Date.parse(oldestAt)) / 1000)),
    deadlineS, overdue, overdueCount };
}
