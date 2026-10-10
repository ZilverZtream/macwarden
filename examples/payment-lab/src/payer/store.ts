import type { DatabaseSync } from 'node:sqlite';
import type { DecodedPayReq, Payment } from '../lnd/types.ts';
import { sha256Hex } from '../util/encoding.ts';
import { saturateInt64 } from '../util/money.ts';
import { entriesFor, legsFor, post, type JournalEntry } from '../ledger/journal.ts';
import { migratePayerLedger } from '../ledger/migrate.ts';
import { budgetConsumed, budgetHeld, budgetReleased, paymentSucceeded, payerDoublePayment } from '../ledger/postings.ts';
import { changes, immediate, int, nowIso, openDatabase, optionalInt, optionalText, text, type Migration, type Row } from '../store/sqlite.ts';

/**
 * The payer's durable records. Four identities are kept apart:
 *
 * - operation_id   the business operation (an order payment, refund or payout)
 * - payment_hash   the Lightning payment LND tracks for it
 * - submissions    how many SendPaymentV2 RPC calls were made for that payment
 * - htlc_attempts  how LND executed the payment (routes, shards, retries)
 *
 * Payment states:
 *   intent      recorded, not sent; may be submitted
 *   submitting  committed immediately before SendPaymentV2 is written; if the
 *               process dies here nobody knows whether LND received it
 *   in_flight   LND reported the payment in flight
 *   uncertain   the connection or process was lost before a terminal state
 *   succeeded / failed   terminal, as reported by LND
 *
 * submitting, in_flight and uncertain are unresolved: the outcome is not known
 * to the business, the operation stays open, a budget reservation stays held,
 * and the partial unique index below refuses a second pending payment (a
 * replacement invoice) for the operation until LND reports this one failed.
 *
 * The index covers pending payments (intent and the unresolved states), not
 * succeeded ones: LND can report success for an earlier payment of an operation
 * after it was recorded failed and a replacement was recorded, and that success
 * must be recorded, because the money left. applyUpdate then withdraws a
 * replacement that was never sent and flags one that may have been sent as a
 * possible double payment. A completed operation accepts no new payment
 * (recordIntent and prepareRetry refuse it).
 */

const MIGRATIONS: Migration[] = [`
CREATE TABLE operations (
  operation_id TEXT PRIMARY KEY CHECK (length(operation_id) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('order-payment', 'refund', 'payout')),
  amount_msat INTEGER NOT NULL CHECK (amount_msat > 0),
  state TEXT NOT NULL CHECK (state IN ('open', 'completed', 'failed')),
  budget_id TEXT REFERENCES budgets (budget_id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE TABLE payments (
  payment_hash TEXT PRIMARY KEY CHECK (length(payment_hash) = 64),
  operation_id TEXT NOT NULL REFERENCES operations (operation_id),
  payment_request TEXT NOT NULL,
  destination TEXT NOT NULL,
  amount_msat INTEGER NOT NULL CHECK (amount_msat > 0),
  fee_limit_msat INTEGER NOT NULL CHECK (fee_limit_msat >= 0),
  max_parts INTEGER NOT NULL CHECK (max_parts BETWEEN 1 AND 128),
  state TEXT NOT NULL CHECK (state IN ('intent', 'submitting', 'in_flight', 'uncertain', 'succeeded', 'failed')),
  submissions INTEGER NOT NULL DEFAULT 0,
  fee_msat INTEGER,
  value_msat INTEGER,
  preimage TEXT,
  failure_reason TEXT,
  uncertain_reason TEXT,
  lnd_payment_index TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE UNIQUE INDEX payments_one_live_per_operation ON payments (operation_id) WHERE state <> 'failed';
CREATE TABLE htlc_attempts (
  payment_hash TEXT NOT NULL REFERENCES payments (payment_hash),
  attempt_id TEXT NOT NULL,
  status TEXT NOT NULL,
  principal_msat INTEGER NOT NULL,
  fee_msat INTEGER NOT NULL,
  hops INTEGER NOT NULL,
  route TEXT NOT NULL,
  failure_code TEXT,
  failure_source_index INTEGER,
  attempt_time_ns INTEGER NOT NULL,
  resolve_time_ns INTEGER NOT NULL,
  PRIMARY KEY (payment_hash, attempt_id)
);
CREATE TABLE payment_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_hash TEXT NOT NULL,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE TABLE ledger_entries (
  entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL REFERENCES operations (operation_id),
  payment_hash TEXT NOT NULL REFERENCES payments (payment_hash),
  account TEXT NOT NULL CHECK (account IN ('principal', 'routing-fee')),
  amount_msat INTEGER NOT NULL CHECK (amount_msat >= 0),
  posted_at TEXT NOT NULL,
  UNIQUE (operation_id, payment_hash, account)
);
CREATE TABLE budgets (
  budget_id TEXT PRIMARY KEY CHECK (length(budget_id) BETWEEN 1 AND 128),
  limit_msat INTEGER NOT NULL CHECK (limit_msat >= 0),
  created_at TEXT NOT NULL
);
CREATE TABLE reservations (
  reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
  budget_id TEXT NOT NULL REFERENCES budgets (budget_id),
  operation_id TEXT NOT NULL REFERENCES operations (operation_id),
  payment_hash TEXT NOT NULL REFERENCES payments (payment_hash),
  principal_msat INTEGER NOT NULL CHECK (principal_msat > 0),
  fee_allowance_msat INTEGER NOT NULL CHECK (fee_allowance_msat >= 0),
  state TEXT NOT NULL CHECK (state IN ('held', 'consumed', 'released')),
  actual_fee_msat INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (state <> 'consumed' OR actual_fee_msat IS NOT NULL)
);
CREATE UNIQUE INDEX reservations_one_held_per_payment ON reservations (payment_hash) WHERE state = 'held';
CREATE TABLE budget_refusals (
  refusal_id INTEGER PRIMARY KEY AUTOINCREMENT,
  budget_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  payment_hash TEXT NOT NULL,
  requested_msat INTEGER NOT NULL,
  available_msat INTEGER NOT NULL,
  at TEXT NOT NULL
);
`, `
-- Each HTLC attempt carries the submission (payments.submissions at the time it was first
-- recorded) it belongs to, so a NotFound for a later submission is judged by that
-- submission's attempts only. Attempts recorded before this column existed are counted
-- as the current submission's, which keeps the old, conservative answer for them.
ALTER TABLE htlc_attempts ADD COLUMN submission INTEGER NOT NULL DEFAULT 0;
UPDATE htlc_attempts SET submission = (SELECT submissions FROM payments WHERE payments.payment_hash = htlc_attempts.payment_hash);
`, `
-- One pending payment per operation, not one non-failed payment ever: a success LND reports for
-- an earlier payment after a replacement was recorded made "UNIQUE constraint failed:
-- payments.operation_id" and the money that left was never recorded. Succeeded rows no longer count.
DROP INDEX payments_one_live_per_operation;
CREATE UNIQUE INDEX payments_one_pending_per_operation ON payments (operation_id)
  WHERE state IN ('intent', 'submitting', 'in_flight', 'uncertain');
`, `
-- Budget admission sums a budget's reservations inside BEGIN IMMEDIATE, under the write lock;
-- without this index every admission scanned the reservations of every budget. Creating the
-- index builds it over the existing rows.
CREATE INDEX reservations_by_budget ON reservations (budget_id);
`, `
-- The highest submission that is over for good: prepareRetry sets it to the submission LND
-- reported failed, so an update or a call outcome read for it (or an earlier one) is stale
-- although no later submission was claimed yet. Staleness was judged by the record being in
-- intent before, which also orphaned the live submission's own updates after a concurrent
-- NotFound revert. A record in intent today keeps the old answer: its submission is closed.
ALTER TABLE payments ADD COLUMN closed_submission INTEGER NOT NULL DEFAULT 0;
UPDATE payments SET closed_submission = submissions WHERE state = 'intent';
`,
// 6: the double-entry journal (src/ledger/). ledger_entries' single-leg rows become balanced entries
// and the table is dropped; see migratePayerLedger for the counter-accounts.
migratePayerLedger];

export type PaymentState = 'intent' | 'submitting' | 'in_flight' | 'uncertain' | 'succeeded' | 'failed';
export type OperationKind = 'order-payment' | 'refund' | 'payout';

export const UNRESOLVED_STATES: readonly PaymentState[] = ['submitting', 'in_flight', 'uncertain'];

export interface PaymentRecord {
  paymentHash: string;
  operationId: string;
  paymentRequest: string;
  destination: string;
  amountMsat: bigint;
  feeLimitMsat: bigint;
  maxParts: number;
  state: PaymentState;
  submissions: number;
  /** The highest submission that is over for good (prepareRetry closed it); 0 when none. */
  closedSubmission: number;
  feeMsat: bigint | undefined;
  valueMsat: bigint | undefined;
  preimage: string | undefined;
  failureReason: string | undefined;
  uncertainReason: string | undefined;
  createdAt: string;
  resolvedAt: string | undefined;
}

export interface OperationRecord {
  operationId: string;
  kind: OperationKind;
  amountMsat: bigint;
  state: 'open' | 'completed' | 'failed';
  budgetId: string | undefined;
  completedAt: string | undefined;
}

export interface BudgetStatus {
  budgetId: string;
  limitMsat: bigint;
  heldMsat: bigint;
  consumedMsat: bigint;
  availableMsat: bigint;
}

export interface AttemptRecord {
  attemptId: string;
  status: string;
  principalMsat: bigint;
  feeMsat: bigint;
  hops: number;
  failureCode: string | undefined;
  failureSourceIndex: number | undefined;
}

export interface LedgerEntry {
  account: 'principal' | 'routing-fee';
  amountMsat: bigint;
  postedAt: string;
}

export type IntentResult =
  | { outcome: 'recorded'; payment: PaymentRecord }
  | { outcome: 'existing'; payment: PaymentRecord }
  | { outcome: 'refused'; reason: string; requestedMsat?: bigint; availableMsat?: bigint };

/**
 * Another payment of the same operation, found when LND reported this one succeeded:
 * `withdrawn` (it was never sent; it is failed and its reservation released),
 * `possible-double-payment` (it may have been sent and is still unresolved) or
 * `double-payment` (LND reported it succeeded too).
 */
export interface PaymentConflict {
  paymentHash: string;
  state: PaymentState;
  action: 'withdrawn' | 'possible-double-payment' | 'double-payment';
}

/** What an LND update changed in the record. `completed` is true exactly once per operation. */
export interface UpdateResult {
  state: PaymentState;
  completed: boolean;
  failed: boolean;
  conflicts: PaymentConflict[];
}

function paymentFrom(row: Row): PaymentRecord {
  return {
    paymentHash: text(row, 'payment_hash'),
    operationId: text(row, 'operation_id'),
    paymentRequest: text(row, 'payment_request'),
    destination: text(row, 'destination'),
    amountMsat: int(row, 'amount_msat'),
    feeLimitMsat: int(row, 'fee_limit_msat'),
    maxParts: Number(int(row, 'max_parts')),
    state: text(row, 'state') as PaymentState,
    submissions: Number(int(row, 'submissions')),
    closedSubmission: Number(int(row, 'closed_submission')),
    feeMsat: optionalInt(row, 'fee_msat'),
    valueMsat: optionalInt(row, 'value_msat'),
    preimage: optionalText(row, 'preimage'),
    failureReason: optionalText(row, 'failure_reason'),
    uncertainReason: optionalText(row, 'uncertain_reason'),
    createdAt: text(row, 'created_at'),
    resolvedAt: optionalText(row, 'resolved_at'),
  };
}

/**
 * Whether a stream or call made for `submission` no longer speaks for the record: a later
 * submission was claimed since, or prepareRetry closed this one. Undefined (a caller that
 * names no submission) is never stale. A revert to intent (markNotInitiated) closes nothing:
 * LND's NotFound is a point-in-time answer, and the submission's own updates still apply.
 */
function superseded(record: PaymentRecord, submission: number | undefined): boolean {
  if (submission === undefined) return false;
  return submission < record.submissions || (record.closedSubmission > 0 && submission <= record.closedSubmission);
}

function operationFrom(row: Row): OperationRecord {
  return {
    operationId: text(row, 'operation_id'),
    kind: text(row, 'kind') as OperationKind,
    amountMsat: int(row, 'amount_msat'),
    state: text(row, 'state') as OperationRecord['state'],
    budgetId: optionalText(row, 'budget_id'),
    completedAt: optionalText(row, 'completed_at'),
  };
}

export class PayerStore {
  readonly db: DatabaseSync;
  /** Which book this is, for verifyLedger (src/ledger/verify.ts). */
  readonly book = 'payer' as const;

  constructor(path: string) {
    this.db = openDatabase(path, MIGRATIONS);
  }

  close(): void {
    this.db.close();
  }

  #event(paymentHash: string, kind: string, detail: Record<string, unknown>): void {
    this.db.prepare('INSERT INTO payment_events (payment_hash, at, kind, detail) VALUES (?, ?, ?, ?)')
      .run(paymentHash, nowIso(), kind, JSON.stringify(detail, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value));
  }

  event(paymentHash: string, kind: string, detail: Record<string, unknown>): void {
    immediate(this.db, () => this.#event(paymentHash, kind, detail));
  }

  payment(paymentHash: string): PaymentRecord | undefined {
    const row = this.db.prepare('SELECT * FROM payments WHERE payment_hash = ?').get(paymentHash);
    return row === undefined ? undefined : paymentFrom(row);
  }

  /**
   * The operation's succeeded payment, else its live one, else its most recently recorded failed one.
   * Recorded order is rowid, not a timestamp: two payments failed or updated in the same millisecond
   * must not make the choice arbitrary (prepareRetry would retry the older invoice).
   */
  paymentForOperation(operationId: string): PaymentRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM payments WHERE operation_id = ?
      ORDER BY CASE state WHEN 'succeeded' THEN 0 WHEN 'failed' THEN 2 ELSE 1 END, rowid DESC LIMIT 1`).get(operationId);
    return row === undefined ? undefined : paymentFrom(row);
  }

  /**
   * The operation's payment for this payment request, if one was recorded. BOLT11 is
   * case-insensitive (QR codes carry it in upper case), so the text is compared lower-cased.
   */
  paymentForRequest(operationId: string, paymentRequest: string): PaymentRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM payments WHERE operation_id = ? AND lower(payment_request) = lower(?)
      ORDER BY CASE WHEN state = 'failed' THEN 1 ELSE 0 END, rowid DESC LIMIT 1`).get(operationId, paymentRequest);
    return row === undefined ? undefined : paymentFrom(row);
  }

  operation(operationId: string): OperationRecord | undefined {
    const row = this.db.prepare('SELECT * FROM operations WHERE operation_id = ?').get(operationId);
    return row === undefined ? undefined : operationFrom(row);
  }

  paymentsForOperation(operationId: string): PaymentRecord[] {
    return this.db.prepare('SELECT * FROM payments WHERE operation_id = ? ORDER BY rowid').all(operationId).map(paymentFrom);
  }

  unresolvedPayments(): PaymentRecord[] {
    return this.db.prepare(`SELECT * FROM payments WHERE state IN ('submitting', 'in_flight', 'uncertain') ORDER BY rowid`)
      .all().map(paymentFrom);
  }

  attempts(paymentHash: string): AttemptRecord[] {
    return this.db.prepare('SELECT * FROM htlc_attempts WHERE payment_hash = ? ORDER BY CAST(attempt_id AS INTEGER)').all(paymentHash)
      .map(row => ({ attemptId: text(row, 'attempt_id'), status: text(row, 'status'), principalMsat: int(row, 'principal_msat'),
        feeMsat: int(row, 'fee_msat'), hops: Number(int(row, 'hops')), failureCode: optionalText(row, 'failure_code'),
        failureSourceIndex: row.failure_source_index === null ? undefined : Number(int(row, 'failure_source_index')) }));
  }

  /**
   * The operation's principal and routing-fee legs, one pair per succeeded payment, in posting
   * order: the 1.2 ledger_entries view, read from the journal's payment-succeeded entries.
   */
  ledger(operationId: string): LedgerEntry[] {
    return legsFor(this.db, operationId, 'payment-succeeded')
      .map(item => ({ account: item.leg as LedgerEntry['account'], amountMsat: item.amountMsat, postedAt: item.postedAt }));
  }

  /** The operation's journal entries with their lines (every event, not only payments). */
  journal(operationId: string): JournalEntry[] {
    return entriesFor(this.db, operationId);
  }

  events(paymentHash: string): { at: string; kind: string; detail: string }[] {
    return this.db.prepare('SELECT at, kind, detail FROM payment_events WHERE payment_hash = ? ORDER BY event_id').all(paymentHash)
      .map(row => ({ at: text(row, 'at'), kind: text(row, 'kind'), detail: text(row, 'detail') }));
  }

  setBudget(budgetId: string, limitMsat: bigint): void {
    immediate(this.db, () => {
      this.db.prepare(`INSERT INTO budgets (budget_id, limit_msat, created_at) VALUES (?, ?, ?)
        ON CONFLICT (budget_id) DO UPDATE SET limit_msat = excluded.limit_msat`).run(budgetId, limitMsat, nowIso());
    });
  }

  #budgetStatus(budgetId: string): BudgetStatus | undefined {
    const budget = this.db.prepare('SELECT limit_msat FROM budgets WHERE budget_id = ?').get(budgetId);
    if (budget === undefined) return undefined;
    // Summed here, not by SQLite: its SUM fails and its + turns to floating point past 2^63, which every
    // stored amount is below but a sum of them need not be.
    let heldMsat = 0n;
    let consumedMsat = 0n;
    for (const row of this.db.prepare(`SELECT state, principal_msat, fee_allowance_msat, actual_fee_msat FROM reservations
        WHERE budget_id = ? AND state IN ('held', 'consumed')`).all(budgetId)) {
      if (text(row, 'state') === 'held') heldMsat += int(row, 'principal_msat') + int(row, 'fee_allowance_msat');
      else consumedMsat += int(row, 'principal_msat') + int(row, 'actual_fee_msat');
    }
    const limitMsat = int(budget, 'limit_msat');
    return { budgetId, limitMsat, heldMsat, consumedMsat, availableMsat: limitMsat - heldMsat - consumedMsat };
  }

  budgetStatus(budgetId: string): BudgetStatus | undefined {
    return this.#budgetStatus(budgetId);
  }

  refusals(budgetId: string): { operationId: string; paymentHash: string; requestedMsat: bigint; availableMsat: bigint; at: string }[] {
    return this.db.prepare('SELECT * FROM budget_refusals WHERE budget_id = ? ORDER BY refusal_id').all(budgetId)
      .map(row => ({ operationId: text(row, 'operation_id'), paymentHash: text(row, 'payment_hash'),
        requestedMsat: int(row, 'requested_msat'), availableMsat: int(row, 'available_msat'), at: text(row, 'at') }));
  }

  /**
   * Records the business operation, the payment identity and (with a budget)
   * the reservation in one transaction, before anything is sent to LND.
   * Principal plus fee allowance is reserved; the fee allowance is also the
   * fee limit LND enforces, so the reservation is an upper bound.
   */
  recordIntent(input: { operationId: string; kind: OperationKind; paymentRequest: string; invoice: DecodedPayReq;
    feeLimitMsat: bigint; maxParts: number; budgetId?: string }): IntentResult {
    return immediate(this.db, (): IntentResult => {
      const hash = input.invoice.paymentHash;
      const existingPayment = this.payment(hash);
      if (existingPayment !== undefined) {
        if (existingPayment.operationId !== input.operationId) {
          return { outcome: 'refused', reason: `payment hash ${hash} already belongs to operation ${existingPayment.operationId}` };
        }
        return { outcome: 'existing', payment: existingPayment };
      }
      const operation = this.operation(input.operationId);
      if (operation !== undefined) {
        const live = this.paymentForOperation(input.operationId);
        if (live !== undefined && live.state !== 'failed') {
          return { outcome: 'refused', reason: `operation ${input.operationId} already has payment ${live.paymentHash} in state ${live.state}; `
            + 'a replacement invoice is accepted only after LND reports that payment failed' };
        }
        if (operation.state === 'completed') return { outcome: 'refused', reason: `operation ${input.operationId} is already completed` };
        if (operation.amountMsat !== input.invoice.amountMsat) {
          return { outcome: 'refused', reason: `invoice amount differs from operation ${input.operationId}` };
        }
      }
      const now = nowIso();
      if (input.budgetId !== undefined) {
        const status = this.#budgetStatus(input.budgetId);
        if (status === undefined) return { outcome: 'refused', reason: `budget ${input.budgetId} does not exist` };
        // Each term fits 64 bits; the sum need not. A budget never exceeds 2^63 - 1, so such a sum is always refused,
        // and the refusal row keeps the figures saturated to what SQLite can store (the reason carries them exactly).
        const requested = input.invoice.amountMsat + input.feeLimitMsat;
        if (requested > status.availableMsat) {
          this.db.prepare(`INSERT INTO budget_refusals (budget_id, operation_id, payment_hash, requested_msat, available_msat, at)
            VALUES (?, ?, ?, ?, ?, ?)`).run(input.budgetId, input.operationId, hash, saturateInt64(requested), saturateInt64(status.availableMsat), now);
          return { outcome: 'refused', reason: `budget ${input.budgetId} has ${status.availableMsat} msat available, ${requested} msat requested`,
            requestedMsat: requested, availableMsat: status.availableMsat };
        }
      }
      if (operation === undefined) {
        this.db.prepare(`INSERT INTO operations (operation_id, kind, amount_msat, state, budget_id, created_at, updated_at)
          VALUES (?, ?, ?, 'open', ?, ?, ?)`).run(input.operationId, input.kind, input.invoice.amountMsat, input.budgetId ?? null, now, now);
      } else {
        // A replacement payment brings its own budget (or none); the operation follows it, so
        // show and prepareRetry see the budget the live payment is reserved against.
        this.db.prepare(`UPDATE operations SET state = 'open', budget_id = ?, updated_at = ? WHERE operation_id = ?`)
          .run(input.budgetId ?? null, now, input.operationId);
      }
      this.db.prepare(`INSERT INTO payments (payment_hash, operation_id, payment_request, destination, amount_msat, fee_limit_msat,
          max_parts, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'intent', ?, ?)`)
        .run(hash, input.operationId, input.paymentRequest, input.invoice.destination, input.invoice.amountMsat, input.feeLimitMsat,
          input.maxParts, now, now);
      if (input.budgetId !== undefined) {
        this.#hold(input.budgetId, input.operationId, hash, input.invoice.amountMsat, input.feeLimitMsat, now);
      }
      this.#event(hash, 'intent-recorded', { operationId: input.operationId, amountMsat: input.invoice.amountMsat,
        feeLimitMsat: input.feeLimitMsat, budgetId: input.budgetId ?? null });
      return { outcome: 'recorded', payment: this.payment(hash) as PaymentRecord };
    });
  }

  /**
   * Claims the payment for one SendPaymentV2 call: intent → submitting, counted.
   * Compare-and-set, so two processes can never both submit the same record.
   */
  claimForSubmission(paymentHash: string): boolean {
    return immediate(this.db, () => {
      const result = this.db.prepare(`UPDATE payments SET state = 'submitting', submissions = submissions + 1, uncertain_reason = NULL,
        updated_at = ? WHERE payment_hash = ? AND state = 'intent'`).run(nowIso(), paymentHash);
      if (changes(result) === 1) this.#event(paymentHash, 'submit', { rpc: 'SendPaymentV2' });
      return changes(result) === 1;
    });
  }

  /** Logs a call outcome for a superseded submission (see superseded); the record is not changed. */
  #stale(record: PaymentRecord, kind: string, submission: number | undefined, detail: Record<string, unknown>): void {
    this.#event(record.paymentHash, 'stale-update', { ...detail, kind, readForSubmission: submission ?? null,
      currentSubmission: record.submissions, closedSubmission: record.closedSubmission, recordState: record.state });
  }

  /**
   * The connection or process was lost before LND reported a terminal state. With
   * `submission`, a call for a superseded submission changes nothing (it is logged as
   * `stale-update`): the record speaks for a later submission. `unchanged`: the record
   * is not unresolved (terminal, or back in intent after a NotFound).
   */
  markUncertain(paymentHash: string, reason: string, submission?: number): 'uncertain' | 'superseded' | 'unchanged' {
    return immediate(this.db, () => {
      const record = this.payment(paymentHash);
      if (record === undefined) return 'unchanged';
      if (superseded(record, submission)) {
        this.#stale(record, 'uncertain', submission, { reason });
        return 'superseded';
      }
      const result = this.db.prepare(`UPDATE payments SET state = 'uncertain', uncertain_reason = ?, updated_at = ?
        WHERE payment_hash = ? AND state IN ('submitting', 'in_flight', 'uncertain')`).run(reason, nowIso(), paymentHash);
      if (changes(result) === 1) this.#event(paymentHash, 'uncertain', { reason });
      return changes(result) === 1 ? 'uncertain' : 'unchanged';
    });
  }

  /**
   * LND has no payment for this hash (TrackPaymentV2 answered NotFound) and the
   * record never saw LND acknowledge it. Back to intent: it may be submitted
   * again with the same payment hash. LND refuses a second payment for a hash
   * that is in flight or settled, so this can not pay twice.
   *
   * Only attempts of the current submission count: after prepareRetry the
   * previous submission's attempts belong to a payment LND already reported
   * failed, and say nothing about whether the retry reached LND.
   *
   * With `submission`, an answer for a superseded submission changes nothing: a NotFound
   * or a refused connection of an earlier call says nothing about the live one. The
   * revert does not close the submission: if LND initiates it after all, its own
   * updates still apply.
   */
  markNotInitiated(paymentHash: string, evidence: string, submission?: number): 'reverted' | 'attempts-recorded' | 'superseded' | 'unchanged' {
    return immediate(this.db, () => {
      const record = this.payment(paymentHash);
      if (record === undefined) return 'unchanged';
      if (superseded(record, submission)) {
        this.#stale(record, 'not-initiated', submission, { evidence });
        return 'superseded';
      }
      const attempts = this.db.prepare(`SELECT COUNT(*) AS n FROM htlc_attempts a JOIN payments p ON p.payment_hash = a.payment_hash
        WHERE a.payment_hash = ? AND a.submission = p.submissions`).get(paymentHash) ?? {};
      if (int(attempts, 'n') > 0n) {
        this.#event(paymentHash, 'not-found-after-attempts', { evidence });
        return 'attempts-recorded';
      }
      const result = this.db.prepare(`UPDATE payments SET state = 'intent', uncertain_reason = NULL, updated_at = ?
        WHERE payment_hash = ? AND state IN ('submitting', 'uncertain')`).run(nowIso(), paymentHash);
      if (changes(result) === 1) this.#event(paymentHash, 'not-initiated', { evidence });
      return changes(result) === 1 ? 'reverted' : 'unchanged';
    });
  }

  /**
   * LND refused SendPaymentV2 with a definite error and has no payment for the
   * hash: nothing was sent, and nothing will be. Terminal failure. Returns false
   * when the record is already terminal, for example because a concurrent
   * tracker recorded LND's success while this caller's lookup was in flight. With
   * `submission`, a refusal of a superseded submission changes nothing (logged as
   * `stale-update`): it neither fails the live submission nor releases its reservation.
   */
  markRejected(paymentHash: string, reason: string, submission?: number): boolean {
    return immediate(this.db, () => {
      const record = this.payment(paymentHash);
      if (record === undefined) return false;
      if (superseded(record, submission)) {
        this.#stale(record, 'rejected', submission, { reason });
        return false;
      }
      return this.#fail(paymentHash, `REJECTED_BEFORE_INITIATION: ${reason}`, undefined);
    });
  }

  /**
   * Moves an unresolved payment to failed. Terminal states are final: a
   * succeeded payment is never failed by this (its operation is completed and
   * its ledger posted), and a failed one is not failed twice.
   */
  #fail(paymentHash: string, reason: string, payment: Payment | undefined): boolean {
    const now = nowIso();
    const result = this.db.prepare(`UPDATE payments SET state = 'failed', failure_reason = ?, lnd_payment_index = COALESCE(?, lnd_payment_index),
      uncertain_reason = NULL, resolved_at = ?, updated_at = ? WHERE payment_hash = ? AND state NOT IN ('failed', 'succeeded')`)
      .run(reason, payment?.paymentIndex ?? null, now, now, paymentHash);
    if (changes(result) !== 1) return false;
    const record = this.payment(paymentHash) as PaymentRecord;
    this.db.prepare(`UPDATE operations SET state = 'failed', updated_at = ? WHERE operation_id = ? AND state = 'open'`).run(now, record.operationId);
    this.#release(paymentHash, now);
    this.#event(paymentHash, 'failed', { reason });
    return true;
  }

  /** Takes a reservation and posts its budget-held entry, in the caller's transaction. */
  #hold(budgetId: string, operationId: string, paymentHash: string, principalMsat: bigint, allowanceMsat: bigint, now: string): void {
    const result = this.db.prepare(`INSERT INTO reservations (budget_id, operation_id, payment_hash, principal_msat, fee_allowance_msat, state,
        created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'held', ?, ?)`)
      .run(budgetId, operationId, paymentHash, principalMsat, allowanceMsat, now, now);
    post(this.db, budgetHeld({ reservationId: BigInt(result.lastInsertRowid), budgetId, operationId, paymentHash,
      amountMsat: principalMsat + allowanceMsat, postedAt: now }));
  }

  /** Releases the payment's held reservation, if any (at most one: reservations_one_held_per_payment), with its entry. */
  #release(paymentHash: string, now: string): void {
    const held = this.db.prepare(`SELECT * FROM reservations WHERE payment_hash = ? AND state = 'held'`).get(paymentHash);
    if (held === undefined) return;
    this.db.prepare(`UPDATE reservations SET state = 'released', updated_at = ? WHERE reservation_id = ?`).run(now, int(held, 'reservation_id'));
    post(this.db, budgetReleased({ reservationId: int(held, 'reservation_id'), budgetId: text(held, 'budget_id'),
      operationId: text(held, 'operation_id'), paymentHash, amountMsat: int(held, 'principal_msat') + int(held, 'fee_allowance_msat'), postedAt: now }));
  }

  /**
   * LND reported success: the payment's held reservation is consumed at principal plus the actual
   * fee. If none is held and the record was failed (the failure released it), the latest released
   * reservation of the payment counts as consumed, because the money left after all.
   */
  #consume(paymentHash: string, feeMsat: bigint, recordFailed: boolean, now: string): void {
    let row = this.db.prepare(`SELECT * FROM reservations WHERE payment_hash = ? AND state = 'held'`).get(paymentHash);
    let fromState: 'held' | 'released' = 'held';
    if (row === undefined && recordFailed) {
      row = this.db.prepare(`SELECT * FROM reservations WHERE payment_hash = ? AND state = 'released'
        ORDER BY reservation_id DESC LIMIT 1`).get(paymentHash);
      fromState = 'released';
    }
    if (row === undefined) return;
    const reservationId = int(row, 'reservation_id');
    this.db.prepare(`UPDATE reservations SET state = 'consumed', actual_fee_msat = ?, updated_at = ? WHERE reservation_id = ?`)
      .run(feeMsat, now, reservationId);
    post(this.db, budgetConsumed({ reservationId, budgetId: text(row, 'budget_id'), operationId: text(row, 'operation_id'), paymentHash,
      fromState, principalMsat: int(row, 'principal_msat'), allowanceMsat: int(row, 'fee_allowance_msat'), feeMsat, postedAt: now }));
  }

  #upsertAttempts(payment: Payment, submission: number | undefined): void {
    // A new attempt is tagged with the submission the update was read for (else the current one);
    // an update to a known attempt keeps its tag.
    const statement = this.db.prepare(`INSERT INTO htlc_attempts (payment_hash, attempt_id, status, principal_msat, fee_msat, hops, route,
        failure_code, failure_source_index, attempt_time_ns, resolve_time_ns, submission)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, (SELECT submissions FROM payments WHERE payment_hash = ?)))
      ON CONFLICT (payment_hash, attempt_id) DO UPDATE SET status = excluded.status, failure_code = excluded.failure_code,
        failure_source_index = excluded.failure_source_index, resolve_time_ns = excluded.resolve_time_ns
        WHERE htlc_attempts.status NOT IN ('SUCCEEDED', 'FAILED')`);
    for (const attempt of payment.htlcs) {
      statement.run(payment.paymentHash, attempt.attemptId, attempt.status, attempt.principalMsat, attempt.route.totalFeesMsat,
        attempt.route.hops.length, attempt.route.hops.map(hop => hop.chanId).join('>'), attempt.failureCode ?? null,
        attempt.failureSourceIndex ?? null, attempt.attemptTimeNs, attempt.resolveTimeNs, submission ?? null, payment.paymentHash);
    }
  }

  /**
   * Applies one update from SendPaymentV2 or TrackPaymentV2. LND is the
   * authority on the outcome; this method only refuses an update that
   * contradicts a terminal state already recorded.
   *
   * `submission` is the submission (payments.submissions) the caller's stream was
   * started for. An update read for a superseded submission (a later one was claimed,
   * or prepareRetry closed it) is stale: a FAILED or IN_FLIGHT snapshot of it says
   * nothing about the current one, so it changes neither the state nor the reservation
   * (it is logged as `stale-update`). A revert to intent after a NotFound closes nothing:
   * the same submission's own IN_FLIGHT and FAILED still apply. A SUCCEEDED update is
   * always applied, whatever submission it was read for: the money left.
   */
  applyUpdate(payment: Payment, source: 'SendPaymentV2' | 'TrackPaymentV2', submission?: number): UpdateResult {
    return immediate(this.db, (): UpdateResult => {
      const record = this.payment(payment.paymentHash);
      if (record === undefined) throw new Error(`update for unknown payment ${payment.paymentHash}`);
      this.#upsertAttempts(payment, submission);
      const now = nowIso();
      if (payment.status !== 'SUCCEEDED' && superseded(record, submission)) {
        this.#stale(record, 'update', submission, { source, status: payment.status });
        return { state: record.state, completed: false, failed: false, conflicts: [] };
      }
      if (payment.status === 'SUCCEEDED') {
        const preimage = payment.preimage;
        if (preimage === undefined || sha256Hex(preimage) !== payment.paymentHash) {
          throw new Error(`LND reported success for ${payment.paymentHash} without a matching preimage`);
        }
        if (record.state === 'succeeded') {
          if (record.feeMsat !== payment.feeMsat || record.valueMsat !== payment.valueMsat) {
            throw new Error(`LND reported different amounts for already settled payment ${payment.paymentHash}`);
          }
          return { state: 'succeeded', completed: false, failed: false, conflicts: [] };
        }
        if (record.state === 'failed') this.#event(payment.paymentHash, 'success-after-failure', { source });
        const conflicts = this.#settleConflicts(record, now);
        if (payment.valueMsat !== record.amountMsat) {
          this.#event(payment.paymentHash, 'amount-mismatch', { expectedMsat: record.amountMsat, lndValueMsat: payment.valueMsat });
        }
        this.db.prepare(`UPDATE payments SET state = 'succeeded', fee_msat = ?, value_msat = ?, preimage = ?, lnd_payment_index = ?,
          uncertain_reason = NULL, failure_reason = NULL, resolved_at = ?, updated_at = ? WHERE payment_hash = ?`)
          .run(payment.feeMsat, payment.valueMsat, preimage, payment.paymentIndex, now, now, payment.paymentHash);
        const completed = changes(this.db.prepare(`UPDATE operations SET state = 'completed', completed_at = ?, updated_at = ?
          WHERE operation_id = ? AND state <> 'completed'`).run(now, now, record.operationId)) === 1;
        // The journal entry commits with the state change: principal and fee as LND reports them, and,
        // when another payment of the operation already succeeded, the principal moved to suspense.
        const kind = (this.operation(record.operationId) as OperationRecord).kind;
        const posting = { operationId: record.operationId, kind, paymentHash: payment.paymentHash, valueMsat: payment.valueMsat, postedAt: now };
        post(this.db, paymentSucceeded({ ...posting, feeMsat: payment.feeMsat }));
        if (conflicts.some(item => item.action === 'double-payment')) post(this.db, payerDoublePayment(posting));
        this.#consume(payment.paymentHash, payment.feeMsat, record.state === 'failed', now);
        this.#event(payment.paymentHash, 'succeeded', { source, valueMsat: payment.valueMsat, feeMsat: payment.feeMsat,
          htlcAttempts: payment.htlcs.length, succeededAttempts: payment.htlcs.filter(item => item.status === 'SUCCEEDED').length });
        return { state: 'succeeded', completed, failed: false, conflicts };
      }
      if (payment.status === 'FAILED') {
        if (record.state === 'succeeded') throw new Error(`LND reported failure for settled payment ${payment.paymentHash}`);
        const failed = this.#fail(payment.paymentHash, payment.failureReason, payment);
        return { state: 'failed', completed: false, failed, conflicts: [] };
      }
      // IN_FLIGHT or INITIATED: LND holds the payment. Not terminal.
      if (record.state === 'succeeded') return { state: 'succeeded', completed: false, failed: false, conflicts: [] };
      // A failed payment stays failed: an IN_FLIGHT snapshot that arrives after the failure is stale
      // (a concurrent tracker, an older page), and reopening the operation would leave its
      // reservation released while the payment looked live. A retry goes through prepareRetry.
      if (record.state === 'failed') return { state: 'failed', completed: false, failed: false, conflicts: [] };
      const result = this.db.prepare(`UPDATE payments SET state = 'in_flight', uncertain_reason = NULL, lnd_payment_index = ?, updated_at = ?
        WHERE payment_hash = ? AND state <> 'in_flight'`).run(payment.paymentIndex, now, payment.paymentHash);
      if (changes(result) === 1) this.#event(payment.paymentHash, 'in-flight', { source, status: payment.status, htlcAttempts: payment.htlcs.length });
      return { state: 'in_flight', completed: false, failed: false, conflicts: [] };
    });
  }

  /**
   * LND reports `record` succeeded: the operation is paid. Every other payment of the
   * operation that is not failed is dealt with first, in the same transaction:
   *
   * - intent (never sent): withdrawn. It becomes failed with reason WITHDRAWN and its
   *   reservation is released; claimForSubmission can no longer take it, so it is
   *   never sent.
   * - submitting, in_flight or uncertain (it may have been sent): it stays unresolved
   *   and is reconciled like any other, because LND may still pay it; both payments
   *   get a `possible-double-payment` event. If LND later reports it succeeded, its
   *   principal and fee are posted and its reservation consumed like this one's
   *   (the money left), and it is a `double-payment`.
   * - succeeded: a `double-payment` event on both.
   */
  #settleConflicts(record: PaymentRecord, now: string): PaymentConflict[] {
    const conflicts: PaymentConflict[] = [];
    const others = this.db.prepare(`SELECT * FROM payments WHERE operation_id = ? AND payment_hash <> ? AND state <> 'failed'
      ORDER BY rowid`).all(record.operationId, record.paymentHash).map(paymentFrom);
    for (const other of others) {
      if (other.state === 'intent') {
        const reason = `WITHDRAWN: operation ${record.operationId} was paid by payment ${record.paymentHash}`;
        this.db.prepare(`UPDATE payments SET state = 'failed', failure_reason = ?, resolved_at = ?, updated_at = ?
          WHERE payment_hash = ? AND state = 'intent'`).run(reason, now, now, other.paymentHash);
        this.#release(other.paymentHash, now);
        this.#event(other.paymentHash, 'withdrawn', { reason, paidBy: record.paymentHash });
        conflicts.push({ paymentHash: other.paymentHash, state: other.state, action: 'withdrawn' });
        continue;
      }
      const action = other.state === 'succeeded' ? 'double-payment' : 'possible-double-payment';
      const detail = { operationId: record.operationId, succeeded: record.paymentHash, other: other.paymentHash, otherState: other.state };
      this.#event(other.paymentHash, action, detail);
      this.#event(record.paymentHash, action, detail);
      conflicts.push({ paymentHash: other.paymentHash, state: other.state, action });
    }
    return conflicts;
  }

  /**
   * Prepares a definitely failed payment for another submission of the same
   * invoice (same payment hash). With a budget, a new reservation is checked
   * and taken in the same transaction. A completed operation is never retried,
   * whatever its payment rows say: completion is final. The budget is the one
   * the failed payment was reserved against (the operation's, for a payment
   * recorded before replacements moved the operation's budget with them), and the
   * operation's budget is set to it, so what show reports is what was reserved. The
   * failed submission is closed: a late update or call outcome for it is stale.
   */
  prepareRetry(operationId: string): IntentResult {
    return immediate(this.db, (): IntentResult => {
      const operation = this.operation(operationId);
      if (operation === undefined) return { outcome: 'refused', reason: `operation ${operationId} does not exist` };
      if (operation.state === 'completed') return { outcome: 'refused', reason: `operation ${operationId} is already completed` };
      const payment = this.paymentForOperation(operationId);
      if (payment === undefined) return { outcome: 'refused', reason: `operation ${operationId} has no payment` };
      if (payment.state !== 'failed') {
        return { outcome: 'refused', reason: `payment ${payment.paymentHash} is ${payment.state}; only a payment LND reported failed is retried` };
      }
      const now = nowIso();
      const reserved = this.db.prepare('SELECT budget_id FROM reservations WHERE payment_hash = ? ORDER BY reservation_id DESC LIMIT 1')
        .get(payment.paymentHash);
      const budgetId = reserved === undefined ? operation.budgetId : text(reserved, 'budget_id');
      if (budgetId !== undefined) {
        const status = this.#budgetStatus(budgetId);
        const requested = payment.amountMsat + payment.feeLimitMsat;
        if (status === undefined || requested > status.availableMsat) {
          const available = status?.availableMsat ?? 0n;
          this.db.prepare(`INSERT INTO budget_refusals (budget_id, operation_id, payment_hash, requested_msat, available_msat, at)
            VALUES (?, ?, ?, ?, ?, ?)`).run(budgetId, operationId, payment.paymentHash, saturateInt64(requested), saturateInt64(available), now);
          return { outcome: 'refused', reason: `budget ${budgetId} has ${available} msat available, ${requested} msat requested`,
            requestedMsat: requested, availableMsat: available };
        }
        this.#hold(budgetId, operationId, payment.paymentHash, payment.amountMsat, payment.feeLimitMsat, now);
      }
      this.db.prepare(`UPDATE payments SET state = 'intent', failure_reason = NULL, resolved_at = NULL, closed_submission = submissions,
        updated_at = ? WHERE payment_hash = ?`).run(now, payment.paymentHash);
      this.db.prepare(`UPDATE operations SET state = 'open', budget_id = ?, updated_at = ? WHERE operation_id = ?`)
        .run(budgetId ?? null, now, operationId);
      this.#event(payment.paymentHash, 'retry-prepared', { previousFailure: payment.failureReason ?? null });
      return { outcome: 'recorded', payment: this.payment(payment.paymentHash) as PaymentRecord };
    });
  }
}
