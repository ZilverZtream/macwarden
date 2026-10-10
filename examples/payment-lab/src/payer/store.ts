import type { DatabaseSync } from 'node:sqlite';
import type { DecodedPayReq, Payment } from '../lnd/types.ts';
import { sha256Hex } from '../util/encoding.ts';
import { changes, immediate, int, nowIso, openDatabase, optionalInt, optionalText, text, type Row } from '../store/sqlite.ts';

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
 * and the partial unique index below refuses a second payment (a replacement
 * invoice) for the operation until LND reports this one failed.
 */

const MIGRATIONS = [`
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
`];

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

/** What an LND update changed in the record. `completed` is true exactly once per operation. */
export interface UpdateResult {
  state: PaymentState;
  completed: boolean;
  failed: boolean;
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
    feeMsat: optionalInt(row, 'fee_msat'),
    valueMsat: optionalInt(row, 'value_msat'),
    preimage: optionalText(row, 'preimage'),
    failureReason: optionalText(row, 'failure_reason'),
    uncertainReason: optionalText(row, 'uncertain_reason'),
    createdAt: text(row, 'created_at'),
    resolvedAt: optionalText(row, 'resolved_at'),
  };
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

  /** The operation's live payment, or its most recent failed one. */
  paymentForOperation(operationId: string): PaymentRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM payments WHERE operation_id = ?
      ORDER BY CASE WHEN state = 'failed' THEN 1 ELSE 0 END, updated_at DESC LIMIT 1`).get(operationId);
    return row === undefined ? undefined : paymentFrom(row);
  }

  operation(operationId: string): OperationRecord | undefined {
    const row = this.db.prepare('SELECT * FROM operations WHERE operation_id = ?').get(operationId);
    return row === undefined ? undefined : operationFrom(row);
  }

  unresolvedPayments(): PaymentRecord[] {
    return this.db.prepare(`SELECT * FROM payments WHERE state IN ('submitting', 'in_flight', 'uncertain') ORDER BY created_at`)
      .all().map(paymentFrom);
  }

  attempts(paymentHash: string): AttemptRecord[] {
    return this.db.prepare('SELECT * FROM htlc_attempts WHERE payment_hash = ? ORDER BY CAST(attempt_id AS INTEGER)').all(paymentHash)
      .map(row => ({ attemptId: text(row, 'attempt_id'), status: text(row, 'status'), principalMsat: int(row, 'principal_msat'),
        feeMsat: int(row, 'fee_msat'), hops: Number(int(row, 'hops')), failureCode: optionalText(row, 'failure_code'),
        failureSourceIndex: row.failure_source_index === null ? undefined : Number(int(row, 'failure_source_index')) }));
  }

  ledger(operationId: string): LedgerEntry[] {
    return this.db.prepare('SELECT * FROM ledger_entries WHERE operation_id = ? ORDER BY entry_id').all(operationId)
      .map(row => ({ account: text(row, 'account') as LedgerEntry['account'], amountMsat: int(row, 'amount_msat'), postedAt: text(row, 'posted_at') }));
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
    const sums = this.db.prepare(`SELECT
        COALESCE(SUM(CASE WHEN state = 'held' THEN principal_msat + fee_allowance_msat END), 0) AS held,
        COALESCE(SUM(CASE WHEN state = 'consumed' THEN principal_msat + actual_fee_msat END), 0) AS consumed
      FROM reservations WHERE budget_id = ?`).get(budgetId) ?? {};
    const limitMsat = int(budget, 'limit_msat');
    const heldMsat = int(sums, 'held');
    const consumedMsat = int(sums, 'consumed');
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
        const requested = input.invoice.amountMsat + input.feeLimitMsat;
        if (requested > status.availableMsat) {
          this.db.prepare(`INSERT INTO budget_refusals (budget_id, operation_id, payment_hash, requested_msat, available_msat, at)
            VALUES (?, ?, ?, ?, ?, ?)`).run(input.budgetId, input.operationId, hash, requested, status.availableMsat, now);
          return { outcome: 'refused', reason: `budget ${input.budgetId} has ${status.availableMsat} msat available, ${requested} msat requested`,
            requestedMsat: requested, availableMsat: status.availableMsat };
        }
      }
      if (operation === undefined) {
        this.db.prepare(`INSERT INTO operations (operation_id, kind, amount_msat, state, budget_id, created_at, updated_at)
          VALUES (?, ?, ?, 'open', ?, ?, ?)`).run(input.operationId, input.kind, input.invoice.amountMsat, input.budgetId ?? null, now, now);
      } else {
        this.db.prepare(`UPDATE operations SET state = 'open', updated_at = ? WHERE operation_id = ?`).run(now, input.operationId);
      }
      this.db.prepare(`INSERT INTO payments (payment_hash, operation_id, payment_request, destination, amount_msat, fee_limit_msat,
          max_parts, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'intent', ?, ?)`)
        .run(hash, input.operationId, input.paymentRequest, input.invoice.destination, input.invoice.amountMsat, input.feeLimitMsat,
          input.maxParts, now, now);
      if (input.budgetId !== undefined) {
        this.db.prepare(`INSERT INTO reservations (budget_id, operation_id, payment_hash, principal_msat, fee_allowance_msat, state,
            created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'held', ?, ?)`)
          .run(input.budgetId, input.operationId, hash, input.invoice.amountMsat, input.feeLimitMsat, now, now);
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

  /** The connection or process was lost before LND reported a terminal state. */
  markUncertain(paymentHash: string, reason: string): void {
    immediate(this.db, () => {
      const result = this.db.prepare(`UPDATE payments SET state = 'uncertain', uncertain_reason = ?, updated_at = ?
        WHERE payment_hash = ? AND state IN ('submitting', 'in_flight', 'uncertain')`).run(reason, nowIso(), paymentHash);
      if (changes(result) === 1) this.#event(paymentHash, 'uncertain', { reason });
    });
  }

  /**
   * LND has no payment for this hash (TrackPaymentV2 answered NotFound) and the
   * record never saw LND acknowledge it. Back to intent: it may be submitted
   * again with the same payment hash. LND refuses a second payment for a hash
   * that is in flight or settled, so this can not pay twice.
   */
  markNotInitiated(paymentHash: string, evidence: string): boolean {
    return immediate(this.db, () => {
      const attempts = this.db.prepare('SELECT COUNT(*) AS n FROM htlc_attempts WHERE payment_hash = ?').get(paymentHash) ?? {};
      if (int(attempts, 'n') > 0n) {
        this.#event(paymentHash, 'not-found-after-attempts', { evidence });
        return false;
      }
      const result = this.db.prepare(`UPDATE payments SET state = 'intent', uncertain_reason = NULL, updated_at = ?
        WHERE payment_hash = ? AND state IN ('submitting', 'uncertain')`).run(nowIso(), paymentHash);
      if (changes(result) === 1) this.#event(paymentHash, 'not-initiated', { evidence });
      return changes(result) === 1;
    });
  }

  /**
   * LND refused SendPaymentV2 with a definite error and has no payment for the
   * hash: nothing was sent, and nothing will be. Terminal failure.
   */
  markRejected(paymentHash: string, reason: string): void {
    immediate(this.db, () => this.#fail(paymentHash, `REJECTED_BEFORE_INITIATION: ${reason}`, undefined));
  }

  #fail(paymentHash: string, reason: string, payment: Payment | undefined): boolean {
    const now = nowIso();
    const result = this.db.prepare(`UPDATE payments SET state = 'failed', failure_reason = ?, lnd_payment_index = COALESCE(?, lnd_payment_index),
      uncertain_reason = NULL, resolved_at = ?, updated_at = ? WHERE payment_hash = ? AND state <> 'failed'`)
      .run(reason, payment?.paymentIndex ?? null, now, now, paymentHash);
    if (changes(result) !== 1) return false;
    const record = this.payment(paymentHash) as PaymentRecord;
    this.db.prepare(`UPDATE operations SET state = 'failed', updated_at = ? WHERE operation_id = ? AND state = 'open'`).run(now, record.operationId);
    this.db.prepare(`UPDATE reservations SET state = 'released', updated_at = ? WHERE payment_hash = ? AND state = 'held'`).run(now, paymentHash);
    this.#event(paymentHash, 'failed', { reason });
    return true;
  }

  #upsertAttempts(payment: Payment): void {
    const statement = this.db.prepare(`INSERT INTO htlc_attempts (payment_hash, attempt_id, status, principal_msat, fee_msat, hops, route,
        failure_code, failure_source_index, attempt_time_ns, resolve_time_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (payment_hash, attempt_id) DO UPDATE SET status = excluded.status, failure_code = excluded.failure_code,
        failure_source_index = excluded.failure_source_index, resolve_time_ns = excluded.resolve_time_ns`);
    for (const attempt of payment.htlcs) {
      statement.run(payment.paymentHash, attempt.attemptId, attempt.status, attempt.principalMsat, attempt.route.totalFeesMsat,
        attempt.route.hops.length, attempt.route.hops.map(hop => hop.chanId).join('>'), attempt.failureCode ?? null,
        attempt.failureSourceIndex ?? null, attempt.attemptTimeNs, attempt.resolveTimeNs);
    }
  }

  /**
   * Applies one update from SendPaymentV2 or TrackPaymentV2. LND is the
   * authority on the outcome; this method only refuses an update that
   * contradicts a terminal state already recorded.
   */
  applyUpdate(payment: Payment, source: 'SendPaymentV2' | 'TrackPaymentV2'): UpdateResult {
    return immediate(this.db, (): UpdateResult => {
      const record = this.payment(payment.paymentHash);
      if (record === undefined) throw new Error(`update for unknown payment ${payment.paymentHash}`);
      this.#upsertAttempts(payment);
      const now = nowIso();
      if (payment.status === 'SUCCEEDED') {
        const preimage = payment.preimage;
        if (preimage === undefined || sha256Hex(preimage) !== payment.paymentHash) {
          throw new Error(`LND reported success for ${payment.paymentHash} without a matching preimage`);
        }
        if (record.state === 'succeeded') {
          if (record.feeMsat !== payment.feeMsat || record.valueMsat !== payment.valueMsat) {
            throw new Error(`LND reported different amounts for already settled payment ${payment.paymentHash}`);
          }
          return { state: 'succeeded', completed: false, failed: false };
        }
        if (record.state === 'failed') this.#event(payment.paymentHash, 'success-after-failure', { source });
        if (payment.valueMsat !== record.amountMsat) {
          this.#event(payment.paymentHash, 'amount-mismatch', { expectedMsat: record.amountMsat, lndValueMsat: payment.valueMsat });
        }
        this.db.prepare(`UPDATE payments SET state = 'succeeded', fee_msat = ?, value_msat = ?, preimage = ?, lnd_payment_index = ?,
          uncertain_reason = NULL, failure_reason = NULL, resolved_at = ?, updated_at = ? WHERE payment_hash = ?`)
          .run(payment.feeMsat, payment.valueMsat, preimage, payment.paymentIndex, now, now, payment.paymentHash);
        const completed = changes(this.db.prepare(`UPDATE operations SET state = 'completed', completed_at = ?, updated_at = ?
          WHERE operation_id = ? AND state <> 'completed'`).run(now, now, record.operationId)) === 1;
        const ledger = this.db.prepare(`INSERT INTO ledger_entries (operation_id, payment_hash, account, amount_msat, posted_at)
          VALUES (?, ?, ?, ?, ?) ON CONFLICT (operation_id, payment_hash, account) DO NOTHING`);
        ledger.run(record.operationId, payment.paymentHash, 'principal', payment.valueMsat, now);
        ledger.run(record.operationId, payment.paymentHash, 'routing-fee', payment.feeMsat, now);
        this.db.prepare(`UPDATE reservations SET state = 'consumed', actual_fee_msat = ?, updated_at = ?
          WHERE payment_hash = ? AND state = 'held'`).run(payment.feeMsat, now, payment.paymentHash);
        this.#event(payment.paymentHash, 'succeeded', { source, valueMsat: payment.valueMsat, feeMsat: payment.feeMsat,
          htlcAttempts: payment.htlcs.length, succeededAttempts: payment.htlcs.filter(item => item.status === 'SUCCEEDED').length });
        return { state: 'succeeded', completed, failed: false };
      }
      if (payment.status === 'FAILED') {
        if (record.state === 'succeeded') throw new Error(`LND reported failure for settled payment ${payment.paymentHash}`);
        const failed = this.#fail(payment.paymentHash, payment.failureReason, payment);
        return { state: 'failed', completed: false, failed };
      }
      // IN_FLIGHT or INITIATED: LND holds the payment. Not terminal.
      if (record.state === 'succeeded') return { state: 'succeeded', completed: false, failed: false };
      const result = this.db.prepare(`UPDATE payments SET state = 'in_flight', uncertain_reason = NULL, lnd_payment_index = ?, updated_at = ?
        WHERE payment_hash = ? AND state <> 'in_flight'`).run(payment.paymentIndex, now, payment.paymentHash);
      if (changes(result) === 1) {
        if (record.state === 'failed') {
          this.db.prepare(`UPDATE operations SET state = 'open', updated_at = ? WHERE operation_id = ? AND state = 'failed'`).run(now, record.operationId);
        }
        this.#event(payment.paymentHash, 'in-flight', { source, status: payment.status, htlcAttempts: payment.htlcs.length });
      }
      return { state: 'in_flight', completed: false, failed: false };
    });
  }

  /**
   * Prepares a definitely failed payment for another submission of the same
   * invoice (same payment hash). With a budget, a new reservation is checked
   * and taken in the same transaction.
   */
  prepareRetry(operationId: string): IntentResult {
    return immediate(this.db, (): IntentResult => {
      const operation = this.operation(operationId);
      if (operation === undefined) return { outcome: 'refused', reason: `operation ${operationId} does not exist` };
      const payment = this.paymentForOperation(operationId);
      if (payment === undefined) return { outcome: 'refused', reason: `operation ${operationId} has no payment` };
      if (payment.state !== 'failed') {
        return { outcome: 'refused', reason: `payment ${payment.paymentHash} is ${payment.state}; only a payment LND reported failed is retried` };
      }
      const now = nowIso();
      if (operation.budgetId !== undefined) {
        const status = this.#budgetStatus(operation.budgetId);
        const requested = payment.amountMsat + payment.feeLimitMsat;
        if (status === undefined || requested > status.availableMsat) {
          const available = status?.availableMsat ?? 0n;
          this.db.prepare(`INSERT INTO budget_refusals (budget_id, operation_id, payment_hash, requested_msat, available_msat, at)
            VALUES (?, ?, ?, ?, ?, ?)`).run(operation.budgetId, operationId, payment.paymentHash, requested, available, now);
          return { outcome: 'refused', reason: `budget ${operation.budgetId} has ${available} msat available, ${requested} msat requested`,
            requestedMsat: requested, availableMsat: available };
        }
        this.db.prepare(`INSERT INTO reservations (budget_id, operation_id, payment_hash, principal_msat, fee_allowance_msat, state,
            created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'held', ?, ?)`)
          .run(operation.budgetId, operationId, payment.paymentHash, payment.amountMsat, payment.feeLimitMsat, now, now);
      }
      this.db.prepare(`UPDATE payments SET state = 'intent', failure_reason = NULL, resolved_at = NULL, updated_at = ?
        WHERE payment_hash = ?`).run(now, payment.paymentHash);
      this.db.prepare(`UPDATE operations SET state = 'open', updated_at = ? WHERE operation_id = ?`).run(now, operationId);
      this.#event(payment.paymentHash, 'retry-prepared', { previousFailure: payment.failureReason ?? null });
      return { outcome: 'recorded', payment: this.payment(payment.paymentHash) as PaymentRecord };
    });
  }
}
