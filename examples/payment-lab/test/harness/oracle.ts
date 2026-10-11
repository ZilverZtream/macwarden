import { DatabaseSync } from 'node:sqlite';
import type { LedgerVerification } from './lab.ts';
import type { FakeLnd, LedgerSource, Proc } from './lnd.ts';

/**
 * The oracle: the payment lab README's rules (examples/payment-lab/README.md, "Design decisions"),
 * each as one named predicate over the durable records, LND's (simulated) truth and the store calls
 * the workflows made. Records are read through a separate read-only connection, so the oracle never
 * goes through the code under test; only the columns the 1.2.0 schema already had are read (plus
 * late_lnd_state when it exists), so the same predicates judge older sources.
 *
 * Predicates are checked after every store call that writes (transitions, staleness, admission) and
 * after every step (static invariants); a few at the moment of an RPC (SettleInvoice) or at the end of
 * a case (quiescence). With a 1.3.0 source the journal is also checked as a whole after every step
 * (`ledger verify`, src/ledger/verify.ts, through the oracle's connection), and the outbox rows and
 * effect files against the settlements and completions they stand for. The ideas come from the verifiers' probes for 1.2.1:
 * mw5/verify-lab3/p1-fuzz.mts (random store calls tagged with a submission against an oracle: stale calls
 * change nothing, live ones apply, reservations follow the state, the ledger follows success) and
 * mw5/verify-lab4/p5-reconcile-counts.mts (reconcile buckets partition the targets; exit 75 iff unknown > 0).
 */

export const PREDICATES = {
  'one-pending-payment-per-operation':
    'One operation has at most one pending payment (intent, submitting, in_flight or uncertain); a payment of an operation another payment completed is never claimed for submission nor reverted to intent (it is withdrawn).',
  'reservation-held-iff-live':
    'A budgeted payment (its operation names a budget, or it has a reservation) holds exactly one reservation, at its amount and fee limit, while it is unresolved; failed releases it; succeeded consumes exactly one, at LND\'s value plus the actual fee.',
  'ledger-once-per-succeeded-payment':
    'A payment LND reports succeeded is recorded succeeded at LND\'s value and fee and posted exactly once (principal = value, routing fee = fee); nothing else is posted (per payment hash only payment-succeeded, budget entries and, for every succeeded payment of an operation but the first, one double-payment entry); the operation is completed iff a payment succeeded; two succeeded payments of one operation are both flagged double-payment.',
  'stale-submission-changes-nothing':
    'An update or call outcome (other than SUCCEEDED) for a superseded submission changes neither the payment, its operation nor its reservation.',
  'notfound-revert-keeps-live-updates':
    'An update or refusal for the live submission applies (IN_FLIGHT -> in_flight, FAILED or a definite refusal -> failed), also after a NotFound sent the record back to intent; a TrackPaymentV2 snapshot LND took before the live submission\'s request reached it (every HTLC attempt in it first shown for an earlier submission, or none and created no later than a payment shown for an earlier submission, or before the live submission was sent when none was) is an earlier submission\'s answer and changes neither the payment, its operation nor its reservation.',
  'terminal-states-final':
    'Succeeded is final and a completed operation stays completed; failed changes only by a retry (to intent) or by LND reporting success.',
  'budget-admission-within-limit':
    'Admission follows bigint arithmetic (admitted iff principal + fee allowance <= limit - committed, where committed is computed from the payments themselves: amount + fee limit for each unresolved budgeted payment, value + fee for each succeeded one), never throws on large sums, budgetStatus equals the exact sums of the reservations, and both the reservations and the payments stay within the limit unless LND reported success after a recorded failure or a budget-overrun event records the excess.',
  'canceled-final-for-open-accepted':
    'A canceled invoice (or a late invoice LND was seen to cancel: its CANCELED is recorded in late_lnd_state) is never made live again by a replayed OPEN or ACCEPTED or a delayed create answer.',
  'settled-outranks-canceled':
    'LND reporting SETTLED for an invoice recorded canceled makes the record settled; at the end of a case (after a subscription catch-up from the cursor and reconciliation), no invoice LND holds SETTLED is recorded canceled.',
  'settlement-posted-once':
    'Every settlement LND reports is posted exactly once (one ledger entry for the amount paid, however often it is delivered; the first settlement recorded wins over a later report of another amount); per payment hash only one invoice-settled (paid in full) or underpaid-settlement entry, and a double-payment entry exactly when an invoice-settled one has no fulfillment; settled is final; an order has at most one fulfillment, and is fulfilled iff it has one; at the end of a case every invoice LND holds SETTLED is recorded settled with exactly one settlement entry, whatever it was paid (unless an explicit cursor-set skipped it, or the subscription cursor never left 0, where LND replays nothing).',
  'cursor-moves-only-from-subscription':
    'The subscription cursor moves only with subscription deliveries or an explicit cursor-set. Its add index moves to the highest seen; its settle index only contiguously: from c to c + 1 when the subscription delivered settlement c + 1, then on over c + 2, ... while the subscription delivered each (from 0, the first settle index the subscription delivers becomes the cursor: LND replays nothing for 0), so a restarted listener never skips a settlement it did not receive; lookups never move it.',
  'reconcile-buckets-partition':
    'receiver reconcile counts every invoice it covers exactly once (resolved + open + unknown = targets), each in its own bucket (resolved: final when listed, or settled, canceled or not-created as LND or the record decided it; open: OPEN or ACCEPTED in LND as the pass looked it up; unknown: only when the pass was stopped, a lookup of it got no answer, a cancel of it by the pass failed, or a creating invoice was not found within its creation window), and exits 75 iff unknown > 0, else 0.',
  'superseded-canceled-never-settled':
    'SettleInvoice is never called for an invoice of an order fulfilled by another invoice; after reconciliation every superseded or late invoice is canceled in LND, so no order has two payable invoices.',
  'ledger-balanced':
    "Both books pass ledger verify after every step: every entry balances and follows its posting rule, the stored balances equal the entries, the payer's budget, wallet and fee accounts equal its records, and the amounts posted equal what LND lists (ListPayments, ListInvoices) for every resolved record.",
  'effects-once':
    "Every fulfilled order has exactly one fulfill-order row (its fulfillment's, with the settlement's amount and entry) and every completed operation one confirm-operation row (its first succeeded payment's); nothing else is enqueued; a done row has its receipt or confirmation, valid under the lab's key and carrying the row's fields; no effect is written twice, also when the worker is killed at any point; after the last pass every row is done.",
  'no-internal-error':
    'Store calls, workflows and the outbox worker on a live process never throw (LND is truthful apart from the injected faults; the only refusal by exception is a FAILED for a payment already succeeded).',
} as const;

export type PredicateName = keyof typeof PREDICATES;

const PENDING = new Set(['intent', 'submitting', 'in_flight', 'uncertain']);
const PAYER_EVENTS = new Set(['payment-succeeded', 'double-payment', 'budget-held', 'budget-released', 'budget-consumed']);
const RECEIVER_EVENTS = new Set(['invoice-settled', 'underpaid-settlement', 'double-payment']);
type Bucket = 'resolved' | 'open' | 'unknown';
/** A record reconciliation has nothing left to do for (receiver.ts final()): settled, canceled, or not-created and LND canceled or settled it. */
const finalRecord = (row: InvoiceRow): boolean => row.state === 'settled' || row.state === 'canceled'
  || (row.state === 'not-created' && (row.late === 'CANCELED' || row.late === 'SETTLED'));
/** A record that is decided: final, or not-created and not live in LND as far as the record knows. */
const decidedRecord = (row: InvoiceRow): boolean => finalRecord(row) || (row.state === 'not-created' && row.late !== 'OPEN' && row.late !== 'ACCEPTED');
const MAX_INT64 = 2n ** 63n - 1n;
/** How long a not-created invoice of unknown late state is rechecked (README, receiver reconcile: 24 hours). */
const LATE_RECHECK_MS = 24 * 60 * 60 * 1000;

export interface PaymentRow { op: string; state: string; subs: number; amount: bigint; feeLimit: bigint; fee: bigint | undefined; value: bigint | undefined }
export interface ReservationRow { id: bigint; budget: string; hash: string; principal: bigint; allowance: bigint; actual: bigint | undefined; state: string }
/** A journal entry: its event, payment hash, operation (or order) and the amount of its first line. */
export interface EntryRow { id: bigint; event: string; hash: string; op: string; amount: bigint }
export interface OutboxRowSnap { id: bigint; kind: string; key: string; subject: string; payload: Record<string, string | number | null>; state: string }
export interface PayerSnap {
  payments: Map<string, PaymentRow>;
  entries: EntryRow[];
  outbox: OutboxRowSnap[];
  operations: Map<string, string>;
  /** Per operation, the budget it names (operations.budget_id), if any. */
  opBudgets: Map<string, string | undefined>;
  reservations: ReservationRow[];
  ledger: { op: string; hash: string; account: string; amount: bigint }[];
  events: Map<string, Set<string>>;
  budgets: Map<string, bigint>;
}
export interface InvoiceRow { order: string; state: string; late: string | undefined; amount: bigint; amtPaid: bigint | undefined; createdAt: string }
export interface ReceiverSnap {
  invoices: Map<string, InvoiceRow>;
  entries: EntryRow[];
  outbox: OutboxRowSnap[];
  orders: Map<string, string>;
  fulfillments: { hash: string; order: string }[];
  ledger: { hash: string; order: string; amount: bigint }[];
  cursor: { settle: bigint; add: bigint };
}

export interface Violation {
  predicate: PredicateName;
  message: string;
  /** The records around the violation: before and after the store call, or after the step. */
  states: Record<string, unknown>;
}

type Row = Record<string, unknown>;

/**
 * The ledger as the 1.2 ledger_entries rows had it, from either schema: the table itself (1.2.0, 1.2.1),
 * or the named legs of the double-entry journal's payment-succeeded and invoice-settled entries (1.3.0),
 * the same view the stores' ledger() methods give.
 */
const PAYER_JOURNAL_LEGS = `SELECT e.operation_id, e.payment_hash, l.leg AS account, l.amount_msat FROM journal_lines l
  JOIN journal_entries e ON e.entry_id = l.entry_id WHERE e.event = 'payment-succeeded' AND l.leg IN ('principal', 'routing-fee')
  ORDER BY e.entry_id, l.line_no`;
const RECEIVER_JOURNAL_LEGS = `SELECT e.payment_hash, e.operation_id AS order_id, l.amount_msat FROM journal_lines l
  JOIN journal_entries e ON e.entry_id = l.entry_id WHERE e.event = 'invoice-settled' AND l.leg = 'sale' ORDER BY e.entry_id, l.line_no`;
const ENTRIES = `SELECT e.entry_id, e.event, e.payment_hash, e.operation_id,
  (SELECT l.amount_msat FROM journal_lines l WHERE l.entry_id = e.entry_id AND l.line_no = 1) AS amount_msat FROM journal_entries e ORDER BY e.entry_id`;
const OUTBOX = 'SELECT outbox_id, kind, idempotency_key, subject, payload, state FROM outbox ORDER BY outbox_id';
const hasTable = (db: DatabaseSync, name: string): boolean =>
  db.prepare(`SELECT 1 AS n FROM sqlite_master WHERE type = 'table' AND name = ?`).get(name) !== undefined;
const big = (value: unknown): bigint => (typeof value === 'bigint' ? value : BigInt(value as number));
const opt = (value: unknown): bigint | undefined => (value === null || value === undefined ? undefined : big(value));

export interface StoreCall {
  proc: Proc;
  side: 'payer' | 'receiver';
  method: string;
  args: unknown[];
  before: PayerSnap | ReceiverSnap;
  after: PayerSnap | ReceiverSnap;
  result: unknown;
  error: unknown;
  /**
   * The submission the call is about, as the harness knows it (the stream being delivered, or the
   * workflow's last stream), not as the call states it: the 1.2.0 workflows passed no submission.
   */
  submission: number | undefined;
}

export class Oracle {
  readonly lnd: FakeLnd;
  readonly violations: Violation[] = [];
  readonly #payerPath: string;
  readonly #receiverPath: string;
  #payerDb: DatabaseSync | undefined;
  #receiverDb: DatabaseSync | undefined;
  #lateColumn: boolean | undefined;
  #payerJournal: boolean | undefined;
  #receiverJournal: boolean | undefined;
  #payerOutbox: boolean | undefined;
  #receiverOutbox: boolean | undefined;
  /** Per payment: the highest submission a retry closed (prepareRetry); the oracle's own model, not the store's column. */
  readonly closed = new Map<string, number>();
  /** The cursor the oracle expects (subscription deliveries and cursor-set only). */
  expectedCursor: { settle: bigint; add: bigint } | undefined;
  /** Settle indexes the subscription gave the store (applyInvoice without an error). */
  readonly #settlesBySubscription = new Set<bigint>();
  /**
   * Invoices delivered SETTLED (any source), and settlements the cursor passed before they were delivered: by an explicit
   * cursor-set, or below the first settle index delivered from a zero cursor (LND replays none of them).
   */
  readonly #settledDelivered = new Set<string>();
  readonly #skippedByCursorSet = new Set<string>();
  /** Budgets on which LND reported success after a recorded failure (the release was undone; the limit may be exceeded). */
  readonly overspendAllowed = new Set<string>();
  /** The budgetStatus of the store under test, read once per step by the runner. */
  budgetStatus: ((budgetId: string) => { heldMsat: bigint; consumedMsat: bigint; availableMsat: bigint } | undefined) | undefined;
  /**
   * `ledger verify` of the source under test (1.3.0), run on the oracle's own read-only connections, with the
   * scripted LND's ListPayments and ListInvoices (FakeLnd.ledgerSource), so posted amounts are compared with LND's.
   */
  verifyLedger: ((store: { db: unknown; book: 'payer' | 'receiver' }, api?: LedgerSource) => Promise<LedgerVerification>) | undefined;
  /** The effect files (1.3.0): read and checked with the source's own functions, by the runner. */
  effects: EffectFiles | undefined;
  /** Effects written per idempotency key (counted by the runner around each claimed row). */
  readonly written = new Map<string, number>();

  constructor(lnd: FakeLnd, payerPath: string, receiverPath: string) {
    this.lnd = lnd;
    this.#payerPath = payerPath;
    this.#receiverPath = receiverPath;
  }

  close(): void {
    this.#payerDb?.close();
    this.#receiverDb?.close();
    this.#payerDb = undefined;
    this.#receiverDb = undefined;
  }

  fail(predicate: PredicateName, message: string, states: Record<string, unknown> = {}): void {
    this.violations.push({ predicate, message, states });
  }

  // ------------------------------------------------------------------------------------------
  // Snapshots.

  #payer(): DatabaseSync {
    this.#payerDb ??= new DatabaseSync(this.#payerPath, { readOnly: true, readBigInts: true });
    return this.#payerDb;
  }

  #receiver(): DatabaseSync {
    this.#receiverDb ??= new DatabaseSync(this.#receiverPath, { readOnly: true, readBigInts: true });
    return this.#receiverDb;
  }

  payerSnap(): PayerSnap {
    const db = this.#payer();
    const all = (sql: string): Row[] => db.prepare(sql).all() as Row[];
    this.#payerJournal ??= hasTable(db, 'journal_lines');
    this.#payerOutbox ??= hasTable(db, 'outbox');
    const events = new Map<string, Set<string>>();
    for (const row of all('SELECT payment_hash, kind FROM payment_events')) {
      const hash = String(row.payment_hash);
      if (!events.has(hash)) events.set(hash, new Set());
      events.get(hash)?.add(String(row.kind));
    }
    return {
      payments: new Map(all('SELECT payment_hash, operation_id, state, submissions, amount_msat, fee_limit_msat, fee_msat, value_msat FROM payments ORDER BY rowid').map(row => [
        String(row.payment_hash), { op: String(row.operation_id), state: String(row.state), subs: Number(row.submissions), amount: big(row.amount_msat),
          feeLimit: big(row.fee_limit_msat), fee: opt(row.fee_msat), value: opt(row.value_msat) }])),
      operations: new Map(all('SELECT operation_id, state FROM operations').map(row => [String(row.operation_id), String(row.state)])),
      opBudgets: new Map(all('SELECT operation_id, budget_id FROM operations').map(row => [String(row.operation_id),
        row.budget_id === null || row.budget_id === undefined ? undefined : String(row.budget_id)])),
      reservations: all('SELECT reservation_id, budget_id, payment_hash, principal_msat, fee_allowance_msat, actual_fee_msat, state FROM reservations ORDER BY reservation_id')
        .map(row => ({ id: big(row.reservation_id), budget: String(row.budget_id), hash: String(row.payment_hash), principal: big(row.principal_msat),
          allowance: big(row.fee_allowance_msat), actual: opt(row.actual_fee_msat), state: String(row.state) })),
      ledger: all(this.#payerJournal ? PAYER_JOURNAL_LEGS : 'SELECT operation_id, payment_hash, account, amount_msat FROM ledger_entries ORDER BY entry_id')
        .map(row => ({ op: String(row.operation_id), hash: String(row.payment_hash), account: String(row.account), amount: big(row.amount_msat) })),
      events,
      budgets: new Map(all('SELECT budget_id, limit_msat FROM budgets').map(row => [String(row.budget_id), big(row.limit_msat)])),
      entries: this.#payerJournal ? all(ENTRIES).map(entryRow) : [],
      outbox: this.#payerOutbox ? all(OUTBOX).map(outboxRow) : [],
    };
  }

  receiverSnap(): ReceiverSnap {
    const db = this.#receiver();
    const all = (sql: string): Row[] => db.prepare(sql).all() as Row[];
    this.#lateColumn ??= all('PRAGMA table_info(invoices)').some(row => row.name === 'late_lnd_state');
    this.#receiverJournal ??= hasTable(db, 'journal_lines');
    this.#receiverOutbox ??= hasTable(db, 'outbox');
    const late = this.#lateColumn ? ', late_lnd_state' : '';
    const cursor = all(`SELECT settle_index, add_index FROM subscription_cursor WHERE name = 'invoices'`)[0] ?? {};
    return {
      invoices: new Map(all(`SELECT payment_hash, order_id, state, amount_msat, amt_paid_msat, created_at${late} FROM invoices ORDER BY rowid`).map(row => [
        String(row.payment_hash), { order: String(row.order_id), state: String(row.state),
          late: row.late_lnd_state === null || row.late_lnd_state === undefined ? undefined : String(row.late_lnd_state),
          amount: big(row.amount_msat), amtPaid: opt(row.amt_paid_msat), createdAt: String(row.created_at) }])),
      orders: new Map(all('SELECT order_id, state FROM orders').map(row => [String(row.order_id), String(row.state)])),
      fulfillments: all('SELECT payment_hash, order_id FROM fulfillments').map(row => ({ hash: String(row.payment_hash), order: String(row.order_id) })),
      ledger: all(this.#receiverJournal ? RECEIVER_JOURNAL_LEGS : 'SELECT payment_hash, order_id, amount_msat FROM ledger_entries ORDER BY entry_id')
        .map(row => ({ hash: String(row.payment_hash), order: String(row.order_id), amount: big(row.amount_msat) })),
      cursor: { settle: big(cursor.settle_index ?? 0n), add: big(cursor.add_index ?? 0n) },
      entries: this.#receiverJournal ? all(ENTRIES).map(entryRow) : [],
      outbox: this.#receiverOutbox ? all(OUTBOX).map(outboxRow) : [],
    };
  }

  /** A snapshot as JSON for a replay file: hashes become their labels (op0/i1, o2#1), bigints decimal strings. */
  readable(value: unknown): unknown {
    const label = (text: string): string => (/^[0-9a-f]{64}$/.test(text) ? this.lnd.labelOf(text) : text);
    const walk = (item: unknown): unknown => {
      if (typeof item === 'bigint') return item.toString();
      if (typeof item === 'string') return label(item);
      if (item instanceof Map) return Object.fromEntries([...item.entries()].map(([key, entry]) => [label(String(key)), walk(entry)]));
      if (item instanceof Set) return [...item].map(walk);
      if (Array.isArray(item)) return item.map(walk);
      if (item !== null && typeof item === 'object') return Object.fromEntries(Object.entries(item).map(([key, entry]) => [key, walk(entry)]));
      return item;
    };
    return walk(value);
  }

  // ------------------------------------------------------------------------------------------
  // Per store call.

  afterCall(call: StoreCall): void {
    if (call.side === 'payer') this.#payerCall(call, call.before as PayerSnap, call.after as PayerSnap);
    else this.#receiverCall(call, call.before as ReceiverSnap, call.after as ReceiverSnap);
  }

  #states(call: StoreCall): Record<string, unknown> {
    return this.readable({ call: { proc: call.proc, method: call.method, args: call.args.map(arg => summarizeArg(arg)),
      error: call.error === undefined ? undefined : String((call.error as Error).message ?? call.error) }, before: call.before, after: call.after }) as Record<string, unknown>;
  }

  #payerCall(call: StoreCall, before: PayerSnap, after: PayerSnap): void {
    const { method, args, error } = call;
    const states = (): Record<string, unknown> => this.#states(call);
    const label = (hash: string): string => this.lnd.labelOf(hash);
    const held = (snap: PayerSnap, hash: string): number => snap.reservations.filter(row => row.hash === hash && row.state === 'held').length;
    let attributed = false;

    if (['applyUpdate', 'markUncertain', 'markNotInitiated', 'markRejected'].includes(method)) {
      const update = method === 'applyUpdate' ? args[0] as { paymentHash: string; status: string } : undefined;
      const hash = update?.paymentHash ?? String(args[0]);
      const submission = call.submission;
      const status = update?.status ?? method;
      const b = before.payments.get(hash);
      const a = after.payments.get(hash);
      if (b !== undefined && a !== undefined && submission !== undefined) {
        const closed = this.closed.get(hash) ?? 0;
        const stale = submission < b.subs || submission <= closed;
        if (stale && status !== 'SUCCEEDED' && (a.state !== b.state || held(after, hash) !== held(before, hash)
          || after.operations.get(a.op) !== before.operations.get(b.op))) {
          this.fail('stale-submission-changes-nothing', `${method}${update === undefined ? '' : ` ${status}`} for superseded submission ${submission} of ${label(hash)} `
            + `(record at submission ${b.subs}, closed ${closed}) moved it ${b.state} -> ${a.state}, held reservations ${held(before, hash)} -> ${held(after, hash)}`, states());
        }
        // A TrackPaymentV2 snapshot LND took before the live submission's request reached it (a retried payment's earlier
        // FAILED, which LND shows until the retry arrives) is an earlier submission's answer: it changes nothing.
        const earlier = update !== undefined && args[1] === 'TrackPaymentV2' && status !== 'SUCCEEDED' && submission === b.subs
          && this.lnd.predatesSubmission(update as Parameters<FakeLnd['predatesSubmission']>[0], submission);
        if (!stale && earlier && error === undefined && (a.state !== b.state || held(after, hash) !== held(before, hash)
          || after.operations.get(a.op) !== before.operations.get(b.op))) {
          this.fail('notfound-revert-keeps-live-updates', `TrackPaymentV2 ${status} taken before the live submission ${submission} of ${label(hash)} reached LND `
            + `moved it ${b.state} -> ${a.state}, held reservations ${held(before, hash)} -> ${held(after, hash)}`, states());
        }
        if (!stale && !earlier && submission === b.subs && PENDING.has(b.state) && error === undefined) {
          const expected = status === 'IN_FLIGHT' || status === 'INITIATED' ? 'in_flight' : status === 'FAILED' || status === 'markRejected' ? 'failed' : undefined;
          if (expected !== undefined && a.state !== expected) {
            this.fail('notfound-revert-keeps-live-updates', `${method}${update === undefined ? '' : ` ${status}`} for the live submission ${submission} of ${label(hash)} left it ${a.state} `
              + `(was ${b.state}), expected ${expected}`, states());
          }
        }
      }
      if (status === 'SUCCEEDED' && b !== undefined) {
        attributed = true;
        if (error !== undefined) {
          this.fail('ledger-once-per-succeeded-payment', `LND reported ${label(hash)} succeeded and the store refused to record it: ${String((error as Error).message)}`, states());
        } else if (a?.state !== 'succeeded') {
          this.fail('ledger-once-per-succeeded-payment', `LND reported ${label(hash)} succeeded; the record is ${a?.state}`, states());
        }
        if (b.state === 'failed' && a?.state === 'succeeded') {
          for (const row of after.reservations) if (row.hash === hash) this.overspendAllowed.add(row.budget);
          const budget = after.opBudgets.get(a.op);
          if (budget !== undefined) this.overspendAllowed.add(budget);
        }
      }
      // The lab refuses a FAILED for a payment already recorded succeeded by throwing; LND sent it before the success.
      if (status === 'FAILED' && b?.state === 'succeeded' && error !== undefined) attributed = true;
    }

    if ((method === 'claimForSubmission' || method === 'markNotInitiated') && error === undefined) {
      const hash = String(args[0]);
      const b = before.payments.get(hash);
      const a = after.payments.get(hash);
      if (b !== undefined && a !== undefined && before.operations.get(b.op) === 'completed'
        && ((method === 'claimForSubmission' && a.state === 'submitting') || (method === 'markNotInitiated' && a.state === 'intent' && b.state !== 'intent'))) {
        this.fail('one-pending-payment-per-operation', `${method} moved ${label(hash)} ${b.state} -> ${a.state} although operation ${b.op} is completed (it must be withdrawn)`, states());
      }
    }

    for (const [hash, b] of before.payments) {
      const a = after.payments.get(hash);
      if (a === undefined) continue;
      if (b.state === 'succeeded' && a.state !== 'succeeded') {
        this.fail('terminal-states-final', `${method} moved succeeded payment ${label(hash)} to ${a.state}`, states());
      }
      if (b.state === 'failed' && a.state !== 'failed' && !(method === 'prepareRetry' && a.state === 'intent')
        && !(method === 'applyUpdate' && a.state === 'succeeded')) {
        this.fail('terminal-states-final', `${method} moved failed payment ${label(hash)} to ${a.state} (only a retry or LND's success may)`, states());
      }
    }
    for (const [op, state] of before.operations) {
      if (state === 'completed' && after.operations.get(op) !== 'completed') {
        this.fail('terminal-states-final', `${method} moved completed operation ${op} to ${after.operations.get(op)}`, states());
      }
    }

    if (method === 'recordIntent' || method === 'prepareRetry') {
      attributed = true;
      if (error !== undefined) {
        this.fail('budget-admission-within-limit', `${method} threw: ${String((error as Error).message)}`, states());
      } else {
        const result = call.result as { outcome: string; payment?: { paymentHash: string }; requestedMsat?: bigint } | undefined;
        const budgetOf = (): { budget: string; requested: bigint } | undefined => {
          if (method === 'recordIntent') {
            const input = args[0] as { budgetId?: string; invoice: { amountMsat: bigint }; feeLimitMsat: bigint };
            return input.budgetId === undefined ? undefined : { budget: input.budgetId, requested: input.invoice.amountMsat + input.feeLimitMsat };
          }
          const added = after.reservations.filter(row => !before.reservations.some(old => old.id === row.id));
          const row = added[0];
          if (row !== undefined) return { budget: row.budget, requested: row.principal + row.allowance };
          // No reservation taken: the failed payment's own figures, against its operation's budget.
          const op = `${String(args[0])}`;
          const failed = [...before.payments.values()].find(item => item.op === op && item.state === 'failed');
          const budget = before.opBudgets.get(op);
          if (failed !== undefined && budget !== undefined) return { budget, requested: failed.amount + failed.feeLimit };
          return result?.requestedMsat === undefined ? undefined : { budget: 'B', requested: result.requestedMsat };
        };
        const admission = budgetOf();
        if (admission !== undefined && before.budgets.has(admission.budget)) {
          // Available as the README defines it: the limit less what the payments themselves commit (not the reservation rows,
          // which a store that forgot to reserve would leave empty); with correct reservations the two agree.
          const available = (before.budgets.get(admission.budget) ?? 0n) - committed(before, admission.budget);
          // Admitted: a reservation was taken, or a payment entered intent (a new one, or a failed one retried).
          const reserved = after.reservations.length > before.reservations.length
            || [...after.payments].some(([hash, row]) => row.state === 'intent' && before.payments.get(hash)?.state !== 'intent');
          if (reserved && admission.requested > available) {
            this.fail('budget-admission-within-limit', `${method} reserved ${admission.requested} msat on budget ${admission.budget} with ${available} msat available`, states());
          }
          if (result?.outcome === 'refused' && result.requestedMsat !== undefined && admission.requested <= available) {
            this.fail('budget-admission-within-limit', `${method} refused ${admission.requested} msat on budget ${admission.budget} with ${available} msat available`, states());
          }
        }
        if (method === 'prepareRetry' && result?.outcome === 'recorded' && result.payment !== undefined) {
          const hash = result.payment.paymentHash;
          this.closed.set(hash, before.payments.get(hash)?.subs ?? 0);
        }
      }
    }

    if (error !== undefined && !attributed) {
      this.fail('no-internal-error', `payer ${method} threw: ${String((error as Error).message)}`, states());
    }
  }

  #receiverCall(call: StoreCall, before: ReceiverSnap, after: ReceiverSnap): void {
    const { method, args, error } = call;
    const states = (): Record<string, unknown> => this.#states(call);
    const label = (hash: string): string => this.lnd.labelOf(hash);
    let attributed = false;
    this.expectedCursor ??= before.cursor;

    for (const [hash, b] of before.invoices) {
      const a = after.invoices.get(hash);
      if (a === undefined) continue;
      if (b.state === 'settled' && a.state !== 'settled') {
        this.fail('settlement-posted-once', `${method} moved settled invoice ${label(hash)} to ${a.state}`, states());
      }
      if (b.state === 'canceled' && a.state !== 'canceled' && a.state !== 'settled') {
        this.fail('canceled-final-for-open-accepted', `${method} moved canceled invoice ${label(hash)} to ${a.state}`, states());
      }
      if (b.late === 'CANCELED' && ((a.late !== 'CANCELED' && a.late !== 'SETTLED') || a.state === 'open' || a.state === 'accepted')) {
        this.fail('canceled-final-for-open-accepted', `${method} made late invoice ${label(hash)}, which LND canceled, live again: `
          + `${b.state}/${b.late} -> ${a.state}/${a.late ?? '-'}`, states());
      }
    }

    if (method === 'applyInvoice') {
      const invoice = args[0] as { paymentHash: string; state: string; amtPaidMsat: bigint; settleIndex: bigint; addIndex: bigint };
      const source = String(args[1]);
      const hash = invoice.paymentHash;
      const b = before.invoices.get(hash);
      const a = after.invoices.get(hash);
      // A late invoice LND reports canceled is recorded so (late_lnd_state CANCELED, unless it was seen settled): canceled is final for it.
      if (invoice.state === 'CANCELED' && b?.state === 'not-created' && a?.state === 'not-created' && error === undefined && a.late !== 'CANCELED' && a.late !== 'SETTLED') {
        this.fail('canceled-final-for-open-accepted', `CANCELED for late invoice ${label(hash)} (via ${source}) left it not-created/${a.late ?? '-'}`, states());
      }
      // A settlement already posted for another amount: LND reported this one settled again for a different amount
      // (a hostile or buggy node). The first settlement recorded wins: nothing about the invoice, its order or the ledger changes.
      const prior = before.entries.find(row => row.hash === hash && (row.event === 'invoice-settled' || row.event === 'underpaid-settlement'));
      if (invoice.state === 'SETTLED' && b !== undefined && prior !== undefined && prior.amount !== invoice.amtPaidMsat) {
        attributed = true;
        const order = b.order;
        const mine = (snap: ReceiverSnap): string => JSON.stringify(this.readable({ entries: snap.entries.filter(row => row.hash === hash),
          invoice: snap.invoices.get(hash), fulfillments: snap.fulfillments.filter(row => row.order === order), order: snap.orders.get(order),
          outbox: snap.outbox.filter(row => row.subject === order) }));
        if (error !== undefined) {
          this.fail('settlement-posted-once', `LND reported ${label(hash)} settled again for ${invoice.amtPaidMsat} msat (via ${source}) and the store refused it: ${String((error as Error).message)}`, states());
        } else if (mine(before) !== mine(after)) {
          this.fail('settlement-posted-once', `LND reported ${label(hash)} settled again for ${invoice.amtPaidMsat} msat (via ${source}) after a settlement of ${prior.amount} msat was posted; `
            + 'the first settlement must win, but the invoice, its order, its entries or its outbox row changed', states());
        }
      } else if (invoice.state === 'SETTLED' && b !== undefined && invoice.amtPaidMsat >= b.amount) {
        attributed = true;
        const entries = after.ledger.filter(row => row.hash === hash);
        if (error !== undefined) {
          this.fail('settlement-posted-once', `LND reported ${label(hash)} settled (via ${source}) and the store refused it: ${String((error as Error).message)}`, states());
        } else if (entries.length !== 1 || entries[0]?.amount !== invoice.amtPaidMsat) {
          this.fail('settlement-posted-once', `after a SETTLED delivery of ${label(hash)} (via ${source}) the ledger holds ${entries.length} entries for it`, states());
        }
        if (error === undefined && b.state === 'canceled' && a?.state !== 'settled') {
          this.fail('settled-outranks-canceled', `SETTLED for canceled invoice ${label(hash)} left it ${a?.state}`, states());
        }
        if (error === undefined && b.state === 'not-created' && b.late === 'CANCELED' && a?.late !== 'SETTLED' && a?.state !== 'settled') {
          this.fail('settled-outranks-canceled', `SETTLED for late invoice ${label(hash)} recorded canceled in LND left it ${a?.state}/${a?.late ?? '-'}`, states());
        }
      }
      if (error === undefined) {
        if (invoice.state === 'SETTLED') this.#settledDelivered.add(hash);
        if (invoice.settleIndex > 0n) {
          if (source === 'subscription') this.#settlesBySubscription.add(invoice.settleIndex);
        }
        if (source === 'subscription') {
          // The settle index moves only contiguously (LABHARNESS-01): SubscribeInvoices sends the add backlog (each invoice
          // in its current state, settled ones with their settle index) before the settle backlog, so moving to the highest
          // index seen would pass settlements not delivered yet. From c it moves to c + 1 when the subscription delivered
          // settlement c + 1, and on over c + 2, ... while the subscription delivered each. From 0 the first settle index the
          // subscription delivers becomes the cursor (LND replays nothing for a cursor of 0, so the lower ones never come;
          // they were settled before the listener started) and it moves on from there. The add index keeps the highest seen.
          const from = this.expectedCursor.settle;
          const start = from === 0n && invoice.settleIndex > 0n ? invoice.settleIndex : from;
          const expected = contiguous(start, this.#settlesBySubscription);
          if (from === 0n && start > 0n) {
            // The settlements below the first one delivered from a zero cursor are left to reconciliation: excused at the end.
            for (const item of this.lnd.invoices.values()) {
              if (item.settleIndex > 0n && item.settleIndex < start && !this.#settledDelivered.has(item.hash)) this.#skippedByCursorSet.add(item.hash);
            }
          }
          const add = max(this.expectedCursor.add, invoice.addIndex);
          if (after.cursor.settle !== expected || after.cursor.add !== add) {
            this.fail('cursor-moves-only-from-subscription', `after applyInvoice via subscription (settle index ${invoice.settleIndex}, add index ${invoice.addIndex}) `
              + `the cursor is settle ${after.cursor.settle} / add ${after.cursor.add}, expected settle ${expected} / add ${add} `
              + `(it was settle ${from}; settlements the subscription delivered: ${sorted(this.#settlesBySubscription)})`, states());
          }
          this.expectedCursor = after.cursor;
        } else {
          this.#checkCursor(after, this.expectedCursor, `applyInvoice via ${source}`, states);
        }
      }
    } else if (method === 'setCursor' && error === undefined) {
      // Settlements an explicit cursor-set moves past before they were delivered are the operator's call: excused at the end.
      for (const item of this.lnd.invoices.values()) {
        if (item.settleIndex > 0n && item.settleIndex <= big(args[0]) && !this.#settledDelivered.has(item.hash)) this.#skippedByCursorSet.add(item.hash);
      }
      this.#checkCursor(after, { settle: big(args[0]), add: big(args[1]) }, 'setCursor', states);
    } else if (error === undefined) {
      this.#checkCursor(after, this.expectedCursor, method, states);
    }

    if (error !== undefined && !attributed) {
      this.fail('no-internal-error', `receiver ${method} threw: ${String((error as Error).message)}`, states());
    }
  }

  #checkCursor(after: ReceiverSnap, expected: { settle: bigint; add: bigint }, what: string, states: () => Record<string, unknown>): void {
    if (after.cursor.settle !== expected.settle || after.cursor.add !== expected.add) {
      this.fail('cursor-moves-only-from-subscription', `after ${what} the cursor is settle ${after.cursor.settle} / add ${after.cursor.add}, `
        + `expected settle ${expected.settle} / add ${expected.add}`, states());
    }
    this.expectedCursor = after.cursor;
  }

  // ------------------------------------------------------------------------------------------
  // At an RPC.

  settleCalled(proc: Proc, hash: string): void {
    const snap = this.receiverSnap();
    const invoice = snap.invoices.get(hash);
    if (invoice === undefined) return;
    const other = snap.fulfillments.find(row => row.order === invoice.order && row.hash !== hash);
    if (other !== undefined) {
      this.fail('superseded-canceled-never-settled', `${proc} called SettleInvoice for ${this.lnd.labelOf(hash)} although order ${invoice.order} `
        + `was fulfilled by ${this.lnd.labelOf(other.hash)}`, this.readable({ after: snap }) as Record<string, unknown>);
    }
  }

  /**
   * The invoices receiver reconcile covers (README: every unresolved invoice, and not-created ones rechecked for 24 hours; or
   * every invoice of one order). A not-created invoice LND was seen to hold OPEN or ACCEPTED stays covered however old; one
   * of unknown late state only while it was created within the last 24 hours (the README's recheck window, computed here from
   * created_at, not taken from the source).
   */
  reconcileTargets(order: string | undefined): Map<string, InvoiceRow> {
    const snap = this.receiverSnap();
    const recheckSince = new Date(Date.now() - LATE_RECHECK_MS).toISOString();
    const targets = new Map<string, InvoiceRow>();
    for (const [hash, row] of snap.invoices) {
      if (order !== undefined) { if (row.order === order) targets.set(hash, row); continue; }
      if (row.state === 'creating' || row.state === 'open' || row.state === 'accepted') targets.set(hash, row);
      if (row.state === 'not-created' && (row.late === 'OPEN' || row.late === 'ACCEPTED' || (row.late === undefined && row.createdAt >= recheckSince))) targets.set(hash, row);
    }
    return targets;
  }

  /**
   * `answers`: per invoice, the lookup answers the reconcile itself received (an invoice state, or not-found), and
   * 'no-answer' for a lookup that ended without one, 'cancel-failed' for a CancelInvoice of the pass that failed.
   * Each target may be in these buckets only: resolved when its record was final as listed, or when the record
   * ends settled, canceled or not-created (not live in LND), or a lookup of the pass answered not-found,
   * CANCELED or SETTLED; open when a lookup of the pass answered OPEN or ACCEPTED (and it was not final as
   * listed); unknown when it was not final as listed and the pass could not decide it (see below). The counts must
   * be an assignment of the targets to buckets they may be in (Hall's condition over the three buckets).
   */
  reconcileDone(targets: Map<string, InvoiceRow>, result: { resolved: number; open: number; unknown: number }, exit: number | undefined,
    answers: Map<string, Set<string>> = new Map(), aborted = false): void {
    const counted = result.resolved + result.open + result.unknown;
    const end = this.receiverSnap();
    const states = (): Record<string, unknown> => this.readable({ targets: [...targets.keys()], result, exit,
      answers: Object.fromEntries([...answers].map(([hash, seen]) => [hash, [...seen]])), after: end }) as Record<string, unknown>;
    if (counted !== targets.size) {
      this.fail('reconcile-buckets-partition', `reconcile counted ${counted} (resolved ${result.resolved}, open ${result.open}, unknown ${result.unknown}) `
        + `for ${targets.size} target invoice(s)`, states());
    } else {
      const allowed = new Map<string, Set<Bucket>>();
      for (const [hash, start] of targets) {
        const may = new Set<Bucket>();
        const seen = answers.get(hash) ?? new Set<string>();
        const row = end.invoices.get(hash);
        if (finalRecord(start)) may.add('resolved');
        else {
          // Unknown only when the pass could not decide (LABHARNESS-06): it was stopped, a lookup of the invoice got no answer
          // ('no-answer'), a cancel of it by the pass failed ('cancel-failed'), or a creating invoice was not found within its
          // creation window (its create call may still reach LND).
          if (aborted || seen.has('no-answer') || seen.has('cancel-failed') || (start.state === 'creating' && seen.has('not-found'))) may.add('unknown');
          if ((row !== undefined && decidedRecord(row)) || [...seen].some(state => state === 'not-found' || state === 'CANCELED' || state === 'SETTLED')) may.add('resolved');
          if ([...seen].some(state => state === 'OPEN' || state === 'ACCEPTED')) may.add('open');
        }
        allowed.set(hash, may);
      }
      const buckets: Bucket[] = ['resolved', 'open', 'unknown'];
      for (let mask = 1; mask < 8; mask += 1) {
        const subset = buckets.filter((_, index) => (mask & (1 << index)) !== 0);
        const need = [...allowed.values()].filter(may => [...may].every(bucket => subset.includes(bucket))).length;
        const have = subset.reduce((sum, bucket) => sum + result[bucket], 0);
        if (need > have) {
          this.fail('reconcile-buckets-partition', `reconcile counted resolved ${result.resolved}, open ${result.open}, unknown ${result.unknown}, but ${need} target(s) `
            + `can only be ${subset.join(' or ')}: ${[...allowed].map(([hash, may]) => `${this.lnd.labelOf(hash)} ${targets.get(hash)?.state}->${end.invoices.get(hash)?.state}`
              + ` [${[...(answers.get(hash) ?? [])].join(',')}] may be ${[...may].join('/')}`).join('; ')}`, states());
          break;
        }
      }
    }
    if (exit !== undefined && exit !== (result.unknown > 0 ? 75 : 0)) {
      this.fail('reconcile-buckets-partition', `receiver reconcile exited ${exit} with unknown ${result.unknown}`, states());
    }
  }

  // ------------------------------------------------------------------------------------------
  // After every step.

  async afterStep(): Promise<void> {
    const payer = this.payerSnap();
    const receiver = this.receiverSnap();
    this.#payerStatic(payer);
    this.#receiverStatic(receiver);
    this.#effectsStatic(payer, receiver);
    await this.#ledgerBalanced(payer, receiver);
  }

  /** Hashes in a message become their labels (op0/i1, o2#1). */
  #labelText(text: string): string {
    return text.replace(/[0-9a-f]{64}/g, hash => this.lnd.labelOf(hash));
  }

  async #ledgerBalanced(payer: PayerSnap, receiver: ReceiverSnap): Promise<void> {
    if (this.verifyLedger === undefined) return;
    for (const book of ['payer', 'receiver'] as const) {
      if (!(book === 'payer' ? this.#payerJournal : this.#receiverJournal)) continue;
      const states = (): Record<string, unknown> => this.readable({ after: book === 'payer' ? payer : receiver }) as Record<string, unknown>;
      let result: LedgerVerification;
      try {
        // LND's lists as a second source, unless a resettle fault made LND report two amounts for one settled invoice.
        const resettled = [...this.lnd.invoices.values()].some(item => item.resettled === true);
        result = await this.verifyLedger({ db: book === 'payer' ? this.#payer() : this.#receiver(), book },
          book === 'receiver' && resettled ? undefined : this.lnd.ledgerSource());
      } catch (error) {
        this.fail('ledger-balanced', `ledger verify of the ${book}'s book threw: ${this.#labelText(String((error as Error).message ?? error))}`, states());
        continue;
      }
      if (!result.balanced) {
        const why = result.unbalancedEntries[0]?.reason ?? result.invalidEntries[0]?.reason ?? result.firstDifference?.reason ?? 'not balanced';
        this.fail('ledger-balanced', `ledger verify of the ${book}'s book: ${this.#labelText(why)}`, states());
      }
    }
  }

  #effectsStatic(payer: PayerSnap, receiver: ReceiverSnap): void {
    const effects = this.effects;
    if (effects === undefined || !this.#payerOutbox || !this.#receiverOutbox) return;
    const problems: string[] = [];
    const label = (text: string): string => this.#labelText(text);
    // Receiver: one fulfill-order row per fulfilled order, its fulfillment's, with the settlement's amount and entry.
    for (const row of receiver.outbox) {
      if (row.kind !== 'fulfill-order' || !receiver.orders.has(row.subject)) problems.push(`receiver row ${label(row.key)} is a ${row.kind} for ${row.subject}`);
    }
    for (const [order] of receiver.orders) {
      const fulfillments = receiver.fulfillments.filter(item => item.order === order);
      const rows = receiver.outbox.filter(item => item.subject === order);
      if (fulfillments.length === 0 && rows.length > 0) problems.push(`order ${order} is not fulfilled but has ${rows.length} fulfill-order row(s)`);
      if (fulfillments.length > 0 && rows.length !== 1) problems.push(`fulfilled order ${order} has ${rows.length} fulfill-order rows`);
      const row = rows[0];
      const hash = fulfillments[0]?.hash;
      if (row === undefined || hash === undefined || rows.length !== 1) continue;
      const entry = receiver.entries.find(item => item.hash === hash && item.event === 'invoice-settled');
      if (row.key !== `${order}:${hash}` || row.payload.paymentHash !== hash || row.payload.amountMsat !== entry?.amount.toString()
        || row.payload.ledgerEntryId !== (entry === undefined ? undefined : Number(entry.id))) {
        problems.push(`order ${order}'s fulfill-order row ${label(row.key)} (amount ${row.payload.amountMsat}, entry ${row.payload.ledgerEntryId}) is not its fulfillment `
          + `${label(hash)}'s (amount ${entry?.amount}, entry ${entry?.id})`);
      }
    }
    // Payer: one confirm-operation row per completed operation, its first succeeded payment's.
    const firstSuccess = new Map<string, EntryRow>();
    for (const entry of payer.entries) if (entry.event === 'payment-succeeded' && !firstSuccess.has(entry.op)) firstSuccess.set(entry.op, entry);
    for (const row of payer.outbox) {
      if (row.kind !== 'confirm-operation' || !payer.operations.has(row.subject)) problems.push(`payer row ${label(row.key)} is a ${row.kind} for ${row.subject}`);
    }
    for (const [op, state] of payer.operations) {
      const rows = payer.outbox.filter(item => item.subject === op);
      if (state !== 'completed' && rows.length > 0) problems.push(`operation ${op} is ${state} but has ${rows.length} confirm-operation row(s)`);
      if (state === 'completed' && rows.length !== 1) problems.push(`completed operation ${op} has ${rows.length} confirm-operation rows`);
      const row = rows[0];
      const entry = firstSuccess.get(op);
      if (row === undefined || rows.length !== 1 || state !== 'completed') continue;
      const payment = entry === undefined ? undefined : payer.payments.get(entry.hash);
      if (entry === undefined || payment === undefined || row.key !== `${op}:${entry.hash}` || row.payload.paymentHash !== entry.hash
        || row.payload.valueMsat !== payment.value?.toString() || row.payload.feeMsat !== payment.fee?.toString() || row.payload.ledgerEntryId !== Number(entry.id)) {
        problems.push(`operation ${op}'s confirm-operation row ${label(row.key)} (value ${row.payload.valueMsat}, fee ${row.payload.feeMsat}, entry ${row.payload.ledgerEntryId}) `
          + `is not its first succeeded payment's (${entry === undefined ? 'none' : `${label(entry.hash)}, value ${payment?.value}, fee ${payment?.fee}, entry ${entry.id}`})`);
      }
    }
    // The files: a done row has its effect; every effect file is a row's, valid and with that row's fields.
    for (const [side, rows] of [['payer', payer.outbox], ['receiver', receiver.outbox]] as const) {
      const subjects = new Set<string>();
      for (const row of rows) {
        subjects.add(row.subject);
        const file = effects.read(side, row.subject);
        if (file.state === 'invalid') problems.push(`the effect file of ${row.subject} is not valid: ${file.reason}`);
        else if (file.state === 'valid' && canonicalFields(file.fields) !== canonicalFields(effects.fields(row))) {
          problems.push(`the effect file of ${row.subject} does not carry row ${label(row.key)}'s fields`);
        } else if (file.state === 'absent' && row.state === 'done') problems.push(`row ${label(row.key)} is done but its effect file is absent`);
      }
      const files = effects.count(side);
      if (files > subjects.size) problems.push(`the ${side} has ${files} effect file(s) for ${subjects.size} outbox subject(s)`);
    }
    for (const [key, count] of this.written) if (count > 1) problems.push(`the effect of ${label(key)} was written ${count} times`);
    if (problems.length > 0) {
      this.fail('effects-once', problems.join('; '), this.readable({ after: { payer: { operations: payer.operations, outbox: payer.outbox },
        receiver: { orders: receiver.orders, fulfillments: receiver.fulfillments, outbox: receiver.outbox } }, written: this.written }) as Record<string, unknown>);
    }
  }

  /** After the last worker pass of a case: every outbox row is done. */
  effectsQuiescent(): void {
    if (this.effects === undefined) return;
    const rows = [...this.payerSnap().outbox, ...this.receiverSnap().outbox].filter(row => row.state !== 'done');
    if (rows.length > 0) {
      this.fail('effects-once', `after the last worker pass ${rows.map(row => `${this.#labelText(row.key)} is ${row.state}`).join(', ')}`,
        this.readable({ rows }) as Record<string, unknown>);
    }
  }

  #payerStatic(snap: PayerSnap): void {
    const states = (): Record<string, unknown> => this.readable({ after: snap }) as Record<string, unknown>;
    const label = (hash: string): string => this.lnd.labelOf(hash);
    const pending = new Map<string, number>();
    for (const row of snap.payments.values()) if (PENDING.has(row.state)) pending.set(row.op, (pending.get(row.op) ?? 0) + 1);
    for (const [op, count] of pending) {
      if (count > 1) this.fail('one-pending-payment-per-operation', `operation ${op} has ${count} pending payments`, states());
    }
    const succeededOf = new Map<string, string[]>();
    for (const [hash, row] of snap.payments) {
      const rows = snap.reservations.filter(item => item.hash === hash);
      const held = rows.filter(item => item.state === 'held').length;
      const consumed = rows.filter(item => item.state === 'consumed');
      // Budgeted: its operation names a budget that exists, or it has reservations (LABHARNESS-03: a store that never
      // reserved left no rows, and the rule was not checked at all).
      const opBudget = snap.opBudgets.get(row.op);
      if (rows.length > 0 || (opBudget !== undefined && snap.budgets.has(opBudget))) {
        const heldRow = rows.find(item => item.state === 'held');
        const fine = PENDING.has(row.state) ? held === 1 && consumed.length === 0 && heldRow?.principal === row.amount && heldRow.allowance === row.feeLimit
          : row.state === 'failed' ? held === 0 && consumed.length === 0
            : held === 0 && consumed.length === 1 && consumed[0]?.actual === row.fee && (row.value === undefined || consumed[0]?.principal === row.value);
        if (!fine) {
          this.fail('reservation-held-iff-live', `${label(hash)} is ${row.state} with ${held} held and ${consumed.length} consumed reservation(s)`
            + (heldRow === undefined ? '' : ` (held ${heldRow.principal} + ${heldRow.allowance} for amount ${row.amount} + fee limit ${row.feeLimit})`)
            + (consumed[0] === undefined ? '' : ` (principal ${consumed[0].principal}, LND value ${row.value}; actual fee ${consumed[0].actual}, recorded fee ${row.fee})`), states());
        }
      }
      const entries = snap.ledger.filter(item => item.hash === hash);
      if (row.state === 'succeeded') {
        succeededOf.set(row.op, [...(succeededOf.get(row.op) ?? []), hash]);
        const principal = entries.filter(item => item.account === 'principal');
        const fee = entries.filter(item => item.account === 'routing-fee');
        if (principal.length !== 1 || fee.length !== 1 || principal[0]?.amount !== row.value || fee[0]?.amount !== row.fee) {
          this.fail('ledger-once-per-succeeded-payment', `succeeded ${label(hash)} has ${principal.length} principal and ${fee.length} fee entries`
            + ` (${principal.map(item => item.amount).join(',')} / ${fee.map(item => item.amount).join(',')}; LND value ${row.value}, fee ${row.fee})`, states());
        }
      } else if (entries.length > 0) {
        this.fail('ledger-once-per-succeeded-payment', `${row.state} ${label(hash)} has ${entries.length} ledger entries`, states());
      }
      const lnd = this.lnd.payments.get(hash);
      if (row.state === 'succeeded' && lnd?.status !== 'SUCCEEDED') {
        this.fail('ledger-once-per-succeeded-payment', `${label(hash)} is recorded succeeded but LND has it ${lnd?.status ?? 'absent'}`, states());
      } else if (row.state === 'succeeded' && lnd !== undefined && (row.value !== lnd.valueMsat || row.fee !== lnd.feeMsat)) {
        // LABHARNESS-04: the record (and so its entries, consumption and confirmation) must carry LND's value and fee, not the invoice's.
        this.fail('ledger-once-per-succeeded-payment', `succeeded ${label(hash)} is recorded at value ${row.value}, fee ${row.fee}; `
          + `LND reports value ${lnd.valueMsat}, fee ${lnd.feeMsat}`, states());
      }
    }
    for (const [op, state] of snap.operations) {
      const paid = (succeededOf.get(op) ?? []).length > 0;
      if (paid !== (state === 'completed')) {
        this.fail('ledger-once-per-succeeded-payment', `operation ${op} is ${state} with ${(succeededOf.get(op) ?? []).length} succeeded payment(s)`, states());
      }
    }
    // Nothing else is posted: per payment hash only the payer's events, and a double-payment entry for every succeeded
    // payment of an operation but the first (the one whose success completed it).
    const firstSuccess = new Map<string, string>();
    for (const entry of snap.entries) if (entry.event === 'payment-succeeded' && !firstSuccess.has(entry.op)) firstSuccess.set(entry.op, entry.hash);
    for (const entry of snap.entries) {
      if (!PAYER_EVENTS.has(entry.event) || !snap.payments.has(entry.hash)) {
        this.fail('ledger-once-per-succeeded-payment', `journal entry ${entry.id} (${entry.event}) for ${label(entry.hash)} is not one the payer posts`, states());
      }
    }
    if (snap.entries.length > 0) {
      for (const [hash, row] of snap.payments) {
        const doubles = snap.entries.filter(entry => entry.hash === hash && entry.event === 'double-payment').length;
        const first = firstSuccess.get(row.op);
        const expected = row.state === 'succeeded' && first !== undefined && first !== hash ? 1 : 0;
        if (doubles !== expected) {
          this.fail('ledger-once-per-succeeded-payment', `${row.state} ${label(hash)} has ${doubles} double-payment entries; expected ${expected} `
            + `(operation ${row.op} was first paid by ${first === undefined ? 'none' : label(first)})`, states());
        }
      }
    }
    for (const [op, hashes] of succeededOf) {
      if (hashes.length < 2) continue;
      for (const hash of hashes) {
        if (!snap.events.get(hash)?.has('double-payment')) {
          this.fail('ledger-once-per-succeeded-payment', `operation ${op} was paid ${hashes.length} times and ${label(hash)} is not flagged double-payment`, states());
        }
      }
    }
    // A budget-overrun event: a success at LND's value took the budget past its limit (the money left; nothing is refused).
    const overrun = new Set<string>();
    for (const [hash, kinds] of snap.events) {
      if (kinds.has('budget-overrun')) for (const row of snap.reservations) if (row.hash === hash) overrun.add(row.budget);
    }
    for (const [budget, limit] of snap.budgets) {
      const { held, consumed } = sums(snap, budget);
      if (held + consumed > limit && !this.overspendAllowed.has(budget) && !overrun.has(budget)) {
        this.fail('budget-admission-within-limit', `budget ${budget}: held ${held} + consumed ${consumed} exceeds the limit ${limit}`, states());
      }
      // The same from the payments themselves (LABHARNESS-03): reservations that were never taken hide nothing.
      const commitment = committed(snap, budget);
      if (commitment > limit && !this.overspendAllowed.has(budget) && !overrun.has(budget)) {
        this.fail('budget-admission-within-limit', `budget ${budget}: its payments commit ${commitment} msat (unresolved at amount + fee limit, `
          + `succeeded at value + fee), more than the limit ${limit}; the reservations hold ${held} and consume ${consumed}`, states());
      }
      if (this.budgetStatus !== undefined) {
        try {
          const status = this.budgetStatus(budget);
          if (status === undefined || status.heldMsat !== held || status.consumedMsat !== consumed || status.availableMsat !== limit - held - consumed) {
            this.fail('budget-admission-within-limit', `budgetStatus(${budget}) reports held ${status?.heldMsat}, consumed ${status?.consumedMsat}, `
              + `available ${status?.availableMsat}; exact sums are ${held}, ${consumed}, ${limit - held - consumed}`, states());
          }
        } catch (error) {
          this.fail('budget-admission-within-limit', `budgetStatus(${budget}) threw: ${String((error as Error).message)}`, states());
        }
      }
    }
  }

  #receiverStatic(snap: ReceiverSnap): void {
    const states = (): Record<string, unknown> => this.readable({ after: snap }) as Record<string, unknown>;
    const label = (hash: string): string => this.lnd.labelOf(hash);
    for (const [hash, row] of snap.invoices) {
      const entries = snap.ledger.filter(item => item.hash === hash);
      const settled = row.state === 'settled' || row.late === 'SETTLED';
      if (entries.length > 1 || (!settled && entries.length > 0)) {
        this.fail('settlement-posted-once', `invoice ${label(hash)} (${row.state}${row.late === undefined ? '' : `/${row.late}`}) has ${entries.length} ledger entries`, states());
      }
      if (row.state === 'settled' && (row.amtPaid ?? 0n) >= row.amount && (entries.length !== 1 || entries[0]?.amount !== row.amtPaid)) {
        this.fail('settlement-posted-once', `settled invoice ${label(hash)} has ${entries.length} ledger entries for ${row.amtPaid} msat paid`, states());
      }
    }
    // Per payment hash only the receiver's events: one settlement (invoice-settled for the full amount or more, or
    // underpaid-settlement for less), and a double-payment entry exactly when an invoice-settled one has no fulfillment.
    for (const entry of snap.entries) {
      if (!RECEIVER_EVENTS.has(entry.event) || !snap.invoices.has(entry.hash)) {
        this.fail('settlement-posted-once', `journal entry ${entry.id} (${entry.event}) for ${label(entry.hash)} is not one the receiver posts`, states());
      }
    }
    for (const [hash, row] of snap.invoices) {
      if (snap.entries.length === 0) break;
      const mine = snap.entries.filter(entry => entry.hash === hash);
      const settled = mine.filter(entry => entry.event === 'invoice-settled');
      const under = mine.filter(entry => entry.event === 'underpaid-settlement');
      const doubles = mine.filter(entry => entry.event === 'double-payment');
      const fulfilled = snap.fulfillments.some(item => item.hash === hash);
      const problems: string[] = [];
      if (settled.length + under.length > 1) problems.push(`${settled.length} invoice-settled and ${under.length} underpaid-settlement entries`);
      if (under[0] !== undefined && under[0].amount >= row.amount) problems.push(`an underpaid-settlement of ${under[0].amount} msat for a ${row.amount} msat invoice`);
      if (settled[0] !== undefined && settled[0].amount < row.amount) problems.push(`an invoice-settled entry of ${settled[0].amount} msat for a ${row.amount} msat invoice`);
      if (under.length > 0 && fulfilled) problems.push('a fulfillment for an underpaid settlement');
      if (fulfilled && settled.length !== 1) problems.push('a fulfillment without its invoice-settled entry');
      if (doubles.length > 1 || (doubles.length === 1) !== (settled.length === 1 && !fulfilled)) {
        problems.push(`${doubles.length} double-payment entries with ${settled.length} invoice-settled entries and ${fulfilled ? 'its' : 'no'} fulfillment`);
      }
      if (problems.length > 0) this.fail('settlement-posted-once', `invoice ${label(hash)} (${row.state}): ${problems.join('; ')}`, states());
    }
    for (const [order, state] of snap.orders) {
      const count = snap.fulfillments.filter(item => item.order === order).length;
      if (count > 1 || (state === 'fulfilled') !== (count === 1)) {
        this.fail('settlement-posted-once', `order ${order} is ${state} with ${count} fulfillment(s)`, states());
      }
    }
  }

  // ------------------------------------------------------------------------------------------
  // At the end of a case, after reconciliation with every call answered.

  /**
   * LABHARNESS-05: every invoice LND holds SETTLED is recorded settled (or, a late invoice, SETTLED in late_lnd_state) with
   * exactly one settlement entry, whatever it was paid. Checked at the end, after the subscription caught up from the
   * cursor (`catchUpSettleIndex`) and reconciliation: a settlement the store was given is required; so is every other one
   * when the catch-up started from a non-zero settle index (LND replays every settlement after it, and the cursor never
   * passes one that was not delivered), except one the cursor passed undelivered: by an explicit cursor-set, or below the
   * first settle index delivered from a zero cursor (those are left to reconciliation). From a zero cursor LND replays
   * nothing, and a canceled record is not looked up again, so a settlement nobody delivered is not required then.
   */
  #settlementsApplied(snap: ReceiverSnap, catchUpSettleIndex: bigint): void {
    const states = (): Record<string, unknown> => this.readable({ after: snap, lnd: [...this.lnd.invoices.values()]
      .map(item => ({ label: item.label, state: item.state, settleIndex: item.settleIndex, amtPaidMsat: item.amtPaidMsat })) }) as Record<string, unknown>;
    for (const item of this.lnd.invoices.values()) {
      const row = snap.invoices.get(item.hash);
      if (item.state !== 'SETTLED' || row === undefined || this.#skippedByCursorSet.has(item.hash)) continue;
      if (catchUpSettleIndex === 0n && !this.#settledDelivered.has(item.hash)) continue;
      const settled = row.state === 'settled' || row.late === 'SETTLED';
      if (row.state === 'canceled') {
        this.fail('settled-outranks-canceled', `at the end of the case LND holds ${item.label} SETTLED (settle index ${item.settleIndex}) and the record is canceled`, states());
      } else if (!settled) {
        this.fail('settlement-posted-once', `at the end of the case LND holds ${item.label} SETTLED (settle index ${item.settleIndex}) and the record is `
          + `${row.state}${row.late === undefined ? '' : `/${row.late}`}`, states());
      }
      if (this.#receiverJournal === true) {
        const settlements = snap.entries.filter(entry => entry.hash === item.hash && (entry.event === 'invoice-settled' || entry.event === 'underpaid-settlement'));
        if (settlements.length !== 1) {
          this.fail('settlement-posted-once', `at the end of the case LND holds ${item.label} SETTLED for ${item.amtPaidMsat} msat and the receiver's journal `
            + `has ${settlements.length} settlement entries for it`, states());
        } else if (item.resettled !== true && settlements[0]?.amount !== item.amtPaidMsat) {
          // The oracle's own comparison with LND, independent of ledger verify's (Improvement 15 of the second external audit).
          this.fail('settlement-posted-once', `at the end of the case LND holds ${item.label} SETTLED for ${item.amtPaidMsat} msat and the receiver posted `
            + `${settlements[0]?.amount} msat`, states());
        }
      }
    }
  }

  quiescent(catchUpSettleIndex = 0n): void {
    const snap = this.receiverSnap();
    this.#settlementsApplied(snap, catchUpSettleIndex);
    for (const [order, state] of snap.orders) {
      // An invoice LND misreported as canceled is left out: the record rightly treats it as canceled.
      const payable = [...snap.invoices].filter(([hash, row]) => row.order === order && this.lnd.invoices.get(hash)?.misreported !== true
        && (this.lnd.invoices.get(hash)?.state === 'OPEN' || this.lnd.invoices.get(hash)?.state === 'ACCEPTED')).map(([hash]) => hash);
      const allowed = state === 'awaiting-payment' ? 1 : 0;
      if (payable.length > allowed) {
        this.fail('superseded-canceled-never-settled', `after reconciliation order ${order} (${state}) has ${payable.length} invoice(s) payable in LND: `
          + payable.map(hash => `${this.lnd.labelOf(hash)} ${this.lnd.invoices.get(hash)?.state}`).join(', '),
        this.readable({ after: snap, lnd: [...this.lnd.invoices.values()].map(item => ({ label: item.label, state: item.state })) }) as Record<string, unknown>);
      }
    }
  }
}

const entryRow = (row: Row): EntryRow => ({ id: big(row.entry_id), event: String(row.event), hash: String(row.payment_hash ?? ''),
  op: String(row.operation_id ?? ''), amount: big(row.amount_msat ?? 0n) });
const outboxRow = (row: Row): OutboxRowSnap => ({ id: big(row.outbox_id), kind: String(row.kind), key: String(row.idempotency_key), subject: String(row.subject),
  payload: JSON.parse(String(row.payload)) as Record<string, string | number | null>, state: String(row.state) });

/** The effect files as the runner reads them with the source's own functions (labKey, effectPath, readEffect, effectFields). */
export interface EffectFiles {
  /** The effect file of a subject: absent, invalid (with why), or valid with its fields. */
  read(side: 'payer' | 'receiver', subject: string): { state: 'absent' } | { state: 'invalid'; reason: string } | { state: 'valid'; fields: Record<string, unknown> };
  /** The fields the effect of a row carries. */
  fields(row: OutboxRowSnap): Record<string, unknown>;
  /** The effect files (final names) in a side's directory. */
  count(side: 'payer' | 'receiver'): number;
}

/** Fields as [name, value] pairs sorted by name, for comparing an effect file with a row. */
const canonicalFields = (fields: Record<string, unknown>): string => JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name] ?? null]));

function max(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

/** From `from`, on over every next index in `delivered` (from + 1, from + 2, ...): the contiguous settle cursor. */
function contiguous(from: bigint, delivered: ReadonlySet<bigint>): bigint {
  let cursor = from;
  while (delivered.has(cursor + 1n)) cursor += 1n;
  return cursor;
}

const sorted = (items: ReadonlySet<bigint>): string => [...items].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).join(',') || 'none';

/**
 * What a budget commits, from the payments themselves (not the reservation rows): amount + fee limit for every
 * unresolved payment of an operation naming the budget (or reserved against it), value + fee for every succeeded one.
 */
export function committed(snap: PayerSnap, budget: string): bigint {
  let total = 0n;
  for (const [hash, row] of snap.payments) {
    const reservedOn = snap.reservations.find(item => item.hash === hash)?.budget;
    if ((reservedOn ?? snap.opBudgets.get(row.op)) !== budget) continue;
    if (PENDING.has(row.state)) total += row.amount + row.feeLimit;
    else if (row.state === 'succeeded') total += (row.value ?? row.amount) + (row.fee ?? 0n);
  }
  return total;
}

/** A budget's held and consumed amounts, summed exactly (bigint), as the README requires of the store. */
export function sums(snap: PayerSnap, budget: string): { held: bigint; consumed: bigint } {
  let held = 0n;
  let consumed = 0n;
  for (const row of snap.reservations) {
    if (row.budget !== budget) continue;
    if (row.state === 'held') held += row.principal + row.allowance;
    if (row.state === 'consumed') consumed += row.principal + (row.actual ?? 0n);
  }
  return { held, consumed };
}

function summarizeArg(arg: unknown): unknown {
  if (arg !== null && typeof arg === 'object' && 'paymentHash' in arg) {
    const item = arg as Record<string, unknown>;
    return { paymentHash: item.paymentHash, state: item.state, status: item.status, settleIndex: item.settleIndex, amtPaidMsat: item.amtPaidMsat,
      htlcs: Array.isArray(item.htlcs) ? item.htlcs.length : undefined };
  }
  if (arg !== null && typeof arg === 'object' && 'operationId' in arg) {
    const item = arg as { operationId: string; invoice: { paymentHash: string; amountMsat: bigint }; feeLimitMsat: bigint; budgetId?: string };
    return { operationId: item.operationId, paymentHash: item.invoice.paymentHash, amountMsat: item.invoice.amountMsat, feeLimitMsat: item.feeLimitMsat,
      budgetId: item.budgetId };
  }
  return arg;
}

export { MAX_INT64 };
