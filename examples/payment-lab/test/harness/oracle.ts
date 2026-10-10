import { DatabaseSync } from 'node:sqlite';
import type { FakeLnd, Proc } from './lnd.ts';

/**
 * The oracle: the payment lab README's rules (examples/payment-lab/README.md, "Design decisions"),
 * each as one named predicate over the durable records, LND's (simulated) truth and the store calls
 * the workflows made. Records are read through a separate read-only connection, so the oracle never
 * goes through the code under test; only the columns the 1.2.0 schema already had are read (plus
 * late_lnd_state when it exists), so the same predicates judge older sources.
 *
 * Predicates are checked after every store call that writes (transitions, staleness, admission) and
 * after every step (static invariants); a few at the moment of an RPC (SettleInvoice) or at the end of
 * a case (quiescence). The ideas come from the verifiers' probes for 1.2.1:
 * mw5/verify-lab3/p1-fuzz.mts (random store calls tagged with a submission against an oracle: stale calls
 * change nothing, live ones apply, reservations follow the state, the ledger follows success) and
 * mw5/verify-lab4/p5-reconcile-counts.mts (reconcile buckets partition the targets; exit 75 iff unknown > 0).
 */

export const PREDICATES = {
  'one-pending-payment-per-operation':
    'One operation has at most one pending payment (intent, submitting, in_flight or uncertain).',
  'reservation-held-iff-live':
    'A budgeted payment holds exactly one reservation while it is unresolved; failed releases it; succeeded consumes exactly one, at principal plus the actual fee.',
  'ledger-once-per-succeeded-payment':
    'A payment LND reports succeeded is recorded succeeded and posted exactly once (principal = value, routing fee = fee); nothing else is posted; the operation is completed iff a payment succeeded; two succeeded payments of one operation are both flagged double-payment.',
  'stale-submission-changes-nothing':
    'An update or call outcome (other than SUCCEEDED) for a superseded submission changes neither the payment, its operation nor its reservation.',
  'notfound-revert-keeps-live-updates':
    'An update or refusal for the live submission applies (IN_FLIGHT -> in_flight, FAILED or a definite refusal -> failed), also after a NotFound sent the record back to intent.',
  'terminal-states-final':
    'Succeeded is final and a completed operation stays completed; failed changes only by a retry (to intent) or by LND reporting success.',
  'budget-admission-within-limit':
    'Admission follows bigint arithmetic (admitted iff principal + fee allowance <= limit - held - consumed), never throws on large sums, budgetStatus equals the exact sums, and held + consumed stays within the limit unless LND reported success after a recorded failure.',
  'canceled-final-for-open-accepted':
    'A canceled invoice (or a late invoice LND was seen to cancel) is never made live again by a replayed OPEN or ACCEPTED or a delayed create answer.',
  'settled-outranks-canceled':
    'LND reporting SETTLED for an invoice recorded canceled makes the record settled.',
  'settlement-posted-once':
    'Every settlement LND reports is posted exactly once (one ledger entry for the amount paid, however often it is delivered); settled is final; an order has at most one fulfillment, and is fulfilled iff it has one.',
  'cursor-moves-only-from-subscription':
    'The subscription cursor moves only with subscription deliveries (to the highest index seen) or an explicit cursor-set.',
  'reconcile-buckets-partition':
    'receiver reconcile counts every invoice it covers exactly once (resolved + open + unknown = targets), and exits 75 iff unknown > 0, else 0.',
  'superseded-canceled-never-settled':
    'SettleInvoice is never called for an invoice of an order fulfilled by another invoice; after reconciliation every superseded or late invoice is canceled in LND, so no order has two payable invoices.',
  'no-internal-error':
    'Store calls and workflows on a live process never throw (LND is truthful; the only refusal by exception is a FAILED for a payment already succeeded).',
} as const;

export type PredicateName = keyof typeof PREDICATES;

const PENDING = new Set(['intent', 'submitting', 'in_flight', 'uncertain']);
const MAX_INT64 = 2n ** 63n - 1n;

export interface PaymentRow { op: string; state: string; subs: number; amount: bigint; fee: bigint | undefined; value: bigint | undefined }
export interface ReservationRow { id: bigint; budget: string; hash: string; principal: bigint; allowance: bigint; actual: bigint | undefined; state: string }
export interface PayerSnap {
  payments: Map<string, PaymentRow>;
  operations: Map<string, string>;
  reservations: ReservationRow[];
  ledger: { op: string; hash: string; account: string; amount: bigint }[];
  events: Map<string, Set<string>>;
  budgets: Map<string, bigint>;
}
export interface InvoiceRow { order: string; state: string; late: string | undefined; amount: bigint; amtPaid: bigint | undefined }
export interface ReceiverSnap {
  invoices: Map<string, InvoiceRow>;
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
  /** Per payment: the highest submission a retry closed (prepareRetry); the oracle's own model, not the store's column. */
  readonly closed = new Map<string, number>();
  /** The cursor the oracle expects (subscription deliveries and cursor-set only). */
  expectedCursor: { settle: bigint; add: bigint } | undefined;
  /** Budgets on which LND reported success after a recorded failure (the release was undone; the limit may be exceeded). */
  readonly overspendAllowed = new Set<string>();
  /** The budgetStatus of the store under test, read once per step by the runner. */
  budgetStatus: ((budgetId: string) => { heldMsat: bigint; consumedMsat: bigint; availableMsat: bigint } | undefined) | undefined;

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
    const events = new Map<string, Set<string>>();
    for (const row of all('SELECT payment_hash, kind FROM payment_events')) {
      const hash = String(row.payment_hash);
      if (!events.has(hash)) events.set(hash, new Set());
      events.get(hash)?.add(String(row.kind));
    }
    return {
      payments: new Map(all('SELECT payment_hash, operation_id, state, submissions, amount_msat, fee_msat, value_msat FROM payments ORDER BY rowid').map(row => [
        String(row.payment_hash), { op: String(row.operation_id), state: String(row.state), subs: Number(row.submissions), amount: big(row.amount_msat),
          fee: opt(row.fee_msat), value: opt(row.value_msat) }])),
      operations: new Map(all('SELECT operation_id, state FROM operations').map(row => [String(row.operation_id), String(row.state)])),
      reservations: all('SELECT reservation_id, budget_id, payment_hash, principal_msat, fee_allowance_msat, actual_fee_msat, state FROM reservations ORDER BY reservation_id')
        .map(row => ({ id: big(row.reservation_id), budget: String(row.budget_id), hash: String(row.payment_hash), principal: big(row.principal_msat),
          allowance: big(row.fee_allowance_msat), actual: opt(row.actual_fee_msat), state: String(row.state) })),
      ledger: all(this.#payerJournal ? PAYER_JOURNAL_LEGS : 'SELECT operation_id, payment_hash, account, amount_msat FROM ledger_entries ORDER BY entry_id')
        .map(row => ({ op: String(row.operation_id), hash: String(row.payment_hash), account: String(row.account), amount: big(row.amount_msat) })),
      events,
      budgets: new Map(all('SELECT budget_id, limit_msat FROM budgets').map(row => [String(row.budget_id), big(row.limit_msat)])),
    };
  }

  receiverSnap(): ReceiverSnap {
    const db = this.#receiver();
    const all = (sql: string): Row[] => db.prepare(sql).all() as Row[];
    this.#lateColumn ??= all('PRAGMA table_info(invoices)').some(row => row.name === 'late_lnd_state');
    this.#receiverJournal ??= hasTable(db, 'journal_lines');
    const late = this.#lateColumn ? ', late_lnd_state' : '';
    const cursor = all(`SELECT settle_index, add_index FROM subscription_cursor WHERE name = 'invoices'`)[0] ?? {};
    return {
      invoices: new Map(all(`SELECT payment_hash, order_id, state, amount_msat, amt_paid_msat${late} FROM invoices ORDER BY rowid`).map(row => [
        String(row.payment_hash), { order: String(row.order_id), state: String(row.state),
          late: row.late_lnd_state === null || row.late_lnd_state === undefined ? undefined : String(row.late_lnd_state),
          amount: big(row.amount_msat), amtPaid: opt(row.amt_paid_msat) }])),
      orders: new Map(all('SELECT order_id, state FROM orders').map(row => [String(row.order_id), String(row.state)])),
      fulfillments: all('SELECT payment_hash, order_id FROM fulfillments').map(row => ({ hash: String(row.payment_hash), order: String(row.order_id) })),
      ledger: all(this.#receiverJournal ? RECEIVER_JOURNAL_LEGS : 'SELECT payment_hash, order_id, amount_msat FROM ledger_entries ORDER BY entry_id')
        .map(row => ({ hash: String(row.payment_hash), order: String(row.order_id), amount: big(row.amount_msat) })),
      cursor: { settle: big(cursor.settle_index ?? 0n), add: big(cursor.add_index ?? 0n) },
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
        if (!stale && submission === b.subs && PENDING.has(b.state) && error === undefined) {
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
        }
      }
      // The lab refuses a FAILED for a payment already recorded succeeded by throwing; LND sent it before the success.
      if (status === 'FAILED' && b?.state === 'succeeded' && error !== undefined) attributed = true;
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
          return result?.requestedMsat === undefined ? undefined : { budget: 'B', requested: result.requestedMsat };
        };
        const admission = budgetOf();
        if (admission !== undefined && before.budgets.has(admission.budget)) {
          const available = (before.budgets.get(admission.budget) ?? 0n) - sums(before, admission.budget).held - sums(before, admission.budget).consumed;
          const reserved = after.reservations.length > before.reservations.length;
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
      if (invoice.state === 'SETTLED' && b !== undefined && invoice.amtPaidMsat >= b.amount) {
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
        const expected = source === 'subscription'
          ? { settle: max(this.expectedCursor.settle, invoice.settleIndex), add: max(this.expectedCursor.add, invoice.addIndex) }
          : this.expectedCursor;
        this.#checkCursor(after, expected, `applyInvoice via ${source}`, states);
      }
    } else if (method === 'setCursor' && error === undefined) {
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

  /** The invoices receiver reconcile covers (README: every unresolved invoice, and not-created ones rechecked for 24 hours; or every invoice of one order). */
  reconcileTargets(order: string | undefined): Set<string> {
    const snap = this.receiverSnap();
    const targets = new Set<string>();
    for (const [hash, row] of snap.invoices) {
      if (order !== undefined) { if (row.order === order) targets.add(hash); continue; }
      if (row.state === 'creating' || row.state === 'open' || row.state === 'accepted') targets.add(hash);
      if (row.state === 'not-created' && row.late !== 'CANCELED' && row.late !== 'SETTLED') targets.add(hash);
    }
    return targets;
  }

  reconcileDone(targets: Set<string>, result: { resolved: number; open: number; unknown: number }, exit: number | undefined): void {
    const counted = result.resolved + result.open + result.unknown;
    const states = (): Record<string, unknown> => this.readable({ targets: [...targets], result, exit, after: this.receiverSnap() }) as Record<string, unknown>;
    if (counted !== targets.size) {
      this.fail('reconcile-buckets-partition', `reconcile counted ${counted} (resolved ${result.resolved}, open ${result.open}, unknown ${result.unknown}) `
        + `for ${targets.size} target invoice(s)`, states());
    }
    if (exit !== undefined && exit !== (result.unknown > 0 ? 75 : 0)) {
      this.fail('reconcile-buckets-partition', `receiver reconcile exited ${exit} with unknown ${result.unknown}`, states());
    }
  }

  // ------------------------------------------------------------------------------------------
  // After every step.

  afterStep(): void {
    this.#payerStatic(this.payerSnap());
    this.#receiverStatic(this.receiverSnap());
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
      if (rows.length > 0) {
        const fine = PENDING.has(row.state) ? held === 1 && consumed.length === 0
          : row.state === 'failed' ? held === 0 && consumed.length === 0
            : held === 0 && consumed.length === 1 && consumed[0]?.actual === row.fee;
        if (!fine) {
          this.fail('reservation-held-iff-live', `${label(hash)} is ${row.state} with ${held} held and ${consumed.length} consumed reservation(s)`
            + (consumed[0] === undefined ? '' : ` (actual fee ${consumed[0].actual}, recorded fee ${row.fee})`), states());
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
      }
    }
    for (const [op, state] of snap.operations) {
      const paid = (succeededOf.get(op) ?? []).length > 0;
      if (paid !== (state === 'completed')) {
        this.fail('ledger-once-per-succeeded-payment', `operation ${op} is ${state} with ${(succeededOf.get(op) ?? []).length} succeeded payment(s)`, states());
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
    for (const [budget, limit] of snap.budgets) {
      const { held, consumed } = sums(snap, budget);
      if (held + consumed > limit && !this.overspendAllowed.has(budget)) {
        this.fail('budget-admission-within-limit', `budget ${budget}: held ${held} + consumed ${consumed} exceeds the limit ${limit}`, states());
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
    for (const [order, state] of snap.orders) {
      const count = snap.fulfillments.filter(item => item.order === order).length;
      if (count > 1 || (state === 'fulfilled') !== (count === 1)) {
        this.fail('settlement-posted-once', `order ${order} is ${state} with ${count} fulfillment(s)`, states());
      }
    }
  }

  // ------------------------------------------------------------------------------------------
  // At the end of a case, after reconciliation with every call answered.

  quiescent(): void {
    const snap = this.receiverSnap();
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

function max(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
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
