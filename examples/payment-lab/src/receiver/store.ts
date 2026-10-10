import type { DatabaseSync } from 'node:sqlite';
import type { Invoice } from '../lnd/types.ts';
import { changes, immediate, int, nowIso, openDatabase, optionalInt, optionalText, text, type Row } from '../store/sqlite.ts';

/**
 * The receiver's durable records (the merchant's order book, or a customer
 * expecting a refund).
 *
 * - order_id       the business operation
 * - payment_hash   the invoice LND tracks for it
 * - deliveries     every invoice update received, from any source, repeats included
 * - fulfillments   the business effect, at most once per (payment_hash, order_id)
 * - ledger_entries the accounting entry, at most once per (order_id, payment_hash, account)
 *
 * The preimage is generated and stored here before the invoice is created, so
 * the payment hash is known before LND is called and an uncertain creation is
 * resolved by looking the hash up. The preimage is the proof of payment: in
 * production keep this file as protected as a credential.
 */

const MIGRATIONS = [`
CREATE TABLE orders (
  order_id TEXT PRIMARY KEY CHECK (length(order_id) BETWEEN 1 AND 128),
  amount_msat INTEGER NOT NULL CHECK (amount_msat > 0),
  state TEXT NOT NULL CHECK (state IN ('awaiting-payment', 'fulfilled', 'canceled')),
  created_at TEXT NOT NULL,
  fulfilled_at TEXT
);
CREATE TABLE invoices (
  payment_hash TEXT PRIMARY KEY CHECK (length(payment_hash) = 64),
  order_id TEXT NOT NULL REFERENCES orders (order_id),
  kind TEXT NOT NULL CHECK (kind IN ('standard', 'hold')),
  preimage TEXT NOT NULL CHECK (length(preimage) = 64),
  amount_msat INTEGER NOT NULL CHECK (amount_msat > 0),
  state TEXT NOT NULL CHECK (state IN ('creating', 'open', 'accepted', 'settled', 'canceled', 'not-created')),
  payment_request TEXT,
  add_index INTEGER,
  settle_index INTEGER,
  amt_paid_msat INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX invoices_one_live_per_order ON invoices (order_id) WHERE state IN ('creating', 'open', 'accepted', 'settled');
CREATE TABLE deliveries (
  delivery_id INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_hash TEXT NOT NULL,
  source TEXT NOT NULL,
  lnd_state TEXT NOT NULL,
  settle_index INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  received_at TEXT NOT NULL
);
CREATE TABLE fulfillments (
  payment_hash TEXT NOT NULL REFERENCES invoices (payment_hash),
  order_id TEXT NOT NULL REFERENCES orders (order_id),
  fulfilled_at TEXT NOT NULL,
  PRIMARY KEY (payment_hash, order_id)
);
CREATE TABLE ledger_entries (
  entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL REFERENCES orders (order_id),
  payment_hash TEXT NOT NULL REFERENCES invoices (payment_hash),
  account TEXT NOT NULL CHECK (account IN ('sales')),
  amount_msat INTEGER NOT NULL CHECK (amount_msat > 0),
  posted_at TEXT NOT NULL,
  UNIQUE (order_id, payment_hash, account)
);
CREATE TABLE subscription_cursor (
  name TEXT PRIMARY KEY,
  add_index INTEGER NOT NULL,
  settle_index INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO subscription_cursor (name, add_index, settle_index, updated_at) VALUES ('invoices', 0, 0, '1970-01-01T00:00:00.000Z');
`, `
-- LND's state of an invoice that turned up in LND after it was recorded not-created (its create
-- call reached LND late). The record keeps not-created while the order has another live invoice;
-- this column says what LND holds, so reconciliation can cancel it (resolveLateInvoice in receiver.ts).
ALTER TABLE invoices ADD COLUMN late_lnd_state TEXT;
`];

export type InvoiceRecordState = 'creating' | 'open' | 'accepted' | 'settled' | 'canceled' | 'not-created';
export type DeliverySource = 'subscription' | 'lookup' | 'single-subscription' | 'settle-call' | 'create-call';

export interface InvoiceRecord {
  paymentHash: string;
  orderId: string;
  kind: 'standard' | 'hold';
  preimage: string;
  amountMsat: bigint;
  state: InvoiceRecordState;
  paymentRequest: string | undefined;
  settleIndex: bigint | undefined;
  amtPaidMsat: bigint | undefined;
  /** For a not-created record: LND's state of the invoice if LND created it after all. */
  lateLndState: string | undefined;
}

export interface OrderRecord {
  orderId: string;
  amountMsat: bigint;
  state: 'awaiting-payment' | 'fulfilled' | 'canceled';
  fulfilledAt: string | undefined;
}

/**
 * What one delivery did. `fulfilled` happens once per order; every repeat is `duplicate`.
 * `late-invoice`: LND holds an open invoice recorded not-created that its order may not adopt
 * (the order has another live invoice, or no longer awaits payment); it is to be canceled in LND.
 * `second-payment`: an invoice of an order already fulfilled by another invoice was paid; the
 * money is posted, the order is not fulfilled again, and the payment is to be returned.
 */
export type DeliveryOutcome = 'fulfilled' | 'duplicate' | 'state-updated' | 'unchanged' | 'unknown-invoice' | 'underpaid'
  | 'late-invoice' | 'second-payment';

function invoiceFrom(row: Row): InvoiceRecord {
  return {
    paymentHash: text(row, 'payment_hash'),
    orderId: text(row, 'order_id'),
    kind: text(row, 'kind') as InvoiceRecord['kind'],
    preimage: text(row, 'preimage'),
    amountMsat: int(row, 'amount_msat'),
    state: text(row, 'state') as InvoiceRecordState,
    paymentRequest: optionalText(row, 'payment_request'),
    settleIndex: optionalInt(row, 'settle_index'),
    amtPaidMsat: optionalInt(row, 'amt_paid_msat'),
    lateLndState: optionalText(row, 'late_lnd_state'),
  };
}

const LND_TO_RECORD: Record<string, InvoiceRecordState | undefined> = {
  OPEN: 'open', ACCEPTED: 'accepted', SETTLED: 'settled', CANCELED: 'canceled',
};

/**
 * States only move forward; a stale delivery never moves a record back. Canceled is final for
 * a replayed OPEN or ACCEPTED, but settled outranks it: an invoice LND reports SETTLED after a
 * CANCELED was recorded (a stale or wrong cancel) was paid, and the record says so.
 */
const RANK: Record<InvoiceRecordState, number> = { 'not-created': 0, creating: 0, open: 1, accepted: 2, canceled: 3, settled: 4 };
/**
 * The order for LND's state of a late invoice (late_lnd_state), so a stale delivery never moves
 * it back from CANCELED or SETTLED. OPEN and ACCEPTED rank alike: LND returns a hold invoice
 * from ACCEPTED to OPEN when its accepted HTLCs are canceled or time out, so either can follow
 * the other, and either way the invoice is live in LND and is to be canceled there.
 */
const LATE_RANK = (expression: string): string =>
  `CASE ${expression} WHEN 'OPEN' THEN 1 WHEN 'ACCEPTED' THEN 1 WHEN 'CANCELED' THEN 3 WHEN 'SETTLED' THEN 4 ELSE 0 END`;
const LND_RANK: Record<string, number> = { OPEN: 1, ACCEPTED: 1, CANCELED: 3, SETTLED: 4 };

export class ReceiverStore {
  readonly db: DatabaseSync;

  constructor(path: string) {
    this.db = openDatabase(path, MIGRATIONS);
  }

  close(): void {
    this.db.close();
  }

  order(orderId: string): OrderRecord | undefined {
    const row = this.db.prepare('SELECT * FROM orders WHERE order_id = ?').get(orderId);
    return row === undefined ? undefined : { orderId: text(row, 'order_id'), amountMsat: int(row, 'amount_msat'),
      state: text(row, 'state') as OrderRecord['state'], fulfilledAt: optionalText(row, 'fulfilled_at') };
  }

  invoice(paymentHash: string): InvoiceRecord | undefined {
    const row = this.db.prepare('SELECT * FROM invoices WHERE payment_hash = ?').get(paymentHash);
    return row === undefined ? undefined : invoiceFrom(row);
  }

  liveInvoiceForOrder(orderId: string): InvoiceRecord | undefined {
    const row = this.db.prepare(`SELECT * FROM invoices WHERE order_id = ? AND state IN ('creating', 'open', 'accepted', 'settled')`).get(orderId);
    return row === undefined ? undefined : invoiceFrom(row);
  }

  invoicesForOrder(orderId: string): InvoiceRecord[] {
    return this.db.prepare('SELECT * FROM invoices WHERE order_id = ? ORDER BY created_at, rowid').all(orderId).map(invoiceFrom);
  }

  unresolvedInvoices(): InvoiceRecord[] {
    return this.db.prepare(`SELECT * FROM invoices WHERE state IN ('creating', 'open', 'accepted') ORDER BY created_at, rowid`).all().map(invoiceFrom);
  }

  /**
   * Not-created records that reconciliation looks up again, because LND may hold them
   * after all: those LND was seen to hold open (still to be canceled), and those whose
   * intent was recorded since `recheckSince` that LND has not been seen to hold.
   */
  lateInvoiceCandidates(recheckSince: string): InvoiceRecord[] {
    return this.db.prepare(`SELECT * FROM invoices WHERE state = 'not-created'
      AND (late_lnd_state IN ('OPEN', 'ACCEPTED') OR (late_lnd_state IS NULL AND created_at >= ?)) ORDER BY created_at, rowid`)
      .all(recheckSince).map(invoiceFrom);
  }

  /**
   * Superseded invoices: those of a fulfilled order that did not fulfill it and are still
   * `creating`, `open` or `accepted` in the record, so still payable (or about to be) in LND.
   * This happens when an invoice recorded not-created turns up late and is paid before the
   * order's replacement; the replacement is then canceled in LND (supersede in receiver.ts).
   */
  supersededInvoices(orderId?: string): InvoiceRecord[] {
    return this.db.prepare(`SELECT invoices.* FROM invoices JOIN orders ON orders.order_id = invoices.order_id
      WHERE orders.state = 'fulfilled' AND invoices.state IN ('creating', 'open', 'accepted')
      AND NOT EXISTS (SELECT 1 FROM fulfillments WHERE fulfillments.payment_hash = invoices.payment_hash)
      AND (? IS NULL OR invoices.order_id = ?) ORDER BY invoices.created_at, invoices.rowid`).all(orderId ?? null, orderId ?? null).map(invoiceFrom);
  }

  /** Whether this invoice is superseded (see supersededInvoices). */
  isSuperseded(paymentHash: string): boolean {
    return this.db.prepare(`SELECT 1 AS n FROM invoices JOIN orders ON orders.order_id = invoices.order_id
      WHERE invoices.payment_hash = ? AND orders.state = 'fulfilled' AND invoices.state IN ('creating', 'open', 'accepted')
      AND NOT EXISTS (SELECT 1 FROM fulfillments WHERE fulfillments.payment_hash = invoices.payment_hash)`).get(paymentHash) !== undefined;
  }

  /**
   * Why this invoice may not be settled now, read in one transaction: its order was
   * fulfilled by another invoice (settling would take a second payment for it), so
   * it is superseded and to be canceled. Undefined when it may be settled.
   */
  settleRefusal(paymentHash: string): string | undefined {
    return immediate(this.db, () => {
      const record = this.invoice(paymentHash);
      if (record === undefined) return `no invoice ${paymentHash}`;
      const other = this.db.prepare('SELECT payment_hash FROM fulfillments WHERE order_id = ? AND payment_hash <> ? LIMIT 1')
        .get(record.orderId, paymentHash);
      if (other !== undefined) return `order ${record.orderId} was fulfilled by invoice ${text(other, 'payment_hash')}`;
      if (this.isSuperseded(paymentHash)) return `order ${record.orderId} was fulfilled by another invoice`;
      return undefined;
    });
  }

  deliveries(paymentHash: string): { source: string; lndState: string; settleIndex: bigint; outcome: string; receivedAt: string }[] {
    return this.db.prepare('SELECT * FROM deliveries WHERE payment_hash = ? ORDER BY delivery_id').all(paymentHash)
      .map(row => ({ source: text(row, 'source'), lndState: text(row, 'lnd_state'), settleIndex: int(row, 'settle_index'),
        outcome: text(row, 'outcome'), receivedAt: text(row, 'received_at') }));
  }

  fulfillmentCount(orderId: string): number {
    return Number(int(this.db.prepare('SELECT COUNT(*) AS n FROM fulfillments WHERE order_id = ?').get(orderId) ?? {}, 'n'));
  }

  ledger(orderId: string): { paymentHash: string; amountMsat: bigint; postedAt: string }[] {
    return this.db.prepare('SELECT * FROM ledger_entries WHERE order_id = ? ORDER BY entry_id').all(orderId)
      .map(row => ({ paymentHash: text(row, 'payment_hash'), amountMsat: int(row, 'amount_msat'), postedAt: text(row, 'posted_at') }));
  }

  cursor(): { addIndex: bigint; settleIndex: bigint } {
    const row = this.db.prepare(`SELECT add_index, settle_index FROM subscription_cursor WHERE name = 'invoices'`).get() ?? {};
    return { addIndex: int(row, 'add_index'), settleIndex: int(row, 'settle_index') };
  }

  /** Moves the subscription cursor to an explicit position. The lab uses it to start a listener from an older point. */
  setCursor(settleIndex: bigint, addIndex: bigint): void {
    immediate(this.db, () => {
      this.db.prepare(`UPDATE subscription_cursor SET settle_index = ?, add_index = ?, updated_at = ? WHERE name = 'invoices'`)
        .run(settleIndex, addIndex, nowIso());
    });
  }

  /** Records the order and the invoice identity (hash and preimage) before LND is asked to create the invoice. */
  recordInvoiceIntent(input: { orderId: string; amountMsat: bigint; kind: 'standard' | 'hold'; preimage: string; paymentHash: string }):
    { outcome: 'recorded' } | { outcome: 'refused'; reason: string } {
    return immediate(this.db, () => {
      const order = this.order(input.orderId);
      const now = nowIso();
      if (order === undefined) {
        this.db.prepare(`INSERT INTO orders (order_id, amount_msat, state, created_at) VALUES (?, ?, 'awaiting-payment', ?)`)
          .run(input.orderId, input.amountMsat, now);
      } else if (order.state !== 'awaiting-payment' || order.amountMsat !== input.amountMsat) {
        return { outcome: 'refused' as const, reason: `order ${input.orderId} is ${order.state} for ${order.amountMsat} msat` };
      }
      const live = this.liveInvoiceForOrder(input.orderId);
      if (live !== undefined) {
        return { outcome: 'refused' as const, reason: `order ${input.orderId} already has invoice ${live.paymentHash} in state ${live.state}` };
      }
      this.db.prepare(`INSERT INTO invoices (payment_hash, order_id, kind, preimage, amount_msat, state, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'creating', ?, ?)`).run(input.paymentHash, input.orderId, input.kind, input.preimage, input.amountMsat, now, now);
      return { outcome: 'recorded' as const };
    });
  }

  /**
   * LND has the invoice (its create answer or a lookup says so). `creating` becomes
   * `open`. LND's answer also wins over an earlier `not-created` decision (the
   * invoice is adopted), unless the order has meanwhile got another live invoice or
   * no longer awaits payment: one live invoice per order is a constraint, so the
   * record then keeps `not-created`, LND's OPEN is noted in late_lnd_state, and the
   * caller cancels the invoice in LND (resolveLateInvoice in receiver.ts). Canceled is
   * final: a create answer that arrives after LND was seen to cancel the invoice (state
   * `canceled`, or late_lnd_state CANCELED) reopens nothing.
   * Returns the record's state afterwards.
   */
  markCreated(paymentHash: string, paymentRequest: string, addIndex: bigint): InvoiceRecordState | undefined {
    return immediate(this.db, () => {
      this.db.prepare(`UPDATE invoices SET state = CASE WHEN state = 'creating' THEN 'open'
          WHEN state = 'not-created' AND (late_lnd_state IS NULL OR late_lnd_state IN ('OPEN', 'ACCEPTED')) AND NOT EXISTS (SELECT 1 FROM invoices other WHERE other.order_id = invoices.order_id
            AND other.payment_hash <> invoices.payment_hash AND other.state IN ('creating', 'open', 'accepted', 'settled'))
            AND EXISTS (SELECT 1 FROM orders WHERE orders.order_id = invoices.order_id AND orders.state = 'awaiting-payment') THEN 'open'
          ELSE state END,
          late_lnd_state = CASE WHEN state = 'not-created' AND late_lnd_state IS NULL THEN 'OPEN' ELSE late_lnd_state END,
          payment_request = ?, add_index = ?, updated_at = ? WHERE payment_hash = ?`)
        .run(paymentRequest, addIndex, nowIso(), paymentHash);
      return this.invoice(paymentHash)?.state;
    });
  }

  /**
   * LND has no such invoice and the create call can no longer be in flight. With
   * `createdBefore`, only a record whose intent was written before that time is
   * decided (see CREATION_WINDOW_MS in receiver.ts). Returns whether it was marked.
   */
  markNotCreated(paymentHash: string, createdBefore?: string): boolean {
    return immediate(this.db, () => changes(this.db.prepare(`UPDATE invoices SET state = 'not-created', updated_at = ?
      WHERE payment_hash = ? AND state = 'creating' AND (? IS NULL OR created_at <= ?)`)
      .run(nowIso(), paymentHash, createdBefore ?? null, createdBefore ?? null)) === 1);
  }

  /** Whether a not-created record may not become its order's live invoice: another one is live, or the order is decided. */
  #mayNotAdopt(record: InvoiceRecord): boolean {
    return this.db.prepare(`SELECT 1 AS n FROM invoices WHERE order_id = ? AND payment_hash <> ?
      AND state IN ('creating', 'open', 'accepted', 'settled')`).get(record.orderId, record.paymentHash) !== undefined
      || this.order(record.orderId)?.state !== 'awaiting-payment';
  }

  /**
   * Applies one invoice update in one transaction: the delivery is logged, the
   * invoice state moves forward, and for a settlement the fulfillment and the
   * accounting entry are inserted keyed on (payment_hash, order_id). A repeat
   * of the same settlement finds both keys present and changes nothing else.
   * Only subscription deliveries move the cursor, because only the
   * subscription delivers settlements in settle-index order.
   */
  applyInvoice(invoice: Invoice, source: DeliverySource): DeliveryOutcome {
    return immediate(this.db, (): DeliveryOutcome => {
      const now = nowIso();
      const outcome = this.#apply(invoice, now);
      this.db.prepare(`INSERT INTO deliveries (payment_hash, source, lnd_state, settle_index, outcome, received_at)
        VALUES (?, ?, ?, ?, ?, ?)`).run(invoice.paymentHash, source, invoice.state, invoice.settleIndex, outcome, now);
      if (source === 'subscription') {
        this.db.prepare(`UPDATE subscription_cursor SET settle_index = MAX(settle_index, ?), add_index = MAX(add_index, ?), updated_at = ?
          WHERE name = 'invoices'`).run(invoice.settleIndex, invoice.addIndex, now);
      }
      return outcome;
    });
  }

  #apply(invoice: Invoice, now: string): DeliveryOutcome {
    const record = this.invoice(invoice.paymentHash);
    if (record === undefined) return 'unknown-invoice';
    const next = LND_TO_RECORD[invoice.state];
    if (next === undefined) return 'unchanged';
    let outcome: DeliveryOutcome = 'unchanged';
    // A record marked not-created that LND reports after all moves to LND's state (it is adopted),
    // unless the order has another live invoice by now or no longer awaits payment: the move would
    // break one-live-invoice-per-order (and a cancellation would cancel the order under the live
    // one). The record then stays not-created with LND's state in late_lnd_state: an open one is
    // `late-invoice`, for the caller to cancel in LND, and a settlement is still posted below.
    // Canceled is final: a late invoice LND canceled is never adopted (its order still awaits a
    // payment, and a replacement may be issued), and an update older than LND's last known state
    // of it (a replayed OPEN after CANCELED) changes nothing. OPEN after ACCEPTED is not older:
    // LND reopens a hold invoice whose accepted HTLCs were canceled, so it is recorded and the
    // invoice is `late-invoice` again, to be canceled.
    const late = record.lateLndState;
    const behind = record.state === 'not-created' && late !== undefined
      && (late === 'CANCELED' || (LND_RANK[invoice.state] ?? 0) < (LND_RANK[late] ?? 0));
    const blocked = record.state === 'not-created' && (next === 'canceled' || behind || this.#mayNotAdopt(record));
    if (blocked) {
      const moved = changes(this.db.prepare(`UPDATE invoices SET late_lnd_state = ?, add_index = COALESCE(add_index, ?),
          payment_request = COALESCE(payment_request, ?), updated_at = ? WHERE payment_hash = ? AND (${LATE_RANK('?')} > ${LATE_RANK('late_lnd_state')}
            OR (? IN ('OPEN', 'ACCEPTED') AND late_lnd_state IN ('OPEN', 'ACCEPTED') AND late_lnd_state <> ?))`)
        .run(invoice.state, invoice.addIndex, invoice.paymentRequest === '' ? null : invoice.paymentRequest, now, invoice.paymentHash,
          invoice.state, invoice.state, invoice.state)) === 1;
      if (next === 'open' || next === 'accepted') return behind ? 'unchanged' : 'late-invoice';
      if (next === 'canceled') return moved ? 'state-updated' : 'unchanged';
    }
    if (!blocked && (RANK[next] > RANK[record.state] || (record.state === 'creating' && next === 'open'))) {
      this.db.prepare(`UPDATE invoices SET state = ?, settle_index = ?, amt_paid_msat = ?, add_index = COALESCE(add_index, ?),
        payment_request = COALESCE(payment_request, ?), updated_at = ? WHERE payment_hash = ?`)
        .run(next, invoice.settleIndex === 0n ? null : invoice.settleIndex, invoice.amtPaidMsat, invoice.addIndex,
          invoice.paymentRequest === '' ? null : invoice.paymentRequest, now, invoice.paymentHash);
      outcome = 'state-updated';
      if (next === 'canceled') {
        this.db.prepare(`UPDATE orders SET state = 'canceled' WHERE order_id = ? AND state = 'awaiting-payment'`).run(record.orderId);
      }
    }
    if (next !== 'settled') return outcome;
    if (invoice.amtPaidMsat < record.amountMsat) return 'underpaid';
    // One fulfillment per order. Another invoice of the order that was paid anyway (one that
    // turned up in LND after it was recorded not created, paid before its cancel reached LND)
    // is posted, because the money arrived, and reported; it does not fulfill the order again.
    const fulfilledByOther = this.db.prepare('SELECT 1 AS n FROM fulfillments WHERE order_id = ? AND payment_hash <> ?')
      .get(record.orderId, invoice.paymentHash) !== undefined;
    if (fulfilledByOther) {
      const posted = changes(this.db.prepare(`INSERT INTO ledger_entries (order_id, payment_hash, account, amount_msat, posted_at)
        VALUES (?, ?, 'sales', ?, ?) ON CONFLICT (order_id, payment_hash, account) DO NOTHING`)
        .run(record.orderId, invoice.paymentHash, invoice.amtPaidMsat, now)) === 1;
      return posted ? 'second-payment' : 'duplicate';
    }
    const fulfilled = changes(this.db.prepare(`INSERT INTO fulfillments (payment_hash, order_id, fulfilled_at) VALUES (?, ?, ?)
      ON CONFLICT (payment_hash, order_id) DO NOTHING`).run(invoice.paymentHash, record.orderId, now)) === 1;
    if (!fulfilled) return 'duplicate';
    this.db.prepare(`INSERT INTO ledger_entries (order_id, payment_hash, account, amount_msat, posted_at) VALUES (?, ?, 'sales', ?, ?)`)
      .run(record.orderId, invoice.paymentHash, invoice.amtPaidMsat, now);
    this.db.prepare(`UPDATE orders SET state = 'fulfilled', fulfilled_at = ? WHERE order_id = ?`).run(now, record.orderId);
    return 'fulfilled';
  }
}
