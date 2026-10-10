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
}

export interface OrderRecord {
  orderId: string;
  amountMsat: bigint;
  state: 'awaiting-payment' | 'fulfilled' | 'canceled';
  fulfilledAt: string | undefined;
}

/** What one delivery did. `fulfilled` happens once per order; every repeat is `duplicate`. */
export type DeliveryOutcome = 'fulfilled' | 'duplicate' | 'state-updated' | 'unchanged' | 'unknown-invoice' | 'underpaid';

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
  };
}

const LND_TO_RECORD: Record<string, InvoiceRecordState | undefined> = {
  OPEN: 'open', ACCEPTED: 'accepted', SETTLED: 'settled', CANCELED: 'canceled',
};

/** States only move forward; a stale delivery never moves a record back. */
const RANK: Record<InvoiceRecordState, number> = { 'not-created': 0, creating: 0, open: 1, accepted: 2, settled: 3, canceled: 3 };

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
    return this.db.prepare('SELECT * FROM invoices WHERE order_id = ? ORDER BY created_at').all(orderId).map(invoiceFrom);
  }

  unresolvedInvoices(): InvoiceRecord[] {
    return this.db.prepare(`SELECT * FROM invoices WHERE state IN ('creating', 'open', 'accepted') ORDER BY created_at`).all().map(invoiceFrom);
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
   * `open`. LND's answer also wins over an earlier `not-created` decision, unless
   * the order has meanwhile got another live invoice: one live invoice per order is
   * a constraint, so the record then keeps `not-created` and the caller reports it.
   * Returns the record's state afterwards.
   */
  markCreated(paymentHash: string, paymentRequest: string, addIndex: bigint): InvoiceRecordState | undefined {
    return immediate(this.db, () => {
      this.db.prepare(`UPDATE invoices SET state = CASE WHEN state = 'creating' THEN 'open'
          WHEN state = 'not-created' AND NOT EXISTS (SELECT 1 FROM invoices other WHERE other.order_id = invoices.order_id
            AND other.payment_hash <> invoices.payment_hash AND other.state IN ('creating', 'open', 'accepted', 'settled')) THEN 'open'
          ELSE state END, payment_request = ?, add_index = ?, updated_at = ? WHERE payment_hash = ?`)
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

  #otherLiveInvoice(record: InvoiceRecord): boolean {
    return this.db.prepare(`SELECT 1 AS n FROM invoices WHERE order_id = ? AND payment_hash <> ?
      AND state IN ('creating', 'open', 'accepted', 'settled')`).get(record.orderId, record.paymentHash) !== undefined;
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
    // A record marked not-created that LND reports after all moves to LND's state, unless the
    // order has another live invoice by now: the move would break one-live-invoice-per-order
    // (and a cancellation would cancel the order under the live one). The record then stays
    // not-created, and a settlement is still posted below: the money for the order arrived.
    const blocked = record.state === 'not-created' && this.#otherLiveInvoice(record);
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
    const fulfilled = changes(this.db.prepare(`INSERT INTO fulfillments (payment_hash, order_id, fulfilled_at) VALUES (?, ?, ?)
      ON CONFLICT (payment_hash, order_id) DO NOTHING`).run(invoice.paymentHash, record.orderId, now)) === 1;
    if (!fulfilled) return 'duplicate';
    this.db.prepare(`INSERT INTO ledger_entries (order_id, payment_hash, account, amount_msat, posted_at) VALUES (?, ?, 'sales', ?, ?)`)
      .run(record.orderId, invoice.paymentHash, invoice.amtPaidMsat, now);
    this.db.prepare(`UPDATE orders SET state = 'fulfilled', fulfilled_at = ? WHERE order_id = ?`).run(now, record.orderId);
    return 'fulfilled';
  }
}
