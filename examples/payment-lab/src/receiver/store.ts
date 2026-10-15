import type { DatabaseSync } from 'node:sqlite';
import type { Invoice } from '../lnd/types.ts';
import { entriesFor, legsFor, post, type JournalEntry } from '../ledger/journal.ts';
import { migrateReceiverLedger, upgradeReceiverLedger } from '../ledger/migrate.ts';
import { migrateReceiverOutbox } from '../outbox/migrate.ts';
import { enqueue, fulfillOrder, outboxRows, type OutboxRow } from '../outbox/outbox.ts';
import { invoiceSettled, receiverDoublePayment, underpaidSettlement } from '../ledger/postings.ts';
import { changes, immediate, int, nowIso, openDatabase, optionalInt, optionalText, text, type Migration, type Row } from '../store/sqlite.ts';

/**
 * The receiver's durable records (the merchant's order book, or a customer
 * expecting a refund).
 *
 * - order_id       the business operation
 * - payment_hash   the invoice LND tracks for it
 * - deliveries     every invoice update received, from any source; a repeat that changed nothing is logged once
 * - fulfillments   the business effect, at most once per (payment_hash, order_id)
 * - journal        the double-entry ledger (src/ledger/): an invoice-settled entry at most once per
 *                  payment hash, posted in the transaction that records the settlement
 * - outbox         the fulfillment's effect (src/outbox/): a fulfill-order row enqueued in the same
 *                  transaction as the fulfillments row, performed later by the outbox worker
 *
 * The preimage is generated and stored here before the invoice is created, so
 * the payment hash is known before LND is called and an uncertain creation is
 * resolved by looking the hash up. The preimage is the proof of payment: in
 * production keep this file as protected as a credential.
 */

const MIGRATIONS: Migration[] = [`
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
`,
// 3: the double-entry journal (src/ledger/). ledger_entries' single-leg 'sales' rows become balanced
// entries and the table is dropped; see migrateReceiverLedger for the counter-account.
migrateReceiverLedger,
// 4: the transactional outbox (src/outbox/); a fulfill-order row for every fulfillment already recorded.
migrateReceiverOutbox, `
-- 5: lookup indexes. invoicesForOrder (show, explain, reconcile --order) scanned invoices and sorted them;
-- deliveries (the timeline) scanned every delivery. Both now read in their output order.
CREATE INDEX IF NOT EXISTS invoices_by_order ON invoices (order_id, created_at);
CREATE INDEX IF NOT EXISTS deliveries_by_payment ON deliveries (payment_hash, delivery_id);
`, `
-- 6: an invoice LND settled for less than its order (underpaid-settlement) no longer counts as the order's
-- live invoice: the order still awaits payment, and a replacement invoice may be issued for it.
DROP INDEX IF EXISTS invoices_one_live_per_order;
CREATE UNIQUE INDEX invoices_one_live_per_order ON invoices (order_id) WHERE ${live('invoices')};
-- The settle cursor moves contiguously over the settle indexes the subscription delivered (applyInvoice): one lookup per index.
CREATE INDEX IF NOT EXISTS deliveries_by_settle_index ON deliveries (source, settle_index);
`,
// 7: the journal's 1.3 upgrade (src/ledger/migrate.ts, upgradeReceiverLedger): idempotent, a no-op on a fresh book.
upgradeReceiverLedger];

/**
 * An invoice that is its order's live invoice: one that may still be paid (creating, open,
 * accepted) or that was settled in full. One settled for less than the order (an
 * underpaid-settlement) is not: the order still awaits payment and may get a replacement.
 * A settled record without an amount counts as live. The unique index invoices_one_live_per_order
 * and every query that looks for an order's live invoice use this predicate.
 */
function live(table: string): string {
  return `(${table}.state IN ('creating', 'open', 'accepted') OR (${table}.state = 'settled'
    AND (${table}.amt_paid_msat IS NULL OR ${table}.amt_paid_msat >= ${table}.amount_msat)))`;
}

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
 * `settlement-amount-conflict`: LND reported the invoice settled again for an amount other than
 * the settlement already posted for its payment hash (a hostile or buggy node); the first
 * settlement recorded wins, and nothing but this delivery is recorded.
 */
export type DeliveryOutcome = 'fulfilled' | 'duplicate' | 'state-updated' | 'unchanged' | 'unknown-invoice' | 'underpaid'
  | 'late-invoice' | 'second-payment' | 'settlement-amount-conflict';

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
 * States only move forward; a stale delivery never moves a record back from canceled or settled.
 * Canceled is final for a replayed OPEN or ACCEPTED, but settled outranks it: an invoice LND
 * reports SETTLED after a CANCELED was recorded (a stale or wrong cancel) was paid, and the
 * record says so. Open and accepted rank alike (as in LATE_RANK below): lnd never returns a hold
 * invoice from ACCEPTED to OPEN (a held HTLC that times out cancels the invoice), so an OPEN
 * after an ACCEPTED is a stale or reordered answer; the record still takes the latest answer
 * (an OPEN clears the amount paid), so that LND's word wins whichever order two answers land in,
 * and either way the invoice is to be settled or canceled only on what LND answers next.
 */
const RANK: Record<InvoiceRecordState, number> = { 'not-created': 0, creating: 0, open: 1, accepted: 1, canceled: 3, settled: 4 };
/**
 * The order for LND's state of a late invoice (late_lnd_state), so a stale delivery never moves
 * it back from CANCELED or SETTLED. OPEN and ACCEPTED rank alike: an OPEN after an ACCEPTED is a
 * stale or reordered answer (lnd never reopens an accepted hold invoice), and either way the
 * invoice is live in LND and is to be canceled there.
 */
const LATE_RANK = (expression: string): string =>
  `CASE ${expression} WHEN 'OPEN' THEN 1 WHEN 'ACCEPTED' THEN 1 WHEN 'CANCELED' THEN 3 WHEN 'SETTLED' THEN 4 ELSE 0 END`;
const LND_RANK: Record<string, number> = { OPEN: 1, ACCEPTED: 1, CANCELED: 3, SETTLED: 4 };

export class ReceiverStore {
  readonly db: DatabaseSync;
  /** Which book this is, for verifyLedger (src/ledger/verify.ts). */
  readonly book = 'receiver' as const;

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
    const row = this.db.prepare(`SELECT * FROM invoices WHERE order_id = ? AND ${live('invoices')}`).get(orderId);
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
   * it is superseded and to be canceled; or the record is no longer open or accepted
   * (decided meanwhile by another process or an older answer: canceled, settled, or
   * not-created again, a late invoice to be canceled in LND). Only an invoice LND
   * holds for its order, open or accepted in the record, is settled. Undefined when
   * it may be settled.
   */
  settleRefusal(paymentHash: string): string | undefined {
    return immediate(this.db, () => {
      const record = this.invoice(paymentHash);
      if (record === undefined) return `no invoice ${paymentHash}`;
      const hint = `invoice ${paymentHash} is to be canceled ("receiver reconcile" or "receiver cancel"), not settled`;
      const other = this.db.prepare('SELECT payment_hash FROM fulfillments WHERE order_id = ? AND payment_hash <> ? LIMIT 1')
        .get(record.orderId, paymentHash);
      if (other !== undefined) return `order ${record.orderId} was fulfilled by invoice ${text(other, 'payment_hash')}; ${hint}`;
      if (this.isSuperseded(paymentHash)) return `order ${record.orderId} was fulfilled by another invoice; ${hint}`;
      if (record.state !== 'open' && record.state !== 'accepted') return `invoice ${paymentHash} is ${record.state}, not open or accepted`;
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

  /**
   * The order's sales: one row per invoice-settled entry (the amount LND reports paid), in posting
   * order. This is the 1.2 ledger_entries view, read from the journal.
   */
  ledger(orderId: string): { paymentHash: string; amountMsat: bigint; postedAt: string }[] {
    return legsFor(this.db, orderId, 'invoice-settled')
      .map(item => ({ paymentHash: item.paymentHash, amountMsat: item.amountMsat, postedAt: item.postedAt }));
  }

  /** The order's journal entries with their lines (settlements, double payments, underpaid settlements). */
  journal(orderId: string): JournalEntry[] {
    return entriesFor(this.db, orderId);
  }

  /** The order's outbox rows (its fulfill-order effect, once the order is fulfilled). */
  outbox(orderId?: string): OutboxRow[] {
    return outboxRows(this.db, orderId);
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
            AND other.payment_hash <> invoices.payment_hash AND ${live('other')})
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

  /** The amount of the settlement posted for this payment hash (invoice-settled or underpaid-settlement), if any. */
  #settledMsat(paymentHash: string): bigint | undefined {
    const row = this.db.prepare(`SELECT journal_lines.amount_msat FROM journal_entries
      JOIN journal_lines ON journal_lines.entry_id = journal_entries.entry_id AND journal_lines.line_no = 1
      WHERE journal_entries.reference = ? AND journal_entries.event IN ('invoice-settled', 'underpaid-settlement')
      ORDER BY journal_entries.entry_id LIMIT 1`).get(paymentHash);
    return row === undefined ? undefined : int(row, 'amount_msat');
  }

  /** Whether a not-created record may not become its order's live invoice: another one is live, or the order is decided. */
  #mayNotAdopt(record: InvoiceRecord): boolean {
    return this.db.prepare(`SELECT 1 AS n FROM invoices WHERE order_id = ? AND payment_hash <> ?
      AND ${live('invoices')}`).get(record.orderId, record.paymentHash) !== undefined
      || this.order(record.orderId)?.state !== 'awaiting-payment';
  }

  /**
   * Applies one invoice update in one transaction: the delivery is logged, the
   * invoice state moves forward, and for a settlement the fulfillment and the
   * journal entry are inserted, keyed on (payment_hash, order_id) and on the
   * payment hash, with the fulfill-order outbox row keyed on order_id:payment_hash. A repeat of the same settlement finds both keys present and
   * changes nothing else.
   * A delivery that changed nothing (`unchanged` or `unknown-invoice`) and repeats the latest
   * delivery logged for its hash (same source, LND state, settle index and outcome) is not logged
   * again: reconciliation looks every open invoice up on every pass, and the subscription reports
   * invoices of other receivers, so logging each repeat would grow the table without bound. Every
   * delivery that changed something, and the first of each run of repeats, is logged.
   * Only subscription deliveries move the cursor, because only the
   * subscription delivers settlements in settle-index order; the settle cursor moves only
   * contiguously over the settle indexes it delivered (#advanceSettleCursor).
   */
  applyInvoice(invoice: Invoice, source: DeliverySource): DeliveryOutcome {
    return immediate(this.db, (): DeliveryOutcome => {
      const now = nowIso();
      const outcome = this.#apply(invoice, now);
      const repeat = (outcome === 'unchanged' || outcome === 'unknown-invoice') && this.db.prepare(`SELECT 1 AS n FROM
          (SELECT source, lnd_state, settle_index, outcome FROM deliveries WHERE payment_hash = ? ORDER BY delivery_id DESC LIMIT 1)
        WHERE source = ? AND lnd_state = ? AND settle_index = ? AND outcome = ?`)
        .get(invoice.paymentHash, source, invoice.state, invoice.settleIndex, outcome) !== undefined;
      if (!repeat) {
        this.db.prepare(`INSERT INTO deliveries (payment_hash, source, lnd_state, settle_index, outcome, received_at)
          VALUES (?, ?, ?, ?, ?, ?)`).run(invoice.paymentHash, source, invoice.state, invoice.settleIndex, outcome, now);
      }
      if (source === 'subscription') {
        this.db.prepare(`UPDATE subscription_cursor SET add_index = MAX(add_index, ?), updated_at = ? WHERE name = 'invoices'`)
          .run(invoice.addIndex, now);
        this.#advanceSettleCursor(invoice.settleIndex);
      }
      return outcome;
    });
  }

  /**
   * The settle cursor moves only over settle indexes the subscription has delivered, contiguously: from cursor c it moves to
   * c + 1 when a subscription delivery with settle index c + 1 is logged, then on over c + 2, c + 3, … as long as each has
   * one. SubscribeInvoices sends its add backlog first, each invoice in its current state, so a settled invoice with a high
   * settle index can come before the settle backlog's lower ones; moving to the highest index seen would skip those if the
   * listener stopped in between, and a restart from that cursor would never deliver them. The add cursor keeps the highest
   * add index seen: the add backlog and new invoices come in add-index order, and the settle backlog comes after the add
   * backlog, so no add index below it is still to come. Runs inside applyInvoice's transaction.
   *
   * A cursor of zero is the exception: LND replays no settlement for it, so the indexes below the first one the
   * subscription delivers will never come (they were settled before the listener started, and reconciliation looks
   * those invoices up). The first delivered settle index `settleIndex` therefore becomes the cursor, and it moves on from
   * there as above; otherwise a listener started on a node whose settle index is past 1 would keep a cursor of zero, and
   * every restart would replay nothing.
   */
  #advanceSettleCursor(settleIndex: bigint): void {
    const start = this.cursor().settleIndex;
    const delivered = this.db.prepare(`SELECT 1 AS n FROM deliveries WHERE source = 'subscription' AND settle_index = ? LIMIT 1`);
    let cursor = start === 0n && settleIndex > 0n ? settleIndex : start;
    while (delivered.get(cursor + 1n) !== undefined) cursor += 1n;
    if (cursor !== start) {
      this.db.prepare(`UPDATE subscription_cursor SET settle_index = ? WHERE name = 'invoices'`).run(cursor);
    }
  }

  #apply(invoice: Invoice, now: string): DeliveryOutcome {
    const record = this.invoice(invoice.paymentHash);
    if (record === undefined) return 'unknown-invoice';
    const next = LND_TO_RECORD[invoice.state];
    if (next === undefined) return 'unchanged';
    // SETTLED with nothing paid is not a settlement LND can report: an unreadable answer, which changes nothing.
    if (next === 'settled' && invoice.amtPaidMsat <= 0n) return 'unchanged';
    // One settlement per payment hash, whichever event posted it: invoice-settled and
    // underpaid-settlement have different (event, reference) keys, so posting idempotency alone
    // would let LND reporting a second, different amount post both (and fulfill an underpaid order).
    // The first settlement recorded wins; a differing one changes no record, order or ledger.
    if (next === 'settled') {
      const settledMsat = this.#settledMsat(invoice.paymentHash);
      if (settledMsat !== undefined && settledMsat !== invoice.amtPaidMsat) return 'settlement-amount-conflict';
    }
    let outcome: DeliveryOutcome = 'unchanged';
    // A record marked not-created that LND reports after all moves to LND's state (it is adopted),
    // unless the order has another live invoice by now or no longer awaits payment: the move would
    // break one-live-invoice-per-order (and a cancellation would cancel the order under the live
    // one). The record then stays not-created with LND's state in late_lnd_state: an open one is
    // `late-invoice`, for the caller to cancel in LND, and a settlement is still posted below.
    // Canceled is final: a late invoice LND canceled is never adopted (its order still awaits a
    // payment, and a replacement may be issued), and an update older than LND's last known state
    // of it (a replayed OPEN after CANCELED) changes nothing. OPEN and ACCEPTED rank alike (an
    // OPEN after an ACCEPTED is a stale or reordered answer; lnd never reopens an accepted hold
    // invoice): it is recorded, and the invoice is `late-invoice` again, to be canceled.
    const late = record.lateLndState;
    const behind = record.state === 'not-created' && late !== undefined
      && (late === 'CANCELED' || (LND_RANK[invoice.state] ?? 0) < (LND_RANK[late] ?? 0));
    const blocked = record.state === 'not-created' && (next === 'canceled' || behind || this.#mayNotAdopt(record));
    if (blocked) {
      // A late SETTLED also keeps LND's amount and settle index (SETTLED ranks highest, so it is written once), so that
      // ledger-verify can compare the settlement's entry with the record without LND (audit 1.3.2).
      const settledLate = invoice.state === 'SETTLED';
      const moved = changes(this.db.prepare(`UPDATE invoices SET late_lnd_state = ?, add_index = COALESCE(add_index, ?),
          amt_paid_msat = CASE WHEN ? THEN ? ELSE amt_paid_msat END, settle_index = CASE WHEN ? THEN ? ELSE settle_index END,
          payment_request = COALESCE(payment_request, ?), updated_at = ? WHERE payment_hash = ? AND (${LATE_RANK('?')} > ${LATE_RANK('late_lnd_state')}
            OR (? IN ('OPEN', 'ACCEPTED') AND late_lnd_state IN ('OPEN', 'ACCEPTED') AND late_lnd_state <> ?))`)
        .run(invoice.state, invoice.addIndex, settledLate ? 1 : 0, invoice.amtPaidMsat, settledLate ? 1 : 0,
          invoice.settleIndex === 0n ? null : invoice.settleIndex, invoice.paymentRequest === '' ? null : invoice.paymentRequest, now,
          invoice.paymentHash, invoice.state, invoice.state, invoice.state)) === 1;
      if (next === 'open' || next === 'accepted') return behind ? 'unchanged' : 'late-invoice';
      if (next === 'canceled') return moved ? 'state-updated' : 'unchanged';
    }
    // Forward, or between open and accepted (which rank alike, see RANK) when LND's state differs from the record's.
    let move = !blocked && RANK[next] === RANK[record.state] && next !== record.state;
    if (!blocked && (RANK[next] > RANK[record.state] || (record.state === 'creating' && next === 'open'))) {
      move = true;
    }
    if (move) {
      this.db.prepare(`UPDATE invoices SET state = ?, settle_index = ?, amt_paid_msat = ?, add_index = COALESCE(add_index, ?),
        payment_request = COALESCE(payment_request, ?), updated_at = ? WHERE payment_hash = ?`)
        // An OPEN invoice holds no accepted HTLCs, so nothing is paid (an OPEN answer landing after an ACCEPTED one).
        .run(next, invoice.settleIndex === 0n ? null : invoice.settleIndex, next === 'open' ? 0n : invoice.amtPaidMsat, invoice.addIndex,
          invoice.paymentRequest === '' ? null : invoice.paymentRequest, now, invoice.paymentHash);
      outcome = 'state-updated';
      if (next === 'canceled') {
        this.db.prepare(`UPDATE orders SET state = 'canceled' WHERE order_id = ? AND state = 'awaiting-payment'`).run(record.orderId);
      }
    }
    if (next !== 'settled') return outcome;
    const posting = { orderId: record.orderId, paymentHash: invoice.paymentHash, amtPaidMsat: invoice.amtPaidMsat, postedAt: now };
    // LND reports the invoice settled for less than the order: the money arrived, so it is posted
    // (to suspense, to be returned), and the order is not fulfilled.
    if (invoice.amtPaidMsat < record.amountMsat) {
      post(this.db, underpaidSettlement(posting));
      return 'underpaid';
    }
    // One fulfillment per order. Another invoice of the order that was paid anyway (one that
    // turned up in LND after it was recorded not created, paid before its cancel reached LND)
    // is posted, because the money arrived, and reported; it does not fulfill the order again.
    const fulfilledByOther = this.db.prepare('SELECT 1 AS n FROM fulfillments WHERE order_id = ? AND payment_hash <> ?')
      .get(record.orderId, invoice.paymentHash) !== undefined;
    if (fulfilledByOther) {
      const posted = post(this.db, invoiceSettled(posting)) !== undefined;
      if (posted) post(this.db, receiverDoublePayment(posting));
      return posted ? 'second-payment' : 'duplicate';
    }
    const fulfilled = changes(this.db.prepare(`INSERT INTO fulfillments (payment_hash, order_id, fulfilled_at) VALUES (?, ?, ?)
      ON CONFLICT (payment_hash, order_id) DO NOTHING`).run(invoice.paymentHash, record.orderId, now)) === 1;
    if (!fulfilled) return 'duplicate';
    const entryId = post(this.db, invoiceSettled(posting));
    // The effect is recorded with the fulfillment, in this transaction: no crash can leave one without the other.
    enqueue(this.db, fulfillOrder({ orderId: record.orderId, paymentHash: invoice.paymentHash, amountMsat: invoice.amtPaidMsat,
      settleIndex: invoice.settleIndex, ledgerEntryId: entryId }), now);
    this.db.prepare(`UPDATE orders SET state = 'fulfilled', fulfilled_at = ? WHERE order_id = ?`).run(now, record.orderId);
    return 'fulfilled';
  }
}
