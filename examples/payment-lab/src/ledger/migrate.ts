import type { DatabaseSync } from 'node:sqlite';
import { repairReceiverOutboxAmounts } from '../outbox/migrate.ts';
import { int, nowIso, optionalInt, text } from '../store/sqlite.ts';
import { JOURNAL_SCHEMA, post } from './journal.ts';
import {
  budgetConsumed, budgetHeld, budgetReleased, invoiceSettled, paymentSucceeded, payerDoublePayment, receiverDoublePayment, underpaidSettlement,
  type OperationKind,
} from './postings.ts';

/**
 * The 1.3 ledger migrations. A 1.2 database kept single-leg rows in ledger_entries; each is
 * converted into the balanced entry the 1.3 code would have posted for the same event, with
 * origin `migrated` and the row's original posted_at, and ledger_entries is dropped. The
 * stores' ledger() accessors read the same legs from the journal afterwards. The conversion
 * records the highest entry ID it posted in journal_migration (the watermark `ledger verify`
 * checks every entry's origin against).
 *
 * A database that already has the journal and no ledger_entries (its user_version was set
 * back by hand) has nothing to convert: the step then only makes sure the journal exists, and
 * keeps the watermark it has (or derives it, see recordWatermark).
 *
 * upgradePayerLedger and upgradeReceiverLedger complete a book a 1.3.0 conversion left: they
 * record the watermark and post what that conversion did not (see each). Both are idempotent;
 * on a book converted by this code they change nothing.
 */

function converted(db: DatabaseSync): boolean {
  db.exec(JOURNAL_SCHEMA);
  return db.prepare(`SELECT 1 AS n FROM sqlite_master WHERE type = 'table' AND name = 'ledger_entries'`).get() === undefined;
}

/**
 * The watermark, if the journal has none: the highest migrated entry below the first live one (0
 * when there is none). After a conversion (`conversion`), the highest entry it posted, replacing
 * any row a set-back database still had.
 */
function recordWatermark(db: DatabaseSync, conversion: boolean): void {
  db.prepare(`INSERT INTO journal_migration (singleton, migrated_through, recorded_at)
    SELECT 1, MAX(0, COALESCE((SELECT MAX(entry_id) FROM journal_entries WHERE origin = 'migrated'
      AND entry_id < COALESCE((SELECT MIN(entry_id) FROM journal_entries WHERE origin = 'live'), 9223372036854775807)), 0)), ?
    WHERE true ON CONFLICT (singleton) DO ${conversion ? 'UPDATE SET migrated_through = excluded.migrated_through, recorded_at = excluded.recorded_at' : 'NOTHING'}`)
    .run(nowIso());
}

/**
 * Payer (migration 6): per payment, the `principal` row and the `routing-fee` row become one
 * payment-succeeded entry whose counter-account is the operation kind's (customer-receivable for
 * an order payment, refunds-payable, payouts-payable), against lnd-wallet-outgoing. A second
 * payment posted for the same operation also gets a double-payment entry (into suspense). Every
 * reservation still held gets a budget-held entry, every released one its budget-held and
 * budget-released pair (so its history is in the book, as a live release leaves it), and every
 * consumed one a budget-consumed entry for principal plus actual fee (two line pairs, so a sum
 * above 2^63 - 1 still posts), so each budget account starts at held plus consumed.
 */
export function migratePayerLedger(db: DatabaseSync): void {
  if (converted(db)) {
    recordWatermark(db, false);
    return;
  }
  const legs = new Map<string, { operationId: string; kind: OperationKind; principal?: bigint; fee?: bigint; postedAt: string }>();
  for (const row of db.prepare(`SELECT l.operation_id, l.payment_hash, l.account, l.amount_msat, l.posted_at, o.kind FROM ledger_entries l
      JOIN operations o ON o.operation_id = l.operation_id ORDER BY l.entry_id`).iterate()) {
    const hash = text(row, 'payment_hash');
    const item = legs.get(hash) ?? { operationId: text(row, 'operation_id'), kind: text(row, 'kind') as OperationKind, postedAt: text(row, 'posted_at') };
    if (text(row, 'account') === 'principal') item.principal = int(row, 'amount_msat'); else item.fee = int(row, 'amount_msat');
    legs.set(hash, item);
  }
  const paidOperations = new Set<string>();
  for (const [paymentHash, item] of legs) {
    const valueMsat = item.principal ?? 0n;
    const common = { operationId: item.operationId, kind: item.kind, paymentHash, origin: 'migrated' as const, postedAt: item.postedAt };
    post(db, paymentSucceeded({ ...common, valueMsat, feeMsat: item.fee ?? 0n }));
    if (paidOperations.has(item.operationId)) post(db, payerDoublePayment({ ...common, valueMsat }));
    paidOperations.add(item.operationId);
  }
  for (const row of db.prepare(`SELECT * FROM reservations WHERE state IN ('held', 'consumed', 'released') ORDER BY reservation_id`).iterate()) {
    const ref = { reservationId: int(row, 'reservation_id'), budgetId: text(row, 'budget_id'), operationId: text(row, 'operation_id'),
      paymentHash: text(row, 'payment_hash'), origin: 'migrated' as const, postedAt: text(row, 'updated_at') };
    const hold = int(row, 'principal_msat') + int(row, 'fee_allowance_msat');
    const state = text(row, 'state');
    if (state === 'held') {
      post(db, budgetHeld({ ...ref, amountMsat: hold }));
    } else if (state === 'released') {
      post(db, budgetHeld({ ...ref, amountMsat: hold, postedAt: text(row, 'created_at') }));
      post(db, budgetReleased({ ...ref, amountMsat: hold }));
    } else {
      post(db, budgetConsumed({ ...ref, fromState: 'released', principalMsat: int(row, 'principal_msat'),
        allowanceMsat: int(row, 'fee_allowance_msat'), feeMsat: optionalInt(row, 'actual_fee_msat') ?? 0n }));
    }
  }
  db.exec('DROP TABLE ledger_entries');
  recordWatermark(db, true);
}

/**
 * Payer, after a 1.3.0 conversion (a migration after the outbox's): records the watermark, and
 * posts the budget-held and budget-released pair of every released reservation that lacks it
 * (1.3.0 converted released reservations into nothing). The pair nets to zero; it is posted now,
 * origin live, above the watermark.
 */
export function upgradePayerLedger(db: DatabaseSync): void {
  db.exec(JOURNAL_SCHEMA);
  recordWatermark(db, false);
  for (const row of db.prepare(`SELECT * FROM reservations r WHERE state = 'released' AND (
      NOT EXISTS (SELECT 1 FROM journal_entries e WHERE e.event = 'budget-held' AND e.reference = 'reservation:' || r.reservation_id)
      OR NOT EXISTS (SELECT 1 FROM journal_entries e WHERE e.event = 'budget-released' AND e.reference = 'reservation:' || r.reservation_id))
    ORDER BY reservation_id`).all()) {
    const ref = { reservationId: int(row, 'reservation_id'), budgetId: text(row, 'budget_id'), operationId: text(row, 'operation_id'),
      paymentHash: text(row, 'payment_hash'), amountMsat: int(row, 'principal_msat') + int(row, 'fee_allowance_msat') };
    post(db, budgetHeld(ref));
    post(db, budgetReleased(ref));
  }
}

/**
 * A settlement whose 1.2 `sales` row (what fulfilled the order) differs from the invoice record's
 * amt_paid_msat: 1.2.1 kept an underpaid first SETTLED in the record and fulfilled the order on a
 * later full one. The record takes the fulfilling amount, so the book and the record agree, and
 * the change is logged as a `settlement-amount-conflict` delivery naming both amounts.
 */
function settleAmountConflict(db: DatabaseSync, paymentHash: string, recorded: bigint | undefined, settledMsat: bigint, settleIndex: bigint | undefined): void {
  const now = nowIso();
  db.prepare('UPDATE invoices SET amt_paid_msat = ?, updated_at = ? WHERE payment_hash = ?').run(settledMsat, now, paymentHash);
  db.prepare(`INSERT INTO deliveries (payment_hash, source, lnd_state, settle_index, outcome, received_at)
    VALUES (?, ?, 'SETTLED', ?, 'settlement-amount-conflict', ?)`)
    .run(paymentHash, `migration: record amt_paid_msat ${recorded ?? 'null'} msat, fulfilling settlement ${settledMsat} msat`, settleIndex ?? 0n, now);
}

/**
 * Receiver (migration 3): each `sales` row becomes an invoice-settled entry, lnd-wallet-incoming
 * against customer-receivable. A row for an invoice that did not fulfill its order (a
 * second-payment) also gets a double-payment entry (into suspense). An invoice recorded settled
 * for less than its amount, which 1.2 did not post, gets an underpaid-settlement entry. A settled
 * record whose amt_paid_msat is not its sales row's takes the sales row's (settleAmountConflict).
 */
export function migrateReceiverLedger(db: DatabaseSync): void {
  if (converted(db)) {
    recordWatermark(db, false);
    return;
  }
  for (const row of db.prepare(`SELECT l.order_id, l.payment_hash, l.amount_msat, l.posted_at, i.state, i.amt_paid_msat, i.settle_index,
      EXISTS (SELECT 1 FROM fulfillments f WHERE f.order_id = l.order_id AND f.payment_hash <> l.payment_hash)
        AND NOT EXISTS (SELECT 1 FROM fulfillments f WHERE f.payment_hash = l.payment_hash) AS second
      FROM ledger_entries l LEFT JOIN invoices i ON i.payment_hash = l.payment_hash ORDER BY l.entry_id`).iterate()) {
    const input = { orderId: text(row, 'order_id'), paymentHash: text(row, 'payment_hash'), amtPaidMsat: int(row, 'amount_msat'),
      origin: 'migrated' as const, postedAt: text(row, 'posted_at') };
    post(db, invoiceSettled(input));
    if (int(row, 'second') === 1n) post(db, receiverDoublePayment(input));
    const recorded = optionalInt(row, 'amt_paid_msat');
    if (row.state === 'settled' && recorded !== input.amtPaidMsat) {
      settleAmountConflict(db, input.paymentHash, recorded, input.amtPaidMsat, optionalInt(row, 'settle_index'));
    }
  }
  for (const row of db.prepare(`SELECT order_id, payment_hash, amt_paid_msat, updated_at FROM invoices
      WHERE state = 'settled' AND amt_paid_msat < amount_msat
        AND NOT EXISTS (SELECT 1 FROM ledger_entries l WHERE l.payment_hash = invoices.payment_hash) ORDER BY rowid`).iterate()) {
    post(db, underpaidSettlement({ orderId: text(row, 'order_id'), paymentHash: text(row, 'payment_hash'),
      amtPaidMsat: int(row, 'amt_paid_msat'), origin: 'migrated', postedAt: text(row, 'updated_at') }));
  }
  db.exec('DROP TABLE ledger_entries');
  recordWatermark(db, true);
}

/**
 * Receiver, after a 1.3.0 conversion (a migration after the outbox's): records the watermark; a
 * settled record whose amt_paid_msat is not the amount of its migrated invoice-settled entry takes
 * the entry's (settleAmountConflict), and a fulfill-order row not yet performed carries the
 * entry's amount (1.3.0 enqueued the record's).
 */
export function upgradeReceiverLedger(db: DatabaseSync): void {
  db.exec(JOURNAL_SCHEMA);
  recordWatermark(db, false);
  for (const row of db.prepare(`SELECT i.payment_hash, i.amt_paid_msat, i.settle_index, l.amount_msat AS settled_msat
      FROM journal_entries e JOIN invoices i ON i.payment_hash = e.reference
      JOIN journal_lines l ON l.entry_id = e.entry_id AND l.line_no = 1
      WHERE e.event = 'invoice-settled' AND e.origin = 'migrated' AND i.state = 'settled'
        AND (i.amt_paid_msat IS NULL OR i.amt_paid_msat <> l.amount_msat) ORDER BY e.entry_id`).all()) {
    settleAmountConflict(db, text(row, 'payment_hash'), optionalInt(row, 'amt_paid_msat'), int(row, 'settled_msat'), optionalInt(row, 'settle_index'));
  }
  repairReceiverOutboxAmounts(db);
}
