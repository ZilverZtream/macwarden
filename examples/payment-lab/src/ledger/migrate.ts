import type { DatabaseSync } from 'node:sqlite';
import { int, optionalInt, text } from '../store/sqlite.ts';
import { JOURNAL_SCHEMA, post } from './journal.ts';
import {
  budgetConsumed, budgetHeld, invoiceSettled, paymentSucceeded, payerDoublePayment, receiverDoublePayment, underpaidSettlement,
  type OperationKind,
} from './postings.ts';

/**
 * The 1.3 ledger migrations. A 1.2 database kept single-leg rows in ledger_entries; each is
 * converted into the balanced entry the 1.3 code would have posted for the same event, with
 * origin `migrated` and the row's original posted_at, and ledger_entries is dropped. The
 * stores' ledger() accessors read the same legs from the journal afterwards.
 *
 * A database that already has the journal and no ledger_entries (its user_version was set
 * back by hand) has nothing to convert: the step then only makes sure the journal exists.
 */

function converted(db: DatabaseSync): boolean {
  db.exec(JOURNAL_SCHEMA);
  return db.prepare(`SELECT 1 AS n FROM sqlite_master WHERE type = 'table' AND name = 'ledger_entries'`).get() === undefined;
}

/**
 * Payer (migration 6): per payment, the `principal` row and the `routing-fee` row become one
 * payment-succeeded entry whose counter-account is the operation kind's (customer-receivable for
 * an order payment, refunds-payable, payouts-payable), against lnd-wallet-outgoing. A second
 * payment posted for the same operation also gets a double-payment entry (into suspense). Every
 * reservation still held gets a budget-held entry and every consumed one a budget-consumed
 * entry for principal plus actual fee (two line pairs, so a sum above 2^63 - 1 still posts),
 * so each budget account starts at held plus consumed.
 */
export function migratePayerLedger(db: DatabaseSync): void {
  if (converted(db)) return;
  const legs = new Map<string, { operationId: string; kind: OperationKind; principal?: bigint; fee?: bigint; postedAt: string }>();
  for (const row of db.prepare(`SELECT l.operation_id, l.payment_hash, l.account, l.amount_msat, l.posted_at, o.kind FROM ledger_entries l
      JOIN operations o ON o.operation_id = l.operation_id ORDER BY l.entry_id`).all()) {
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
  for (const row of db.prepare(`SELECT * FROM reservations WHERE state IN ('held', 'consumed') ORDER BY reservation_id`).all()) {
    const ref = { reservationId: int(row, 'reservation_id'), budgetId: text(row, 'budget_id'), operationId: text(row, 'operation_id'),
      paymentHash: text(row, 'payment_hash'), origin: 'migrated' as const, postedAt: text(row, 'updated_at') };
    if (text(row, 'state') === 'held') {
      post(db, budgetHeld({ ...ref, amountMsat: int(row, 'principal_msat') + int(row, 'fee_allowance_msat') }));
    } else {
      post(db, budgetConsumed({ ...ref, fromState: 'released', principalMsat: int(row, 'principal_msat'),
        allowanceMsat: int(row, 'fee_allowance_msat'), feeMsat: optionalInt(row, 'actual_fee_msat') ?? 0n }));
    }
  }
  db.exec('DROP TABLE ledger_entries');
}

/**
 * Receiver (migration 3): each `sales` row becomes an invoice-settled entry, lnd-wallet-incoming
 * against customer-receivable. A row for an invoice that did not fulfill its order (a
 * second-payment) also gets a double-payment entry (into suspense). An invoice recorded settled
 * for less than its amount, which 1.2 did not post, gets an underpaid-settlement entry.
 */
export function migrateReceiverLedger(db: DatabaseSync): void {
  if (converted(db)) return;
  for (const row of db.prepare(`SELECT l.order_id, l.payment_hash, l.amount_msat, l.posted_at,
      EXISTS (SELECT 1 FROM fulfillments f WHERE f.order_id = l.order_id AND f.payment_hash <> l.payment_hash)
        AND NOT EXISTS (SELECT 1 FROM fulfillments f WHERE f.payment_hash = l.payment_hash) AS second
      FROM ledger_entries l ORDER BY l.entry_id`).all()) {
    const input = { orderId: text(row, 'order_id'), paymentHash: text(row, 'payment_hash'), amtPaidMsat: int(row, 'amount_msat'),
      origin: 'migrated' as const, postedAt: text(row, 'posted_at') };
    post(db, invoiceSettled(input));
    if (int(row, 'second') === 1n) post(db, receiverDoublePayment(input));
  }
  for (const row of db.prepare(`SELECT order_id, payment_hash, amt_paid_msat, updated_at FROM invoices
      WHERE state = 'settled' AND amt_paid_msat < amount_msat
        AND NOT EXISTS (SELECT 1 FROM ledger_entries l WHERE l.payment_hash = invoices.payment_hash) ORDER BY rowid`).all()) {
    post(db, underpaidSettlement({ orderId: text(row, 'order_id'), paymentHash: text(row, 'payment_hash'),
      amtPaidMsat: int(row, 'amt_paid_msat'), origin: 'migrated', postedAt: text(row, 'updated_at') }));
  }
  db.exec('DROP TABLE ledger_entries');
}
