import type { DatabaseSync } from 'node:sqlite';
import { int, nowIso, optionalInt, text } from '../store/sqlite.ts';
import { OUTBOX_SCHEMA, confirmOperation, enqueue, fulfillOrder } from './outbox.ts';

/**
 * The outbox migrations (receiver 4, payer 7). They create the table and enqueue a pending row for
 * every effect an earlier database recorded without one, so no fulfilled order or completed
 * operation is left without its receipt or confirmation: the worker writes those once, like any
 * other row. Both run inside openDatabase's migration transaction, and are idempotent (the
 * idempotency key is unique).
 */

/** Receiver: one fulfill-order row per fulfillments row, with the invoice-settled entry it posted. */
export function migrateReceiverOutbox(db: DatabaseSync): void {
  db.exec(OUTBOX_SCHEMA);
  const now = nowIso();
  const rows = db.prepare(`SELECT f.order_id, f.payment_hash, COALESCE(i.amt_paid_msat, i.amount_msat) AS amount_msat, i.settle_index,
      (SELECT e.entry_id FROM journal_entries e WHERE e.event = 'invoice-settled' AND e.reference = f.payment_hash) AS entry_id
    FROM fulfillments f JOIN invoices i ON i.payment_hash = f.payment_hash ORDER BY f.fulfilled_at, f.rowid`).all();
  for (const row of rows) {
    const entryId = optionalInt(row, 'entry_id');
    enqueue(db, fulfillOrder({ orderId: text(row, 'order_id'), paymentHash: text(row, 'payment_hash'), amountMsat: int(row, 'amount_msat'),
      settleIndex: optionalInt(row, 'settle_index') ?? 0n, ledgerEntryId: entryId === undefined ? undefined : Number(entryId) }), now);
  }
}

/**
 * Payer: one confirm-operation row per completed operation, for the payment that completed it: the
 * succeeded payment whose payment-succeeded entry came first and that is not a double payment.
 */
export function migratePayerOutbox(db: DatabaseSync): void {
  db.exec(OUTBOX_SCHEMA);
  const now = nowIso();
  const rows = db.prepare(`SELECT o.operation_id, o.kind, p.payment_hash, p.value_msat, p.fee_msat, p.amount_msat,
      (SELECT e.entry_id FROM journal_entries e WHERE e.event = 'payment-succeeded' AND e.reference = p.payment_hash) AS entry_id
    FROM operations o JOIN payments p ON p.operation_id = o.operation_id AND p.state = 'succeeded'
    WHERE o.state = 'completed'
      AND NOT EXISTS (SELECT 1 FROM journal_entries d WHERE d.event = 'double-payment' AND d.reference = p.payment_hash)
    ORDER BY o.operation_id, entry_id IS NULL, entry_id, p.rowid`).all();
  const seen = new Set<string>();
  for (const row of rows) {
    const operationId = text(row, 'operation_id');
    if (seen.has(operationId)) continue;
    seen.add(operationId);
    const entryId = optionalInt(row, 'entry_id');
    enqueue(db, confirmOperation({ operationId, operationKind: text(row, 'kind'), paymentHash: text(row, 'payment_hash'),
      valueMsat: optionalInt(row, 'value_msat') ?? int(row, 'amount_msat'), feeMsat: optionalInt(row, 'fee_msat') ?? 0n,
      ledgerEntryId: entryId === undefined ? undefined : Number(entryId) }), now);
  }
}
