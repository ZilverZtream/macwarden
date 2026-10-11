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

/** An entry ID as a payload number: undefined when there is none or a number can not hold it exactly (the worker then refuses the row). */
function payloadEntryId(entryId: bigint | undefined): number | undefined {
  return entryId === undefined || entryId > BigInt(Number.MAX_SAFE_INTEGER) || entryId < -BigInt(Number.MAX_SAFE_INTEGER) ? undefined : Number(entryId);
}

/**
 * Receiver: one fulfill-order row per fulfillments row, with the invoice-settled entry it posted and
 * that entry's amount (its line 1, what the order was fulfilled for; the record's amt_paid_msat only
 * when there is no entry).
 */
export function migrateReceiverOutbox(db: DatabaseSync): void {
  db.exec(OUTBOX_SCHEMA);
  const now = nowIso();
  const rows = db.prepare(`SELECT f.order_id, f.payment_hash, i.settle_index, e.entry_id,
      COALESCE((SELECT l.amount_msat FROM journal_lines l WHERE l.entry_id = e.entry_id AND l.line_no = 1), i.amt_paid_msat, i.amount_msat) AS amount_msat
    FROM fulfillments f JOIN invoices i ON i.payment_hash = f.payment_hash
    LEFT JOIN journal_entries e ON e.event = 'invoice-settled' AND e.reference = f.payment_hash
    ORDER BY f.fulfilled_at, f.rowid`).iterate();
  for (const row of rows) {
    enqueue(db, fulfillOrder({ orderId: text(row, 'order_id'), paymentHash: text(row, 'payment_hash'), amountMsat: int(row, 'amount_msat'),
      settleIndex: optionalInt(row, 'settle_index') ?? 0n, ledgerEntryId: payloadEntryId(optionalInt(row, 'entry_id')) }), now);
  }
}

/**
 * Receiver, after a 1.3.0 migration 4 (which took the record's amt_paid_msat): a fulfill-order
 * row not yet performed whose amountMsat is not its ledger entry's line 1 takes the entry's: a
 * pending row, or one a worker left leased and whose lease has run out by `now` (the worker died
 * holding it; the next claim takes it as it is, see claim). A row with a running lease or done is
 * left alone (a worker may be writing it, or its receipt exists). The worker also refuses to
 * publish a row whose amount is not its entry's (checkLedgerEntry), so a row this misses fails
 * by name instead of writing the old amount.
 */
export function repairReceiverOutboxAmounts(db: DatabaseSync, now: string = nowIso()): void {
  db.exec(OUTBOX_SCHEMA);
  db.prepare(`UPDATE outbox SET payload = json_set(payload, '$.amountMsat', (SELECT CAST(l.amount_msat AS TEXT) FROM journal_lines l
      WHERE l.entry_id = json_extract(outbox.payload, '$.ledgerEntryId') AND l.line_no = 1))
    WHERE kind = 'fulfill-order' AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= ?))
      AND EXISTS (SELECT 1 FROM journal_entries e JOIN journal_lines l ON l.entry_id = e.entry_id AND l.line_no = 1
      WHERE e.entry_id = json_extract(outbox.payload, '$.ledgerEntryId') AND e.event = 'invoice-settled'
        AND e.reference = json_extract(outbox.payload, '$.paymentHash') AND CAST(l.amount_msat AS TEXT) IS NOT json_extract(outbox.payload, '$.amountMsat'))`)
    .run(now);
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
    ORDER BY o.operation_id, entry_id IS NULL, entry_id, p.rowid`).iterate();
  const seen = new Set<string>();
  for (const row of rows) {
    const operationId = text(row, 'operation_id');
    if (seen.has(operationId)) continue;
    seen.add(operationId);
    enqueue(db, confirmOperation({ operationId, operationKind: text(row, 'kind'), paymentHash: text(row, 'payment_hash'),
      valueMsat: optionalInt(row, 'value_msat') ?? int(row, 'amount_msat'), feeMsat: optionalInt(row, 'fee_msat') ?? 0n,
      ledgerEntryId: payloadEntryId(optionalInt(row, 'entry_id')) }), now);
  }
}
