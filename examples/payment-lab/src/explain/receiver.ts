import type { ReceiverStore } from '../receiver/store.ts';
import { int, optionalInt, optionalText, text, type Row } from '../store/sqlite.ts';
import { fingerprint } from './format.ts';
import { decisions, journalLine, journalView, outboxItems, outboxView, Timeline, type Explanation } from './model.ts';
import type { RuleId } from './rules.ts';

/**
 * `receiver explain`: one order's story from the receiver's records. The order, each invoice's
 * identity recorded before LND created it, every delivery of an invoice update with what it did,
 * late and superseded invoices, the fulfillment, the journal and the outbox, each decision with the
 * README rule that made it. Nothing here writes; the invoice's preimage and payment request columns
 * are never read: an invoice appears as its hash's fingerprint and its amount.
 */

interface InvoiceRow {
  paymentHash: string; kind: string; amountMsat: bigint; state: string; settleIndex: bigint | undefined; amtPaidMsat: bigint | undefined;
  lateLndState: string | undefined; createdAt: string; updatedAt: string;
}

function invoices(store: ReceiverStore, orderId: string): InvoiceRow[] {
  return store.db.prepare(`SELECT payment_hash, kind, amount_msat, state, settle_index, amt_paid_msat, late_lnd_state, created_at, updated_at
      FROM invoices WHERE order_id = ? ORDER BY created_at, rowid`).all(orderId)
    .map((row: Row) => ({ paymentHash: text(row, 'payment_hash'), kind: text(row, 'kind'), amountMsat: int(row, 'amount_msat'),
      state: text(row, 'state'), settleIndex: optionalInt(row, 'settle_index'), amtPaidMsat: optionalInt(row, 'amt_paid_msat'),
      lateLndState: optionalText(row, 'late_lnd_state'), createdAt: text(row, 'created_at'), updatedAt: text(row, 'updated_at') }));
}

function fulfillments(store: ReceiverStore, orderId: string): { paymentHash: string; fulfilledAt: string }[] {
  return store.db.prepare('SELECT payment_hash, fulfilled_at FROM fulfillments WHERE order_id = ? ORDER BY fulfilled_at, rowid').all(orderId)
    .map((row: Row) => ({ paymentHash: text(row, 'payment_hash'), fulfilledAt: text(row, 'fulfilled_at') }));
}

const OUTCOME_TEXT: Record<string, string> = {
  fulfilled: 'the first settlement of the order: fulfillment, invoice-settled entry and outbox row inserted in one transaction',
  duplicate: 'already recorded: the insert keyed on (payment hash, order) changed nothing; logged only',
  'second-payment': 'another invoice of the order already fulfilled it: the money is posted and to be returned; not fulfilled again',
  'late-invoice': 'LND holds an invoice recorded not-created that the order may not adopt: to be canceled in LND',
  underpaid: 'settled for less than the order: posted to suspense, to be returned; the order is not fulfilled',
  'settlement-amount-conflict': 'a settlement of another amount than the one already posted for the hash: the first one stands; logged only',
  'unknown-invoice': 'no invoice with this hash in the records',
};

/** The rule a delivery's outcome follows; `canceledBefore`: an earlier delivery of the invoice was CANCELED. */
function deliveryRule(outcome: string, lndState: string, invoice: InvoiceRow, canceledBefore: boolean): RuleId | undefined {
  if (lndState === 'SETTLED' && canceledBefore && (outcome === 'fulfilled' || outcome === 'state-updated' || outcome === 'second-payment')) {
    return 'settledOutranks';
  }
  switch (outcome) {
    case 'fulfilled':
    case 'duplicate':
    case 'settlement-amount-conflict':
      return 'idempotency';
    case 'second-payment':
    case 'late-invoice':
      return 'lateInvoice';
    case 'underpaid':
      return 'ledger';
    case 'unchanged':
      return (lndState === 'OPEN' || lndState === 'ACCEPTED') && (canceledBefore || invoice.state === 'canceled' || invoice.lateLndState === 'CANCELED')
        ? 'canceledFinal' : undefined;
    case 'state-updated':
      return invoice.state === 'not-created' ? 'lateInvoice' : undefined;
    default:
      return undefined;
  }
}

/** The order the subject names, or undefined when the records have no such order or invoice. */
export function resolveReceiverSubject(store: ReceiverStore, subject: { orderId?: string; paymentHash?: string }): string | undefined {
  if (subject.paymentHash !== undefined) return store.invoice(subject.paymentHash.toLowerCase())?.orderId;
  return subject.orderId !== undefined && store.order(subject.orderId) !== undefined ? subject.orderId : undefined;
}

export function explainReceiver(store: ReceiverStore, orderId: string): Explanation {
  const row = store.db.prepare('SELECT amount_msat, state, created_at, fulfilled_at FROM orders WHERE order_id = ?').get(orderId);
  if (row === undefined) throw new Error(`no order ${orderId}`);
  const order = { orderId, amountMsat: int(row, 'amount_msat').toString(), state: text(row, 'state'), createdAt: text(row, 'created_at'),
    fulfilledAt: optionalText(row, 'fulfilled_at') ?? null };
  const list = invoices(store, orderId);
  const known = new Set(list.map(item => item.paymentHash.toLowerCase()));
  const timeline = new Timeline(known);
  timeline.add(order.createdAt, 'order', `order ${orderId} for ${order.amountMsat} msat recorded`);
  const superseded = new Set(list.filter(item => store.isSuperseded(item.paymentHash)).map(item => item.paymentHash));
  for (const invoice of list) {
    const fp = fingerprint(invoice.paymentHash);
    timeline.add(invoice.createdAt, 'invoice-intent', `${fp} ${invoice.kind} invoice for ${invoice.amountMsat} msat: preimage and hash recorded `
      + `before ${invoice.kind === 'hold' ? 'AddHoldInvoice' : 'AddInvoice'} was called`, 'durableIntent');
    let canceledBefore = false;
    for (const delivery of store.deliveries(invoice.paymentHash)) {
      const rule = deliveryRule(delivery.outcome, delivery.lndState, invoice, canceledBefore);
      const meaning = rule === 'settledOutranks' ? 'SETTLED after CANCELED: the invoice was paid, and the record says so'
        : rule === 'canceledFinal' ? 'a replayed update after CANCELED: canceled is final, nothing changed' : OUTCOME_TEXT[delivery.outcome];
      timeline.add(delivery.receivedAt, 'delivery', `${fp} via ${delivery.source}: LND ${delivery.lndState} (settle index ${delivery.settleIndex}) `
        + `-> ${delivery.outcome}${meaning === undefined ? '' : `; ${meaning}`}`, rule ?? (delivery.source === 'lookup' ? 'lookups' : undefined));
      if (delivery.lndState === 'CANCELED') canceledBefore = true;
    }
    if (invoice.state === 'not-created') {
      timeline.add(invoice.updatedAt, 'not-created', `${fp} not created: LND had no such invoice once the create call was over`, 'durableIntent');
    }
    if (invoice.lateLndState !== undefined) {
      timeline.add(invoice.updatedAt, 'late-invoice', `${fp} turned up in LND after it was recorded not-created (LND state ${invoice.lateLndState}): `
        + (invoice.lateLndState === 'CANCELED' ? 'canceled in LND, never adopted' : invoice.lateLndState === 'SETTLED' ? 'paid, posted'
          : 'not adopted, to be canceled in LND'), invoice.lateLndState === 'CANCELED' ? 'canceledFinal' : 'lateInvoice');
    }
    if (superseded.has(invoice.paymentHash)) {
      timeline.add(invoice.updatedAt, 'superseded', `${fp} ${invoice.state}, but the order was fulfilled by another invoice: to be canceled in `
        + 'LND by every reconciliation pass, never settled', 'lateInvoice');
    }
  }
  const fulfilled = fulfillments(store, orderId);
  for (const item of fulfilled) {
    timeline.add(item.fulfilledAt, 'fulfillment', `${fingerprint(item.paymentHash)} fulfilled the order (once, keyed on payment hash and order)`,
      'idempotency');
  }
  const journal = journalView(store.journal(orderId), known);
  for (const entry of journal) {
    const rule: RuleId = entry.event === 'invoice-settled' ? 'idempotency' : entry.event === 'double-payment' ? 'lateInvoice' : 'ledger';
    timeline.add(entry.postedAt, 'journal', journalLine(entry), rule);
  }
  const outbox = outboxView(store.outbox(orderId), known);
  outboxItems(timeline, outbox);

  const settled = list.filter(item => item.state === 'settled' || item.lateLndState === 'SETTLED');
  const live = list.filter(item => ['creating', 'open', 'accepted'].includes(item.state));
  const summary = order.state === 'fulfilled'
    ? `order fulfilled by ${fulfilled.map(item => fingerprint(item.paymentHash)).join(', ')}; ${settled.length} settled invoice(s)`
      + `${superseded.size > 0 ? `, ${superseded.size} superseded invoice(s) to cancel` : ''}`
    : order.state === 'canceled' ? 'order canceled: its invoice was canceled before it was paid'
      : `order awaiting payment${live.length > 0 ? `: ${live.map(item => `${fingerprint(item.paymentHash)} ${item.state}`).join(', ')}` : ''}`
        + `${settled.length > 0 ? `; ${settled.length} settled invoice(s) did not fulfill it` : ''}`;
  // The outcome closes the timeline: its time is the latest recorded one.
  const lastAt = timeline.sorted().at(-1)?.at ?? order.createdAt;
  timeline.add(lastAt, 'outcome', summary);
  const sorted = timeline.sorted();
  return {
    subject: { component: 'receiver', orderId, payments: list.map(item => fingerprint(item.paymentHash)) },
    timeline: sorted,
    outcome: { summary, order, fulfillments: fulfilled.length, invoices: list.map(item => ({ invoice: fingerprint(item.paymentHash), kind: item.kind,
      amountMsat: item.amountMsat.toString(), state: item.state, lateLndState: item.lateLndState ?? null,
      settleIndex: item.settleIndex?.toString() ?? null, amtPaidMsat: item.amtPaidMsat?.toString() ?? null, superseded: superseded.has(item.paymentHash),
      createdAt: item.createdAt })) },
    reservation: null,
    journal,
    outbox,
    reconciliation: decisions(sorted),
  };
}
