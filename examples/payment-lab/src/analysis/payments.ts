import type { ReadApi } from '../lnd/api.ts';
import type { ForwardingEvent, Payment } from '../lnd/types.ts';

/**
 * Evidence read with the read-only credential. ListPayments has no filter by
 * hash, so the payments are paged through; the scan is bounded and says when
 * it stopped early, so "no second payment" is never claimed from a partial read.
 */

const PAGE_SIZE = 500;
const MAX_PAGES = 200;

/**
 * A payment as the analysis reports it: without the preimage (the proof of payment; only
 * whether LND holds one) and without the payment request (the invoice, which can be paid
 * again or replayed). The evidence is printed, so neither may be in it.
 */
export type PaymentView = Omit<Payment, 'preimage' | 'paymentRequest'> & { preimagePresent: boolean };

export function paymentView(payment: Payment): PaymentView {
  // Field by field, so a field added to Payment later is not printed by accident.
  return { paymentHash: payment.paymentHash, status: payment.status, valueMsat: payment.valueMsat, feeMsat: payment.feeMsat,
    failureReason: payment.failureReason, creationTimeNs: payment.creationTimeNs, paymentIndex: payment.paymentIndex, htlcs: payment.htlcs,
    preimagePresent: payment.preimage !== undefined && payment.preimage !== '' };
}

export interface PaymentsForHash {
  payments: PaymentView[];
  scanned: number;
  complete: boolean;
}

export async function paymentsForHash(read: ReadApi, paymentHash: string): Promise<PaymentsForHash> {
  const payments: PaymentView[] = [];
  let offset = 0n;
  let scanned = 0;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await read.listPaymentsPage(offset, PAGE_SIZE);
    scanned += result.payments.length;
    payments.push(...result.payments.filter(item => item.paymentHash === paymentHash).map(paymentView));
    // A short page is the end. A full page whose offset did not advance cannot be paged past: the scan stops incomplete.
    if (result.payments.length < PAGE_SIZE || result.lastIndexOffset <= offset) {
      return { payments, scanned, complete: result.payments.length < PAGE_SIZE };
    }
    offset = result.lastIndexOffset;
  }
  return { payments, scanned, complete: false };
}

const FORWARDS_PAGE = 1000;
const MAX_FORWARD_PAGES = 100;

/** Forwarding events of a routing node since a time, for corroborating the fees a sender paid. */
export async function forwardsSince(read: ReadApi, sinceSeconds: bigint): Promise<{ events: ForwardingEvent[]; complete: boolean }> {
  const events: ForwardingEvent[] = [];
  const until = BigInt(Math.floor(Date.now() / 1000) + 60);
  let offset = 0;
  for (let page = 0; page < MAX_FORWARD_PAGES; page += 1) {
    const result = await read.forwardingHistory(sinceSeconds, until, offset, FORWARDS_PAGE);
    events.push(...result.events);
    // As in paymentsForHash: a full page whose offset did not advance ends the scan incomplete.
    if (result.events.length < FORWARDS_PAGE || result.lastOffsetIndex <= offset) {
      return { events, complete: result.events.length < FORWARDS_PAGE };
    }
    offset = result.lastOffsetIndex;
  }
  return { events, complete: false };
}
