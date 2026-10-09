import type { ReadApi } from '../lnd/api.ts';
import type { ForwardingEvent, Payment } from '../lnd/types.ts';

/**
 * Evidence read with the read-only credential. ListPayments has no filter by
 * hash, so the payments are paged through; the scan is bounded and says when
 * it stopped early, so "no second payment" is never claimed from a partial read.
 */

const PAGE_SIZE = 500;
const MAX_PAGES = 200;

export interface PaymentsForHash {
  payments: Payment[];
  scanned: number;
  complete: boolean;
}

export async function paymentsForHash(read: ReadApi, paymentHash: string): Promise<PaymentsForHash> {
  const payments: Payment[] = [];
  let offset = 0n;
  let scanned = 0;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const result = await read.listPaymentsPage(offset, PAGE_SIZE);
    scanned += result.payments.length;
    payments.push(...result.payments.filter(item => item.paymentHash === paymentHash));
    if (result.payments.length < PAGE_SIZE || result.lastIndexOffset <= offset) return { payments, scanned, complete: true };
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
    if (result.events.length < FORWARDS_PAGE || result.lastOffsetIndex <= offset) return { events, complete: true };
    offset = result.lastOffsetIndex;
  }
  return { events, complete: false };
}
