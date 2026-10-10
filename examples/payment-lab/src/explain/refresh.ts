import type { StreamDecision } from '../lnd/rest.ts';
import type { Invoice, Payment } from '../lnd/types.ts';
import { describeError } from '../lnd/errors.ts';
import { fingerprint, scrub } from './format.ts';
import type { Explanation, TimelineItem } from './model.ts';

/**
 * `explain --refresh`: read-only lookups that put LND's current view next to the records. The payer
 * reads each payment's current state with TrackPaymentV2 (its first message, then the stream is
 * closed); the receiver looks each invoice up with LookupInvoiceV2. Nothing is applied to the
 * records: a difference is reported as a `refreshed` fact for `payer reconcile` or `receiver
 * reconcile` to act on. A node error stops the refresh; the explanation from the records stands.
 */

export interface TrackSource {
  trackPaymentV2(paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void>;
}

export interface LookupSource {
  lookupInvoice(paymentHash: string, signal?: AbortSignal): Promise<Invoice>;
}

export type RefreshResult = { facts: TimelineItem[]; error?: string };

const REFRESH_TIMEOUT_MS = 30_000;

/** LND itself answered NotFound (gRPC code 5): see LndError.notFound. Read by shape, so any copy of the class counts. */
function notFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { notFound?: unknown }).notFound === true;
}

const LND_TO_PAYMENT_STATE: Record<string, string> = { SUCCEEDED: 'succeeded', FAILED: 'failed', IN_FLIGHT: 'in_flight', INITIATED: 'in_flight' };
const LND_TO_INVOICE_STATE: Record<string, string> = { OPEN: 'open', ACCEPTED: 'accepted', SETTLED: 'settled', CANCELED: 'canceled' };
const UNRESOLVED = new Set(['submitting', 'in_flight', 'uncertain']);

interface RecordedPayment { payment: string; state: string; valueMsat: string | null; feeMsat: string | null }
interface RecordedInvoice { invoice: string; state: string; amtPaidMsat: string | null; lateLndState: string | null }

function fact(detail: string, known: ReadonlySet<string>): TimelineItem {
  return { at: new Date().toISOString(), kind: 'refreshed', detail: `${scrub(detail, known)}; read-only, the record is unchanged` };
}

export async function refreshPayer(explanation: Explanation, hashes: string[], api: TrackSource): Promise<RefreshResult> {
  const known = new Set(hashes.map(hash => hash.toLowerCase()));
  const recorded = (explanation.outcome.payments ?? []) as RecordedPayment[];
  const facts: TimelineItem[] = [];
  for (const hash of hashes) {
    const record = recorded.find(item => item.payment === fingerprint(hash));
    let first: Payment | undefined;
    try {
      await api.trackPaymentV2(hash, update => { first = update; return 'stop'; }, AbortSignal.timeout(REFRESH_TIMEOUT_MS));
    } catch (error) {
      if (notFound(error)) {
        facts.push(fact(`${fingerprint(hash)} TrackPaymentV2: LND has no payment for the hash (record ${record?.state ?? 'unknown'})`, known));
        continue;
      }
      return { facts, error: `TrackPaymentV2 for ${fingerprint(hash)}: ${scrub(describeError(error), known)}` };
    }
    const now: Payment | undefined = first;
    if (now === undefined) {
      facts.push(fact(`${fingerprint(hash)} TrackPaymentV2 ended without an update (record ${record?.state ?? 'unknown'})`, known));
      continue;
    }
    const lndState = LND_TO_PAYMENT_STATE[now.status] ?? now.status;
    const agrees = record !== undefined && (record.state === lndState || (lndState === 'in_flight' && UNRESOLVED.has(record.state)))
      && (lndState !== 'succeeded' || (record.valueMsat === now.valueMsat.toString() && record.feeMsat === now.feeMsat.toString()));
    facts.push(fact(`${fingerprint(hash)} TrackPaymentV2 now: ${now.status}, value ${now.valueMsat} msat, fee ${now.feeMsat} msat, `
      + `${now.htlcs.length} HTLC attempt(s)${now.status === 'FAILED' ? `, ${now.failureReason}` : ''}; `
      + (agrees ? `agrees with the record (${record.state})` : `differs from the record (${record === undefined ? 'no record' : `${record.state}`
        + `${record.valueMsat === null ? '' : `, value ${record.valueMsat} msat, fee ${record.feeMsat ?? '0'} msat`}`}): run payer reconcile`), known));
  }
  return { facts };
}

export async function refreshReceiver(explanation: Explanation, hashes: string[], api: LookupSource): Promise<RefreshResult> {
  const known = new Set(hashes.map(hash => hash.toLowerCase()));
  const recorded = (explanation.outcome.invoices ?? []) as RecordedInvoice[];
  const facts: TimelineItem[] = [];
  for (const hash of hashes) {
    const record = recorded.find(item => item.invoice === fingerprint(hash));
    let invoice: Invoice;
    try {
      invoice = await api.lookupInvoice(hash, AbortSignal.timeout(REFRESH_TIMEOUT_MS));
    } catch (error) {
      if (notFound(error)) {
        facts.push(fact(`${fingerprint(hash)} LookupInvoice: LND has no invoice for the hash (record ${record?.state ?? 'unknown'})`, known));
        continue;
      }
      return { facts, error: `LookupInvoice for ${fingerprint(hash)}: ${scrub(describeError(error), known)}` };
    }
    const lndState = LND_TO_INVOICE_STATE[invoice.state] ?? invoice.state;
    const recordState = record?.state === 'not-created' ? (record.lateLndState === null ? 'not-created' : LND_TO_INVOICE_STATE[record.lateLndState])
      : record?.state;
    const agrees = recordState === lndState && (lndState !== 'settled' || record?.amtPaidMsat === invoice.amtPaidMsat.toString()
      || record?.state === 'not-created');
    facts.push(fact(`${fingerprint(hash)} LookupInvoice now: ${invoice.state}, paid ${invoice.amtPaidMsat} msat, settle index ${invoice.settleIndex}, `
      + `memo ${JSON.stringify(invoice.memo)}; ${agrees ? `agrees with the record (${record?.state ?? 'unknown'})`
        : `differs from the record (${record === undefined ? 'no record' : `${record.state}${record.amtPaidMsat === null ? '' : `, paid ${record.amtPaidMsat} msat`}`}): `
          + 'run receiver reconcile'}`, known));
  }
  return { facts };
}
