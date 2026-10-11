import type { StreamDecision } from '../lnd/rest.ts';
import type { Invoice, Payment } from '../lnd/types.ts';
import { describeError } from '../lnd/errors.ts';
import { fingerprint, scrub } from './format.ts';
import { keepEnds, LIMITS, type Explanation, type TimelineItem } from './model.ts';

/**
 * `explain --refresh`: read-only lookups that put LND's current view next to the records. The payer
 * reads each payment's current state with TrackPaymentV2 (its first message, then the stream is
 * closed); the receiver looks each invoice up with LookupInvoiceV2. Nothing is applied to the
 * records: a difference is reported as a `refreshed` fact for `payer reconcile` or `receiver
 * reconcile` to act on. A node error stops the refresh; the explanation from the records stands.
 *
 * Bounded: at most LIMITS.refresh hashes are looked up (the first and the last halves; a fact counts the others, and
 * `skipped` says how many), one after another, each within REFRESH_TIMEOUT_MS and all within REFRESH_DEADLINE_MS. A
 * refresh that reaches its deadline stops there with an error, like a node error.
 */

export interface TrackSource {
  trackPaymentV2(paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void>;
}

export interface LookupSource {
  lookupInvoice(paymentHash: string, signal?: AbortSignal): Promise<Invoice>;
}

export type RefreshResult = { facts: TimelineItem[]; error?: string; skipped: number };

/** One lookup's timeout. */
const REFRESH_TIMEOUT_MS = 30_000;
/** The whole refresh's deadline, however many lookups it makes. */
export const REFRESH_DEADLINE_MS = 60_000;

export interface RefreshOptions {
  /** The overall deadline; REFRESH_DEADLINE_MS when not given (the tests shorten it). */
  deadlineMs?: number;
}

/**
 * Runs `lookup` for the hashes kept (LIMITS.refresh, first and last halves), one at a time, within the deadline. `lookup` adds
 * its facts and returns an error message to stop with, or undefined.
 */
async function bounded(hashes: string[], options: RefreshOptions, noun: string, known: ReadonlySet<string>, facts: TimelineItem[],
  lookup: (hash: string, signal: AbortSignal) => Promise<string | undefined>): Promise<RefreshResult> {
  const { kept, omitted } = keepEnds(hashes, LIMITS.refresh);
  if (omitted > 0) {
    facts.push(fact(`${omitted} ${noun} not looked up: --refresh looks up at most ${LIMITS.refresh}, the first ${LIMITS.refresh / 2} `
      + `and the last ${LIMITS.refresh / 2}`, known));
  }
  const deadlineMs = options.deadlineMs ?? REFRESH_DEADLINE_MS;
  const overall = AbortSignal.timeout(deadlineMs);
  const late = (done: number): RefreshResult => ({ facts, skipped: omitted,
    error: `--refresh stopped at its ${deadlineMs / 1000} s deadline after ${done} of ${kept.length} lookup(s)` });
  for (const [index, hash] of kept.entries()) {
    if (overall.aborted) return late(index);
    const error = await lookup(hash, AbortSignal.any([AbortSignal.timeout(REFRESH_TIMEOUT_MS), overall]));
    if (error !== undefined) return overall.aborted ? late(index) : { facts, error, skipped: omitted };
  }
  return { facts, skipped: omitted };
}

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

export async function refreshPayer(explanation: Explanation, hashes: string[], api: TrackSource, options: RefreshOptions = {}):
  Promise<RefreshResult> {
  const known = new Set(hashes.map(hash => hash.toLowerCase()));
  const recorded = new Map(((explanation.outcome.payments ?? []) as RecordedPayment[]).map(item => [item.payment, item]));
  const facts: TimelineItem[] = [];
  return await bounded(hashes, options, 'payment hash(es)', known, facts, async (hash, signal) => {
    const record = recorded.get(fingerprint(hash));
    let first: Payment | undefined;
    try {
      await api.trackPaymentV2(hash, update => { first = update; return 'stop'; }, signal);
    } catch (error) {
      if (notFound(error)) {
        facts.push(fact(`${fingerprint(hash)} TrackPaymentV2: LND has no payment for the hash (record ${record?.state ?? 'unknown'})`, known));
        return undefined;
      }
      return `TrackPaymentV2 for ${fingerprint(hash)}: ${scrub(describeError(error), known)}`;
    }
    const now: Payment | undefined = first;
    if (now === undefined) {
      facts.push(fact(`${fingerprint(hash)} TrackPaymentV2 ended without an update (record ${record?.state ?? 'unknown'})`, known));
      return undefined;
    }
    const lndState = LND_TO_PAYMENT_STATE[now.status] ?? now.status;
    const agrees = record !== undefined && (record.state === lndState || (lndState === 'in_flight' && UNRESOLVED.has(record.state)))
      && (lndState !== 'succeeded' || (record.valueMsat === now.valueMsat.toString() && record.feeMsat === now.feeMsat.toString()));
    facts.push(fact(`${fingerprint(hash)} TrackPaymentV2 now: ${now.status}, value ${now.valueMsat} msat, fee ${now.feeMsat} msat, `
      + `${now.htlcs.length} HTLC attempt(s)${now.status === 'FAILED' ? `, ${now.failureReason}` : ''}; `
      + (agrees ? `agrees with the record (${record.state})` : `differs from the record (${record === undefined ? 'no record' : `${record.state}`
        + `${record.valueMsat === null ? '' : `, value ${record.valueMsat} msat, fee ${record.feeMsat ?? '0'} msat`}`}): run payer reconcile`), known));
    return undefined;
  });
}

export async function refreshReceiver(explanation: Explanation, hashes: string[], api: LookupSource, options: RefreshOptions = {}):
  Promise<RefreshResult> {
  const known = new Set(hashes.map(hash => hash.toLowerCase()));
  const recorded = new Map(((explanation.outcome.invoices ?? []) as RecordedInvoice[]).map(item => [item.invoice, item]));
  const facts: TimelineItem[] = [];
  return await bounded(hashes, options, 'invoice(s)', known, facts, async (hash, signal) => {
    const record = recorded.get(fingerprint(hash));
    let invoice: Invoice;
    try {
      invoice = await api.lookupInvoice(hash, signal);
    } catch (error) {
      if (notFound(error)) {
        facts.push(fact(`${fingerprint(hash)} LookupInvoice: LND has no invoice for the hash (record ${record?.state ?? 'unknown'})`, known));
        return undefined;
      }
      return `LookupInvoice for ${fingerprint(hash)}: ${scrub(describeError(error), known)}`;
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
    return undefined;
  });
}
