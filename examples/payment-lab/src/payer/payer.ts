import type { PayerApi } from '../lnd/api.ts';
import { LndError, TransportError, definiteRefusal, describeError } from '../lnd/errors.ts';
import type { StreamDecision } from '../lnd/rest.ts';
import { isTerminal, type DecodedPayReq, type Payment } from '../lnd/types.ts';
import type { IntentResult, OperationKind, PayerStore, PaymentState, UpdateResult } from './store.ts';

/**
 * The payment workflow. Rules it never breaks:
 *
 * 1. Business intent and payment identity are committed before SendPaymentV2.
 * 2. A transport error or timeout is never a failed payment. The record becomes
 *    uncertain and only TrackPaymentV2 resolves it.
 * 3. SendPaymentV2 is called only for a record in `intent`, claimed by
 *    compare-and-set, so a restart or a second worker never pays again.
 * 4. Only LND's terminal answer completes or fails the business operation.
 * 5. Every update, and every outcome of a call (an error, a stream that ended), is
 *    applied with the submission it was made for, so a late answer about an earlier
 *    submission never decides the current one; that call reports its own outcome.
 */

export type Emit = (event: Record<string, unknown>) => void;

export interface PayerDeps {
  api: PayerApi;
  store: PayerStore;
  emit: Emit;
}

/** A fault the lab injects to show what a real network failure does. */
export type Fault = 'none' | 'drop-stream-after-in-flight';

export type PayOutcome =
  | { kind: 'succeeded'; paymentHash: string; feeMsat: bigint }
  | { kind: 'failed'; paymentHash: string; reason: string }
  | { kind: 'unresolved'; paymentHash: string; state: PaymentState; reason: string }
  | { kind: 'refused'; reason: string; paymentHash?: string }
  | { kind: 'not-submitted'; paymentHash: string; reason: string };

function summary(payment: Payment): Record<string, unknown> {
  return {
    paymentHash: payment.paymentHash,
    status: payment.status,
    valueMsat: payment.valueMsat.toString(),
    feeMsat: payment.feeMsat.toString(),
    htlcAttempts: payment.htlcs.length,
    attemptsInFlight: payment.htlcs.filter(item => item.status === 'IN_FLIGHT').length,
    attemptsSucceeded: payment.htlcs.filter(item => item.status === 'SUCCEEDED').length,
    attemptsFailed: payment.htlcs.filter(item => item.status === 'FAILED').length,
    failureReason: payment.failureReason,
  };
}

const CONFLICT_REASON = {
  'withdrawn': 'it was never sent and is withdrawn; its reservation is released',
  'possible-double-payment': 'it may have been sent and is still unresolved; if LND reports it succeeded the operation was paid twice; '
    + 'it is reconciled with TrackPaymentV2 and must be watched',
  'double-payment': 'LND reported it succeeded too: the operation was paid twice; recover the second payment from the payee',
} as const;

/** Tells the operator about the operation's other payments when LND reports one succeeded (see PayerStore.applyUpdate). */
function reportConflicts(deps: PayerDeps, paymentHash: string, result: UpdateResult): void {
  for (const conflict of result.conflicts) {
    deps.emit({ event: conflict.action, paymentHash: conflict.paymentHash, state: conflict.state, succeeded: paymentHash,
      reason: `payment ${paymentHash} of the same operation succeeded; ${CONFLICT_REASON[conflict.action]}` });
  }
}

/** Validates the decoded invoice against what the business expects to pay. */
export function checkInvoice(invoice: DecodedPayReq, nowSeconds: bigint): string | undefined {
  if (invoice.amountMsat <= 0n) return 'invoice has no amount; this service pays only invoices that state the amount';
  if (invoice.timestamp + invoice.expirySeconds <= nowSeconds) return 'invoice has expired';
  return undefined;
}

export async function decodeInvoice(deps: PayerDeps, paymentRequest: string): Promise<{ invoice: DecodedPayReq } | { error: string }> {
  try {
    const invoice = await deps.api.decodePayReq(paymentRequest);
    const problem = checkInvoice(invoice, BigInt(Math.floor(Date.now() / 1000)));
    return problem === undefined ? { invoice } : { error: problem };
  } catch (error) {
    // DecodePayReq only reads; nothing was recorded or sent, so any error is safe to report as is.
    return { error: `DecodePayReq: ${describeError(error)}` };
  }
}

export function recordIntent(deps: PayerDeps, input: { operationId: string; kind: OperationKind; paymentRequest: string;
  invoice: DecodedPayReq; feeLimitMsat: bigint; maxParts: number; budgetId?: string }): IntentResult {
  const result = deps.store.recordIntent(input);
  if (result.outcome === 'refused') {
    deps.emit({ event: 'intent-refused', operationId: input.operationId, paymentHash: input.invoice.paymentHash, reason: result.reason,
      requestedMsat: result.requestedMsat?.toString(), availableMsat: result.availableMsat?.toString() });
  } else {
    deps.emit({ event: result.outcome === 'recorded' ? 'intent-recorded' : 'intent-existing', operationId: input.operationId,
      paymentHash: result.payment.paymentHash, state: result.payment.state });
  }
  return result;
}

/**
 * Submits a recorded intent with SendPaymentV2 and follows it until LND
 * reports a terminal state or the connection ends. Never retries the call.
 */
export async function submit(deps: PayerDeps, paymentHash: string, options: { timeoutSeconds: number; fault: Fault; signal?: AbortSignal }): Promise<PayOutcome> {
  const record = deps.store.payment(paymentHash);
  if (record === undefined) return { kind: 'refused', reason: `no payment ${paymentHash}` };
  if (record.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: record.feeMsat ?? 0n };
  if (!deps.store.claimForSubmission(paymentHash)) {
    // The claim withdraws an intent whose operation another payment completed: report what the record says now.
    const now = deps.store.payment(paymentHash);
    if (now?.state === 'failed') return { kind: 'failed', paymentHash, reason: now.failureReason ?? 'unknown' };
    return { kind: 'refused', paymentHash, reason: `payment is ${now?.state ?? record.state}, not intent; it is reconciled, never submitted again` };
  }
  // The submission this call is: the claim counted it.
  const submission = deps.store.payment(paymentHash)?.submissions;
  deps.emit({ event: 'submitted', paymentHash, rpc: 'SendPaymentV2' });
  let updates = 0;
  let lastState: PaymentState = 'submitting';
  let dropped = false;
  let terminal: Payment | undefined;
  const onUpdate = (payment: Payment): StreamDecision => {
    if (payment.paymentHash !== paymentHash) throw new Error('SendPaymentV2 returned an update for another payment hash');
    updates += 1;
    const result = deps.store.applyUpdate(payment, 'SendPaymentV2', submission);
    reportConflicts(deps, paymentHash, result);
    lastState = result.state;
    deps.emit({ event: 'payment-update', source: 'SendPaymentV2', ...summary(payment), recordState: result.state,
      operationCompleted: result.completed });
    if (isTerminal(payment.status)) {
      terminal = payment;
      return 'stop';
    }
    const holding = payment.htlcs.some(item => item.status === 'IN_FLIGHT');
    if (options.fault === 'drop-stream-after-in-flight' && holding && !dropped) {
      dropped = true;
      deps.emit({ event: 'fault-injected', fault: options.fault, paymentHash });
      return 'drop';
    }
    return 'continue';
  };
  try {
    await deps.api.sendPaymentV2({ paymentRequest: record.paymentRequest, feeLimitMsat: record.feeLimitMsat,
      timeoutSeconds: options.timeoutSeconds, maxParts: record.maxParts }, onUpdate, options.signal);
  } catch (error) {
    return await afterSubmitError(deps, paymentHash, error, updates, submission, options.signal);
  }
  const final = deps.store.payment(paymentHash);
  if (final?.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: final.feeMsat ?? 0n };
  if (final?.state === 'failed') return { kind: 'failed', paymentHash, reason: final.failureReason ?? 'unknown' };
  // A terminal update the store refused as stale: a later submission is the record's now.
  const ended = terminal as Payment | undefined;
  if (ended !== undefined) return superseded(deps, paymentHash, submission, `SendPaymentV2 reported this submission ${ended.status}`);
  // The server ended the stream without a terminal state: outcome unknown.
  const reason = `SendPaymentV2 stream ended in state ${lastState} without a terminal update`;
  return markUncertain(deps, paymentHash, submission, reason);
}

/**
 * This call's submission is superseded (a later one was claimed, or prepareRetry closed it):
 * its outcome is reported, and the record, which speaks for the later submission, is left alone.
 */
function superseded(deps: PayerDeps, paymentHash: string, submission: number | undefined, what: string): PayOutcome {
  const record = deps.store.payment(paymentHash);
  const state = record?.state ?? 'uncertain';
  const reason = `${what}; submission ${submission ?? '?'} is superseded (the record is at submission ${record?.submissions ?? '?'}, `
    + `state ${state}), so the record was not changed`;
  deps.emit({ event: 'submission-superseded', paymentHash, submission, currentSubmission: record?.submissions, recordState: state, reason });
  return { kind: 'unresolved', paymentHash, state, reason };
}

/** LND never had the payment and another payment completed its operation: the store withdrew it (failed, reservation released). */
function withdrawn(deps: PayerDeps, paymentHash: string): PayOutcome {
  const reason = deps.store.payment(paymentHash)?.failureReason ?? 'WITHDRAWN';
  deps.emit({ event: 'withdrawn', paymentHash, reason });
  return { kind: 'failed', paymentHash, reason };
}

/** The call for `submission` ended without a terminal state: the record becomes uncertain, unless the submission is superseded. */
function markUncertain(deps: PayerDeps, paymentHash: string, submission: number | undefined, reason: string): PayOutcome {
  const marked = deps.store.markUncertain(paymentHash, reason, submission);
  if (marked === 'superseded') return superseded(deps, paymentHash, submission, reason);
  if (marked === 'uncertain') {
    deps.emit({ event: 'uncertain', paymentHash, reason });
    return { kind: 'unresolved', paymentHash, state: 'uncertain', reason };
  }
  // Not unresolved any more: a concurrent tracker recorded LND's answer, or a NotFound reverted it to intent.
  const record = deps.store.payment(paymentHash);
  if (record?.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: record.feeMsat ?? 0n };
  if (record?.state === 'failed') return { kind: 'failed', paymentHash, reason: record.failureReason ?? 'unknown' };
  return { kind: 'unresolved', paymentHash, state: record?.state ?? 'uncertain', reason: `${reason}; the record is ${record?.state ?? 'missing'}` };
}

/**
 * SendPaymentV2 ended with an error. Only two answers end the payment here: the
 * connection was never established (back to intent), or LND definitely refused the
 * call (definiteRefusal) and TrackPaymentV2 then has no payment for the hash
 * (failed, reservation released). An ambiguous error (DeadlineExceeded,
 * Unavailable, a gateway's 502, 503 or 504, ...) followed by NotFound proves
 * nothing: the request may still reach LND after the lookup. The payment stays
 * `uncertain`, its reservation held, for reconciliation to decide.
 */
async function afterSubmitError(deps: PayerDeps, paymentHash: string, error: unknown, updates: number, submission: number | undefined,
  signal: AbortSignal | undefined): Promise<PayOutcome> {
  if (error instanceof TransportError && error.notDelivered && updates === 0) {
    // No connection was ever established: LND never saw this request. Only this submission's
    // record goes back to intent; a later submission is not this call's business.
    const reverted = deps.store.markNotInitiated(paymentHash, `connection not established: ${error.message}`, submission);
    if (reverted === 'superseded') return superseded(deps, paymentHash, submission, `connection not established: ${error.message}`);
    if (reverted === 'withdrawn') return withdrawn(deps, paymentHash);
    deps.emit({ event: 'not-submitted', paymentHash, reason: error.message });
    return { kind: 'not-submitted', paymentHash, reason: error.message };
  }
  if (error instanceof LndError && updates === 0) {
    // LND answered with an error before any update. Whether it initiated a
    // payment (for example "payment is in transition" for a hash it already
    // holds) is settled by asking it, not by reading the message.
    const definite = definiteRefusal(error);
    deps.emit({ event: definite ? 'send-refused-by-lnd' : 'send-error-ambiguous', paymentHash, message: error.message,
      grpcCode: error.grpcCode, httpStatus: error.httpStatus });
    const settled = await trackOnce(deps, paymentHash, submission, signal);
    // The lookup is asynchronous: another tracker may have recorded a terminal state
    // meanwhile. markRejected leaves a terminal record alone, and a record a later submission
    // speaks for; the record below answers.
    if (settled === 'not-found' && definite && deps.store.markRejected(paymentHash, error.message, submission)) {
      deps.emit({ event: 'failed', paymentHash, reason: `rejected before initiation: ${error.message}` });
      return { kind: 'failed', paymentHash, reason: `rejected before initiation: ${error.message}` };
    }
  }
  const record = deps.store.payment(paymentHash);
  if (record?.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: record.feeMsat ?? 0n };
  if (record?.state === 'failed') return { kind: 'failed', paymentHash, reason: record.failureReason ?? 'unknown' };
  return markUncertain(deps, paymentHash, submission, `SendPaymentV2 ended without a terminal state: ${describeError(error)}`);
}

/** One TrackPaymentV2 read of the current state, without waiting for a terminal one. */
async function trackOnce(deps: PayerDeps, paymentHash: string, submission: number | undefined,
  signal: AbortSignal | undefined): Promise<'not-found' | 'found' | 'unknown'> {
  try {
    let found = false;
    await deps.api.trackPaymentV2(paymentHash, payment => {
      found = true;
      reportConflicts(deps, paymentHash, deps.store.applyUpdate(payment, 'TrackPaymentV2', submission));
      return 'stop';
    }, signal);
    return found ? 'found' : 'unknown';
  } catch (error) {
    if (error instanceof LndError && error.notFound) return 'not-found';
    return 'unknown';
  }
}

const BACKOFF_START_MS = 1_000;
const BACKOFF_MAX_MS = 15_000;

function delay(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise(resolve => {
    const timer = setTimeout(done, ms);
    function done(): void { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve(); }
    signal?.addEventListener('abort', done, { once: true });
  });
}

/**
 * Resolves one unresolved payment through TrackPaymentV2: keeps the stream
 * open while LND holds the payment and reconnects with backoff when it drops,
 * until a terminal state or until `signal` aborts. It never calls SendPaymentV2.
 */
export async function reconcile(deps: PayerDeps, paymentHash: string, signal?: AbortSignal): Promise<PayOutcome> {
  let backoff = BACKOFF_START_MS;
  for (;;) {
    const record = deps.store.payment(paymentHash);
    if (record === undefined) return { kind: 'refused', reason: `no payment ${paymentHash}` };
    if (record.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: record.feeMsat ?? 0n };
    if (record.state === 'failed') return { kind: 'failed', paymentHash, reason: record.failureReason ?? 'unknown' };
    if (record.state === 'intent') return { kind: 'not-submitted', paymentHash, reason: 'recorded but never submitted' };
    if (signal?.aborted) return { kind: 'unresolved', paymentHash, state: record.state, reason: 'reconciliation deadline reached' };
    deps.emit({ event: 'track-started', paymentHash, recordState: record.state });
    let terminal = false;
    // This stream reads for the submission the record is at now; a retry started meanwhile is not its business.
    const submission = record.submissions;
    try {
      await deps.api.trackPaymentV2(paymentHash, payment => {
        const result = deps.store.applyUpdate(payment, 'TrackPaymentV2', submission);
        reportConflicts(deps, paymentHash, result);
        deps.emit({ event: 'payment-update', source: 'TrackPaymentV2', ...summary(payment), recordState: result.state,
          operationCompleted: result.completed });
        backoff = BACKOFF_START_MS;
        terminal = isTerminal(payment.status);
        return terminal ? 'stop' : 'continue';
      }, signal);
      if (terminal) continue;
      // LND ended the stream while the payment is still open: track again after a pause.
      deps.emit({ event: 'track-ended-early', paymentHash, retryInMs: backoff });
      await delay(backoff, signal);
      backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
    } catch (error) {
      if (error instanceof LndError && error.notFound) {
        const reverted = deps.store.markNotInitiated(paymentHash, `TrackPaymentV2: ${error.message}`, submission);
        // A submission claimed since this stream opened: this NotFound is not about it. Track the record as it is now.
        if (reverted === 'superseded') continue;
        if (reverted === 'withdrawn') return withdrawn(deps, paymentHash);
        deps.emit({ event: reverted === 'reverted' ? 'not-initiated' : 'not-found-kept-unresolved', paymentHash, message: error.message });
        if (reverted === 'reverted') return { kind: 'not-submitted', paymentHash, reason: 'LND has no payment for this hash; it may be submitted with the same hash' };
        return { kind: 'unresolved', paymentHash, state: record.state, reason: 'LND reports no payment although attempts were recorded; operator review needed' };
      }
      if (signal?.aborted) {
        const current = deps.store.payment(paymentHash);
        return { kind: 'unresolved', paymentHash, state: current?.state ?? record.state, reason: 'reconciliation deadline reached' };
      }
      deps.store.event(paymentHash, 'track-interrupted', { error: describeError(error) });
      deps.emit({ event: 'track-interrupted', paymentHash, error: describeError(error), retryInMs: backoff });
      await delay(backoff, signal);
      backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
    }
  }
}
