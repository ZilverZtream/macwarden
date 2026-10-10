import type { PayerApi } from '../lnd/api.ts';
import { LndError, TransportError, describeError } from '../lnd/errors.ts';
import type { StreamDecision } from '../lnd/rest.ts';
import { isTerminal, type DecodedPayReq, type Payment } from '../lnd/types.ts';
import type { IntentResult, OperationKind, PayerStore, PaymentState } from './store.ts';

/**
 * The payment workflow. Rules it never breaks:
 *
 * 1. Business intent and payment identity are committed before SendPaymentV2.
 * 2. A transport error or timeout is never a failed payment. The record becomes
 *    uncertain and only TrackPaymentV2 resolves it.
 * 3. SendPaymentV2 is called only for a record in `intent`, claimed by
 *    compare-and-set, so a restart or a second worker never pays again.
 * 4. Only LND's terminal answer completes or fails the business operation.
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
    return { kind: 'refused', paymentHash, reason: `payment is ${record.state}, not intent; it is reconciled, never submitted again` };
  }
  deps.emit({ event: 'submitted', paymentHash, rpc: 'SendPaymentV2' });
  let updates = 0;
  let lastState: PaymentState = 'submitting';
  let dropped = false;
  const onUpdate = (payment: Payment): StreamDecision => {
    if (payment.paymentHash !== paymentHash) throw new Error('SendPaymentV2 returned an update for another payment hash');
    updates += 1;
    const result = deps.store.applyUpdate(payment, 'SendPaymentV2');
    lastState = result.state;
    deps.emit({ event: 'payment-update', source: 'SendPaymentV2', ...summary(payment), recordState: result.state,
      operationCompleted: result.completed });
    if (isTerminal(payment.status)) return 'stop';
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
    return await afterSubmitError(deps, paymentHash, error, updates);
  }
  const final = deps.store.payment(paymentHash);
  if (final?.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: final.feeMsat ?? 0n };
  if (final?.state === 'failed') return { kind: 'failed', paymentHash, reason: final.failureReason ?? 'unknown' };
  // The server ended the stream without a terminal state: outcome unknown.
  const reason = `SendPaymentV2 stream ended in state ${lastState} without a terminal update`;
  deps.store.markUncertain(paymentHash, reason);
  deps.emit({ event: 'uncertain', paymentHash, reason });
  return { kind: 'unresolved', paymentHash, state: 'uncertain', reason };
}

async function afterSubmitError(deps: PayerDeps, paymentHash: string, error: unknown, updates: number): Promise<PayOutcome> {
  if (error instanceof TransportError && error.notDelivered && updates === 0) {
    // No connection was ever established: LND never saw the request.
    deps.store.markNotInitiated(paymentHash, `connection not established: ${error.message}`);
    deps.emit({ event: 'not-submitted', paymentHash, reason: error.message });
    return { kind: 'not-submitted', paymentHash, reason: error.message };
  }
  if (error instanceof LndError && updates === 0) {
    // LND answered with an error before any update. Whether it initiated a
    // payment (for example "payment is in transition" for a hash it already
    // holds) is settled by asking it, not by reading the message.
    deps.emit({ event: 'send-refused-by-lnd', paymentHash, message: error.message, grpcCode: error.grpcCode });
    const settled = await trackOnce(deps, paymentHash);
    // The lookup is asynchronous: another tracker may have recorded a terminal state
    // meanwhile. markRejected leaves a terminal record alone; the record below answers.
    if (settled === 'not-found' && deps.store.markRejected(paymentHash, error.message)) {
      deps.emit({ event: 'failed', paymentHash, reason: `rejected before initiation: ${error.message}` });
      return { kind: 'failed', paymentHash, reason: `rejected before initiation: ${error.message}` };
    }
  }
  const record = deps.store.payment(paymentHash);
  if (record?.state === 'succeeded') return { kind: 'succeeded', paymentHash, feeMsat: record.feeMsat ?? 0n };
  if (record?.state === 'failed') return { kind: 'failed', paymentHash, reason: record.failureReason ?? 'unknown' };
  const reason = `SendPaymentV2 ended without a terminal state: ${describeError(error)}`;
  deps.store.markUncertain(paymentHash, reason);
  deps.emit({ event: 'uncertain', paymentHash, reason });
  return { kind: 'unresolved', paymentHash, state: 'uncertain', reason };
}

/** One TrackPaymentV2 read of the current state, without waiting for a terminal one. */
async function trackOnce(deps: PayerDeps, paymentHash: string): Promise<'not-found' | 'found' | 'unknown'> {
  try {
    let found = false;
    await deps.api.trackPaymentV2(paymentHash, payment => {
      found = true;
      deps.store.applyUpdate(payment, 'TrackPaymentV2');
      return 'stop';
    });
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
    try {
      await deps.api.trackPaymentV2(paymentHash, payment => {
        const result = deps.store.applyUpdate(payment, 'TrackPaymentV2');
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
        const reverted = deps.store.markNotInitiated(paymentHash, `TrackPaymentV2: ${error.message}`);
        deps.emit({ event: reverted ? 'not-initiated' : 'not-found-kept-unresolved', paymentHash, message: error.message });
        if (reverted) return { kind: 'not-submitted', paymentHash, reason: 'LND has no payment for this hash; it may be submitted with the same hash' };
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
