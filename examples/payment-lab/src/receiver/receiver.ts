import { randomBytes } from 'node:crypto';
import type { InvoiceApi } from '../lnd/api.ts';
import { LndError, TransportError, describeError } from '../lnd/errors.ts';
import type { Invoice } from '../lnd/types.ts';
import { sha256Hex } from '../util/encoding.ts';
import type { DeliveryOutcome, DeliverySource, InvoiceRecord, ReceiverStore } from './store.ts';

/**
 * The receiving side: invoices for orders, hold-invoice settlement and the
 * settlement consumer. Every path that learns of a settlement (subscription,
 * lookup, the settle call itself) goes through ReceiverStore.applyInvoice, so
 * the order is fulfilled and the sale posted once however often it is told.
 */

export type Emit = (event: Record<string, unknown>) => void;

export interface ReceiverDeps {
  api: InvoiceApi;
  store: ReceiverStore;
  emit: Emit;
}

function apply(deps: ReceiverDeps, invoice: Invoice, source: DeliverySource): DeliveryOutcome {
  const outcome = deps.store.applyInvoice(invoice, source);
  deps.emit({ event: 'invoice-delivery', source, paymentHash: invoice.paymentHash, lndState: invoice.state,
    settleIndex: invoice.settleIndex.toString(), amtPaidMsat: invoice.amtPaidMsat.toString(), outcome });
  if (outcome === 'late-invoice' || outcome === 'second-payment') {
    const orderId = deps.store.invoice(invoice.paymentHash)?.orderId;
    deps.emit(outcome === 'late-invoice'
      ? { event: 'late-invoice', orderId, paymentHash: invoice.paymentHash, lndState: invoice.state,
        reason: `LND holds invoice ${invoice.paymentHash} after it was recorded as not created, and order ${orderId} may not adopt it; `
          + 'reconciliation cancels it in LND' }
      : { event: 'second-payment', orderId, paymentHash: invoice.paymentHash, amtPaidMsat: invoice.amtPaidMsat.toString(),
        reason: `order ${orderId} was already fulfilled by another invoice; this payment was posted and did not fulfill the order again; `
          + 'return it to the payer' });
  }
  return outcome;
}

/** Looks the invoice up; NotFound is a definite answer, anything else leaves the question open. */
async function lookup(deps: ReceiverDeps, paymentHash: string): Promise<Invoice | 'not-found' | 'unknown'> {
  try {
    return await deps.api.lookupInvoice(paymentHash);
  } catch (error) {
    if (error instanceof LndError && error.notFound) return 'not-found';
    deps.emit({ event: 'lookup-failed', paymentHash, error: describeError(error) });
    return 'unknown';
  }
}

/**
 * When NotFound decides an invoice in `creating`. The state means "the create call
 * may be in flight", and while it may be, a lookup that finds nothing proves
 * nothing: LND can still create the invoice a moment later. So NotFound is
 * conclusive only when the call is known to be over:
 *
 * - LND itself refused the create call (definiteRefusal below; the creator saw the
 *   answer), or
 * - the intent was recorded longer ago than CREATION_WINDOW_MS. AddInvoice and
 *   AddHoldInvoice use the REST client's default unary timeout (30 s), so a call
 *   still pending after the window has been abandoned by its caller.
 *
 * Anything else (another process reconciling, the creator's own call timing out
 * or losing its connection after the request was sent, an ambiguous error) leaves
 * the invoice `creating`: the order keeps it as its live invoice, no replacement
 * is issued, and a later pass decides. LND can still create an invoice after the
 * window (a stalled call); resolveLateInvoice handles one that turns up.
 */
export const CREATION_WINDOW_MS = 120_000;

/**
 * How long after its intent a not-created invoice is still looked up by
 * reconciliation in case LND created it late. The subscription sees a late
 * creation at any age (LND replays invoice additions after the stored add index);
 * this lookup is the backstop for a listener that was not running.
 */
export const LATE_RECHECK_MS = 24 * 60 * 60 * 1000;

function creationCutoff(): string {
  return new Date(Date.now() - CREATION_WINDOW_MS).toISOString();
}

/**
 * gRPC status codes with which LND itself refuses a create call: the request was
 * handled and nothing was created. 2 Unknown is how LND returns most of its own
 * application errors (HTTP 500 from its gateway, for example "invoice with payment
 * hash already exists").
 */
const DEFINITE_REFUSAL_CODES: ReadonlySet<number> = new Set([
  2, // Unknown: an LND application error
  3, // InvalidArgument
  5, // NotFound
  6, // AlreadyExists
  7, // PermissionDenied
  8, // ResourceExhausted (request too large, rate limit inside LND)
  9, // FailedPrecondition
  11, // OutOfRange
  12, // Unimplemented
  16, // Unauthenticated
]);

/** HTTP statuses that a gateway or proxy in front of LND produces when the call was cut off, whatever the body says. */
const AMBIGUOUS_HTTP: ReadonlySet<number> = new Set([408, 499, 502, 503, 504]);

/**
 * Whether an error from the create call is a definite refusal, which lets a NotFound
 * lookup decide the invoice at once. The classes:
 *
 * - not delivered: a TransportError in phase `connect`; the request never left
 *   (handled before this is asked, without a lookup).
 * - definite refusal: an LndError with one of DEFINITE_REFUSAL_CODES from LND's
 *   gateway, or a 400-class response (other than 408 and 499) whose body carries a
 *   message, and in neither case an HTTP status from AMBIGUOUS_HTTP.
 * - ambiguous, everything else: gRPC 1 Cancelled, 4 DeadlineExceeded, 10 Aborted,
 *   13 Internal, 14 Unavailable, 15 DataLoss (the call may have been cut off after
 *   LND began creating the invoice); HTTP 408, 499, 502, 503 or 504 from a gateway
 *   or proxy; a 5xx without an LND body; a TransportError after the connection was
 *   established; a ProtocolError (an unreadable answer); any other error. The
 *   invoice stays `creating` until CREATION_WINDOW_MS has passed.
 */
export function definiteRefusal(error: unknown): boolean {
  if (!(error instanceof LndError)) return false;
  const status = error.httpStatus;
  if (status !== undefined && AMBIGUOUS_HTTP.has(status)) return false;
  if (error.grpcCode !== undefined) return DEFINITE_REFUSAL_CODES.has(error.grpcCode);
  // No gRPC code: only a 400-class answer with a message from the body (not the client's "HTTP <status>" stand-in).
  return status !== undefined && status >= 400 && status < 500 && error.message !== `HTTP ${status}`;
}

export type CreateOutcome =
  | { kind: 'created'; paymentHash: string; paymentRequest: string }
  | { kind: 'refused'; reason: string }
  | { kind: 'not-created'; paymentHash: string; reason: string }
  | { kind: 'unresolved'; paymentHash: string; reason: string };

/**
 * Creates the invoice for an order. The preimage and hash are generated and
 * committed first; LND is then asked to create exactly that invoice. If the
 * answer is lost, a lookup of the known hash tells whether it exists, and no
 * second invoice is created for the order while that is unknown.
 */
export async function createInvoice(deps: ReceiverDeps, input: { orderId: string; amountMsat: bigint; hold: boolean; memo: string;
  expirySeconds: number }): Promise<CreateOutcome> {
  const preimage = randomBytes(32).toString('hex');
  const paymentHash = sha256Hex(preimage);
  const recorded = deps.store.recordInvoiceIntent({ orderId: input.orderId, amountMsat: input.amountMsat,
    kind: input.hold ? 'hold' : 'standard', preimage, paymentHash });
  if (recorded.outcome === 'refused') return { kind: 'refused', reason: recorded.reason };
  deps.emit({ event: 'invoice-intent-recorded', orderId: input.orderId, paymentHash, kind: input.hold ? 'hold' : 'standard' });
  try {
    const created = input.hold
      ? await deps.api.addHoldInvoice({ paymentHash, valueMsat: input.amountMsat, memo: input.memo, expirySeconds: input.expirySeconds })
      : await deps.api.addInvoice({ preimage, valueMsat: input.amountMsat, memo: input.memo, expirySeconds: input.expirySeconds });
    if ('paymentHash' in created && created.paymentHash !== paymentHash) {
      throw new Error('LND created an invoice for a different payment hash');
    }
    const state = deps.store.markCreated(paymentHash, created.paymentRequest, created.addIndex);
    if (state === 'not-created') return await lateCreation(deps, paymentHash, undefined);
    deps.emit({ event: 'invoice-created', orderId: input.orderId, paymentHash, rpc: input.hold ? 'AddHoldInvoice' : 'AddInvoice' });
    return { kind: 'created', paymentHash, paymentRequest: created.paymentRequest };
  } catch (error) {
    return await resolveCreation(deps, paymentHash, error);
  }
}

/** The create call's answer (or its lookup) shows LND created an invoice already recorded not-created. */
async function lateCreation(deps: ReceiverDeps, paymentHash: string, found: Invoice | undefined): Promise<CreateOutcome> {
  const record = deps.store.invoice(paymentHash);
  const current = found ?? await lookup(deps, paymentHash);
  if (record === undefined || current === 'not-found' || current === 'unknown') {
    return { kind: 'unresolved', paymentHash, reason: `LND created invoice ${paymentHash} after it was recorded as not created; `
      + 'run "receiver reconcile" to cancel or adopt it' };
  }
  const late = await resolveLateInvoice(deps, record, current, 'create-call');
  if (late.kind === 'adopted') return { kind: 'created', paymentHash, paymentRequest: current.paymentRequest };
  if (late.kind === 'canceled') return { kind: 'not-created', paymentHash, reason: late.reason };
  return { kind: 'unresolved', paymentHash, reason: late.reason };
}

async function resolveCreation(deps: ReceiverDeps, paymentHash: string, error: unknown): Promise<CreateOutcome> {
  if (error instanceof TransportError && error.notDelivered) {
    deps.store.markNotCreated(paymentHash);
    return { kind: 'not-created', paymentHash, reason: error.message };
  }
  const found = await lookup(deps, paymentHash);
  if (found === 'not-found') {
    // Conclusive at once only if LND itself refused the call; otherwise after the window (see CREATION_WINDOW_MS).
    if (deps.store.markNotCreated(paymentHash, definiteRefusal(error) ? undefined : creationCutoff())) {
      return { kind: 'not-created', paymentHash, reason: describeError(error) };
    }
    return { kind: 'unresolved', paymentHash, reason: `${describeError(error)}; LND has no invoice for the hash yet, but the create call may still `
      + `reach it, so it stays creating; run "receiver reconcile" after ${CREATION_WINDOW_MS / 1000} s to decide it` };
  }
  if (found === 'unknown') {
    return { kind: 'unresolved', paymentHash, reason: `${describeError(error)}; run "receiver reconcile" to resolve it` };
  }
  if (deps.store.markCreated(paymentHash, found.paymentRequest, found.addIndex) === 'not-created') {
    return await lateCreation(deps, paymentHash, found);
  }
  apply(deps, found, 'create-call');
  return { kind: 'created', paymentHash, paymentRequest: found.paymentRequest };
}

export type LateOutcome =
  | { kind: 'adopted' | 'canceled' | 'recorded'; reason: string }
  | { kind: 'unresolved'; reason: string };

/**
 * An invoice recorded `not-created` that LND holds after all: its create call
 * reached LND after the creation window, or a not-created decision was followed by
 * LND's late answer. The rule, applied however it is learned (the create call's
 * answer, the subscription, a reconciliation lookup):
 *
 * - The order still awaits payment and has no other live invoice: the invoice is
 *   adopted and becomes the order's live invoice.
 * - Otherwise (another live invoice, or the order is fulfilled or canceled) and
 *   LND holds it OPEN or ACCEPTED: it is canceled in LND with CancelInvoice, so the
 *   order never has two payable invoices; an accepted HTLC returns to the payer.
 *   Until LND reports it canceled, every reconciliation pass tries again.
 * - LND reports it settled (paid before the cancel reached LND): the payment is
 *   recorded and posted, because the money arrived. If the order was already
 *   fulfilled by another invoice it is not fulfilled again; the delivery is
 *   `second-payment` and the operator is told to return the money.
 */
export async function resolveLateInvoice(deps: ReceiverDeps, record: InvoiceRecord, found: Invoice, source: DeliverySource): Promise<LateOutcome> {
  const { paymentHash, orderId } = record;
  const what = `LND holds invoice ${paymentHash} (${found.state}) for order ${orderId} after it was recorded as not created`;
  const outcome = apply(deps, found, source);
  if (deps.store.invoice(paymentHash)?.state !== 'not-created') {
    const reason = `${what}; the order had no other live invoice, so it was adopted`;
    deps.emit({ event: 'late-invoice-adopted', orderId, paymentHash, lndState: found.state, reason });
    return { kind: 'adopted', reason };
  }
  if (outcome !== 'late-invoice') return { kind: 'recorded', reason: `${what}; recorded (${outcome})` };
  let callError: unknown;
  try {
    await deps.api.cancelInvoice(paymentHash);
    deps.emit({ event: 'cancel-called', orderId, paymentHash, rpc: 'CancelInvoice', reason: what });
  } catch (error) {
    callError = error;
  }
  const after = await lookup(deps, paymentHash);
  if (after !== 'not-found' && after !== 'unknown') apply(deps, after, 'lookup');
  if (after !== 'not-found' && after !== 'unknown' && after.state === 'CANCELED') {
    const reason = `${what}; order ${orderId} has another live invoice or no longer awaits payment, so it was canceled in LND`;
    deps.emit({ event: 'late-invoice-canceled', orderId, paymentHash, reason });
    return { kind: 'canceled', reason };
  }
  if (after !== 'not-found' && after !== 'unknown' && after.state === 'SETTLED') {
    return { kind: 'recorded', reason: `${what}; it was paid before it could be canceled, and the payment was recorded` };
  }
  const reason = `${what}; CancelInvoice ${callError === undefined ? 'sent' : `failed: ${describeError(callError)}`}, `
    + `invoice ${after === 'not-found' || after === 'unknown' ? `lookup ${after}` : after.state}; the next reconciliation tries again`;
  deps.emit({ event: 'late-invoice-cancel-failed', orderId, paymentHash, reason });
  return { kind: 'unresolved', reason };
}

export type SettleOutcome =
  | { kind: 'settled'; outcome: DeliveryOutcome }
  | { kind: 'refused'; reason: string }
  | { kind: 'unresolved'; reason: string };

function holdInvoiceFor(deps: ReceiverDeps, orderId: string): InvoiceRecord | string {
  const invoice = deps.store.liveInvoiceForOrder(orderId);
  if (invoice === undefined) return `order ${orderId} has no live invoice`;
  if (invoice.kind !== 'hold') return `order ${orderId} has a standard invoice; LND settles it on its own`;
  return invoice;
}

/** Releases the preimage of a hold invoice whose HTLCs LND has accepted. */
export async function settleHoldInvoice(deps: ReceiverDeps, orderId: string): Promise<SettleOutcome> {
  const invoice = holdInvoiceFor(deps, orderId);
  if (typeof invoice === 'string') return { kind: 'refused', reason: invoice };
  const before = await lookup(deps, invoice.paymentHash);
  if (before === 'not-found' || before === 'unknown') return { kind: 'unresolved', reason: `invoice lookup: ${before}` };
  const beforeOutcome = apply(deps, before, 'lookup');
  if (before.state === 'SETTLED') return { kind: 'settled', outcome: beforeOutcome };
  if (before.state !== 'ACCEPTED') return { kind: 'refused', reason: `invoice is ${before.state}; settle only after LND accepted the HTLCs` };
  let callError: unknown;
  try {
    await deps.api.settleInvoice(invoice.preimage);
    deps.emit({ event: 'settle-called', orderId, paymentHash: invoice.paymentHash, rpc: 'SettleInvoice' });
  } catch (error) {
    callError = error;
    deps.emit({ event: 'settle-call-error', orderId, paymentHash: invoice.paymentHash, error: describeError(error) });
  }
  // Whatever the call returned, LND's invoice state is the answer.
  const after = await lookup(deps, invoice.paymentHash);
  if (after === 'not-found' || after === 'unknown') {
    return { kind: 'unresolved', reason: `settle ${callError === undefined ? 'sent' : describeError(callError)}; lookup ${after}` };
  }
  const outcome = apply(deps, after, 'settle-call');
  if (after.state === 'SETTLED') return { kind: 'settled', outcome };
  return { kind: 'unresolved', reason: `invoice is ${after.state} after SettleInvoice${callError === undefined ? '' : `: ${describeError(callError)}`}` };
}

export async function cancelHoldInvoice(deps: ReceiverDeps, orderId: string): Promise<{ kind: 'canceled' } | { kind: 'refused' | 'unresolved'; reason: string }> {
  const invoice = holdInvoiceFor(deps, orderId);
  if (typeof invoice === 'string') return { kind: 'refused', reason: invoice };
  let callError: unknown;
  try {
    await deps.api.cancelInvoice(invoice.paymentHash);
    deps.emit({ event: 'cancel-called', orderId, paymentHash: invoice.paymentHash, rpc: 'CancelInvoice' });
  } catch (error) {
    callError = error;
  }
  const after = await lookup(deps, invoice.paymentHash);
  if (after === 'not-found' || after === 'unknown') return { kind: 'unresolved', reason: `lookup ${after}` };
  apply(deps, after, 'lookup');
  if (after.state === 'CANCELED') return { kind: 'canceled' };
  return { kind: 'refused', reason: `invoice is ${after.state}${callError === undefined ? '' : `: ${describeError(callError)}`}` };
}

/** Resolves every invoice that is not final by looking it up: the receiver's reconciliation. */
export async function reconcileInvoices(deps: ReceiverDeps, onlyOrder?: string): Promise<{ resolved: number; open: number; unknown: number }> {
  let resolved = 0;
  let open = 0;
  let unknown = 0;
  const recheckSince = new Date(Date.now() - LATE_RECHECK_MS).toISOString();
  const targets = onlyOrder === undefined
    ? [...deps.store.unresolvedInvoices(), ...deps.store.lateInvoiceCandidates(recheckSince)]
    : deps.store.invoicesForOrder(onlyOrder);
  for (const invoice of targets) {
    if (invoice.state === 'canceled') continue;
    if (invoice.state === 'not-created') {
      // LND may have created it after all (a create call that stalled past the window): cancel or adopt it.
      if (invoice.lateLndState === 'CANCELED' || invoice.lateLndState === 'SETTLED') continue;
      const late = await lookup(deps, invoice.paymentHash);
      if (late === 'unknown') { unknown += 1; continue; }
      if (late === 'not-found') continue;
      const result = await resolveLateInvoice(deps, invoice, late, 'lookup');
      if (result.kind === 'unresolved') unknown += 1; else if (result.kind === 'adopted' && late.state !== 'SETTLED') open += 1; else resolved += 1;
      continue;
    }
    const found = await lookup(deps, invoice.paymentHash);
    if (found === 'unknown') { unknown += 1; continue; }
    if (found === 'not-found') {
      // A creating invoice is decided only after the creation window: its create call may still be in flight.
      if (invoice.state === 'creating' && deps.store.markNotCreated(invoice.paymentHash, creationCutoff())) resolved += 1; else unknown += 1;
      continue;
    }
    if (invoice.state === 'creating') deps.store.markCreated(invoice.paymentHash, found.paymentRequest, found.addIndex);
    apply(deps, found, 'lookup');
    if (found.state === 'SETTLED' || found.state === 'CANCELED') resolved += 1; else open += 1;
  }
  return { resolved, open, unknown };
}

const BACKOFF_START_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    const timer = setTimeout(done, ms);
    function done(): void { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); }
    signal.addEventListener('abort', done, { once: true });
  });
}

/**
 * The settlement consumer. Subscribes from the stored cursor (LND replays every
 * settlement after a non-zero settle index), reconnects with backoff, and runs
 * lookups for unresolved invoices on start and every `reconcileIntervalMs`:
 * a subscription is a fast path, the lookups are the ground truth, and LND
 * replays nothing for a cursor of zero.
 */
export async function listen(deps: ReceiverDeps, options: { reconcileIntervalMs: number; signal: AbortSignal }): Promise<void> {
  const { signal } = options;
  const reconcileTick = async (): Promise<void> => {
    try {
      const result = await reconcileInvoices(deps);
      deps.emit({ event: 'reconcile-pass', ...result });
    } catch (error) {
      deps.emit({ event: 'reconcile-pass-failed', error: describeError(error) });
    }
  };
  let reconciling: Promise<void> | undefined;
  const timer = setInterval(() => { reconciling ??= reconcileTick().finally(() => { reconciling = undefined; }); }, options.reconcileIntervalMs);
  try {
    let backoff = BACKOFF_START_MS;
    let first = true;
    while (!signal.aborted) {
      const cursor = deps.store.cursor();
      deps.emit({ event: 'subscribing', rpc: 'SubscribeInvoices', settleIndex: cursor.settleIndex.toString(), addIndex: cursor.addIndex.toString() });
      const subscription = deps.api.subscribeInvoices(cursor, invoice => {
        backoff = BACKOFF_START_MS;
        // A late invoice (recorded not-created, now open in LND) is canceled by the next reconciliation pass; start one now.
        if (apply(deps, invoice, 'subscription') === 'late-invoice') reconciling ??= reconcileTick().finally(() => { reconciling = undefined; });
        return 'continue';
      }, signal);
      if (first) {
        first = false;
        reconciling ??= reconcileTick().finally(() => { reconciling = undefined; });
      }
      try {
        await subscription;
        deps.emit({ event: 'subscription-ended' });
      } catch (error) {
        if (signal.aborted) break;
        deps.emit({ event: 'subscription-lost', error: describeError(error), retryInMs: backoff });
      }
      await delay(backoff, signal);
      backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
    }
  } finally {
    clearInterval(timer);
    await reconciling;
  }
}
