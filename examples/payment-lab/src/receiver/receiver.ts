import { randomBytes } from 'node:crypto';
import type { InvoiceApi } from '../lnd/api.ts';
import { LndError, TransportError, definiteRefusal, describeError } from '../lnd/errors.ts';
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
async function lookup(deps: ReceiverDeps, paymentHash: string, signal?: AbortSignal): Promise<Invoice | 'not-found' | 'unknown'> {
  try {
    return await deps.api.lookupInvoice(paymentHash, signal);
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
 * - LND itself refused the create call (definiteRefusal in lnd/errors.ts; the creator saw the
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

/** The classification of create-call errors; it lives with the error types because the payer uses it too. */
export { definiteRefusal };

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

export type CreateOutcome =
  | { kind: 'created'; paymentHash: string; paymentRequest: string }
  | { kind: 'refused'; reason: string }
  | { kind: 'not-created'; paymentHash: string; reason: string }
  | { kind: 'canceled'; paymentHash: string; reason: string }
  | { kind: 'unresolved'; paymentHash: string; reason: string };

/**
 * The invoice was canceled (a reconciliation pass, "receiver cancel", or LND) while its
 * create call was in flight: the record says canceled, and so does the outcome.
 */
function canceledOnCreation(deps: ReceiverDeps, paymentHash: string): CreateOutcome | undefined {
  const record = deps.store.invoice(paymentHash);
  if (record?.state !== 'canceled') return undefined;
  const reason = `invoice ${paymentHash} of order ${record.orderId} was canceled before its creation was recorded; it is not payable`;
  deps.emit({ event: 'invoice-canceled-on-creation', orderId: record.orderId, paymentHash, reason });
  return { kind: 'canceled', paymentHash, reason };
}

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
    const canceled = canceledOnCreation(deps, paymentHash);
    if (canceled !== undefined) return canceled;
    deps.emit({ event: 'invoice-created', orderId: input.orderId, paymentHash, rpc: input.hold ? 'AddHoldInvoice' : 'AddInvoice' });
    if (deps.store.isSuperseded(paymentHash)) return await supersededOnCreation(deps, paymentHash, undefined);
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
  const canceled = canceledOnCreation(deps, paymentHash);
  if (canceled !== undefined) return canceled;
  if (deps.store.isSuperseded(paymentHash)) return await supersededOnCreation(deps, paymentHash, found);
  return { kind: 'created', paymentHash, paymentRequest: found.paymentRequest };
}

/** The order was fulfilled by another invoice while this one's create call was in flight: it is canceled as it turns up. */
async function supersededOnCreation(deps: ReceiverDeps, paymentHash: string, found: Invoice | undefined): Promise<CreateOutcome> {
  const record = deps.store.invoice(paymentHash);
  const result = record === undefined ? 'failed' : await supersede(deps, record, found);
  const what = `order ${record?.orderId} was fulfilled by another invoice while the create call for ${paymentHash} was in flight`;
  if (result === 'canceled') return { kind: 'not-created', paymentHash, reason: `${what}; the invoice was canceled in LND` };
  if (result === 'paid') return { kind: 'unresolved', paymentHash, reason: `${what}; it was paid before it could be canceled (second-payment)` };
  return { kind: 'unresolved', paymentHash, reason: `${what}; canceling it in LND failed; run "receiver reconcile" to try again` };
}

type SupersedeResult = 'canceled' | 'paid' | 'waiting' | 'failed';

/**
 * One reconciliation pass: the invoices whose superseded cancel was already tried in
 * it (one CancelInvoice per invoice per pass) with how each attempt ended, and the
 * caller's cancellation: once it aborts, the pass starts no further call and its
 * lookups are cut off (what was already recorded stays recorded).
 */
interface Pass { handled: Map<string, SupersedeResult>; signal?: AbortSignal }

/**
 * A superseded invoice: its order was fulfilled by another invoice (an invoice recorded
 * not-created that turned up late and was paid first), and it is still `creating`,
 * `open` or `accepted` in the record. The rule: it is canceled in LND with
 * CancelInvoice in the same step that fulfills the order (whichever invoice settles
 * first fulfills it), so the customer cannot pay the order twice; an accepted HTLC
 * returns to the payer. One whose create call is still in flight is canceled as soon
 * as it turns up (the create call's answer, the subscription, a reconciliation
 * lookup). Until LND reports it canceled, every reconciliation pass tries again
 * (`superseded-invoice-cancel-failed`). If it was paid before the cancel reached LND,
 * the payment is a `second-payment`: posted, reported, to be returned.
 *
 * `found` is LND's state, already applied by the caller; without it, it is looked up.
 */
async function supersede(deps: ReceiverDeps, record: InvoiceRecord, found: Invoice | undefined, pass?: Pass):
  Promise<SupersedeResult | 'skipped'> {
  if (pass?.handled.has(record.paymentHash)) return 'skipped';
  const result = await supersedeOnce(deps, record, found, pass);
  pass?.handled.set(record.paymentHash, result);
  return result;
}

async function supersedeOnce(deps: ReceiverDeps, record: InvoiceRecord, found: Invoice | undefined, pass?: Pass): Promise<SupersedeResult> {
  const { paymentHash, orderId } = record;
  // Marked before the first await, so a nested step of this pass does not try it again; the result is set by supersede.
  pass?.handled.set(paymentHash, 'failed');
  const what = `order ${orderId} was fulfilled by another invoice, and its invoice ${paymentHash} was still ${record.state}`;
  const failed = (reason: string): 'failed' => {
    deps.emit({ event: 'superseded-invoice-cancel-failed', orderId, paymentHash, reason: `${what}; ${reason}; the next reconciliation tries again` });
    return 'failed';
  };
  let current = found;
  if (current === undefined) {
    if (pass?.signal?.aborted) return failed('stopped before its lookup');
    const looked = await lookup(deps, paymentHash, pass?.signal);
    if (looked === 'not-found' && record.state === 'creating') return 'waiting'; // the create call may still be in flight
    if (looked === 'not-found' || looked === 'unknown') return failed(`lookup ${looked}`);
    if (record.state === 'creating') deps.store.markCreated(paymentHash, looked.paymentRequest, looked.addIndex);
    apply(deps, looked, 'lookup');
    current = looked;
  }
  if (current.state === 'SETTLED') return 'paid';
  if (current.state !== 'CANCELED') {
    if (pass?.signal?.aborted) return failed('stopped before CancelInvoice');
    let callError: unknown;
    try {
      await deps.api.cancelInvoice(paymentHash);
      deps.emit({ event: 'cancel-called', orderId, paymentHash, rpc: 'CancelInvoice', reason: what });
    } catch (error) {
      callError = error;
    }
    const after = await lookup(deps, paymentHash, pass?.signal);
    if (after !== 'not-found' && after !== 'unknown') apply(deps, after, 'lookup');
    if (after !== 'not-found' && after !== 'unknown' && after.state === 'SETTLED') return 'paid';
    if (after === 'not-found' || after === 'unknown' || after.state !== 'CANCELED') {
      return failed(`CancelInvoice ${callError === undefined ? 'sent' : `failed: ${describeError(callError)}`}, `
        + `invoice ${after === 'not-found' || after === 'unknown' ? `lookup ${after}` : after.state}`);
    }
  }
  deps.emit({ event: 'superseded-invoice-canceled', orderId, paymentHash, reason: `${what}; it was canceled in LND` });
  return 'canceled';
}

/** After a delivery that fulfilled an order: cancels every superseded invoice of the order, in the same step. */
async function supersedeOthers(deps: ReceiverDeps, outcome: DeliveryOutcome, paymentHash: string, pass?: Pass): Promise<void> {
  if (outcome !== 'fulfilled') return;
  const orderId = deps.store.invoice(paymentHash)?.orderId;
  if (orderId === undefined) return;
  for (const record of deps.store.supersededInvoices(orderId)) await supersede(deps, record, undefined, pass);
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
export async function resolveLateInvoice(deps: ReceiverDeps, record: InvoiceRecord, found: Invoice, source: DeliverySource,
  pass?: Pass): Promise<LateOutcome> {
  const { paymentHash, orderId } = record;
  const what = `LND holds invoice ${paymentHash} (${found.state}) for order ${orderId} after it was recorded as not created`;
  const outcome = apply(deps, found, source);
  // Paid late, and first: it fulfilled the order, so the order's replacement is canceled now.
  await supersedeOthers(deps, outcome, paymentHash, pass);
  if (deps.store.invoice(paymentHash)?.state !== 'not-created') {
    const reason = `${what}; the order had no other live invoice, so it was adopted`;
    deps.emit({ event: 'late-invoice-adopted', orderId, paymentHash, lndState: found.state, reason });
    return { kind: 'adopted', reason };
  }
  if (outcome !== 'late-invoice') return { kind: 'recorded', reason: `${what}; recorded (${outcome})` };
  if (pass?.signal?.aborted) return { kind: 'unresolved', reason: `${what}; stopped before CancelInvoice; the next reconciliation tries again` };
  let callError: unknown;
  try {
    await deps.api.cancelInvoice(paymentHash);
    deps.emit({ event: 'cancel-called', orderId, paymentHash, rpc: 'CancelInvoice', reason: what });
  } catch (error) {
    callError = error;
  }
  const after = await lookup(deps, paymentHash, pass?.signal);
  // Paid before the cancel reached LND, and first: it fulfilled the order, so the replacement is canceled now.
  if (after !== 'not-found' && after !== 'unknown') await supersedeOthers(deps, apply(deps, after, 'lookup'), paymentHash, pass);
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
  // Settling a superseded hold invoice would take a second payment for a fulfilled order; it is to be canceled.
  if (typeof invoice !== 'string' && deps.store.isSuperseded(invoice.paymentHash)) {
    return { kind: 'refused', reason: `order ${orderId} was already fulfilled by another invoice; invoice ${invoice.paymentHash} is to be `
      + 'canceled ("receiver reconcile" or "receiver cancel"), not settled' };
  }
  if (typeof invoice === 'string') return { kind: 'refused', reason: invoice };
  const before = await lookup(deps, invoice.paymentHash);
  if (before === 'not-found' || before === 'unknown') return { kind: 'unresolved', reason: `invoice lookup: ${before}` };
  const beforeOutcome = apply(deps, before, 'lookup');
  if (before.state === 'SETTLED') return { kind: 'settled', outcome: beforeOutcome };
  if (before.state !== 'ACCEPTED') return { kind: 'refused', reason: `invoice is ${before.state}; settle only after LND accepted the HTLCs` };
  // The lookup was awaited: meanwhile another invoice's settlement may have fulfilled the order. Checked again in one
  // transaction, with nothing awaited between this check and the SettleInvoice request below.
  const refusal = deps.store.settleRefusal(invoice.paymentHash);
  if (refusal !== undefined) {
    return { kind: 'refused', reason: `${refusal}; invoice ${invoice.paymentHash} is to be canceled ("receiver reconcile" or "receiver cancel"), `
      + 'not settled' };
  }
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

/**
 * Whether a looked-up invoice is decided: settled or canceled, by LND's answer or by the
 * record (canceled is final, also when a stale lookup still says OPEN), or a not-created
 * record that stays not-created (a late invoice LND canceled or settled, or one it does not hold).
 */
function decided(deps: ReceiverDeps, paymentHash: string, lndState: string): boolean {
  const state = deps.store.invoice(paymentHash)?.state;
  return lndState === 'SETTLED' || lndState === 'CANCELED' || state === 'settled' || state === 'canceled' || state === 'not-created';
}

/** A record reconciliation has nothing left to do for: settled, canceled, or a not-created one LND canceled or settled. */
function final(invoice: InvoiceRecord): boolean {
  return invoice.state === 'settled' || invoice.state === 'canceled'
    || (invoice.state === 'not-created' && (invoice.lateLndState === 'CANCELED' || invoice.lateLndState === 'SETTLED'));
}

type Bucket = 'resolved' | 'open' | 'unknown';

/** How a superseded cancel tried in the pass counts: canceled or paid is decided; failed or still waiting for its create call is not. */
function supersededBucket(result: SupersedeResult): Bucket {
  return result === 'canceled' || result === 'paid' ? 'resolved' : 'unknown';
}

/**
 * Resolves every invoice that is not final by looking it up: the receiver's reconciliation.
 * Once `signal` aborts, no further invoice is looked up and the lookup in progress is cut
 * off; invoices not decided in this pass count as unknown. Recorded outcomes stay recorded.
 * Every target is counted exactly once: resolved (settled, canceled, or not-created and
 * staying so), open (OPEN or ACCEPTED in LND), or unknown (not decided in this pass).
 */
export async function reconcileInvoices(deps: ReceiverDeps, onlyOrder?: string, signal?: AbortSignal):
  Promise<{ resolved: number; open: number; unknown: number }> {
  const recheckSince = new Date(Date.now() - LATE_RECHECK_MS).toISOString();
  const listed = onlyOrder === undefined
    ? [...deps.store.unresolvedInvoices(), ...deps.store.lateInvoiceCandidates(recheckSince)]
    : deps.store.invoicesForOrder(onlyOrder);
  const targets = [...new Map(listed.map(item => [item.paymentHash, item])).values()];
  const pass: Pass = { handled: new Map(), signal };
  // Each target lands in exactly one bucket: resolved, open and unknown partition the targets.
  const buckets = new Map<string, Bucket>();
  for (const invoice of targets) {
    const { paymentHash } = invoice;
    // Settled and canceled are final, also when the pass was stopped before reaching them.
    if (final(invoice)) { buckets.set(paymentHash, 'resolved'); continue; }
    if (signal?.aborted) { buckets.set(paymentHash, 'unknown'); continue; }
    // Already canceled (or tried) in this pass, as a superseded invoice of an order fulfilled earlier in it: counted below.
    if (pass.handled.has(paymentHash)) continue;
    if (invoice.state === 'not-created') {
      // LND may have created it after all (a create call that stalled past the window): cancel or adopt it.
      const late = await lookup(deps, paymentHash, signal);
      if (late === 'unknown') { buckets.set(paymentHash, 'unknown'); continue; }
      // LND does not hold it: it stays not-created, which is decided.
      if (late === 'not-found') { buckets.set(paymentHash, 'resolved'); continue; }
      const result = await resolveLateInvoice(deps, invoice, late, 'lookup', pass);
      buckets.set(paymentHash, result.kind === 'unresolved' ? 'unknown' : decided(deps, paymentHash, late.state) ? 'resolved' : 'open');
      continue;
    }
    const found = await lookup(deps, paymentHash, signal);
    if (found === 'unknown') { buckets.set(paymentHash, 'unknown'); continue; }
    if (found === 'not-found') {
      // A creating invoice is decided only after the creation window: its create call may still be in flight.
      const notCreated = invoice.state === 'creating' && deps.store.markNotCreated(paymentHash, creationCutoff());
      buckets.set(paymentHash, notCreated ? 'resolved' : 'unknown');
      continue;
    }
    if (invoice.state === 'creating') deps.store.markCreated(paymentHash, found.paymentRequest, found.addIndex);
    const outcome = apply(deps, found, 'lookup');
    await supersedeOthers(deps, outcome, paymentHash, pass);
    if (deps.store.isSuperseded(paymentHash)) {
      // Its order was fulfilled by another invoice: cancel it (retried on every pass until LND reports it canceled).
      await supersede(deps, invoice, found, pass);
      continue;
    }
    buckets.set(paymentHash, decided(deps, paymentHash, found.state) ? 'resolved' : 'open');
  }
  const counts = { resolved: 0, open: 0, unknown: 0 };
  for (const { paymentHash } of targets) {
    // A superseded cancel tried in this pass is the latest word on that invoice, also when it was counted open
    // before a later invoice in the pass fulfilled its order.
    const superseded = pass.handled.get(paymentHash);
    counts[superseded === undefined ? buckets.get(paymentHash) ?? 'unknown' : supersededBucket(superseded)] += 1;
  }
  return counts;
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
      const result = await reconcileInvoices(deps, undefined, signal);
      deps.emit({ event: 'reconcile-pass', ...result });
    } catch (error) {
      deps.emit({ event: 'reconcile-pass-failed', error: describeError(error) });
    }
  };
  let reconciling: Promise<void> | undefined;
  // Superseded cancels started by subscription deliveries, run one after another.
  let superseding: Promise<void> = Promise.resolve();
  const supersedeLater = (work: () => Promise<unknown>): void => {
    superseding = superseding.then(work).then(() => undefined, (error: unknown) => {
      deps.emit({ event: 'supersede-failed', error: describeError(error) });
    });
  };
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
        const outcome = apply(deps, invoice, 'subscription');
        if (outcome === 'late-invoice') reconciling ??= reconcileTick().finally(() => { reconciling = undefined; });
        // A fulfillment cancels the order's superseded invoices at once; so does a superseded invoice turning up in LND.
        if (outcome === 'fulfilled') supersedeLater(() => supersedeOthers(deps, outcome, invoice.paymentHash, { handled: new Map(), signal }));
        else if ((invoice.state === 'OPEN' || invoice.state === 'ACCEPTED') && deps.store.isSuperseded(invoice.paymentHash)) {
          supersedeLater(async () => {
            const record = deps.store.invoice(invoice.paymentHash);
            if (record !== undefined && deps.store.isSuperseded(record.paymentHash)) {
              await supersede(deps, record, undefined, { handled: new Map(), signal });
            }
          });
        }
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
    await superseding;
  }
}
