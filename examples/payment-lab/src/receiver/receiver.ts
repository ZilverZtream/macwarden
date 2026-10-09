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
    deps.store.markCreated(paymentHash, created.paymentRequest, created.addIndex);
    deps.emit({ event: 'invoice-created', orderId: input.orderId, paymentHash, rpc: input.hold ? 'AddHoldInvoice' : 'AddInvoice' });
    return { kind: 'created', paymentHash, paymentRequest: created.paymentRequest };
  } catch (error) {
    return await resolveCreation(deps, paymentHash, error);
  }
}

async function resolveCreation(deps: ReceiverDeps, paymentHash: string, error: unknown): Promise<CreateOutcome> {
  if (error instanceof TransportError && error.notDelivered) {
    deps.store.markNotCreated(paymentHash);
    return { kind: 'not-created', paymentHash, reason: error.message };
  }
  const found = await lookup(deps, paymentHash);
  if (found === 'not-found') {
    deps.store.markNotCreated(paymentHash);
    return { kind: 'not-created', paymentHash, reason: describeError(error) };
  }
  if (found === 'unknown') {
    return { kind: 'unresolved', paymentHash, reason: `${describeError(error)}; run "receiver reconcile" to resolve it` };
  }
  deps.store.markCreated(paymentHash, found.paymentRequest, found.addIndex);
  apply(deps, found, 'create-call');
  return { kind: 'created', paymentHash, paymentRequest: found.paymentRequest };
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
  const targets = onlyOrder === undefined ? deps.store.unresolvedInvoices() : deps.store.invoicesForOrder(onlyOrder);
  for (const invoice of targets) {
    if (invoice.state === 'not-created' || invoice.state === 'canceled') continue;
    const found = await lookup(deps, invoice.paymentHash);
    if (found === 'unknown') { unknown += 1; continue; }
    if (found === 'not-found') {
      if (invoice.state === 'creating') { deps.store.markNotCreated(invoice.paymentHash); resolved += 1; } else unknown += 1;
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
        apply(deps, invoice, 'subscription');
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
