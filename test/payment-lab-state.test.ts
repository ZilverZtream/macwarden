import { isAbsolute } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  loadLab, preimageFor, tempDirectory,
  type DecodedPayReq, type FakeInvoiceApi, type FakePayerApi, type Invoice, type Lab, type Payment, type PayerDeps, type PayerStore,
  type ReceiverDeps, type ReceiverStore, type StreamDecision,
} from './helpers/payment-lab-modules.js';

/**
 * Regressions for the payment lab's state machines (examples/payment-lab), audit
 * 6e6665a findings F01-F07 and O03. Each runs the lab's real stores (SQLite through
 * node:sqlite, in a temporary directory), its payer and receiver workflows and its CLI
 * main, against scripted stand-ins for the LND API; no node, no Docker, no credential.
 */

type Stream = (onUpdate: (payment: Payment) => StreamDecision, signal: AbortSignal | undefined) => Promise<void>;

let lab: Lab;
const dir = tempDirectory();

beforeAll(async () => { lab = await loadLab(); });
afterAll(() => dir.remove());

// Every store a test opens is closed after it, also when an assertion failed first (Windows keeps open files locked).
const opened: { close(): void }[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});

/** Opens a payer store: `file` is a name in the temporary directory or a path made with dir.path. */
function payerStore(file: string): PayerStore {
  const store = new lab.PayerStore(isAbsolute(file) ? file : dir.path(file));
  opened.push(store);
  return store;
}

function receiverStore(file: string): ReceiverStore {
  const store = new lab.ReceiverStore(dir.path(file));
  opened.push(store);
  return store;
}

const DESTINATION = `02${'11'.repeat(32)}`;
const quiet = (): void => undefined;

function decoded(paymentHash: string, amountMsat: bigint): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-state' };
}

function payment(label: string, status: 'IN_FLIGHT' | 'FAILED' | 'SUCCEEDED', amountMsat = 1000n): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: amountMsat, feeMsat: status === 'SUCCEEDED' ? 10n : 0n,
    preimage: status === 'SUCCEEDED' ? preimage : undefined, paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '',
    creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
}

function invoice(paymentHash: string, state: string, amtPaidMsat = 0n, settleIndex = 0n): Invoice {
  return { paymentHash, state, memo: '', valueMsat: 1000n, amtPaidMsat, addIndex: 1n, settleIndex, paymentRequest: '', htlcs: [] };
}

/** A stream or call that stays open until the caller's signal aborts. Without a signal it fails at once rather than hang the test. */
function heldUntilAborted(signal: AbortSignal | undefined): Promise<never> {
  return new Promise((_resolve, reject) => {
    const abort = (): void => reject(new lab.TransportError('aborted by the caller', 'response'));
    if (signal === undefined) { reject(new lab.TransportError('no cancellation signal was passed', 'response')); return; }
    if (signal.aborted) { abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
  });
}

/** Lets pending promise callbacks and I/O run until `check` holds (bounded; no timers). */
async function until(check: () => boolean): Promise<void> {
  for (let turn = 0; turn < 2000 && !check(); turn += 1) await new Promise(resolve => setImmediate(resolve));
}

/** Each SendPaymentV2 / TrackPaymentV2 call takes the next scripted stream; with none left, it stays open until aborted. */
class ScriptedPayerApi implements FakePayerApi {
  readonly send: Stream[] = [];
  readonly track: Stream[] = [];
  readonly trackSignals: (AbortSignal | undefined)[] = [];
  invoice: DecodedPayReq | undefined;

  async decodePayReq(): Promise<DecodedPayReq> {
    if (this.invoice === undefined) throw new Error('no invoice scripted');
    return this.invoice;
  }

  sendPaymentV2(_request: unknown, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    return (this.send.shift() ?? ((_update, held) => heldUntilAborted(held)))(onUpdate, signal);
  }

  trackPaymentV2(_paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    this.trackSignals.push(signal);
    return (this.track.shift() ?? ((_update, held) => heldUntilAborted(held)))(onUpdate, signal);
  }
}

function payer(store: PayerStore, api = new ScriptedPayerApi()): PayerDeps & { api: ScriptedPayerApi } {
  return { api, store, emit: quiet };
}

/** Records a budgeted payment of 1000 msat with a 100 msat fee limit: the budget of 1100 msat is then fully held. */
function budgeted(store: PayerStore, label: string, operationId: string): string {
  const { paymentHash } = preimageFor(label);
  store.setBudget('B', 1100n);
  const intent = store.recordIntent({ operationId, kind: 'payout', paymentRequest: `lnbcrt-${label}`, invoice: decoded(paymentHash, 1000n),
    feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' });
  expect(intent.outcome).toBe('recorded');
  return paymentHash;
}

/** A replacement invoice for the operation: admitted only when no payment of the operation is pending. */
function replacement(store: PayerStore, operationId: string): string {
  return store.recordIntent({ operationId, kind: 'payout', paymentRequest: 'lnbcrt-replacement',
    invoice: decoded(preimageFor(`${operationId}-replacement`).paymentHash, 1000n), feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' }).outcome;
}

describe('payment lab payer', () => {
  it('F01: a delayed FAILED from an earlier submission neither fails the live retry nor releases its reservation', async () => {
    const store = payerStore('f01.db');
    const hash = budgeted(store, 'f01', 'OP-F01');
    const deps = payer(store);
    // Submission 1 goes in flight; a concurrent tracker follows it; then LND fails it.
    let releaseSend1: (() => void) | undefined;
    deps.api.send.push(async onUpdate => {
      onUpdate(payment('f01', 'IN_FLIGHT'));
      await new Promise<void>(resolve => { releaseSend1 = resolve; });
      onUpdate(payment('f01', 'FAILED'));
    });
    let tracker1: ((update: Payment) => StreamDecision) | undefined;
    let endTracker1: (() => void) | undefined;
    deps.api.track.push(onUpdate => new Promise<void>(resolve => { tracker1 = onUpdate; endTracker1 = resolve; }));
    const stop = new AbortController();
    const first = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    await until(() => releaseSend1 !== undefined);
    const tracking = lab.reconcile(deps, hash, stop.signal);
    let trackingDone = false;
    void tracking.finally(() => { trackingDone = true; });
    await until(() => tracker1 !== undefined);
    releaseSend1?.();
    expect((await first).kind).toBe('failed');
    // The retry: submission 2 reaches IN_FLIGHT and stays there.
    expect(store.prepareRetry('OP-F01').outcome).toBe('recorded');
    deps.api.send.push((onUpdate, signal) => { onUpdate(payment('f01', 'IN_FLIGHT')); return heldUntilAborted(signal); });
    const second = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none', signal: stop.signal });
    await until(() => store.payment(hash)?.state === 'in_flight');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
    // Now the first tracker's delayed FAILED snapshot arrives.
    tracker1?.(payment('f01', 'FAILED'));
    endTracker1?.();
    await until(() => deps.api.trackSignals.length === 2 || trackingDone);
    expect(store.payment(hash)).toMatchObject({ state: 'in_flight', submissions: 2 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
    expect(replacement(store, 'OP-F01')).toBe('refused');
    expect(store.events(hash).map(item => item.kind)).toContain('stale-update');
    stop.abort();
    expect((await second).kind).toBe('unresolved');
    expect((await tracking).kind).toBe('unresolved');
    store.close();
  });

  it('F01: a SUCCEEDED read for an earlier submission is still recorded (the money left)', async () => {
    const store = payerStore('f01-success.db');
    const hash = budgeted(store, 'f01-success', 'OP-F01S');
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(payment('f01-success', 'FAILED'), 'SendPaymentV2', 1);
    expect(store.prepareRetry('OP-F01S').outcome).toBe('recorded');
    expect(store.claimForSubmission(hash)).toBe(true);
    expect(store.applyUpdate(payment('f01-success', 'SUCCEEDED'), 'TrackPaymentV2', 1).state).toBe('succeeded');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 1010n });
    store.close();
  });

  it.each([
    ['DeadlineExceeded behind a gateway 504', 4, 504],
    ['Unavailable', 14, 503],
    ['a gateway 502 without a gRPC code', undefined, 502],
    ['a gateway 504 without a gRPC code', undefined, 504],
  ])('F02: %s then NotFound leaves the payment uncertain with its reservation held', async (_name, grpcCode, httpStatus) => {
    const store = payerStore(`f02-${String(grpcCode)}-${httpStatus}.db`);
    const hash = budgeted(store, `f02-${String(grpcCode)}-${httpStatus}`, 'OP-F02');
    const deps = payer(store);
    deps.api.send.push(async () => { throw new lab.LndError('upstream deadline exceeded', grpcCode, httpStatus); });
    deps.api.track.push(async () => { throw new lab.LndError('payment isn\'t initiated', 5, 404); });
    const outcome = await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    expect(outcome).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
    expect(store.payment(hash)?.state).toBe('uncertain');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
    expect(replacement(store, 'OP-F02')).toBe('refused');
    store.close();
  });

  it('F02: a definite refusal then NotFound still fails the payment before initiation and releases it', async () => {
    const store = payerStore('f02-definite.db');
    const hash = budgeted(store, 'f02-definite', 'OP-F02D');
    const deps = payer(store);
    deps.api.send.push(async () => { throw new lab.LndError('invoice expired', 2, 500); });
    deps.api.track.push(async () => { throw new lab.LndError('payment isn\'t initiated', 5, 404); });
    const outcome = await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    expect(outcome.kind).toBe('failed');
    expect(store.payment(hash)?.failureReason).toMatch(/^REJECTED_BEFORE_INITIATION/);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    store.close();
  });

  it('F05: the recovery lookup after a submission error carries the caller\'s cancellation signal', async () => {
    const store = payerStore('f05.db');
    const hash = budgeted(store, 'f05', 'OP-F05');
    const deps = payer(store);
    const stop = new AbortController();
    deps.api.send.push(async () => { stop.abort(); throw new lab.LndError('upstream deadline exceeded', 4, 504); });
    const outcome = await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none', signal: stop.signal });
    expect(deps.api.trackSignals).toHaveLength(1);
    expect(deps.api.trackSignals[0]).toBe(stop.signal);
    expect(outcome).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
    store.close();
  });

  it('O03: budget admission reads reservations through a budget index, also after upgrading an existing database', () => {
    const file = dir.path('o03.db');
    const store = payerStore(file);
    budgeted(store, 'o03', 'OP-O03');
    const plan = (): string => store.db.prepare(`EXPLAIN QUERY PLAN SELECT
        COALESCE(SUM(CASE WHEN state = 'held' THEN principal_msat + fee_allowance_msat END), 0) AS held
      FROM reservations WHERE budget_id = ?`).all('B').map(row => String(row.detail)).join('\n');
    expect(plan()).toMatch(/SEARCH reservations USING INDEX reservations_by_budget \(budget_id=\?\)/);
    // A database written before the index existed: the migration builds it over the existing rows.
    store.db.exec('DROP INDEX reservations_by_budget; PRAGMA user_version = 3');
    store.close();
    const upgraded = payerStore(file);
    expect(upgraded.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'reservations_by_budget'`).all()).toHaveLength(1);
    expect(upgraded.budgetStatus('B')).toMatchObject({ heldMsat: 1100n });
    upgraded.close();
  });
});

describe('payment lab CLI', () => {
  let stdout: string[];
  beforeEach(() => {
    stdout = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => { vi.restoreAllMocks(); });

  /** main with the payer profile opened on `file` (a fresh store per call: main closes it) and the scripted API. */
  function services(file: string, api: ScriptedPayerApi) {
    return {
      payer: () => ({ api, store: payerStore(file), emit: quiet }),
      receiver: (): ReceiverDeps => { throw new Error('not used'); },
    };
  }

  function outcomes(): Record<string, unknown>[] {
    return stdout.flatMap(chunk => chunk.split('\n')).filter(line => line !== '')
      .map(line => JSON.parse(line) as Record<string, unknown>).filter(event => event.event === 'outcome');
  }

  it('F04: an invalid --timeout-s on retry is a usage error that changes nothing, and the corrected retry runs', async () => {
    const file = dir.path('f04-retry.db');
    const setup = payerStore(file);
    const hash = budgeted(setup, 'f04', 'OP-F04');
    expect(setup.claimForSubmission(hash)).toBe(true);
    setup.applyUpdate(payment('f04', 'FAILED'), 'SendPaymentV2', 1);
    setup.close();
    const api = new ScriptedPayerApi();
    const run = services(file, api);
    expect(await lab.main(['payer', 'retry', '--as', 'customer-payer', '--operation', 'OP-F04', '--timeout-s', 'banana'], run)).toBe(2);
    const after = payerStore(file);
    expect(after.payment(hash)?.state).toBe('failed');
    expect(after.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    after.close();
    api.send.push(async onUpdate => { onUpdate(payment('f04', 'SUCCEEDED')); });
    expect(await lab.main(['payer', 'retry', '--as', 'customer-payer', '--operation', 'OP-F04', '--timeout-s', '30'], run)).toBe(0);
  });

  it('F04: an invalid --timeout-s on pay is a usage error before the intent is recorded', async () => {
    const file = dir.path('f04-pay.db');
    const setup = payerStore(file);
    setup.setBudget('B', 1100n);
    setup.close();
    const api = new ScriptedPayerApi();
    const { paymentHash } = preimageFor('f04-pay');
    api.invoice = decoded(paymentHash, 1000n);
    expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-F04-PAY', '--kind', 'payout', '--invoice', 'lnbcrt1f04pay',
      '--fee-limit-msat', '100', '--budget', 'B', '--timeout-s', 'banana'], services(file, api))).toBe(2);
    const after = payerStore(file);
    expect(after.operation('OP-F04-PAY')).toBeUndefined();
    expect(after.payment(paymentHash)).toBeUndefined();
    expect(after.budgetStatus('B')).toMatchObject({ heldMsat: 0n });
    after.close();
  });

  it('F06: reconciling a payment LND reports failed exits 1, as pay and retry do', async () => {
    const file = dir.path('f06.db');
    const setup = payerStore(file);
    const hash = budgeted(setup, 'f06', 'OP-F06');
    expect(setup.claimForSubmission(hash)).toBe(true);
    setup.applyUpdate(payment('f06', 'IN_FLIGHT'), 'SendPaymentV2', 1);
    setup.close();
    const api = new ScriptedPayerApi();
    api.track.push(async onUpdate => { onUpdate(payment('f06', 'FAILED')); });
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer', '--payment-hash', hash], services(file, api))).toBe(1);
    expect(outcomes()).toEqual([expect.objectContaining({ kind: 'failed', paymentHash: hash })]);
  });
});

describe('payment lab receiver', () => {
  it('F03: a hold invoice whose order another invoice fulfilled during the lookup is refused, not settled', async () => {
    const store = receiverStore('f03.db');
    const late = preimageFor('f03-late');
    const hold = preimageFor('f03-hold');
    // A: the create call was recorded not-created; B: the order's live hold invoice.
    expect(store.recordInvoiceIntent({ orderId: 'ORD-F03', amountMsat: 1000n, kind: 'standard', ...late }).outcome).toBe('recorded');
    expect(store.markNotCreated(late.paymentHash)).toBe(true);
    expect(store.recordInvoiceIntent({ orderId: 'ORD-F03', amountMsat: 1000n, kind: 'hold', ...hold }).outcome).toBe('recorded');
    expect(store.markCreated(hold.paymentHash, 'lnbcrt-f03-hold', 2n)).toBe('open');
    const settled: string[] = [];
    let lookups = 0;
    const api: FakeInvoiceApi = {
      lookupInvoice: async paymentHash => {
        lookups += 1;
        // While the first lookup is awaited, A turns up late and paid: it fulfills the order.
        if (lookups === 1) expect(store.applyInvoice(invoice(late.paymentHash, 'SETTLED', 1000n, 7n), 'subscription')).toBe('fulfilled');
        return invoice(paymentHash, settled.length > 0 ? 'SETTLED' : 'ACCEPTED', settled.length > 0 ? 1000n : 0n, settled.length > 0 ? 8n : 0n);
      },
      settleInvoice: async preimage => { settled.push(preimage); },
      cancelInvoice: async () => undefined,
      subscribeInvoices: (_from, _onInvoice, signal) => heldUntilAborted(signal),
    };
    const outcome = await lab.settleHoldInvoice({ api, store, emit: quiet }, 'ORD-F03');
    expect(outcome.kind).toBe('refused');
    expect(outcome.reason).toMatch(/fulfilled by invoice/);
    expect(settled).toHaveLength(0);
    expect(store.fulfillmentCount('ORD-F03')).toBe(1);
    expect(store.ledger('ORD-F03')).toHaveLength(1);
    store.close();
  });

  /** Three orders with open invoices, and a listener whose subscription stays open until it is stopped. */
  function threeOpenInvoices(name: string): { deps: (api: FakeInvoiceApi) => ReceiverDeps; close(): void; orders: string[] } {
    const store = receiverStore(name);
    const orders = ['ORD-1', 'ORD-2', 'ORD-3'];
    for (const orderId of orders) {
      const identity = preimageFor(`${name}-${orderId}`);
      expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...identity }).outcome).toBe('recorded');
      expect(store.markCreated(identity.paymentHash, `lnbcrt-${orderId}`, 1n)).toBe('open');
    }
    return { deps: api => ({ api, store, emit: quiet }), close: () => store.close(), orders };
  }

  it('F07: stopping the listener cuts off the reconciliation lookup in progress and starts no further lookup', async () => {
    const fixture = threeOpenInvoices('f07.db');
    const stop = new AbortController();
    const lookups: { paymentHash: string; signal: AbortSignal | undefined }[] = [];
    let releaseFirst: ((value: Invoice) => void) | undefined;
    const api: FakeInvoiceApi = {
      lookupInvoice: (paymentHash, signal) => {
        lookups.push({ paymentHash, signal });
        if (lookups.length > 1) return Promise.resolve(invoice(paymentHash, 'OPEN'));
        return new Promise<Invoice>((resolve, reject) => {
          releaseFirst = resolve;
          signal?.addEventListener('abort', () => reject(new lab.TransportError('aborted by the caller', 'response')), { once: true });
        });
      },
      settleInvoice: async () => undefined,
      cancelInvoice: async () => undefined,
      subscribeInvoices: (_from, _onInvoice, signal) => heldUntilAborted(signal),
    };
    const listening = lab.listen(fixture.deps(api), { reconcileIntervalMs: 3_600_000, signal: stop.signal });
    await until(() => lookups.length === 1);
    stop.abort();
    releaseFirst?.(invoice(lookups[0]?.paymentHash ?? '', 'OPEN'));
    await listening;
    expect(lookups).toHaveLength(1);
    expect(lookups[0]?.signal?.aborted).toBe(true);
    fixture.close();
  });

  it('F07: an outcome recorded before the stop stays recorded; the remaining invoices are not looked up', async () => {
    const fixture = threeOpenInvoices('f07-durable.db');
    const stop = new AbortController();
    const looked: string[] = [];
    const api: FakeInvoiceApi = {
      lookupInvoice: async paymentHash => {
        looked.push(paymentHash);
        if (looked.length === 1) { stop.abort(); return invoice(paymentHash, 'SETTLED', 1000n, 1n); }
        return invoice(paymentHash, 'OPEN');
      },
      settleInvoice: async () => undefined,
      cancelInvoice: async () => undefined,
      subscribeInvoices: (_from, _onInvoice, signal) => heldUntilAborted(signal),
    };
    const deps = fixture.deps(api);
    await lab.listen(deps, { reconcileIntervalMs: 3_600_000, signal: stop.signal });
    expect(looked).toHaveLength(1);
    const fulfilled = fixture.orders.filter(orderId => deps.store.order(orderId)?.state === 'fulfilled');
    expect(fulfilled).toHaveLength(1);
    expect(deps.store.fulfillmentCount(fulfilled[0] ?? '')).toBe(1);
    fixture.close();
  });
});
