import { existsSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  loadLab, loadLabModule, preimageFor, tempDirectory,
  type DecodedPayReq, type FakeInvoiceApi, type FakePayerApi, type HtlcAttempt, type Invoice, type Lab, type Payment, type PayerDeps, type PayerStore,
  type ReceiverDeps, type ReceiverStore, type StreamDecision,
} from './helpers/payment-lab-modules.js';

/**
 * Regressions for the payment lab's state machines (examples/payment-lab), audit
 * 6e6665a findings F01-F07 and O03, the verifier's residuals of those fixes (V1-V6) and
 * the owner's reviewers' findings (L1-L4). Each runs the lab's real stores (SQLite through
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

function payment(label: string, status: 'IN_FLIGHT' | 'FAILED' | 'SUCCEEDED', amountMsat = 1000n, htlcs: HtlcAttempt[] = []): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: amountMsat, feeMsat: status === 'SUCCEEDED' ? 10n : 0n,
    preimage: status === 'SUCCEEDED' ? preimage : undefined, paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '',
    creationTimeNs: 1n, paymentIndex: '1', htlcs };
}

/** One HTLC attempt over a one-hop route, delivering 1000 msat. */
function attempt(attemptId: string, status: HtlcAttempt['status']): HtlcAttempt {
  return { attemptId, status, route: { totalAmtMsat: 1000n, totalFeesMsat: 0n, hops: [{ chanId: '1', pubKey: DESTINATION, amtToForwardMsat: 1000n }] },
    principalMsat: 1000n, attemptTimeNs: 1n, resolveTimeNs: status === 'IN_FLIGHT' ? 0n : 2n,
    failureCode: status === 'FAILED' ? 'TEMPORARY_CHANNEL_FAILURE' : undefined, failureSourceIndex: status === 'FAILED' ? 1 : undefined };
}

/** The HTLC attempts recorded for a payment, as "attempt:submission:status". */
function attemptTags(store: PayerStore): string[] {
  return store.db.prepare('SELECT attempt_id, submission, status FROM htlc_attempts ORDER BY attempt_id').all()
    .map(row => `${String(row.attempt_id)}:${String(row.submission)}:${String(row.status)}`);
}

const notFound = (): Promise<never> => Promise.reject(new lab.LndError('payment isn\'t initiated', 5, 404));

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

  it('V1: a definite refusal and NotFound for an earlier submission neither fail the live one nor release its reservation', async () => {
    const store = payerStore('v1.db');
    const hash = budgeted(store, 'v1', 'OP-V1');
    const deps = payer(store);
    let refuseFirst: ((error: unknown) => void) | undefined;
    deps.api.send.push(() => new Promise<void>((_resolve, reject) => { refuseFirst = reject; }));
    const first = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    await until(() => refuseFirst !== undefined);
    // Another process reconciles while submission 1 is on its way: LND has nothing yet, so back to intent.
    deps.api.track.push(notFound);
    expect((await lab.reconcile(deps, hash)).kind).toBe('not-submitted');
    // Submission 2 is claimed; its request is on its way.
    const stop = new AbortController();
    const second = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none', signal: stop.signal });
    await until(() => store.payment(hash)?.submissions === 2);
    // Submission 1 ends with a definite refusal; its lookup finds nothing (LND has not initiated submission 2 yet).
    deps.api.track.push(notFound);
    refuseFirst?.(new lab.LndError('rate limit exceeded', 8, 429));
    const outcome = await first;
    expect(outcome.kind).toBe('unresolved');
    expect(outcome.reason).toMatch(/superseded/);
    expect(store.payment(hash)).toMatchObject({ state: 'submitting', submissions: 2 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
    expect(replacement(store, 'OP-V1')).toBe('refused');
    expect(store.events(hash).map(item => item.kind)).toContain('stale-update');
    stop.abort();
    await second;
  });

  it('V2: an earlier submission\'s stream ending with a stale FAILED changes nothing and reports its own outcome', async () => {
    const store = payerStore('v2.db');
    const hash = budgeted(store, 'v2', 'OP-V2');
    const deps = payer(store);
    let releaseFirst: (() => void) | undefined;
    deps.api.send.push(async onUpdate => {
      onUpdate(payment('v2', 'IN_FLIGHT', 1000n, [attempt('1', 'IN_FLIGHT')]));
      await new Promise<void>(resolve => { releaseFirst = resolve; });
      onUpdate(payment('v2', 'FAILED', 1000n, [attempt('1', 'FAILED')]));
    });
    const first = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    await until(() => releaseFirst !== undefined);
    // A tracker in another process records LND's FAILED for submission 1, and the operator retries.
    store.applyUpdate(payment('v2', 'FAILED', 1000n, [attempt('1', 'FAILED')]), 'TrackPaymentV2', 1);
    expect(store.prepareRetry('OP-V2').outcome).toBe('recorded');
    const stop = new AbortController();
    deps.api.send.push((onUpdate, signal) => {
      onUpdate(payment('v2', 'IN_FLIGHT', 1000n, [attempt('1', 'FAILED'), attempt('2', 'IN_FLIGHT')]));
      return heldUntilAborted(signal);
    });
    const second = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none', signal: stop.signal });
    await until(() => store.payment(hash)?.state === 'in_flight');
    const before = store.events(hash).length;
    // Submission 1's stream now delivers its FAILED and ends.
    releaseFirst?.();
    const outcome = await first;
    expect(outcome).toMatchObject({ kind: 'unresolved', state: 'in_flight' });
    expect(outcome.reason).toMatch(/FAILED.*superseded/);
    expect(store.payment(hash)).toMatchObject({ state: 'in_flight', submissions: 2 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
    expect(store.events(hash).slice(before).map(item => item.kind)).toEqual(['stale-update']);
    // Each attempt carries the submission it was first seen for.
    expect(attemptTags(store)).toEqual(['1:1:FAILED', '2:2:IN_FLIGHT']);
    stop.abort();
    await second;
  });

  it('V3: a refused connection of an earlier submission does not revert the live one to intent', async () => {
    const store = payerStore('v3.db');
    const hash = budgeted(store, 'v3', 'OP-V3');
    const deps = payer(store);
    let failFirst: ((error: unknown) => void) | undefined;
    deps.api.send.push(() => new Promise<void>((_resolve, reject) => { failFirst = reject; }));
    const first = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    await until(() => failFirst !== undefined);
    deps.api.track.push(notFound);
    expect((await lab.reconcile(deps, hash)).kind).toBe('not-submitted');
    let releaseSecond: (() => void) | undefined;
    deps.api.send.push(async onUpdate => {
      await new Promise<void>(resolve => { releaseSecond = resolve; });
      onUpdate(payment('v3', 'IN_FLIGHT'));
      onUpdate(payment('v3', 'FAILED'));
    });
    const second = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    await until(() => releaseSecond !== undefined);
    failFirst?.(new lab.TransportError('connect ECONNREFUSED', 'connect'));
    const outcome = await first;
    expect(outcome.kind).toBe('unresolved');
    expect(outcome.reason).toMatch(/superseded/);
    expect(store.payment(hash)).toMatchObject({ state: 'submitting', submissions: 2 });
    // Submission 2's own answers decide it.
    releaseSecond?.();
    expect((await second).kind).toBe('failed');
    expect(store.payment(hash)?.state).toBe('failed');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
  });

  it('V4: after a concurrent NotFound revert, the same submission\'s own IN_FLIGHT and FAILED still apply', async () => {
    const store = payerStore('v4.db');
    const hash = budgeted(store, 'v4', 'OP-V4');
    const deps = payer(store);
    let go: (() => void) | undefined;
    deps.api.send.push(async onUpdate => {
      await new Promise<void>(resolve => { go = resolve; });
      onUpdate(payment('v4', 'IN_FLIGHT'));
      onUpdate(payment('v4', 'FAILED'));
    });
    const first = lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    await until(() => go !== undefined);
    // Another process reconciles while the request is still on its way: NotFound, back to intent.
    deps.api.track.push(notFound);
    expect((await lab.reconcile(deps, hash)).kind).toBe('not-submitted');
    expect(store.payment(hash)?.state).toBe('intent');
    // LND then initiates and fails submission 1 on its own stream.
    go?.();
    expect((await first).kind).toBe('failed');
    expect(store.payment(hash)).toMatchObject({ state: 'failed', submissions: 1 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    expect(store.events(hash).map(item => item.kind)).not.toContain('stale-update');
    expect(store.prepareRetry('OP-V4').outcome).toBe('recorded');
    // The retry closed submission 1: a late update for it is stale before submission 2 is claimed too.
    expect(store.applyUpdate(payment('v4', 'FAILED'), 'TrackPaymentV2', 1).state).toBe('intent');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
  });

  it('V5: a bodiless HTTP 404 is not LND\'s NotFound: after a definite send error the payment stays uncertain', async () => {
    expect(new lab.LndError('payment isn\'t initiated', 5, 404).notFound).toBe(true);
    // Without gRPC code 5 a 404 is not LND's, whatever its body says (N1).
    expect(new lab.LndError('payment isn\'t initiated', undefined, 404).notFound).toBe(false);
    expect(new lab.LndError('HTTP 404', undefined, 404).notFound).toBe(false);
    const store = payerStore('v5.db');
    const hash = budgeted(store, 'v5', 'OP-V5');
    const deps = payer(store);
    deps.api.send.push(async () => { throw new lab.LndError('invoice expired', 2, 500); });
    // A proxy in front of LND answers the track path with a 404 and no body.
    deps.api.track.push(async () => { throw new lab.LndError('HTTP 404', undefined, 404); });
    expect(await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' })).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
    expect(store.payment(hash)?.state).toBe('uncertain');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
  });

  it('L2: retry takes the most recently recorded failed payment and reserves against its budget, also with equal timestamps', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-10T12:00:00.000Z'));
    try {
      const store = payerStore('l2.db');
      store.setBudget('B1', 1100n);
      store.setBudget('B2', 1100n);
      const pay = (label: string, budgetId: string): string => {
        const { paymentHash } = preimageFor(label);
        expect(store.recordIntent({ operationId: 'OP-L2', kind: 'payout', paymentRequest: `lnbcrt-${label}`, invoice: decoded(paymentHash, 1000n),
          feeLimitMsat: 100n, maxParts: 1, budgetId }).outcome).toBe('recorded');
        expect(store.claimForSubmission(paymentHash)).toBe(true);
        store.applyUpdate(payment(label, 'FAILED'), 'SendPaymentV2', 1);
        return paymentHash;
      };
      // The original invoice against B1 fails; its replacement against B2 fails in the same millisecond.
      pay('l2-original', 'B1');
      const newer = pay('l2-replacement', 'B2');
      const retried = store.prepareRetry('OP-L2');
      expect(retried).toMatchObject({ outcome: 'recorded', payment: { paymentHash: newer } });
      expect(store.budgetStatus('B2')).toMatchObject({ heldMsat: 1100n });
      expect(store.budgetStatus('B1')).toMatchObject({ heldMsat: 0n });
      expect(store.operation('OP-L2')?.budgetId).toBe('B2');
    } finally {
      vi.useRealTimers();
    }
  });

  it('NotFound after a retry is judged by the retry\'s own HTLC attempts, each tagged with its submission', async () => {
    const store = payerStore('attempts.db');
    const hash = budgeted(store, 'attempts', 'OP-ATTEMPTS');
    const deps = payer(store);
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(payment('attempts', 'IN_FLIGHT', 1000n, [attempt('1', 'IN_FLIGHT')]), 'SendPaymentV2', 1);
    store.applyUpdate(payment('attempts', 'FAILED', 1000n, [attempt('1', 'FAILED')]), 'SendPaymentV2', 1);
    expect(store.prepareRetry('OP-ATTEMPTS').outcome).toBe('recorded');
    // Submission 2 was claimed and then lost; LND has nothing for it: submission 1's attempt does not count.
    expect(store.claimForSubmission(hash)).toBe(true);
    deps.api.track.push(notFound);
    expect((await lab.reconcile(deps, hash)).kind).toBe('not-submitted');
    expect(store.payment(hash)).toMatchObject({ state: 'intent', submissions: 2 });
    // Submission 3 records an attempt of its own: a NotFound now needs an operator.
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(payment('attempts', 'IN_FLIGHT', 1000n, [attempt('1', 'FAILED'), attempt('2', 'IN_FLIGHT')]), 'SendPaymentV2', 3);
    deps.api.track.push(notFound);
    const outcome = await lab.reconcile(deps, hash);
    expect(outcome).toMatchObject({ kind: 'unresolved', state: 'in_flight' });
    expect(outcome.reason).toMatch(/operator review/);
    expect(attemptTags(store)).toEqual(['1:1:FAILED', '2:3:IN_FLIGHT']);
    expect(store.events(hash).map(item => item.kind)).toContain('not-found-after-attempts');
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
    store.db.exec('DROP INDEX reservations_by_budget; ALTER TABLE payments DROP COLUMN closed_submission; PRAGMA user_version = 3');
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

  it('V6: a malformed amount or payment hash on the command line is a usage error (exit 2) that changes nothing', async () => {
    const file = dir.path('v6.db');
    const setup = payerStore(file);
    setup.setBudget('B', 1100n);
    setup.close();
    const api = new ScriptedPayerApi();
    const { paymentHash } = preimageFor('v6');
    api.invoice = decoded(paymentHash, 1000n);
    const run = services(file, api);
    expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-V6', '--kind', 'payout', '--invoice', 'lnbcrt1v6',
      '--fee-limit-msat', 'x', '--budget', 'B'], run)).toBe(2);
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer', '--payment-hash', 'zz'], run)).toBe(2);
    expect(await lab.main(['payer', 'budget-set', '--as', 'customer-payer', '--budget', 'B', '--limit-msat', '-5'], run)).toBe(2);
    expect(api.trackSignals).toHaveLength(0);
    const after = payerStore(file);
    expect(after.operation('OP-V6')).toBeUndefined();
    expect(after.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    after.close();
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

  const noCalls: FakeInvoiceApi = {
    lookupInvoice: async () => { throw new Error('not scripted'); },
    settleInvoice: async () => undefined,
    cancelInvoice: async () => undefined,
    subscribeInvoices: (_from, _onInvoice, signal) => heldUntilAborted(signal),
  };

  /**
   * Order ORD-<name> whose first invoice A was recorded not-created, turned up late in LND while
   * invoice B was live, and was canceled there; B was then decided not-created too. The order
   * awaits payment and has no live invoice.
   */
  function canceledLateInvoice(name: string): { store: ReceiverStore; late: string; orderId: string } {
    const store = receiverStore(`${name}.db`);
    const orderId = `ORD-${name}`;
    const late = preimageFor(`${name}-late`);
    const other = preimageFor(`${name}-other`);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...late }).outcome).toBe('recorded');
    expect(store.markNotCreated(late.paymentHash)).toBe(true);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...other }).outcome).toBe('recorded');
    expect(store.applyInvoice(invoice(late.paymentHash, 'OPEN'), 'subscription')).toBe('late-invoice');
    expect(store.applyInvoice(invoice(late.paymentHash, 'CANCELED'), 'lookup')).toBe('state-updated');
    expect(store.markNotCreated(other.paymentHash)).toBe(true);
    expect(store.invoice(late.paymentHash)).toMatchObject({ state: 'not-created', lateLndState: 'CANCELED' });
    return { store, late: late.paymentHash, orderId };
  }

  it('L1: a delayed create answer for a late invoice LND canceled does not make it live again', () => {
    const { store, late, orderId } = canceledLateInvoice('l1-create');
    expect(store.markCreated(late, 'lnbcrt-l1-late', 1n)).toBe('not-created');
    const next = preimageFor('l1-create-next');
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...next }).outcome).toBe('recorded');
  });

  it('L1: a replayed OPEN for a late invoice LND canceled does not make it live again', () => {
    const { store, late, orderId } = canceledLateInvoice('l1-replay');
    expect(store.applyInvoice(invoice(late, 'OPEN'), 'subscription')).toBe('unchanged');
    expect(store.invoice(late)).toMatchObject({ state: 'not-created', lateLndState: 'CANCELED' });
    const next = preimageFor('l1-replay-next');
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...next }).outcome).toBe('recorded');
  });

  it('L3: an invoice canceled while AddHoldInvoice was in flight is reported canceled, not created', async () => {
    const store = receiverStore('l3.db');
    const api: FakeInvoiceApi = {
      ...noCalls,
      addHoldInvoice: async request => {
        // Meanwhile "receiver cancel" (or a reconciliation pass) learned from LND that the invoice is canceled.
        expect(store.applyInvoice(invoice(request.paymentHash, 'CANCELED'), 'lookup')).toBe('state-updated');
        return { paymentRequest: 'lnbcrt-l3', addIndex: 1n };
      },
    };
    const outcome = await lab.createInvoice({ api, store, emit: quiet }, { orderId: 'ORD-L3', amountMsat: 1000n, hold: true, memo: 'l3',
      expirySeconds: 3600 });
    expect(outcome.kind).toBe('canceled');
    expect(store.invoice(outcome.paymentHash ?? '')?.state).toBe('canceled');
  });

  it('L3: a create call whose answer was lost and whose lookup finds the invoice canceled is reported canceled', async () => {
    const store = receiverStore('l3-lookup.db');
    const api: FakeInvoiceApi = {
      ...noCalls,
      addInvoice: async () => { throw new lab.TransportError('socket hang up', 'response'); },
      lookupInvoice: async paymentHash => invoice(paymentHash, 'CANCELED'),
    };
    const outcome = await lab.createInvoice({ api, store, emit: quiet }, { orderId: 'ORD-L3L', amountMsat: 1000n, hold: false, memo: 'l3',
      expirySeconds: 3600 });
    expect(outcome.kind).toBe('canceled');
    expect(store.invoice(outcome.paymentHash ?? '')?.state).toBe('canceled');
  });

  it('L4: a late invoice LND reports canceled is counted resolved, is not adopted, and leaves its order open for a replacement', async () => {
    const store = receiverStore('l4-late.db');
    const late = preimageFor('l4-late');
    expect(store.recordInvoiceIntent({ orderId: 'ORD-L4', amountMsat: 1000n, kind: 'standard', ...late }).outcome).toBe('recorded');
    expect(store.markNotCreated(late.paymentHash)).toBe(true);
    const api: FakeInvoiceApi = { ...noCalls, lookupInvoice: async paymentHash => invoice(paymentHash, 'CANCELED') };
    expect(await lab.reconcileInvoices({ api, store, emit: quiet })).toEqual({ resolved: 1, open: 0, unknown: 0 });
    expect(store.invoice(late.paymentHash)).toMatchObject({ state: 'not-created', lateLndState: 'CANCELED' });
    expect(store.order('ORD-L4')?.state).toBe('awaiting-payment');
    const next = preimageFor('l4-next');
    expect(store.recordInvoiceIntent({ orderId: 'ORD-L4', amountMsat: 1000n, kind: 'standard', ...next }).outcome).toBe('recorded');
  });

  it('L4: an invoice canceled locally while its lookup was in flight is counted resolved, not open', async () => {
    const store = receiverStore('l4-local.db');
    const identity = preimageFor('l4-local');
    expect(store.recordInvoiceIntent({ orderId: 'ORD-L4L', amountMsat: 1000n, kind: 'hold', ...identity }).outcome).toBe('recorded');
    expect(store.markCreated(identity.paymentHash, 'lnbcrt-l4-local', 1n)).toBe('open');
    const api: FakeInvoiceApi = {
      ...noCalls,
      lookupInvoice: async paymentHash => {
        // "receiver cancel" in another process records LND's CANCELED; this lookup's answer was read just before.
        expect(store.applyInvoice(invoice(paymentHash, 'CANCELED'), 'lookup')).toBe('state-updated');
        return invoice(paymentHash, 'OPEN');
      },
    };
    expect(await lab.reconcileInvoices({ api, store, emit: quiet })).toEqual({ resolved: 1, open: 0, unknown: 0 });
    expect(store.invoice(identity.paymentHash)?.state).toBe('canceled');
  });
});

/**
 * Round 4 (the verifier's probes of d70fe42): NotFound needs LND's gRPC code (N1), every
 * stored amount and index fits SQLite's 64 bits (N2), and reconciliation counts each
 * invoice exactly once (N3, N4); a canceled invoice LND later reports settled reads settled (N5).
 */
describe('payment lab round 4', () => {
  beforeEach(() => {
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => { vi.restoreAllMocks(); });

  const noInvoiceCalls: FakeInvoiceApi = {
    lookupInvoice: async () => { throw new Error('not scripted'); },
    settleInvoice: async () => undefined,
    cancelInvoice: async () => undefined,
    subscribeInvoices: (_from, _onInvoice, signal) => heldUntilAborted(signal),
  };

  /** main with fresh stores on `payerFile` / `receiverFile` per call (main closes them). */
  function services(payerFile: string, api: ScriptedPayerApi, receiverFile = dir.path('n2-unused-receiver.db'), invoiceApi = noInvoiceCalls) {
    return {
      payer: () => ({ api, store: payerStore(payerFile), emit: quiet }),
      receiver: (): ReceiverDeps => ({ api: invoiceApi, store: new lab.ReceiverStore(receiverFile), emit: quiet }),
    };
  }

  // A proxy's 404 bodies: an API gateway's, and Kong's for a path it has no route for.
  const proxy404 = (): Error[] => [new lab.LndError('Not Found', undefined, 404), new lab.LndError('no Route matched with those values', undefined, 404)];

  it('N1: a 404 without gRPC code 5 is neither LND\'s NotFound nor a definite refusal; code 5 is NotFound at any status', () => {
    for (const error of proxy404()) {
      expect((error as Error & { notFound: boolean }).notFound).toBe(false);
      expect(lab.definiteRefusal(error)).toBe(false);
    }
    expect(new lab.LndError('payment isn\'t initiated', 5, 404).notFound).toBe(true);
    expect(new lab.LndError('payment isn\'t initiated', 5, 200).notFound).toBe(true);
    expect(lab.definiteRefusal(new lab.LndError('payment isn\'t initiated', 5, 404))).toBe(true);
    // Other 400-class answers with a body are still definite refusals.
    expect(lab.definiteRefusal(new lab.LndError('amount must be positive', undefined, 400))).toBe(true);
  });

  it('N1: a proxy\'s JSON 404 on TrackPaymentV2 after a definite send error leaves the payment uncertain, reservation held', async () => {
    for (const [index, proxied] of proxy404().entries()) {
      const store = payerStore(`n1-pay-${index}.db`);
      const hash = budgeted(store, `n1-pay-${index}`, `OP-N1-${index}`);
      const deps = payer(store);
      deps.api.send.push(async () => { throw new lab.LndError('invoice expired', 2, 500); });
      deps.api.track.push(async () => { throw proxied; });
      expect(await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' })).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
      expect(store.payment(hash)?.state).toBe('uncertain');
      expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
      // Reconciling through the same proxy does not send it back to intent either (stopped after one try).
      const stop = new AbortController();
      deps.api.track.push(async () => { stop.abort(); throw proxied; });
      expect(await lab.reconcile(deps, hash, stop.signal)).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
      expect(store.payment(hash)?.state).toBe('uncertain');
    }
  });

  it('N1: a proxy\'s JSON 404 on AddInvoice and on the lookup does not decide a creating invoice', async () => {
    const store = receiverStore('n1-create.db');
    const [gateway, kong] = proxy404();
    const api: FakeInvoiceApi = {
      ...noInvoiceCalls,
      addInvoice: async () => { throw gateway; },
      lookupInvoice: async () => { throw kong; },
    };
    const outcome = await lab.createInvoice({ api, store, emit: quiet }, { orderId: 'ORD-N1', amountMsat: 1000n, hold: false, memo: 'n1',
      expirySeconds: 3600 });
    expect(outcome.kind).toBe('unresolved');
    expect(store.invoice(outcome.paymentHash ?? '')?.state).toBe('creating');
  });

  const TOO_LARGE = '9223372036854775808'; // 2^63
  const MAX = '9223372036854775807'; // 2^63 - 1

  it('N2: an amount or index of 2^63 or more on the command line is a usage error (exit 2) that changes nothing', async () => {
    const file = dir.path('n2-usage.db');
    const setup = payerStore(file);
    setup.setBudget('B', 1100n);
    setup.close();
    const api = new ScriptedPayerApi();
    api.invoice = decoded(preimageFor('n2-usage').paymentHash, 1000n);
    const receiverFile = dir.path('n2-usage-receiver.db');
    let created = 0;
    const invoiceApi: FakeInvoiceApi = { ...noInvoiceCalls, addInvoice: async () => { created += 1; throw new Error('not expected'); } };
    const run = services(file, api, receiverFile, invoiceApi);
    for (const budget of [[], ['--budget', 'B']]) {
      expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-N2', '--kind', 'payout', '--invoice', 'lnbcrt1n2',
        '--fee-limit-msat', TOO_LARGE, ...budget], run)).toBe(2);
    }
    expect(await lab.main(['payer', 'budget-set', '--as', 'customer-payer', '--budget', 'B', '--limit-msat', TOO_LARGE], run)).toBe(2);
    expect(await lab.main(['receiver', 'cursor-set', '--as', 'merchant', '--settle-index', TOO_LARGE], run)).toBe(2);
    expect(await lab.main(['receiver', 'create-invoice', '--as', 'merchant', '--order', 'ORD-N2', '--amount-msat', TOO_LARGE], run)).toBe(2);
    expect(await lab.main(['receiver', 'create-invoice', '--as', 'merchant', '--order', 'ORD-N2', '--amount-msat', '9999999999999999999'], run))
      .toBe(2);
    expect(created).toBe(0);
    const after = payerStore(file);
    expect(after.operation('OP-N2')).toBeUndefined();
    expect(after.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    expect(after.refusals('B')).toEqual([]);
    const receiver = receiverStore('n2-usage-receiver.db');
    expect(receiver.order('ORD-N2')).toBeUndefined();
  });

  it('N2: a fee limit of 2^63 - 1 with a budget is refused (exit 3) with a reason; the refusal row is saturated, not a crash', async () => {
    const file = dir.path('n2-sum.db');
    const setup = payerStore(file);
    setup.setBudget('B', 1100n);
    setup.close();
    const api = new ScriptedPayerApi();
    api.invoice = decoded(preimageFor('n2-sum').paymentHash, 1000n);
    const events: Record<string, unknown>[] = [];
    const run = { ...services(file, api), payer: () => ({ api, store: payerStore(file), emit: (event: Record<string, unknown>) => { events.push(event); } }) };
    expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-N2S', '--kind', 'payout', '--invoice', 'lnbcrt1n2s',
      '--fee-limit-msat', MAX, '--budget', 'B'], run)).toBe(3);
    expect(events.filter(event => event.event === 'intent-refused')).toEqual([expect.objectContaining({ requestedMsat: '9223372036854776807',
      availableMsat: '1100', reason: expect.stringMatching(/1100 msat available, 9223372036854776807 msat requested/) as unknown })]);
    const after = payerStore(file);
    expect(after.refusals('B')).toEqual([expect.objectContaining({ operationId: 'OP-N2S', requestedMsat: BigInt(MAX), availableMsat: 1100n })]);
    expect(after.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    expect(after.operation('OP-N2S')).toBeUndefined();
  });

  it('N2: budget sums past 2^63 are added up exactly, so admission still works', () => {
    const store = payerStore('n2-budget-sum.db');
    store.setBudget('B', BigInt(MAX));
    const half = 2n ** 62n;
    const { paymentHash } = preimageFor('n2-budget-sum');
    expect(store.recordIntent({ operationId: 'OP-N2B', kind: 'payout', paymentRequest: 'lnbcrt-n2b', invoice: decoded(paymentHash, half),
      feeLimitMsat: 1n, maxParts: 1, budgetId: 'B' }).outcome).toBe('recorded');
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    // LND reports a fee far above the allowance: the consumed figure passes 2^63.
    store.applyUpdate({ ...payment('n2-budget-sum', 'SUCCEEDED', half), feeMsat: half }, 'SendPaymentV2', 1);
    expect(store.budgetStatus('B')).toMatchObject({ consumedMsat: 2n ** 63n, availableMsat: -1n });
    const next = preimageFor('n2-budget-sum-next');
    expect(store.recordIntent({ operationId: 'OP-N2B2', kind: 'payout', paymentRequest: 'lnbcrt-n2b2', invoice: decoded(next.paymentHash, 1000n),
      feeLimitMsat: 1n, maxParts: 1, budgetId: 'B' }).outcome).toBe('refused');
  });

  it('N2: an LND amount or index past 2^63 is an unreadable answer; a channel ID up to 2^64 - 1 still reads', () => {
    const json = { payment_hash: preimageFor('n2-json').paymentHash, status: 'IN_FLIGHT', value_msat: '1000', fee_msat: '0',
      payment_index: '18446744073709551615',
      htlcs: [{ attempt_id: '1', status: 'IN_FLIGHT', route: { total_amt_msat: '1000', total_fees_msat: '0', hops: [{ chan_id: '17592186044416000001' }] } }] };
    const parsed = lab.parsePayment(json);
    expect(parsed.htlcs[0]?.route.hops[0]?.chanId).toBe('17592186044416000001');
    expect(parsed.paymentIndex).toBe('18446744073709551615');
    expect(() => lab.parsePayment({ ...json, fee_msat: TOO_LARGE })).toThrow(lab.ProtocolError);
    expect(() => lab.parsePayment({ ...json, value_msat: '-9223372036854775809' })).toThrow(lab.ProtocolError);
  });

  /** An invoice intent for `orderId`, created in LND unless `created` is false. */
  function intent(store: ReceiverStore, orderId: string, label: string, created = true): string {
    const identity = preimageFor(label);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...identity }).outcome).toBe('recorded');
    if (created) expect(store.markCreated(identity.paymentHash, `lnbcrt-${label}`, 1n)).toBe('open');
    return identity.paymentHash;
  }

  /** LND's invoices by hash: a state, 'not-found' (NotFound) or 'error' (a dropped connection). CancelInvoice always fails. */
  function scriptedInvoices(states: Map<string, string>): FakeInvoiceApi {
    return {
      ...noInvoiceCalls,
      lookupInvoice: async paymentHash => {
        const state = states.get(paymentHash) ?? 'not-found';
        if (state === 'not-found') throw new lab.LndError('unable to locate invoice', 5, 404);
        if (state === 'error') throw new lab.TransportError('socket hang up', 'response');
        return invoice(paymentHash, state, state === 'SETTLED' ? 1000n : 0n, state === 'SETTLED' ? 1n : 0n);
      },
      cancelInvoice: async () => { throw new lab.TransportError('socket hang up', 'response'); },
    };
  }

  it('N3: resolved, open and unknown partition the targets; each invoice lands in its own bucket', async () => {
    const store = receiverStore('n3-mixed.db');
    const lnd = new Map<string, string>();
    lnd.set(intent(store, 'ORD-OPEN', 'n3-open'), 'OPEN');
    lnd.set(intent(store, 'ORD-ACC', 'n3-acc'), 'ACCEPTED');
    lnd.set(intent(store, 'ORD-SET', 'n3-set'), 'SETTLED');
    lnd.set(intent(store, 'ORD-CAN', 'n3-can'), 'CANCELED');
    lnd.set(intent(store, 'ORD-CRE', 'n3-cre', false), 'not-found'); // creating, within its creation window
    lnd.set(intent(store, 'ORD-ERR', 'n3-err'), 'error');
    const notCreated = intent(store, 'ORD-NC', 'n3-nc', false);
    expect(store.markNotCreated(notCreated)).toBe(true);
    lnd.set(notCreated, 'not-found');
    // ORD-X: the original was recorded not-created and its replacement is live. The original turns up late
    // and paid, which fulfills the order after the replacement was counted open; the replacement's cancel fails.
    const lateOriginal = intent(store, 'ORD-X', 'n3-x-late', false);
    expect(store.markNotCreated(lateOriginal)).toBe(true);
    const replacementR = intent(store, 'ORD-X', 'n3-x-replacement');
    lnd.set(lateOriginal, 'SETTLED');
    lnd.set(replacementR, 'OPEN');
    const result = await lab.reconcileInvoices({ api: scriptedInvoices(lnd), store, emit: quiet });
    expect(result.resolved + result.open + result.unknown).toBe(lnd.size);
    // resolved: settled, canceled, not-created, the late original; open: open, accepted; unknown: creating, dropped, the replacement.
    expect(result).toEqual({ resolved: 4, open: 2, unknown: 3 });
    expect(store.invoice(notCreated)?.state).toBe('not-created');
    expect(store.order('ORD-X')?.state).toBe('fulfilled');
    expect(store.isSuperseded(replacementR)).toBe(true);
  });

  it('N3: an invoice counted open and then superseded with a failing cancel in the same pass counts once, as unknown', async () => {
    const store = receiverStore('n3-superseded.db');
    const lateOriginal = intent(store, 'ORD-S', 'n3s-late', false);
    expect(store.markNotCreated(lateOriginal)).toBe(true);
    const replacementR = intent(store, 'ORD-S', 'n3s-replacement');
    const lnd = new Map([[lateOriginal, 'SETTLED'], [replacementR, 'OPEN']]);
    expect(await lab.reconcileInvoices({ api: scriptedInvoices(lnd), store, emit: quiet })).toEqual({ resolved: 1, open: 0, unknown: 1 });
  });

  it('N3: a not-created invoice LND does not hold is counted resolved', async () => {
    const store = receiverStore('n3-notcreated.db');
    expect(store.markNotCreated(intent(store, 'ORD-NC1', 'n3-nc1', false))).toBe(true);
    expect(await lab.reconcileInvoices({ api: scriptedInvoices(new Map()), store, emit: quiet })).toEqual({ resolved: 1, open: 0, unknown: 0 });
  });

  it('N4: a pass stopped before its first lookup counts settled and canceled invoices resolved, and looks nothing up', async () => {
    const store = receiverStore('n4.db');
    expect(store.applyInvoice(invoice(intent(store, 'ORD-N4', 'n4-settled'), 'SETTLED', 1000n, 1n), 'subscription')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(intent(store, 'ORD-N4C', 'n4-canceled'), 'CANCELED'), 'lookup')).toBe('state-updated');
    const stop = new AbortController();
    stop.abort();
    const deps = { api: noInvoiceCalls, store, emit: quiet };
    expect(await lab.reconcileInvoices(deps, 'ORD-N4', stop.signal)).toEqual({ resolved: 1, open: 0, unknown: 0 });
    expect(await lab.reconcileInvoices(deps, 'ORD-N4C', stop.signal)).toEqual({ resolved: 1, open: 0, unknown: 0 });
    // Not stopped: a settled invoice is final too and is not looked up again (noInvoiceCalls has no lookup).
    expect(await lab.reconcileInvoices(deps, 'ORD-N4')).toEqual({ resolved: 1, open: 0, unknown: 0 });
  });

  it('N5: a canceled invoice LND later reports settled reads settled; canceled stays final for a replayed OPEN', () => {
    const store = receiverStore('n5.db');
    const hash = intent(store, 'ORD-N5', 'n5');
    expect(store.applyInvoice(invoice(hash, 'CANCELED'), 'lookup')).toBe('state-updated');
    expect(store.applyInvoice(invoice(hash, 'OPEN'), 'subscription')).toBe('unchanged');
    expect(store.invoice(hash)?.state).toBe('canceled');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1000n, 7n), 'subscription')).toBe('fulfilled');
    expect(store.invoice(hash)).toMatchObject({ state: 'settled', amtPaidMsat: 1000n, settleIndex: 7n });
    expect(store.ledger('ORD-N5')).toHaveLength(1);
    expect(store.applyInvoice(invoice(hash, 'CANCELED'), 'lookup')).toBe('unchanged');
    expect(store.invoice(hash)?.state).toBe('settled');
  });
});

/**
 * Round 5 (the verifier's probes of 3705845): no amount, fee, time or index LND sends is
 * negative, so a negative one is an unreadable answer (P1); a late invoice LND returns from
 * ACCEPTED to OPEN is still canceled and never counted resolved while LND holds it (P2).
 */
describe('payment lab round 5', () => {
  const HASH = preimageFor('p1-json').paymentHash;
  const paymentJson = {
    payment_hash: HASH, status: 'IN_FLIGHT', value_msat: '1000', fee_msat: '0', creation_time_ns: '1', payment_index: '1',
    htlcs: [{ attempt_id: '1', status: 'IN_FLIGHT', attempt_time_ns: '1', resolve_time_ns: '0',
      route: { total_amt_msat: '1000', total_fees_msat: '0', hops: [{ chan_id: '1', amt_to_forward_msat: '1000', fee_msat: '0' }] } }],
  };
  const invoiceJson = { r_hash: Buffer.from(HASH, 'hex').toString('base64'), state: 'OPEN', value_msat: '1000', amt_paid_msat: '0',
    add_index: '1', settle_index: '0', htlcs: [{ chan_id: '1', htlc_index: '0', amt_msat: '1000', state: 'ACCEPTED' }] };
  const payReqJson = { destination: DESTINATION, payment_hash: HASH, num_msat: '1000', timestamp: '1', expiry: '3600' };

  /** A copy of `json` with the field at `path` set to `value`. */
  function withField(json: unknown, path: (string | number)[], value: unknown): unknown {
    const copy = structuredClone(json) as Record<string | number, unknown>;
    let at = copy;
    for (const key of path.slice(0, -1)) at = at[key] as Record<string | number, unknown>;
    at[path[path.length - 1] ?? ''] = value;
    return copy;
  }

  it('P1: a negative amount, fee, time or index from LND is an unreadable answer; zero still reads', () => {
    expect(lab.parsePayment(paymentJson).feeMsat).toBe(0n);
    expect(lab.parseInvoice(invoiceJson).amtPaidMsat).toBe(0n);
    expect(lab.parsePayReq(payReqJson).amountMsat).toBe(1000n);
    const cases: [(json: unknown) => unknown, unknown, (string | number)[]][] = [
      [lab.parsePayment, paymentJson, ['fee_msat']],
      [lab.parsePayment, paymentJson, ['value_msat']],
      [lab.parsePayment, paymentJson, ['creation_time_ns']],
      [lab.parsePayment, paymentJson, ['htlcs', 0, 'attempt_time_ns']],
      [lab.parsePayment, paymentJson, ['htlcs', 0, 'route', 'total_fees_msat']],
      [lab.parsePayment, paymentJson, ['htlcs', 0, 'route', 'total_amt_msat']],
      [lab.parsePayment, paymentJson, ['htlcs', 0, 'route', 'hops', 0, 'fee_msat']],
      [lab.parsePayment, paymentJson, ['htlcs', 0, 'route', 'hops', 0, 'amt_to_forward_msat']],
      [lab.parseInvoice, invoiceJson, ['value_msat']],
      [lab.parseInvoice, invoiceJson, ['amt_paid_msat']],
      [lab.parseInvoice, invoiceJson, ['add_index']],
      [lab.parseInvoice, invoiceJson, ['settle_index']],
      [lab.parseInvoice, invoiceJson, ['htlcs', 0, 'amt_msat']],
      [lab.parsePayReq, payReqJson, ['num_msat']],
      [lab.parsePayReq, payReqJson, ['expiry']],
    ];
    for (const [parse, json, path] of cases) {
      for (const value of ['-5', -5, '-9223372036854775808']) {
        expect(() => parse(withField(json, path, value)), `${path.join('.')} = ${String(value)}`).toThrow(lab.ProtocolError);
      }
    }
    // Route fees above the route total would make a negative principal: unreadable too.
    expect(() => lab.parsePayment(withField(paymentJson, ['htlcs', 0, 'route', 'total_fees_msat'], '1001'))).toThrow(lab.ProtocolError);
  });

  it('P1: a SUCCEEDED answer with a negative fee leaves the payment uncertain with its reservation held, not stuck submitting', async () => {
    const store = payerStore('p1-negative-fee.db');
    const hash = budgeted(store, 'p1-negative-fee', 'OP-P1');
    const deps = payer(store);
    const { preimage } = preimageFor('p1-negative-fee');
    // The REST client parses each stream message before the workflow sees it; a parse error ends the stream with that error.
    deps.api.send.push(async onUpdate => {
      onUpdate(lab.parsePayment({ payment_hash: hash, status: 'SUCCEEDED', value_msat: '1000', fee_msat: '-5', payment_preimage: preimage }));
    });
    deps.api.track.push(async () => { throw new lab.TransportError('socket hang up', 'response'); });
    expect(await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' })).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
    expect(store.payment(hash)?.state).toBe('uncertain');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, consumedMsat: 0n });
  });

  /**
   * Order ORD-<name>: hold invoice B recorded not-created, then A created and live; B turns up
   * late in LND and is seen ACCEPTED. The tests then have LND return B to OPEN (its accepted
   * HTLCs were canceled or timed out).
   */
  function lateAccepted(name: string): { store: ReceiverStore; live: string; late: string } {
    const store = receiverStore(`${name}.db`);
    const late = preimageFor(`${name}-late`);
    const live = preimageFor(`${name}-live`);
    const orderId = `ORD-${name}`;
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'hold', ...late }).outcome).toBe('recorded');
    expect(store.markNotCreated(late.paymentHash)).toBe(true);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'hold', ...live }).outcome).toBe('recorded');
    expect(store.markCreated(live.paymentHash, `lnbcrt-${name}-live`, 1n)).toBe('open');
    expect(store.applyInvoice(invoice(late.paymentHash, 'ACCEPTED'), 'lookup')).toBe('late-invoice');
    expect(store.invoice(late.paymentHash)).toMatchObject({ state: 'not-created', lateLndState: 'ACCEPTED' });
    return { store, live: live.paymentHash, late: late.paymentHash };
  }

  /** LND's invoices by hash; CancelInvoice moves an OPEN or ACCEPTED one to CANCELED, or fails with `cancelFails`. */
  function lndInvoices(states: Map<string, string>, cancelFails: boolean): FakeInvoiceApi & { cancels: string[] } {
    const cancels: string[] = [];
    return {
      cancels,
      lookupInvoice: async paymentHash => invoice(paymentHash, states.get(paymentHash) ?? 'OPEN'),
      settleInvoice: async () => undefined,
      cancelInvoice: async paymentHash => {
        cancels.push(paymentHash);
        if (cancelFails) throw new lab.TransportError('socket hang up', 'response');
        if (states.get(paymentHash) === 'OPEN' || states.get(paymentHash) === 'ACCEPTED') states.set(paymentHash, 'CANCELED');
      },
      subscribeInvoices: (_from, _onInvoice, signal) => heldUntilAborted(signal),
    };
  }

  it('P2: OPEN after ACCEPTED for a late invoice is recorded and is late-invoice again; canceled stays final, settled outranks it', () => {
    const { store, late } = lateAccepted('p2-store');
    expect(store.applyInvoice(invoice(late, 'OPEN'), 'lookup')).toBe('late-invoice');
    expect(store.invoice(late)).toMatchObject({ state: 'not-created', lateLndState: 'OPEN' });
    expect(store.applyInvoice(invoice(late, 'ACCEPTED'), 'subscription')).toBe('late-invoice');
    expect(store.invoice(late)?.lateLndState).toBe('ACCEPTED');
    expect(store.applyInvoice(invoice(late, 'CANCELED'), 'lookup')).toBe('state-updated');
    expect(store.applyInvoice(invoice(late, 'OPEN'), 'subscription')).toBe('unchanged');
    expect(store.applyInvoice(invoice(late, 'ACCEPTED'), 'subscription')).toBe('unchanged');
    expect(store.invoice(late)?.lateLndState).toBe('CANCELED');
    // The order's live invoice A is still open: B's payment is posted and fulfills the order (A is then superseded).
    expect(store.applyInvoice(invoice(late, 'SETTLED', 1000n, 3n), 'subscription')).toBe('fulfilled');
    expect(store.invoice(late)?.lateLndState).toBe('SETTLED');
    expect(store.applyInvoice(invoice(late, 'OPEN'), 'subscription')).toBe('unchanged');
    expect(store.invoice(late)?.lateLndState).toBe('SETTLED');
  });

  it('P2: a late invoice LND returned from ACCEPTED to OPEN is canceled in LND, and counted resolved once LND reports it canceled', async () => {
    const { store, live, late } = lateAccepted('p2-cancel');
    const api = lndInvoices(new Map([[live, 'OPEN'], [late, 'OPEN']]), false);
    expect(await lab.reconcileInvoices({ api, store, emit: quiet })).toEqual({ resolved: 1, open: 1, unknown: 0 });
    expect(api.cancels).toEqual([late]);
    expect(store.invoice(late)).toMatchObject({ state: 'not-created', lateLndState: 'CANCELED' });
  });

  it('P2: while its cancel fails, the reopened late invoice is never counted resolved, on this pass or the next', async () => {
    const { store, live, late } = lateAccepted('p2-fail');
    const api = lndInvoices(new Map([[live, 'OPEN'], [late, 'OPEN']]), true);
    for (let pass = 0; pass < 2; pass += 1) {
      expect(await lab.reconcileInvoices({ api, store, emit: quiet })).toEqual({ resolved: 0, open: 1, unknown: 1 });
    }
    expect(api.cancels).toEqual([late, late]);
    expect(store.invoice(late)).toMatchObject({ state: 'not-created', lateLndState: 'OPEN' });
  });
});

/**
 * Ledger verifier finding (H3c): LND reporting two different amounts for one settled invoice (a hostile
 * or buggy node) must never post two settlements for one payment hash. invoice-settled and
 * underpaid-settlement are different journal events, so their (event, reference) keys did not stop
 * both being posted; the first settlement recorded for a hash now wins and a differing one is a
 * settlement-amount-conflict delivery that changes nothing else.
 */
describe('payment lab one settlement per payment hash', () => {
  function created(store: ReceiverStore, label: string, orderId: string): string {
    const { preimage, paymentHash } = preimageFor(label);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', preimage, paymentHash }).outcome).toBe('recorded');
    store.markCreated(paymentHash, `lnbcrt-${label}`, 1n);
    return paymentHash;
  }

  function snapshot(store: ReceiverStore): string {
    const tables = ['journal_entries', 'journal_lines', 'balances', 'fulfillments', 'orders', 'invoices', 'outbox'];
    return JSON.stringify(tables.map(table => store.db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()),
      (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value);
  }

  function outcomes(store: ReceiverStore, paymentHash: string): string[] {
    return store.db.prepare('SELECT outcome FROM deliveries WHERE payment_hash = ? ORDER BY delivery_id').all(paymentHash)
      .map(row => String(row.outcome));
  }

  function walletIncoming(store: ReceiverStore): string | undefined {
    const [row] = store.db.prepare(`SELECT balance_msat FROM balances WHERE account = 'lnd-wallet-incoming'`).all();
    return row === undefined ? undefined : String(row.balance_msat);
  }

  async function balancedAgainst(store: ReceiverStore, paid: Invoice[]): Promise<void> {
    expect((await lab.verifyLedger(store)).balanced).toBe(true);
    const lnd = await lab.verifyLedger(store, { listInvoicesPage: () => Promise.resolve({ invoices: paid, lastIndexOffset: BigInt(paid.length) }) });
    expect(lnd.lnd).toBe('compared');
    expect(lnd.balanced).toBe(true);
  }

  it('H3c: full then underpaid for one hash: the second posts nothing, is a settlement-amount-conflict, the order stays fulfilled', async () => {
    const store = receiverStore('h3c-full-under.db');
    const hash = created(store, 'h3c-full-under', 'O-full-under');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1000n, 1n), 'subscription')).toBe('fulfilled');
    const before = snapshot(store);
    for (const source of ['lookup', 'subscription']) {
      expect(store.applyInvoice(invoice(hash, 'SETTLED', 999n, 1n), source)).toBe('settlement-amount-conflict');
    }
    expect(snapshot(store)).toBe(before);
    expect(store.journal('O-full-under').map(entry => entry.event)).toEqual(['invoice-settled']);
    expect(walletIncoming(store)).toBe('1000');
    expect(store.order('O-full-under')?.state).toBe('fulfilled');
    expect(store.invoice(hash)?.amtPaidMsat).toBe(1000n);
    expect(outcomes(store, hash)).toEqual(['fulfilled', 'settlement-amount-conflict', 'settlement-amount-conflict']);
    await balancedAgainst(store, [invoice(hash, 'SETTLED', 1000n, 1n)]);
  });

  it('H3c: underpaid then full for one hash: the second posts nothing and does not fulfill the order', async () => {
    const store = receiverStore('h3c-under-full.db');
    const hash = created(store, 'h3c-under-full', 'O-under-full');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 999n, 1n), 'subscription')).toBe('underpaid');
    const before = snapshot(store);
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1000n, 1n), 'lookup')).toBe('settlement-amount-conflict');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1001n, 1n), 'subscription')).toBe('settlement-amount-conflict');
    expect(snapshot(store)).toBe(before);
    expect(store.journal('O-under-full').map(entry => entry.event)).toEqual(['underpaid-settlement']);
    expect(walletIncoming(store)).toBe('999');
    expect(store.order('O-under-full')?.state).toBe('awaiting-payment');
    expect(store.fulfillmentCount('O-under-full')).toBe(0);
    expect(store.outbox('O-under-full')).toEqual([]);
    await balancedAgainst(store, [invoice(hash, 'SETTLED', 999n, 1n)]);
  });

  it('H3c: a replay with the recorded amount is unchanged (duplicate after fulfilled, underpaid after underpaid)', async () => {
    const store = receiverStore('h3c-replay.db');
    const full = created(store, 'h3c-replay-full', 'O-replay-full');
    const under = created(store, 'h3c-replay-under', 'O-replay-under');
    expect(store.applyInvoice(invoice(full, 'SETTLED', 1000n, 1n), 'subscription')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(under, 'SETTLED', 999n, 2n), 'subscription')).toBe('underpaid');
    const before = snapshot(store);
    expect(store.applyInvoice(invoice(full, 'SETTLED', 1000n, 1n), 'lookup')).toBe('duplicate');
    expect(store.applyInvoice(invoice(under, 'SETTLED', 999n, 2n), 'lookup')).toBe('underpaid');
    expect(snapshot(store)).toBe(before);
    expect(walletIncoming(store)).toBe('1999');
    await balancedAgainst(store, [invoice(full, 'SETTLED', 1000n, 1n), invoice(under, 'SETTLED', 999n, 2n)]);
  });
});

/**
 * Audit 5a8ddb1 (functional, against an older tree): the exact orderings of N02 and N03 not covered
 * above (N04 is L3, N05 is L4), N13 (an initialization failure closes the handle), a database newer
 * than the code is refused, the lookup indexes, and two conditional store invariants: the budget
 * consumes what the ledger posts when LND's value differs from the invoice, and a completed
 * operation's replacement is never reverted to intent or claimed.
 */
describe('payment lab audit 5a8ddb1', () => {
  /** node:sqlite and the lab's openDatabase, loaded the way the helpers load the lab (no typed import of the example's sources). */
  interface RawHandle { isOpen: boolean; exec(sql: string): void; prepare(sql: string): { all(...params: unknown[]): Record<string, unknown>[] }; close(): void }
  type OpenDatabase = (path: string, migrations: readonly (string | ((db: RawHandle) => void))[]) => RawHandle;
  const sqliteModule = '../examples/payment-lab/src/store/sqlite.ts';
  const loadSqlite = async (): Promise<{ openDatabase: OpenDatabase }> => await import(/* @vite-ignore */ sqliteModule) as { openDatabase: OpenDatabase };
  const rawOpen = async (path: string): Promise<RawHandle> => {
    const { DatabaseSync } = await import('node:sqlite') as unknown as { DatabaseSync: new (path: string) => RawHandle };
    return new DatabaseSync(path);
  };
  const version = (db: { prepare(sql: string): { all(): Record<string, unknown>[] } }): unknown => db.prepare('PRAGMA user_version').all()[0]?.user_version;
  const plan = (db: { prepare(sql: string): { all(...params: unknown[]): Record<string, unknown>[] } }, sql: string): string =>
    db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all('x').map(row => String(row.detail)).join('\n');

  it('N02: retry takes the replacement also when the clock went back between the two payments', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const store = payerStore('n02-clock.db');
      store.setBudget('B1', 1100n);
      store.setBudget('B2', 1100n);
      const pay = (label: string, budgetId: string): string => {
        const { paymentHash } = preimageFor(label);
        expect(store.recordIntent({ operationId: 'OP-N02', kind: 'payout', paymentRequest: `lnbcrt-${label}`, invoice: decoded(paymentHash, 1000n),
          feeLimitMsat: 100n, maxParts: 1, budgetId }).outcome).toBe('recorded');
        expect(store.claimForSubmission(paymentHash)).toBe(true);
        store.applyUpdate(payment(label, 'FAILED'), 'SendPaymentV2', 1);
        return paymentHash;
      };
      vi.setSystemTime(new Date('2026-10-10T12:00:00.000Z'));
      pay('n02-original', 'B1');
      // The wall clock is set back a minute: the replacement's timestamps are older than the original's.
      vi.setSystemTime(new Date('2026-10-10T11:59:00.000Z'));
      const newer = pay('n02-replacement', 'B2');
      expect(store.prepareRetry('OP-N02')).toMatchObject({ outcome: 'recorded', payment: { paymentHash: newer } });
      expect(store.budgetStatus('B2')).toMatchObject({ heldMsat: 1100n });
      expect(store.budgetStatus('B1')).toMatchObject({ heldMsat: 0n });
      expect(store.operation('OP-N02')?.budgetId).toBe('B2');
    } finally {
      vi.useRealTimers();
    }
  });

  it('N03: a CANCELED lookup of a late invoice LND canceled, after its replacement was not created, leaves the order open', () => {
    const store = receiverStore('n03.db');
    const orderId = 'ORD-N03';
    const late = preimageFor('n03-late');
    const other = preimageFor('n03-other');
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...late }).outcome).toBe('recorded');
    expect(store.markNotCreated(late.paymentHash)).toBe(true);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...other }).outcome).toBe('recorded');
    expect(store.applyInvoice(invoice(late.paymentHash, 'OPEN'), 'subscription')).toBe('late-invoice');
    expect(store.applyInvoice(invoice(late.paymentHash, 'CANCELED'), 'lookup')).toBe('state-updated');
    expect(store.markNotCreated(other.paymentHash)).toBe(true);
    // The delayed create answer, the stale OPEN and a repeated CANCELED: none revives A or cancels the order.
    expect(store.markCreated(late.paymentHash, 'lnbcrt-n03-late', 1n)).toBe('not-created');
    expect(store.applyInvoice(invoice(late.paymentHash, 'OPEN'), 'subscription')).toBe('unchanged');
    expect(store.applyInvoice(invoice(late.paymentHash, 'CANCELED'), 'lookup')).toBe('unchanged');
    expect(store.invoice(late.paymentHash)).toMatchObject({ state: 'not-created', lateLndState: 'CANCELED' });
    expect(store.order(orderId)?.state).toBe('awaiting-payment');
    const next = preimageFor('n03-next');
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind: 'standard', ...next }).outcome).toBe('recorded');
  });

  it('N13: a failing migration rolls back and closes the database handle; the original error propagates', async () => {
    const { openDatabase } = await loadSqlite();
    const file = dir.path('n13.db');
    let handle: RawHandle | undefined;
    expect(() => openDatabase(file, ['CREATE TABLE kept (x INTEGER);', db => { handle = db; throw new Error('migration 2 failed'); }]))
      .toThrow('migration 2 failed');
    expect(handle?.isOpen).toBe(false);
    const raw = await rawOpen(file);
    try {
      expect(version(raw)).toBe(0);
      expect(raw.prepare(`SELECT name FROM sqlite_master WHERE name = 'kept'`).all()).toEqual([]);
    } finally {
      raw.close();
    }
  });

  it('a database newer than the code is refused, naming both versions, and left unchanged', async () => {
    const { createHash } = await import('node:crypto');
    const { readFileSync } = await import('node:fs');
    const file = dir.path('newer.db');
    const store = payerStore(file);
    budgeted(store, 'newer', 'OP-NEWER');
    const known = Number(version(store.db));
    store.db.exec(`PRAGMA user_version = ${known + 1}`);
    store.close();
    const digest = (): string => createHash('sha256').update(readFileSync(file)).digest('hex');
    const before = digest();
    expect(() => new lab.PayerStore(file)).toThrow(new RegExp(`schema version ${known + 1} is newer than this code supports \\(${known}\\)`));
    expect(digest()).toBe(before);
    const { openDatabase } = await loadSqlite();
    let ran = false;
    expect(() => openDatabase(file, [() => { ran = true; }])).toThrow(/schema version \d+ is newer than this code supports \(1\)/);
    expect(ran).toBe(false);
    expect(digest()).toBe(before);
  });

  it('lookup indexes: payments and events by payment or operation, invoices by order, deliveries by payment; rerunnable', () => {
    const payerFile = dir.path('indexes-payer.db');
    const p = payerStore(payerFile);
    expect(plan(p.db, 'SELECT * FROM payments WHERE operation_id = ? ORDER BY rowid')).toMatch(/^SEARCH payments USING INDEX payments_by_operation \(operation_id=\?\)$/);
    expect(plan(p.db, 'SELECT at, kind, detail FROM payment_events WHERE payment_hash = ? ORDER BY event_id'))
      .toMatch(/^SEARCH payment_events USING INDEX payment_events_by_payment \(payment_hash=\?\)$/);
    const r = receiverStore('indexes-receiver.db');
    expect(plan(r.db, 'SELECT * FROM invoices WHERE order_id = ? ORDER BY created_at, rowid')).toMatch(/^SEARCH invoices USING INDEX invoices_by_order \(order_id=\?\)$/);
    expect(plan(r.db, 'SELECT * FROM deliveries WHERE payment_hash = ? ORDER BY delivery_id'))
      .toMatch(/^SEARCH deliveries USING INDEX deliveries_by_payment \(payment_hash=\?\)$/);
    // The methods still answer through them.
    const hash = budgeted(p, 'indexes', 'OP-IDX');
    expect(p.events(hash).map(item => item.kind)).toEqual(['intent-recorded']);
    // Reopening changes nothing; a database rewound to the previous version runs the step again without error.
    const payerVersion = version(p.db);
    p.db.exec(`PRAGMA user_version = ${Number(payerVersion) - 1}`);
    p.close();
    const reopened = payerStore(payerFile);
    expect(version(reopened.db)).toBe(payerVersion);
    expect(reopened.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('payments_by_operation', 'payment_events_by_payment')`).all())
      .toHaveLength(2);
    reopened.close();
    expect(version(payerStore(payerFile).db)).toBe(payerVersion);
  });

  /** A SUCCEEDED for a budgeted 1000 msat intent (fee limit 100) on which LND reports `valueMsat` and a fee of 1. */
  async function succeededWith(file: string, valueMsat: bigint, failFirst = false): Promise<{ store: PayerStore; hash: string }> {
    const store = payerStore(file);
    const hash = budgeted(store, file, `OP-${file}`);
    expect(store.claimForSubmission(hash)).toBe(true);
    if (failFirst) store.applyUpdate(payment(file, 'FAILED'), 'SendPaymentV2', 1);
    const success = { ...payment(file, 'SUCCEEDED', valueMsat), feeMsat: 1n };
    expect(store.applyUpdate(success, 'TrackPaymentV2', 1).state).toBe('succeeded');
    const result = await lab.verifyLedger(store);
    expect(result).toMatchObject({ balanced: true, unbalancedEntries: [], invalidEntries: [] });
    const budget = result.accounts.find(account => account.account === 'budget:B');
    // The budget's account, its records and the ledger's principal plus fee agree.
    expect(budget).toMatchObject({ computed: valueMsat + 1n, records: valueMsat + 1n });
    expect(store.ledger(`OP-${file}`).map(item => item.amountMsat)).toEqual([valueMsat, 1n]);
    return { store, hash };
  }

  it('an accepted SUCCEEDED above the invoice amount consumes the actual principal and records the overrun', async () => {
    const { store, hash } = await succeededWith('amount-above.db', 1500n);
    expect(store.budgetStatus('B')).toEqual({ budgetId: 'B', limitMsat: 1100n, heldMsat: 0n, consumedMsat: 1501n, availableMsat: -401n });
    const kinds = store.events(hash).map(item => item.kind);
    expect(kinds).toEqual(expect.arrayContaining(['amount-mismatch', 'budget-actual-principal', 'budget-overrun']));
    expect(JSON.parse(store.events(hash).find(item => item.kind === 'budget-overrun')?.detail ?? '{}')).toMatchObject({ overMsat: '401' });
  });

  it('an accepted SUCCEEDED below the invoice amount consumes the actual principal; no overrun', async () => {
    const { store, hash } = await succeededWith('amount-below.db', 500n);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 501n, availableMsat: 599n });
    const kinds = store.events(hash).map(item => item.kind);
    expect(kinds).toEqual(expect.arrayContaining(['amount-mismatch', 'budget-actual-principal']));
    expect(kinds).not.toContain('budget-overrun');
  });

  it('a SUCCEEDED after a recorded failure, above the invoice amount, also consumes the actual principal', async () => {
    const { store } = await succeededWith('amount-after-failure.db', 1500n, true);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 1501n });
  });

  it('a replacement of an operation another payment completed is withdrawn on NotFound, never reverted to intent or claimed', async () => {
    const store = payerStore('completed-invariant.db');
    store.setBudget('B', 10_000n);
    const first = preimageFor('completed-first').paymentHash;
    expect(store.recordIntent({ operationId: 'OP-DONE', kind: 'payout', paymentRequest: 'lnbcrt-first', invoice: decoded(first, 1000n),
      feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' }).outcome).toBe('recorded');
    expect(store.claimForSubmission(first)).toBe(true);
    store.applyUpdate(payment('completed-first', 'FAILED'), 'SendPaymentV2', 1);
    expect(replacement(store, 'OP-DONE')).toBe('recorded');
    const second = preimageFor('OP-DONE-replacement').paymentHash;
    expect(store.claimForSubmission(second)).toBe(true);
    expect(store.markUncertain(second, 'connection lost', 1)).toBe('uncertain');
    // LND reports the first payment succeeded after all: the operation is completed; the replacement may have been sent.
    store.applyUpdate(payment('completed-first', 'SUCCEEDED'), 'TrackPaymentV2', 1);
    expect(store.operation('OP-DONE')?.state).toBe('completed');
    // LND has no payment for the replacement: it is withdrawn, its reservation released, not put back to intent.
    const deps = payer(store);
    deps.api.track.push(notFound);
    expect(await lab.reconcile(deps, second)).toMatchObject({ kind: 'failed', reason: expect.stringMatching(/^WITHDRAWN: operation OP-DONE was paid by payment /) as string });
    expect(store.payment(second)).toMatchObject({ state: 'failed' });
    expect(store.claimForSubmission(second)).toBe(false);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 1010n });
    // Direct store calls: a revert finds nothing to revert; an intent of a completed operation (written by hand) is not claimed but withdrawn.
    expect(store.markNotInitiated(second, 'NotFound', 1)).toBe('unchanged');
    store.db.exec(`UPDATE payments SET state = 'intent' WHERE payment_hash = '${second}'`);
    expect(store.claimForSubmission(second)).toBe(false);
    expect(store.payment(second)).toMatchObject({ state: 'failed', submissions: 1 });
    expect(store.events(second).map(item => item.kind).filter(kind => kind === 'submit')).toHaveLength(1);
    expect(await lab.verifyLedger(store)).toMatchObject({ balanced: true, invalidEntries: [] });
  });
});

describe('payment lab audit 9245e00', () => {
  it('F01: a delayed tracker of submission 1 that observes submission 2\'s payment does not make submission 2\'s own FAILED look earlier', async () => {
    const store = payerStore('audit-f01-delayed-tracker.db');
    const hash = budgeted(store, 'audit-f01', 'OP-AUDIT-F01');
    // Submission 1's SendPaymentV2 never connected: another worker reverts it to intent (submission 1 stays open, not closed) and claims submission 2.
    const first: { submission?: number } = {};
    expect(store.claimForSubmission(hash, first)).toBe(true);
    expect(first.submission).toBe(1);
    expect(store.markNotInitiated(hash, 'connection not established: connect ECONNREFUSED', 1)).toBe('reverted');
    const second: { submission?: number } = {};
    expect(store.claimForSubmission(hash, second)).toBe(true);
    expect(second.submission).toBe(2);
    // LND initialises the payment for submission 2 and makes HTLC attempt 42; a TrackPaymentV2 request opened for submission 1 sees it first.
    const created = (BigInt(Date.now()) + 60_000n) * 1_000_000n;
    const inFlight = { ...payment('audit-f01', 'IN_FLIGHT', 1000n, [attempt('42', 'IN_FLIGHT')]), creationTimeNs: created };
    expect(store.applyUpdate(inFlight, 'TrackPaymentV2', 1)).toMatchObject({ state: 'submitting', stale: true });
    expect(store.applyUpdate(inFlight, 'SendPaymentV2', 2)).toMatchObject({ state: 'in_flight' });
    // The attempt belongs to the payment LND holds now, submission 2's, whichever stream showed it first.
    expect(attemptTags(store)).toEqual(['42:2:IN_FLIGHT']);
    // The sending process stops; a fresh reconciliation receives submission 2's genuine FAILED (same creation time, attempt 42 failed).
    const deps = payer(store);
    const failed = { ...payment('audit-f01', 'FAILED', 1000n, [attempt('42', 'FAILED')]), creationTimeNs: created };
    deps.api.track.push(async onUpdate => { onUpdate(failed); });
    expect(await lab.reconcile(deps, hash)).toMatchObject({ kind: 'failed', paymentHash: hash, reason: 'FAILURE_REASON_NO_ROUTE' });
    expect(store.payment(hash)).toMatchObject({ state: 'failed', submissions: 2, failureReason: 'FAILURE_REASON_NO_ROUTE' });
    expect(attemptTags(store)).toEqual(['42:2:FAILED']);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, availableMsat: 1100n });
    expect(store.prepareRetry('OP-AUDIT-F01')).toMatchObject({ outcome: 'recorded', payment: { paymentHash: hash, state: 'intent', submissions: 2 } });
    expect(store.events(hash).map(item => item.kind)).toEqual(['intent-recorded', 'submit', 'not-initiated', 'submit', 'stale-update', 'in-flight', 'failed',
      'retry-prepared']);
  });
});

describe('payment lab audit 1.3.2: LND\'s answer is held to the payment hash the request carries', () => {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  /** A synthetic, checksum-valid BOLT11-shaped string carrying `hash` in its `p` field (as test/payment-lab-payer-audit.test.ts builds it). */
  function synthetic(hash: string): string {
    const hrp = 'lnbcrt';
    let bits = BigInt(`0x${hash}`) << 4n;
    const hashWords: number[] = [];
    for (let index = 0; index < 52; index += 1) { hashWords.unshift(Number(bits & 31n)); bits >>= 5n; }
    const words = [...Array<number>(7).fill(22), 1, 1, 20, ...hashWords, ...Array<number>(104).fill(22)];
    const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const polymod = (values: number[]): number => {
      let checksum = 1;
      for (const value of values) {
        const top = checksum >>> 25;
        checksum = ((checksum & 0x1ffffff) << 5) ^ value;
        for (let bit = 0; bit < 5; bit += 1) if ((top >>> bit) & 1) checksum ^= GENERATOR[bit] ?? 0;
      }
      return checksum;
    };
    const expanded = [...hrp].map(char => char.charCodeAt(0) >> 5).concat([0], [...hrp].map(char => char.charCodeAt(0) & 31));
    const mod = polymod([...expanded, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
    const checksum = Array.from({ length: 6 }, (_unused, index) => (mod >> (5 * (5 - index))) & 31);
    return `${hrp}1${[...words, ...checksum].map(word => CHARSET[word]).join('')}`;
  }

  type Client = { call(method: string, path: string, body?: unknown): Promise<unknown>; stream(): Promise<void> };
  type ApiModule = {
    PayerApi: new (client: Client) => { decodePayReq(paymentRequest: string): Promise<DecodedPayReq> };
    InvoiceApi: new (client: Client) => { addInvoice(request: { preimage: string; valueMsat: bigint; memo: string; expirySeconds: number }):
      Promise<{ paymentHash: string }> };
  };
  /** A REST client that answers every call with `answer` and counts the calls. */
  function client(answer: unknown): Client & { calls: string[] } {
    const calls: string[] = [];
    return { calls, call: async (method, path) => { calls.push(`${method} ${path}`); return answer; }, stream: () => Promise.reject(new Error('no stream')) };
  }

  const realHash = preimageFor('audit-132-real').paymentHash;
  const fakeHash = preimageFor('audit-132-fake').paymentHash;

  it('payer pay: a DecodePayReq answer for another payment hash is refused before an intent is recorded or anything is sent', async () => {
    const stdout: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      const file = dir.path('audit-132-lying-payreq.db');
      const api = new ScriptedPayerApi();
      api.invoice = decoded(fakeHash, 1000n);
      let sent = 0;
      api.send.push(async () => { sent += 1; });
      const run = { payer: () => ({ api, store: payerStore(file), emit: quiet }), receiver: (): ReceiverDeps => { throw new Error('not used'); } };
      expect(await lab.main(['payer', 'pay', '--as', 'customer-payer', '--operation', 'OP-132', '--kind', 'payout', '--invoice', synthetic(realHash),
        '--fee-limit-msat', '100'], run)).toBe(3);
      expect(sent).toBe(0);
      const refused = stdout.flatMap(chunk => chunk.split('\n')).filter(line => line !== '').map(line => JSON.parse(line) as Record<string, unknown>)
        .find(event => event.event === 'invoice-refused');
      expect(String(refused?.reason)).toContain(fakeHash);
      expect(String(refused?.reason)).toContain(realHash);
      const after = payerStore(file);
      expect(after.payment(fakeHash)).toBeUndefined();
      expect(after.payment(realHash)).toBeUndefined();
      expect(after.operation('OP-132')).toBeUndefined();
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('PayerApi.decodePayReq: an answer for another payment hash is a ProtocolError; the request\'s own hash, or one not readable offline, is accepted', async () => {
    const { PayerApi } = await loadLabModule<ApiModule>('lnd/api.ts');
    const answer = (hash: string) => ({ destination: DESTINATION, payment_hash: hash, num_msat: '1000', timestamp: '1', expiry: '3600', description: '' });
    await expect(new PayerApi(client(answer(fakeHash))).decodePayReq(synthetic(realHash))).rejects.toBeInstanceOf(lab.ProtocolError);
    await expect(new PayerApi(client(answer(realHash))).decodePayReq(synthetic(realHash))).resolves.toMatchObject({ paymentHash: realHash });
    // Not BOLT11 offline (no valid checksum): left to LND, as the receiver's foreignAnswer leaves it.
    await expect(new PayerApi(client(answer(fakeHash))).decodePayReq('lnbcrt1notreadable')).resolves.toMatchObject({ paymentHash: fakeHash });
  });

  it('InvoiceApi.addInvoice: a malformed or short r_hash is a ProtocolError, not some other hex hash', async () => {
    const { InvoiceApi } = await loadLabModule<ApiModule>('lnd/api.ts');
    const request = { preimage: preimageFor('audit-132-add').preimage, valueMsat: 1000n, memo: '', expirySeconds: 3600 };
    const answer = (rHash: string) => ({ r_hash: rHash, payment_request: 'lnbcrt1x', add_index: '1' });
    for (const rHash of ['not base64!', Buffer.alloc(16, 1).toString('base64'), '']) {
      await expect(new InvoiceApi(client(answer(rHash))).addInvoice(request), JSON.stringify(rHash)).rejects.toBeInstanceOf(lab.ProtocolError);
    }
    const good = Buffer.from(realHash, 'hex').toString('base64');
    await expect(new InvoiceApi(client(answer(good))).addInvoice(request)).resolves.toMatchObject({ paymentHash: realHash });
  });
});

describe('payment lab audit 1.3.2: store/sqlite.ts opens', () => {
  interface Handle { prepare(sql: string): { get(): Record<string, unknown> | undefined }; exec(sql: string): void; close(): void }
  type Sqlite = { openDatabase(path: string, migrations: readonly string[]): Handle; readOnly<T>(open: () => T): T };
  const MIGRATIONS = ['CREATE TABLE t (x INTEGER)', 'CREATE TABLE u (y INTEGER)'];
  const version = (db: Handle): number => Number(db.prepare('PRAGMA user_version').get()?.user_version);

  it('\':memory:\' and \'\' are SQLite\'s in-memory and temporary databases: no file is pre-created for them', async () => {
    const sqlite = await loadLabModule<Sqlite>('store/sqlite.ts');
    const stray = join(process.cwd(), ':memory:');
    const before = existsSync(stray);
    try {
      for (const path of [':memory:', '']) {
        const db = sqlite.openDatabase(path, MIGRATIONS);
        expect(version(db)).toBe(2);
        db.close();
      }
      // On Windows the pre-create failed with ENOENT (':' is not allowed in a name); on POSIX it left a file named ':memory:'.
      expect(existsSync(stray)).toBe(before);
    } finally {
      if (!before && existsSync(stray)) rmSync(stray);
    }
  });

  it('a read-only open of a database at schema version 0 with no tables (an interrupted first open) reads it as missing', async () => {
    const sqlite = await loadLabModule<Sqlite>('store/sqlite.ts');
    const empty = dir.path('sqlite-132-empty.db');
    writeFileSync(empty, '');
    const walOnly = dir.path('sqlite-132-wal-only.db');
    const { DatabaseSync } = await import('node:sqlite');
    const raw = new DatabaseSync(walOnly);
    raw.exec('PRAGMA journal_mode = WAL');
    raw.close();
    for (const path of [empty, walOnly]) {
      const size = statSync(path).size;
      const db = sqlite.readOnly(() => sqlite.openDatabase(path, MIGRATIONS));
      expect(version(db)).toBe(2);
      expect(db.prepare('SELECT COUNT(*) AS n FROM t').get()?.n).toBe(0n);
      db.close();
      expect(statSync(path).size).toBe(size);
    }
    // A version-0 database that has tables is not an interrupted first open: it is still refused, unchanged.
    const tables = dir.path('sqlite-132-tables.db');
    const other = new DatabaseSync(tables);
    other.exec('CREATE TABLE legacy (z INTEGER)');
    other.close();
    expect(() => sqlite.readOnly(() => sqlite.openDatabase(tables, MIGRATIONS))).toThrow(/schema version 0 is older than this code's \(2\)/);
  });
});
