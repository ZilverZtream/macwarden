import { spawnSync } from 'node:child_process';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { readFileSync, writeFileSync } from 'node:fs';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  loadLab, loadLabModule, preimageFor, tempDirectory,
  type DecodedPayReq, type FakePayerApi, type HtlcAttempt, type Lab, type Payment, type PayerDeps, type PayerStore, type StreamDecision,
} from './helpers/payment-lab-modules.js';

/**
 * Regressions for the pre-1.4 audit of the payment lab's payer (examples/payment-lab/src/payer, lnd/rest.ts,
 * util/bolt11.ts): a retried payment is never failed by the FAILED LND still shows for the earlier submission;
 * the claim returns its own submission; a proxy's status is not overridden by a relayed body; the offline BOLT11
 * reader refuses non-ASCII look-alikes; reconcile's backoff grows against a node that ends every stream at once.
 */

type Stream = (onUpdate: (payment: Payment) => StreamDecision, signal: AbortSignal | undefined) => Promise<void>;

let lab: Lab;
const dir = tempDirectory();
beforeAll(async () => { lab = await loadLab(); });
afterAll(() => dir.remove());

const opened: { close(): void }[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});

function payerStore(file: string): PayerStore {
  const store = new lab.PayerStore(dir.path(file));
  opened.push(store);
  return store;
}

const DESTINATION = `02${'11'.repeat(32)}`;
/** A creation time long before any claim this test makes (LND's creation_time_ns of the earlier submission). */
const OLD_NS = 1_000_000_000n;
/** A creation time after every claim this test makes (LND initialised the payment again for the retry). */
const FRESH_NS = (BigInt(Date.now()) + 3_600_000n) * 1_000_000n;

function decoded(paymentHash: string, amountMsat: bigint): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-payer-audit' };
}

function payment(label: string, status: 'IN_FLIGHT' | 'FAILED' | 'SUCCEEDED', htlcs: HtlcAttempt[] = [], creationTimeNs = OLD_NS): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: 1000n, feeMsat: status === 'SUCCEEDED' ? 10n : 0n,
    preimage: status === 'SUCCEEDED' ? preimage : undefined, paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '',
    creationTimeNs, paymentIndex: '1', htlcs };
}

function attempt(attemptId: string, status: HtlcAttempt['status']): HtlcAttempt {
  return { attemptId, status, route: { totalAmtMsat: 1000n, totalFeesMsat: 0n, hops: [{ chanId: '1', pubKey: DESTINATION, amtToForwardMsat: 1000n }] },
    principalMsat: 1000n, attemptTimeNs: 1n, resolveTimeNs: status === 'IN_FLIGHT' ? 0n : 2n,
    failureCode: status === 'FAILED' ? 'TEMPORARY_CHANNEL_FAILURE' : undefined, failureSourceIndex: status === 'FAILED' ? 1 : undefined };
}

function heldUntilAborted(signal: AbortSignal | undefined): Promise<never> {
  return new Promise((_resolve, reject) => {
    const abort = (): void => reject(new lab.TransportError('aborted by the caller', 'response'));
    if (signal === undefined) { reject(new lab.TransportError('no cancellation signal was passed', 'response')); return; }
    if (signal.aborted) { abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
  });
}

class ScriptedPayerApi implements FakePayerApi {
  readonly send: Stream[] = [];
  readonly track: Stream[] = [];
  decodePayReq(): Promise<DecodedPayReq> { return Promise.reject(new Error('not scripted')); }
  sendPaymentV2(_request: unknown, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    return (this.send.shift() ?? ((_update, held) => heldUntilAborted(held)))(onUpdate, signal);
  }
  trackPaymentV2(_paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    return (this.track.shift() ?? ((_update, held) => heldUntilAborted(held)))(onUpdate, signal);
  }
}

function payer(store: PayerStore, events: Record<string, unknown>[] = []): PayerDeps & { api: ScriptedPayerApi } {
  return { api: new ScriptedPayerApi(), store, emit: event => { events.push(event); } };
}

/** A budgeted 1000 msat payment (fee limit 100) whose submission 1 LND failed after one HTLC attempt, retried: the budget is held again. */
function retried(store: PayerStore, label: string, operationId: string, withAttempt = true): string {
  const { paymentHash } = preimageFor(label);
  store.setBudget('B', 1100n);
  expect(store.recordIntent({ operationId, kind: 'payout', paymentRequest: `lnbcrt-${label}`, invoice: decoded(paymentHash, 1000n),
    feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' }).outcome).toBe('recorded');
  expect(store.claimForSubmission(paymentHash)).toBe(true);
  store.applyUpdate(payment(label, 'FAILED', withAttempt ? [attempt('1', 'FAILED')] : []), 'SendPaymentV2', 1);
  expect(store.payment(paymentHash)?.state).toBe('failed');
  expect(store.prepareRetry(operationId).outcome).toBe('recorded');
  expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n });
  return paymentHash;
}

/** A replacement invoice for the operation: admitted only when no payment of the operation is pending. */
function replacement(store: PayerStore, operationId: string): string {
  return store.recordIntent({ operationId, kind: 'payout', paymentRequest: 'lnbcrt-replacement',
    invoice: decoded(preimageFor(`${operationId}-replacement`).paymentHash, 1000n), feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' }).outcome;
}

/** The record stayed unresolved: reservation held, operation open, no replacement admitted. */
function expectStillLive(store: PayerStore, hash: string, operationId: string, state: string): void {
  expect(store.payment(hash)).toMatchObject({ state, submissions: 2 });
  expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
  expect(store.operation(operationId)?.state).toBe('open');
  expect(replacement(store, operationId)).toBe('refused');
  expect(store.events(hash).map(item => item.kind)).toContain('stale-update');
}

describe('payment lab payer audit: a retry is not failed by the earlier submission\'s FAILED', () => {
  it.each([
    ['with the earlier submission\'s HTLC attempt', true],
    ['without attempts, created before the retry was claimed', false],
  ])('an ambiguous send error (503) and a lookup that still shows submission 1\'s FAILED (%s) leave the retry uncertain', async (_name, withAttempt) => {
    const store = payerStore(`stale-submit-${String(withAttempt)}.db`);
    const hash = retried(store, `stale-submit-${String(withAttempt)}`, 'OP-STALE-SUBMIT', withAttempt);
    const deps = payer(store);
    deps.api.send.push(async () => { throw new lab.LndError('service unavailable', undefined, 503); });
    deps.api.track.push(async onUpdate => {
      onUpdate(payment(`stale-submit-${String(withAttempt)}`, 'FAILED', withAttempt ? [attempt('1', 'FAILED')] : []));
    });
    const outcome = await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    expect(outcome).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
    expectStillLive(store, hash, 'OP-STALE-SUBMIT', 'uncertain');
    // The retry reaches LND late and pays: recorded once, the operation completed, the budget consumed once.
    expect(store.applyUpdate(payment(`stale-submit-${String(withAttempt)}`, 'SUCCEEDED', [attempt('2', 'SUCCEEDED')], FRESH_NS), 'TrackPaymentV2', 2).state)
      .toBe('succeeded');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 1010n });
  });

  it('a reconcile running while the retry is submitting reads the earlier FAILED: back to intent, reservation held, the retry\'s own answers still apply', async () => {
    const store = payerStore('stale-reconcile.db');
    const hash = retried(store, 'stale-reconcile', 'OP-STALE-RECONCILE');
    expect(store.claimForSubmission(hash)).toBe(true);
    const events: Record<string, unknown>[] = [];
    const deps = payer(store, events);
    deps.api.track.push(async onUpdate => { onUpdate(payment('stale-reconcile', 'FAILED', [attempt('1', 'FAILED')])); });
    const outcome = await lab.reconcile(deps, hash);
    expect(outcome).toMatchObject({ kind: 'not-submitted' });
    expect(events.find(event => event.event === 'payment-update')).toMatchObject({ stale: true, recordState: 'submitting' });
    expect(store.payment(hash)).toMatchObject({ state: 'intent', submissions: 2 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n, availableMsat: 0n });
    expect(store.operation('OP-STALE-RECONCILE')?.state).toBe('open');
    expect(replacement(store, 'OP-STALE-RECONCILE')).toBe('refused');
    expect(store.events(hash).map(item => item.kind)).toEqual(expect.arrayContaining(['stale-update', 'not-initiated']));
    // The retry's request reaches LND after all and pays: its own update still applies.
    expect(store.applyUpdate(payment('stale-reconcile', 'SUCCEEDED', [attempt('2', 'SUCCEEDED')], FRESH_NS), 'SendPaymentV2', 2).state).toBe('succeeded');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 1010n });
  });

  it.each([
    ['without attempts', false],
    ['with the earlier submission\'s attempt', true],
  ])('a crash between the retry\'s claim and its send (%s): reconcile returns it to intent and it can be submitted again', async (_name, withAttempt) => {
    const label = `crash-retry-${String(withAttempt)}`;
    const store = payerStore(`${label}.db`);
    const hash = retried(store, label, 'OP-CRASH', withAttempt);
    // The process claims submission 2 and dies before SendPaymentV2: LND keeps showing submission 1's FAILED.
    expect(store.claimForSubmission(hash)).toBe(true);
    const deps = payer(store);
    deps.api.track.push(async onUpdate => { onUpdate(payment(label, 'FAILED', withAttempt ? [attempt('1', 'FAILED')] : [])); });
    expect(await lab.reconcile(deps, hash)).toMatchObject({ kind: 'not-submitted' });
    expect(store.payment(hash)).toMatchObject({ state: 'intent', submissions: 2 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n });
    expect(store.events(hash).map(item => item.kind)).toContain('stale-update');
    // Submitted again as submission 3, it succeeds once.
    deps.api.send.push(async onUpdate => { onUpdate(payment(label, 'SUCCEEDED', [attempt('3', 'SUCCEEDED')], FRESH_NS)); });
    expect(await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' })).toMatchObject({ kind: 'succeeded' });
    expect(store.payment(hash)).toMatchObject({ state: 'succeeded', submissions: 3 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: 1010n });
  });

  it('a snapshot of the retry itself still decides it: a new attempt, or no attempt and a creation time after the earlier submission\'s', () => {
    const store = payerStore('live-snapshots.db');
    const hash = retried(store, 'live-a', 'OP-LIVE-A');
    expect(store.claimForSubmission(hash)).toBe(true);
    expect(store.applyUpdate(payment('live-a', 'IN_FLIGHT', [attempt('2', 'IN_FLIGHT')]), 'TrackPaymentV2', 2).state).toBe('in_flight');
    expect(store.applyUpdate(payment('live-a', 'FAILED', [attempt('2', 'FAILED')]), 'TrackPaymentV2', 2).state).toBe('failed');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n });
    // Submission 1 of live-b was reported FAILED, created at OLD_NS (LND's clock).
    const other = retried(store, 'live-b', 'OP-LIVE-B', false);
    expect(store.claimForSubmission(other)).toBe(true);
    expect(store.applyUpdate(payment('live-b', 'FAILED', [], OLD_NS), 'TrackPaymentV2', 2).state).toBe('submitting');
    expect(store.applyUpdate(payment('live-b', 'FAILED', [], OLD_NS + 1n), 'TrackPaymentV2', 2).state).toBe('failed');
  });

  it('without a creation time recorded for the earlier submission (refused before initiation), the claim time decides', () => {
    const store = payerStore('claim-time.db');
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor('claim-time');
    store.recordIntent({ operationId: 'OP-CT', kind: 'payout', paymentRequest: 'lnbcrt-ct', invoice: decoded(hash, 1000n), feeLimitMsat: 100n,
      maxParts: 1, budgetId: 'B' });
    expect(store.claimForSubmission(hash)).toBe(true);
    expect(store.markRejected(hash, 'rate limit exceeded', 1)).toBe(true);
    expect(store.prepareRetry('OP-CT').outcome).toBe('recorded');
    expect(store.claimForSubmission(hash)).toBe(true);
    const claimedAt = store.payment(hash)?.submittedAtNs as bigint;
    expect(typeof claimedAt).toBe('bigint');
    expect(store.applyUpdate(payment('claim-time', 'FAILED', [], claimedAt - 1n), 'TrackPaymentV2', 2).state).toBe('submitting');
    expect(store.applyUpdate(payment('claim-time', 'FAILED', [], claimedAt), 'TrackPaymentV2', 2).state).toBe('failed');
  });

  it('LND\'s clock 5 s ahead of this host: the earlier FAILED, created after the retry\'s claim by this clock, is still stale', async () => {
    const store = payerStore('skew-ahead.db');
    const ahead = (BigInt(Date.now()) + 5_000n) * 1_000_000n;
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor('skew-ahead');
    store.recordIntent({ operationId: 'OP-AHEAD', kind: 'payout', paymentRequest: 'lnbcrt-ahead', invoice: decoded(hash, 1000n), feeLimitMsat: 100n,
      maxParts: 1, budgetId: 'B' });
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(payment('skew-ahead', 'FAILED', [], ahead), 'SendPaymentV2', 1);
    expect(store.prepareRetry('OP-AHEAD').outcome).toBe('recorded');
    const deps = payer(store);
    deps.api.send.push(async () => { throw new lab.LndError('service unavailable', undefined, 503); });
    deps.api.track.push(async onUpdate => { onUpdate(payment('skew-ahead', 'FAILED', [], ahead)); });
    expect(await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' })).toMatchObject({ kind: 'unresolved', state: 'uncertain' });
    expectStillLive(store, hash, 'OP-AHEAD', 'uncertain');
  });

  it('LND\'s clock 5 s behind this host: the retry\'s own FAILED, created before its claim by this clock, still fails it', () => {
    const store = payerStore('skew-behind.db');
    const now = BigInt(Date.now()) * 1_000_000n;
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor('skew-behind');
    store.recordIntent({ operationId: 'OP-BEHIND', kind: 'payout', paymentRequest: 'lnbcrt-behind', invoice: decoded(hash, 1000n), feeLimitMsat: 100n,
      maxParts: 1, budgetId: 'B' });
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(payment('skew-behind', 'FAILED', [], now - 10_000_000_000n), 'SendPaymentV2', 1);
    expect(store.prepareRetry('OP-BEHIND').outcome).toBe('recorded');
    expect(store.claimForSubmission(hash)).toBe(true);
    // LND initialised the retry at its "now", 5 s behind this host's.
    expect(store.applyUpdate(payment('skew-behind', 'IN_FLIGHT', [], now - 5_000_000_000n), 'TrackPaymentV2', 2).state).toBe('in_flight');
    expect(store.applyUpdate(payment('skew-behind', 'FAILED', [], now - 5_000_000_000n), 'TrackPaymentV2', 2).state).toBe('failed');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n });
  });

  it('SendPaymentV2 updates of the retry are trusted: its FAILED fails it', () => {
    const store = payerStore('send-trusted.db');
    const hash = retried(store, 'send-trusted', 'OP-SEND-TRUSTED');
    expect(store.claimForSubmission(hash)).toBe(true);
    expect(store.applyUpdate(payment('send-trusted', 'FAILED', []), 'SendPaymentV2', 2).state).toBe('failed');
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n });
  });

  it('a retry LND refused definitely, while it still shows the earlier FAILED, fails before initiation', async () => {
    const store = payerStore('stale-definite.db');
    const hash = retried(store, 'stale-definite', 'OP-STALE-DEFINITE');
    const deps = payer(store);
    deps.api.send.push(async () => { throw new lab.LndError('rate limit exceeded', 8, 429); });
    deps.api.track.push(async onUpdate => { onUpdate(payment('stale-definite', 'FAILED', [attempt('1', 'FAILED')])); });
    expect((await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' })).kind).toBe('failed');
    expect(store.payment(hash)?.failureReason).toMatch(/^REJECTED_BEFORE_INITIATION/);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n });
  });

  it('migration 9 records claim times; it runs again on a database set back a version, and an older one gets it', () => {
    const file = dir.path('migration-9.db');
    const store = new lab.PayerStore(file);
    opened.push(store);
    const hash = retried(store, 'migration-9', 'OP-MIG9');
    expect(store.claimForSubmission(hash)).toBe(true);
    const version = (db: PayerStore['db']): unknown => db.prepare('PRAGMA user_version').all()[0]?.user_version;
    const current = version(store.db);
    // Set back past migration 9 with the column already there: the step runs again without error.
    store.db.exec(`PRAGMA user_version = ${Number(current) - 2}`);
    store.close();
    const again = new lab.PayerStore(file);
    opened.push(again);
    expect(version(again.db)).toBe(current);
    // A database from before the column: an unresolved payment gets its last change as its claim time.
    again.db.exec(`ALTER TABLE payments DROP COLUMN submitted_at_ns; PRAGMA user_version = 8`);
    again.close();
    const upgraded = payerStore('migration-9.db');
    expect(version(upgraded.db)).toBe(current);
    const claimedAt = upgraded.payment(hash)?.submittedAtNs as bigint;
    const updatedMs = BigInt(Date.parse(String(upgraded.db.prepare('SELECT updated_at FROM payments WHERE payment_hash = ?').all(hash)[0]?.updated_at)));
    expect(claimedAt).toBe(updatedMs * 1_000_000n);
  });
});

describe('payment lab payer audit: the claim reports its own submission', () => {
  it('a revert and a second claim by another process right after the claim do not make this call speak for submission 2', async () => {
    const store = payerStore('claim-returning.db');
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor('claim-returning');
    expect(store.recordIntent({ operationId: 'OP-CLAIM', kind: 'payout', paymentRequest: 'lnbcrt-claim-returning', invoice: decoded(hash, 1000n),
      feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' }).outcome).toBe('recorded');
    // Between this call's claim and anything it reads next, another process's NotFound reverts the record and claims submission 2.
    const racing = new Proxy(store, {
      get(target, property) {
        if (property !== 'claimForSubmission') {
          // Methods run on the store itself (its private fields are not reachable through a proxy).
          const value = Reflect.get(target, property, target) as unknown;
          return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
        }
        return (paymentHash: string, claimed?: { submission?: number }): boolean => {
          const result = target.claimForSubmission(paymentHash, claimed);
          expect(target.markNotInitiated(paymentHash, 'NotFound', 1)).toBe('reverted');
          expect(target.claimForSubmission(paymentHash)).toBe(true);
          return result;
        };
      },
    });
    const deps = { ...payer(store), store: racing };
    deps.api.send.push(async () => { throw new lab.TransportError('connect ECONNREFUSED', 'connect'); });
    const outcome = await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    // This call was submission 1: its refused connection is superseded and leaves submission 2 submitting.
    expect(outcome).toMatchObject({ kind: 'unresolved' });
    expect(outcome.reason).toMatch(/submission 1 is superseded/);
    expect(store.payment(hash)).toMatchObject({ state: 'submitting', submissions: 2 });
  });
});

describe('payment lab payer audit: the claim reports its own submission, across two processes', () => {
  it('claim 1, another process\'s NotFound revert and claim 2, then submission 1\'s FAILED: it is stale, submission 2 stays live', async () => {
    const store = payerStore('claim-two-stores.db');
    const other = payerStore('claim-two-stores.db');
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor('claim-two-stores');
    expect(store.recordIntent({ operationId: 'OP-CLAIM2', kind: 'payout', paymentRequest: 'lnbcrt-claim-two-stores', invoice: decoded(hash, 1000n),
      feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' }).outcome).toBe('recorded');
    // Right after this process's claim commits, the other process (its own connection to the same file) reverts and claims again.
    const racing = new Proxy(store, {
      get(target, property) {
        const value = Reflect.get(target, property, target) as unknown;
        if (property !== 'claimForSubmission') return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
        return (paymentHash: string, claimed?: { submission?: number }): boolean => {
          const result = target.claimForSubmission(paymentHash, claimed);
          expect(other.markNotInitiated(paymentHash, 'NotFound', 1)).toBe('reverted');
          expect(other.claimForSubmission(paymentHash)).toBe(true);
          return result;
        };
      },
    });
    const deps = { ...payer(store), store: racing };
    // LND initiated submission 1 after all and fails it on its own stream.
    deps.api.send.push(async onUpdate => {
      onUpdate(payment('claim-two-stores', 'IN_FLIGHT', [], FRESH_NS));
      onUpdate(payment('claim-two-stores', 'FAILED', [], FRESH_NS));
    });
    const outcome = await lab.submit(deps, hash, { timeoutSeconds: 30, fault: 'none' });
    expect(outcome).toMatchObject({ kind: 'unresolved' });
    expect(outcome.reason).toMatch(/submission 1 is superseded/);
    expect(store.payment(hash)).toMatchObject({ state: 'submitting', submissions: 2 });
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 1100n });
    expect(store.events(hash).map(item => item.kind)).toContain('stale-update');
  });
});

describe('payment lab payer audit: reconcile answers from the record as it is after the lookup', () => {
  /** A submitting payment; its reconcile's lookup ends with `end` after another process recorded LND's success. */
  async function successDuringLookup(file: string, withAttempt: boolean, end: (stop: AbortController) => Error): Promise<{ outcome: { kind: string }; store: PayerStore }> {
    const store = payerStore(file);
    const other = payerStore(file);
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor(file);
    store.recordIntent({ operationId: `OP-${file}`, kind: 'payout', paymentRequest: `lnbcrt-${file}`, invoice: decoded(hash, 1000n), feeLimitMsat: 100n,
      maxParts: 1, budgetId: 'B' });
    expect(store.claimForSubmission(hash)).toBe(true);
    const deps = payer(store);
    const stop = new AbortController();
    deps.api.track.push(() => {
      expect(other.applyUpdate(payment(file, 'SUCCEEDED', withAttempt ? [attempt('1', 'SUCCEEDED')] : [], FRESH_NS), 'SendPaymentV2', 1).state).toBe('succeeded');
      return Promise.reject(end(stop));
    });
    return { outcome: await lab.reconcile(deps, hash, stop.signal), store };
  }

  it.each([['with', true], ['without', false]])('a NotFound after another tracker recorded success (%s attempts) reports succeeded', async (_name, withAttempt) => {
    const { outcome } = await successDuringLookup(`nf-success-${String(withAttempt)}.db`, withAttempt,
      () => new lab.LndError('payment isn\'t initiated', 5, 404));
    expect(outcome).toMatchObject({ kind: 'succeeded' });
  });

  it('a lookup cut off by the deadline after another tracker recorded success reports succeeded', async () => {
    const { outcome } = await successDuringLookup('abort-success.db', true, stop => { stop.abort(); return new lab.TransportError('aborted by the caller', 'response'); });
    expect(outcome).toMatchObject({ kind: 'succeeded' });
  });
});

describe('payment lab payer audit: reconcile', () => {
  it('NotFound for a payment in flight without attempts does not claim attempts were recorded', async () => {
    const store = payerStore('notfound-unchanged.db');
    store.setBudget('B', 1100n);
    const { paymentHash: hash } = preimageFor('notfound-unchanged');
    store.recordIntent({ operationId: 'OP-NF', kind: 'payout', paymentRequest: 'lnbcrt-nf', invoice: decoded(hash, 1000n), feeLimitMsat: 100n,
      maxParts: 1, budgetId: 'B' });
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(payment('notfound-unchanged', 'IN_FLIGHT'), 'SendPaymentV2', 1);
    const deps = payer(store);
    deps.api.track.push(() => Promise.reject(new lab.LndError('payment isn\'t initiated', 5, 404)));
    const outcome = await lab.reconcile(deps, hash);
    expect(outcome).toMatchObject({ kind: 'unresolved', state: 'in_flight' });
    expect(outcome.reason).not.toMatch(/attempts were recorded/);
    expect(outcome.reason).toMatch(/in_flight and was left unchanged/);
  });

  it('a node that answers every TrackPaymentV2 with one IN_FLIGHT and ends it is asked again with a growing backoff', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    try {
      const store = payerStore('backoff.db');
      store.setBudget('B', 1100n);
      const { paymentHash: hash } = preimageFor('backoff');
      store.recordIntent({ operationId: 'OP-BACKOFF', kind: 'payout', paymentRequest: 'lnbcrt-backoff', invoice: decoded(hash, 1000n),
        feeLimitMsat: 100n, maxParts: 1, budgetId: 'B' });
      expect(store.claimForSubmission(hash)).toBe(true);
      store.markUncertain(hash, 'stream dropped', 1);
      const events: Record<string, unknown>[] = [];
      const deps = payer(store, events);
      const rounds = 5;
      for (let round = 0; round < rounds; round += 1) {
        deps.api.track.push(async onUpdate => { onUpdate(payment('backoff', 'IN_FLIGHT', [attempt('1', 'IN_FLIGHT')])); });
      }
      const stop = new AbortController();
      const done = lab.reconcile(deps, hash, stop.signal);
      const waits = (): number[] => events.filter(event => event.event === 'track-ended-early').map(event => Number(event.retryInMs));
      for (let turn = 0; turn < 200 && waits().length < rounds; turn += 1) await vi.advanceTimersByTimeAsync(500);
      stop.abort();
      await done;
      // The first stream moved the record uncertain -> in_flight; the others changed nothing.
      expect(waits()).toEqual([1000, 2000, 4000, 8000, 15000]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('payment lab payer audit: LND REST errors', () => {
  let server: Server | undefined;
  afterEach(async () => { await new Promise<void>(done => { if (server === undefined) done(); else server.close(() => done()); }); server = undefined; });

  /** A local HTTPS server with a disposable self-signed certificate for 127.0.0.1. */
  async function serve(handler: (incoming: IncomingMessage, response: ServerResponse) => void): Promise<{ port: number; cert: Buffer }> {
    const cert = dir.path(`peer-${Date.now()}.crt`);
    const key = dir.path(`peer-${Date.now()}.key`);
    const config = dir.path('openssl.cnf');
    writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-config', config,
      '-keyout', key, '-out', cert, '-subj', '/CN=payment-lab-test', '-addext', 'subjectAltName=IP:127.0.0.1'], { timeout: 60_000 });
    expect(made.status, 'disposable certificate generation').toBe(0);
    const tlsCert = readFileSync(cert);
    server = createServer({ cert: tlsCert, key: readFileSync(key) }, handler);
    await new Promise<void>((done, fail) => server?.listen(0, '127.0.0.1', done).once('error', fail));
    return { port: (server?.address() as AddressInfo).port, cert: tlsCert };
  }

  interface RestClient {
    call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown>;
    stream(method: 'GET' | 'POST', path: string, body: unknown, onMessage: (message: unknown) => StreamDecision): Promise<void>;
  }
  type RestModule = { LndRestClient: new (connection: { label: string; host: string; port: number; tlsCert: Buffer; macaroonHex: string }) => RestClient };

  it('a proxy\'s 504 with a relayed body carrying http_code 500 keeps status 504 and is not a definite refusal', async () => {
    const { port, cert } = await serve((incoming, response) => {
      incoming.resume();
      response.writeHead(504, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ code: 2, message: 'payment is in transition', http_code: 500 }));
    });
    const { LndRestClient } = await loadLabModule<RestModule>('lnd/rest.ts');
    const client = new LndRestClient({ label: 'test', host: '127.0.0.1', port, tlsCert: cert, macaroonHex: '00' });
    const error = await client.call('POST', '/v2/router/send', {}).then(() => undefined, (thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(lab.LndError);
    expect((error as { httpStatus?: number }).httpStatus).toBe(504);
    expect(lab.definiteRefusal(error)).toBe(false);
  }, 90_000);

  it('an error frame inside a 200 stream takes its http_code from the body', async () => {
    const { port, cert } = await serve((incoming, response) => {
      incoming.resume();
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(`${JSON.stringify({ error: { code: 2, message: 'invoice expired', http_code: 500 } })}\n`);
    });
    const { LndRestClient } = await loadLabModule<RestModule>('lnd/rest.ts');
    const client = new LndRestClient({ label: 'test', host: '127.0.0.1', port, tlsCert: cert, macaroonHex: '00' });
    const error = await client.stream('POST', '/v2/router/send', {}, () => 'continue').then(() => undefined, (thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(lab.LndError);
    expect((error as { httpStatus?: number }).httpStatus).toBe(500);
  }, 90_000);
});

describe('payment lab payer audit: offline BOLT11 reading', () => {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  /** A synthetic, checksum-valid BOLT11-shaped string: timestamp words, a `p` field with `hash`, 104 signature words. */
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
  type Bolt11 = { bolt11PaymentHash(paymentRequest: string): string | undefined; damagedPaymentRequest(paymentRequest: string): boolean };

  it('a look-alike that case-folds to ASCII (Kelvin sign, long s, dotted I) is not read as an invoice', async () => {
    const { bolt11PaymentHash, damagedPaymentRequest } = await loadLabModule<Bolt11>('util/bolt11.ts');
    const hash = 'ab'.repeat(32);
    const invoice = synthetic(hash);
    expect(bolt11PaymentHash(invoice)).toBe(hash);
    expect(bolt11PaymentHash(invoice.toUpperCase())).toBe(hash);
    const kelvin = invoice.replace('k', 'K');
    expect(kelvin).not.toBe(invoice);
    for (const variant of [kelvin, kelvin.toUpperCase(), invoice.replace('k', 'ſ'), `${invoice.slice(0, -1)}İ`]) {
      expect(bolt11PaymentHash(variant), JSON.stringify(variant)).toBeUndefined();
    }
    expect(damagedPaymentRequest(kelvin)).toBe(true);
    expect(damagedPaymentRequest(invoice)).toBe(false);
  });

  it('damagedPaymentRequest answers a long string without backtracking over it', async () => {
    const { damagedPaymentRequest } = await loadLabModule<Bolt11>('util/bolt11.ts');
    const long = `ln${'a1'.repeat(100_000)}!`;
    const began = performance.now();
    expect(damagedPaymentRequest(long)).toBe(true);
    expect(performance.now() - began).toBeLessThan(2_000);
    expect(damagedPaymentRequest('ln1')).toBe(true);
    expect(damagedPaymentRequest('ln1q')).toBe(true);
  });
});
