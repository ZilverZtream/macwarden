import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { CORPUS, loadHarness, type Harness } from './helpers/payment-lab-harness.js';
import {
  loadExplain, loadHarnessRunner, loadLab, preimageFor, tempDirectory,
  type DecodedPayReq, type Explain, type ExplainDocument, type FakeInvoiceApi, type FakePayerApi, type HtlcAttempt, type Invoice, type Lab,
  type Payment, type PayerStore, type ReceiverStore, type StreamDecision,
} from './helpers/payment-lab-modules.js';

/**
 * `payer explain` and `receiver explain` (design brief 1.3.0, item 4): the timeline of one payment from
 * the records, each decision with the README rule that made it, never a preimage or a payment request.
 * The records are built with the lab's real stores and workflows against scripted LND stand-ins, the
 * README scenario families one by one; the replay corpus of the state-machine harness is explained
 * subject by subject. No node, no Docker, no credential.
 */

let lab: Lab;
let explain: Explain;
let harness: Harness;
const dir = tempDirectory();
const README = readFileSync(join('examples', 'payment-lab', 'README.md'), 'utf8');

beforeAll(async () => {
  lab = await loadLab();
  explain = await loadExplain();
  harness = await loadHarness();
});
afterAll(() => dir.remove());

let stdout: string[];
let stderr: string[];
beforeEach(() => {
  stdout = [];
  stderr = [];
  vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation(chunk => { stderr.push(String(chunk)); return true; });
});
const opened: { close(): void }[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const store of opened.splice(0)) {
    try { store.close(); } catch { /* already closed */ }
  }
});

const DESTINATION = `02${'11'.repeat(32)}`;
const quiet = (): void => undefined;
/** A payment request shaped like BOLT 11, so a leak would be found by text. */
const requestFor = (label: string): string => `lnbcrt10u1p${label.replace(/[^a-z]/g, 'q')}qqqqsecretqqqqqqqqqqqqqqqqqqqqqqqqqq`;

function decoded(paymentHash: string, amountMsat: bigint): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-explain' };
}

function attempt(attemptId: string, status: HtlcAttempt['status'], options: { hops?: number; fee?: bigint; code?: string; source?: number } = {}):
  HtlcAttempt {
  const hops = Array.from({ length: options.hops ?? 2 }, (_item, index) => ({ chanId: String(100 + index), pubKey: DESTINATION, amtToForwardMsat: 1000n }));
  return { attemptId, status, route: { totalAmtMsat: 1000n + (options.fee ?? 0n), totalFeesMsat: options.fee ?? 0n, hops }, principalMsat: 1000n,
    attemptTimeNs: 1n, resolveTimeNs: status === 'IN_FLIGHT' ? 0n : 2n, failureCode: status === 'FAILED' ? options.code ?? 'TEMPORARY_CHANNEL_FAILURE' : undefined,
    failureSourceIndex: status === 'FAILED' ? options.source ?? 1 : undefined };
}

function payment(label: string, status: 'IN_FLIGHT' | 'FAILED' | 'SUCCEEDED', htlcs: HtlcAttempt[] = [], fee = 10n,
  failureReason = 'FAILURE_REASON_NO_ROUTE'): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: 1000n, feeMsat: status === 'SUCCEEDED' ? fee : 0n, preimage: status === 'SUCCEEDED' ? preimage : undefined,
    paymentRequest: '', failureReason: status === 'FAILED' ? failureReason : '', creationTimeNs: 1n, paymentIndex: '1', htlcs };
}

function invoice(paymentHash: string, state: string, amtPaidMsat = 0n, settleIndex = 0n, memo = ''): Invoice {
  return { paymentHash, state, memo, valueMsat: 1000n, amtPaidMsat, addIndex: 1n, settleIndex, paymentRequest: '', htlcs: [] };
}

type Stream = (onUpdate: (payment: Payment) => StreamDecision, signal: AbortSignal | undefined) => Promise<void>;

/** SendPaymentV2 / TrackPaymentV2 take the next scripted stream; with none left they fail at once. */
class ScriptedPayerApi implements FakePayerApi {
  readonly send: Stream[] = [];
  readonly track: Stream[] = [];
  invoice: DecodedPayReq | undefined;
  async decodePayReq(): Promise<DecodedPayReq> {
    if (this.invoice === undefined) throw new Error('no invoice scripted');
    return this.invoice;
  }
  sendPaymentV2(_request: unknown, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    const next = this.send.shift();
    return next === undefined ? Promise.reject(new lab.TransportError('no stream scripted', 'connect')) : next(onUpdate, signal);
  }
  trackPaymentV2(_paymentHash: string, onUpdate: (payment: Payment) => StreamDecision, signal?: AbortSignal): Promise<void> {
    const next = this.track.shift();
    return next === undefined ? Promise.reject(new lab.TransportError('no stream scripted', 'connect')) : next(onUpdate, signal);
  }
}

const noInvoiceCalls: FakeInvoiceApi = {
  lookupInvoice: () => Promise.reject(new Error('lookupInvoice not scripted')),
  settleInvoice: () => Promise.reject(new Error('not used')),
  cancelInvoice: () => Promise.reject(new Error('not used')),
  subscribeInvoices: () => Promise.reject(new Error('not used')),
};

function payerStore(file: string): PayerStore {
  const store = new lab.PayerStore(file);
  opened.push(store);
  return store;
}

function receiverStore(file: string): ReceiverStore {
  const store = new lab.ReceiverStore(file);
  opened.push(store);
  return store;
}

/** main with fresh stores on the files (main closes them) and the given stand-ins. */
function services(files: { payer?: string; receiver?: string }, payerApi: FakePayerApi = new ScriptedPayerApi(), invoiceApi: FakeInvoiceApi = noInvoiceCalls) {
  return {
    payer: () => ({ api: payerApi, store: new lab.PayerStore(files.payer ?? dir.path('unused-payer.db')), emit: quiet }),
    receiver: () => ({ api: invoiceApi, store: new lab.ReceiverStore(files.receiver ?? dir.path('unused-receiver.db')), emit: quiet }),
  };
}

interface Explained { code: number; doc: ExplainDocument; text: string; textCode: number; stderr: string }

/** Runs explain twice through main, with --json and as text, and returns both. */
async function run(argv: string[], svc: ReturnType<typeof services>): Promise<Explained> {
  stdout.length = 0;
  stderr.length = 0;
  const code = await lab.main([...argv, '--json'], svc);
  const json = stdout.join('');
  expect(json.trim().split('\n'), 'one JSON document').toHaveLength(1);
  const doc = JSON.parse(json) as ExplainDocument;
  stdout.length = 0;
  const textCode = await lab.main(argv, svc);
  return { code, doc, text: stdout.join(''), textCode, stderr: stderr.join('') };
}

const kinds = (doc: ExplainDocument): string[] => doc.result?.timeline.map(item => item.kind) ?? [];
const rules = (doc: ExplainDocument): string[] => [...new Set(doc.result?.timeline.flatMap(item => item.rule === undefined ? [] : [item.rule]) ?? [])];

/** Nothing secret in either output: no preimage, no payment request, no full payment hash; every text line within 120 characters. */
function assertClean(result: Explained, secrets: string[]): void {
  const both = `${JSON.stringify(result.doc)}\n${result.text}\n${result.stderr}`;
  for (const secret of secrets) {
    expect(both.toLowerCase(), 'a secret or a full payment hash in the output').not.toContain(secret.toLowerCase());
  }
  expect(both).not.toMatch(/lnbcrt[0-9a-z]*1[0-9a-z]{20,}/i);
  for (const line of result.text.split('\n')) expect(line.length, line).toBeLessThanOrEqual(120);
  // eslint-disable-next-line no-control-regex
  expect(result.text).not.toMatch(/[\x00-\x09\x0b-\x1f\x7f]/);
}

function payerSecrets(label: string): string[] {
  const { preimage, paymentHash } = preimageFor(label);
  return [preimage, preimage.slice(0, 16), paymentHash, requestFor(label)];
}

describe('payer explain', () => {
  it('scenario 1, dropped connection: intent, submission, in flight, uncertain, then TrackPaymentV2 succeeds; journal and outbox', async () => {
    const file = dir.path('s1-payer.db');
    const store = payerStore(file);
    const { paymentHash } = preimageFor('s1');
    expect(store.recordIntent({ operationId: 'PAY-ORD-1', kind: 'order-payment', paymentRequest: requestFor('s1'), invoice: decoded(paymentHash, 1000n),
      feeLimitMsat: 100n, maxParts: 16 }).outcome).toBe('recorded');
    const api = new ScriptedPayerApi();
    api.send.push(async onUpdate => {
      onUpdate(payment('s1', 'IN_FLIGHT', [attempt('1', 'IN_FLIGHT', { fee: 10n })]));
      throw new lab.TransportError('connection reset by peer', 'response');
    });
    const deps = { api, store, emit: quiet };
    expect((await lab.submit(deps, paymentHash, { timeoutSeconds: 30, fault: 'none' })).kind).toBe('unresolved');
    api.track.push(async onUpdate => { onUpdate(payment('s1', 'SUCCEEDED', [attempt('1', 'SUCCEEDED', { fee: 10n })])); });
    expect((await lab.reconcile(deps, paymentHash)).kind).toBe('succeeded');
    store.close();

    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'PAY-ORD-1'], services({ payer: file }));
    expect(result.code).toBe(0);
    expect(result.textCode).toBe(0);
    expect(Object.keys(result.doc)).toEqual(['schema', 'command', 'ok', 'warnings', 'result', 'error']);
    expect(result.doc).toMatchObject({ schema: 1, command: 'explain', ok: true, warnings: [], error: null });
    expect(Object.keys(result.doc.result ?? {})).toEqual(['subject', 'timeline', 'outcome', 'reservation', 'journal', 'outbox', 'reconciliation']);
    expect(result.doc.result?.subject).toEqual({ component: 'payer', operationId: 'PAY-ORD-1', payments: [explain.fingerprint(paymentHash)] });
    expect(kinds(result.doc)).toEqual(expect.arrayContaining(['operation', 'intent', 'submission', 'lnd-update', 'uncertain', 'htlc-attempt',
      'succeeded', 'journal', 'outbox-enqueued', 'outcome']));
    const order = kinds(result.doc);
    expect(order.indexOf('intent')).toBeLessThan(order.indexOf('submission'));
    expect(order.indexOf('uncertain')).toBeLessThan(order.indexOf('succeeded'));
    expect(rules(result.doc)).toEqual(expect.arrayContaining(['Durable intent before submission', 'SendPaymentV2 is called only by compare-and-set',
      'A timeout is not a failure', 'Accounting from LND\'s numbers', 'Fulfillment']));
    for (const item of result.doc.result?.timeline ?? []) expect(Object.keys(item).every(key => ['at', 'kind', 'detail', 'rule'].includes(key))).toBe(true);
    const attemptItem = result.doc.result?.timeline.find(item => item.kind === 'htlc-attempt');
    expect(attemptItem?.detail).toContain('route of 2 hop(s)');
    expect(attemptItem?.detail).toContain('fee 10 msat');
    expect(result.doc.result?.outcome.summary).toContain('operation completed');
    expect(result.doc.result?.journal.map(entry => entry.event)).toEqual(['payment-succeeded']);
    expect(result.doc.result?.outbox).toMatchObject([{ kind: 'confirm-operation', state: 'pending' }]);
    expect(result.doc.result?.reconciliation.map(item => item.rule)).toContain('A timeout is not a failure');
    for (const section of ['outcome', 'timeline', 'reservation', 'journal', 'outbox', 'reconciliation']) {
      expect(result.text.split('\n')).toContain(section);
    }
    assertClean(result, payerSecrets('s1'));
    // The same explanation for the payment hash.
    const byHash = await run(['payer', 'explain', '--as', 'customer-payer', '--payment-hash', paymentHash.toUpperCase()], services({ payer: file }));
    expect(byHash.code).toBe(0);
    expect(kinds(byHash.doc)).toEqual(kinds(result.doc));
  });

  it('scenario 3, directional liquidity: failed, retried, second submission succeeds; scenario 4: HTLC attempts with failure code and source', async () => {
    const file = dir.path('s3-payer.db');
    const store = payerStore(file);
    const { paymentHash } = preimageFor('s3');
    store.recordIntent({ operationId: 'REFUND-3', kind: 'refund', paymentRequest: requestFor('s3'), invoice: decoded(paymentHash, 1000n),
      feeLimitMsat: 100n, maxParts: 16 });
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    store.applyUpdate(payment('s3', 'FAILED', [], 0n, 'FAILURE_REASON_INSUFFICIENT_BALANCE'), 'SendPaymentV2', 1);
    expect(store.prepareRetry('REFUND-3').outcome).toBe('recorded');
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    store.applyUpdate(payment('s3', 'IN_FLIGHT', [attempt('7', 'FAILED', { hops: 3, code: 'TEMPORARY_CHANNEL_FAILURE', source: 2 }),
      attempt('8', 'IN_FLIGHT')]), 'SendPaymentV2', 2);
    store.applyUpdate(payment('s3', 'SUCCEEDED', [attempt('7', 'FAILED', { hops: 3, source: 2 }), attempt('8', 'SUCCEEDED', { fee: 12n })], 12n),
      'SendPaymentV2', 2);
    // A late FAILED for the closed first submission is ignored.
    store.applyUpdate(payment('s3', 'FAILED'), 'TrackPaymentV2', 1);
    store.close();

    const result = await run(['payer', 'explain', '--as', 'merchant-refunds', '--operation', 'REFUND-3'], services({ payer: file }));
    expect(result.code).toBe(0);
    const order = kinds(result.doc);
    expect(order.filter(kind => kind === 'submission')).toHaveLength(2);
    expect(order).toEqual(expect.arrayContaining(['failed', 'retry', 'htlc-attempt', 'succeeded']));
    expect(order.indexOf('failed')).toBeLessThan(order.indexOf('retry'));
    expect(order.indexOf('retry')).toBeLessThan(order.lastIndexOf('submission'));
    const failedAttempt = result.doc.result?.timeline.find(item => item.kind === 'htlc-attempt' && item.detail.includes('FAILED'));
    expect(failedAttempt?.detail).toMatch(/attempt 7 \(submission 2\): FAILED, route of 3 hop\(s\).*failure TEMPORARY_CHANNEL_FAILURE from hop index 2/);
    expect(result.doc.result?.timeline.find(item => item.kind === 'failed')?.detail).toContain('FAILURE_REASON_INSUFFICIENT_BALANCE');
    expect(rules(result.doc)).toEqual(expect.arrayContaining(['Unresolved is a state, not an error', 'SendPaymentV2 is called only by compare-and-set']));
    const outcomePayments = result.doc.result?.outcome.payments as { submissions: number; state: string }[];
    expect(outcomePayments).toMatchObject([{ submissions: 2, state: 'succeeded' }]);
    assertClean(result, payerSecrets('s3'));
  });

  it('stale updates and a NotFound revert: each named with its rule', async () => {
    const file = dir.path('stale-payer.db');
    const store = payerStore(file);
    const { paymentHash } = preimageFor('stale');
    store.recordIntent({ operationId: 'OP-STALE', kind: 'payout', paymentRequest: requestFor('stale'), invoice: decoded(paymentHash, 1000n),
      feeLimitMsat: 100n, maxParts: 1 });
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    expect(store.claimForSubmission(paymentHash)).toBe(false);
    expect(store.markUncertain(paymentHash, 'transport error during response: reset', 1)).toBe('uncertain');
    expect(store.markNotInitiated(paymentHash, 'TrackPaymentV2 NotFound', 1)).toBe('reverted');
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    store.applyUpdate(payment('stale', 'IN_FLIGHT'), 'TrackPaymentV2', 1);
    store.close();

    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-STALE'], services({ payer: file }));
    expect(result.code).toBe(0);
    expect(kinds(result.doc)).toEqual(expect.arrayContaining(['revert', 'stale-update']));
    const stale = result.doc.result?.reconciliation.find(item => item.decision === 'stale-update');
    expect(stale).toMatchObject({ rule: 'SendPaymentV2 is called only by compare-and-set' });
    expect(stale?.predicates).toContain('stale-submission-changes-nothing');
    expect(result.doc.result?.reconciliation.find(item => item.decision === 'revert')?.rule).toBe('A timeout is not a failure');
    expect(result.doc.result?.outcome.summary).toContain('operation open');
    assertClean(result, payerSecrets('stale'));
  });

  it('scenario 5, concurrent budget: refusal, reservation held, released on failure, consumed at principal plus the actual fee', async () => {
    const file = dir.path('s5-payer.db');
    const store = payerStore(file);
    store.setBudget('PAYOUTS', 2300n);
    const a = preimageFor('s5-a').paymentHash;
    const b = preimageFor('s5-b').paymentHash;
    const intent = (label: string, hash: string): string => store.recordIntent({ operationId: 'PO-5', kind: 'payout', paymentRequest: requestFor(label),
      invoice: decoded(hash, 1000n), feeLimitMsat: 100n, maxParts: 1, budgetId: 'PAYOUTS' }).outcome;
    expect(intent('s5-a', a)).toBe('recorded');
    store.recordIntent({ operationId: 'PO-5-OTHER', kind: 'payout', paymentRequest: requestFor('s5-c'),
      invoice: decoded(preimageFor('s5-c').paymentHash, 1500n), feeLimitMsat: 100n, maxParts: 1, budgetId: 'PAYOUTS' });
    expect(store.claimForSubmission(a)).toBe(true);
    store.applyUpdate(payment('s5-a', 'FAILED'), 'SendPaymentV2', 1);
    expect(intent('s5-b', b)).toBe('recorded');
    expect(store.claimForSubmission(b)).toBe(true);
    store.applyUpdate(payment('s5-b', 'SUCCEEDED', [attempt('1', 'SUCCEEDED', { fee: 7n })], 7n), 'SendPaymentV2', 1);
    // A refusal recorded for the operation (a concurrent worker that did not fit).
    store.db.prepare(`INSERT INTO budget_refusals (budget_id, operation_id, payment_hash, requested_msat, available_msat, at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run('PAYOUTS', 'PO-5', b, 1100n, 900n, new Date().toISOString());
    store.close();

    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'PO-5'], services({ payer: file }));
    expect(result.code).toBe(0);
    expect(kinds(result.doc)).toEqual(expect.arrayContaining(['reservation-held', 'reservation-released', 'reservation-consumed', 'budget-refused']));
    expect(result.doc.result?.timeline.find(item => item.kind === 'reservation-consumed')?.detail).toContain('principal 1000 + actual fee 7 = 1007 msat');
    expect(rules(result.doc)).toContain('Reservations');
    const reservation = result.doc.result?.reservation as { budgetId: string; reservations: { state: string }[]; refusals: unknown[] };
    expect(reservation.budgetId).toBe('PAYOUTS');
    expect(reservation.reservations.map(item => item.state)).toEqual(['released', 'consumed']);
    expect(reservation.refusals).toHaveLength(1);
    expect(result.doc.result?.journal.map(entry => entry.event)).toEqual(expect.arrayContaining(['budget-held', 'budget-released', 'budget-consumed',
      'payment-succeeded']));
    expect(result.doc.result?.subject.payments).toEqual([explain.fingerprint(a), explain.fingerprint(b)]);
    assertClean(result, [...payerSecrets('s5-a'), ...payerSecrets('s5-b')]);
  });

  it('an LND-supplied failure message is escaped in text output', async () => {
    const file = dir.path('escape-payer.db');
    const store = payerStore(file);
    const { paymentHash } = preimageFor('escape');
    store.recordIntent({ operationId: 'OP-ESC', kind: 'payout', paymentRequest: requestFor('escape'), invoice: decoded(paymentHash, 1000n),
      feeLimitMsat: 100n, maxParts: 1 });
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    store.markUncertain(paymentHash, `reset \u001b[2J by peer \u202e ::stop-commands:: ##[error] ${requestFor('escape')} ${preimageFor('escape').preimage}`);
    store.close();
    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-ESC'], services({ payer: file }));
    expect(result.code).toBe(0);
    const joined = result.text.replace(/\n +/g, ' ');
    expect(joined).toContain('reset \\x1b[2J by peer \\u202e');
    expect(joined).toContain('##\\x5berror]');
    expect(result.text).not.toContain('\u202e');
    expect(joined).toContain('[payment request]');
    expect(joined).toContain('[redacted]');
    assertClean(result, payerSecrets('escape'));
  });
});

describe('receiver explain', () => {
  function recordInvoice(store: ReceiverStore, label: string, orderId: string, kind: 'standard' | 'hold' = 'standard'): string {
    const { preimage, paymentHash } = preimageFor(label);
    expect(store.recordInvoiceIntent({ orderId, amountMsat: 1000n, kind, preimage, paymentHash }).outcome).toBe('recorded');
    return paymentHash;
  }

  function receiverSecrets(label: string): string[] {
    const { preimage, paymentHash } = preimageFor(label);
    return [preimage, preimage.slice(0, 16), paymentHash, requestFor(label)];
  }

  it('scenarios 1 and 2: settlement via the settle call, repeated by the subscription and a lookup, fulfilled once', async () => {
    const file = dir.path('s2-receiver.db');
    const store = receiverStore(file);
    const hash = recordInvoice(store, 'r-s2', 'ORD-2B', 'hold');
    expect(store.markCreated(hash, requestFor('r-s2'), 1n)).toBe('open');
    expect(store.applyInvoice(invoice(hash, 'ACCEPTED'), 'lookup')).toBe('state-updated');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1000n, 4n), 'settle-call')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1000n, 4n), 'subscription')).toBe('duplicate');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', 1000n, 4n), 'lookup')).toBe('duplicate');
    store.close();

    const result = await run(['receiver', 'explain', '--as', 'merchant', '--order', 'ORD-2B'], services({ receiver: file }));
    expect(result.code).toBe(0);
    expect(result.doc.result?.subject).toEqual({ component: 'receiver', orderId: 'ORD-2B', payments: [explain.fingerprint(hash)] });
    expect(kinds(result.doc)).toEqual(expect.arrayContaining(['order', 'invoice-intent', 'delivery', 'fulfillment', 'journal', 'outbox-enqueued',
      'outcome']));
    expect(result.doc.result?.timeline.filter(item => item.kind === 'delivery').map(item => item.rule))
      .toEqual(['Subscriptions are a fast path; lookups are the ground truth', 'Idempotency keys', 'Idempotency keys', 'Idempotency keys']);
    expect(result.doc.result?.reservation).toBeNull();
    expect(result.doc.result?.outbox).toMatchObject([{ kind: 'fulfill-order' }]);
    expect(result.doc.result?.outcome.summary).toContain('order fulfilled');
    expect(result.doc.result?.reconciliation.find(item => item.rule === 'Idempotency keys')?.predicates).toContain('settlement-posted-once');
    assertClean(result, receiverSecrets('r-s2'));
    const byHash = await run(['receiver', 'explain', '--as', 'merchant', '--payment-hash', hash], services({ receiver: file }));
    expect(byHash.doc.result?.subject.orderId).toBe('ORD-2B');
  });

  it('late, superseded, canceled-final and settled-outranks-canceled invoices name their rules', async () => {
    const file = dir.path('late-receiver.db');
    const store = receiverStore(file);
    // A first invoice decided not created; a replacement; the first turns up late and is paid first.
    const late = recordInvoice(store, 'r-late', 'ORD-L');
    expect(store.markNotCreated(late)).toBe(true);
    const replacement = recordInvoice(store, 'r-repl', 'ORD-L');
    expect(store.markCreated(replacement, requestFor('r-repl'), 2n)).toBe('open');
    expect(store.applyInvoice(invoice(late, 'OPEN'), 'lookup')).toBe('late-invoice');
    expect(store.applyInvoice(invoice(late, 'SETTLED', 1000n, 5n), 'subscription')).toBe('fulfilled');
    expect(store.isSuperseded(replacement)).toBe(true);
    // Another order: canceled, a replayed OPEN, then SETTLED after all.
    const canceled = recordInvoice(store, 'r-cancel', 'ORD-C');
    store.markCreated(canceled, requestFor('r-cancel'), 3n);
    expect(store.applyInvoice(invoice(canceled, 'CANCELED'), 'lookup')).toBe('state-updated');
    expect(store.applyInvoice(invoice(canceled, 'OPEN'), 'subscription')).toBe('unchanged');
    store.applyInvoice(invoice(canceled, 'SETTLED', 1000n, 6n), 'lookup');
    store.close();

    const lateResult = await run(['receiver', 'explain', '--as', 'merchant', '--order', 'ORD-L'], services({ receiver: file }));
    expect(lateResult.code).toBe(0);
    expect(kinds(lateResult.doc)).toEqual(expect.arrayContaining(['not-created', 'late-invoice', 'superseded', 'fulfillment']));
    expect(rules(lateResult.doc)).toEqual(expect.arrayContaining(['An invoice that turns up late', 'Durable intent before submission']));
    expect(lateResult.doc.result?.reconciliation.find(item => item.decision === 'superseded')?.predicates).toContain('superseded-canceled-never-settled');
    assertClean(lateResult, [...receiverSecrets('r-late'), ...receiverSecrets('r-repl')]);

    const canceledResult = await run(['receiver', 'explain', '--as', 'merchant', '--order', 'ORD-C'], services({ receiver: file }));
    expect(rules(canceledResult.doc)).toEqual(expect.arrayContaining(['Canceled is final', 'Settled outranks canceled']));
    assertClean(canceledResult, receiverSecrets('r-cancel'));
  });
});

describe('explain: subjects, usage and --refresh', () => {
  it('an unknown subject exits 3 with the error in the document; a usage error exits 2', async () => {
    const file = dir.path('empty-payer.db');
    payerStore(file).close();
    const unknown = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'NOPE'], services({ payer: file }));
    expect(unknown.code).toBe(3);
    expect(unknown.textCode).toBe(3);
    expect(unknown.doc).toMatchObject({ schema: 1, command: 'explain', ok: false, result: null, error: { code: 3, step: 'subject' } });
    expect(unknown.stderr).toContain('error: subject:');
    const byHash = await run(['receiver', 'explain', '--as', 'merchant', '--payment-hash', 'ab'.repeat(32)], services({ receiver: dir.path('empty-r.db') }));
    expect(byHash.code).toBe(3);
    expect(JSON.stringify(byHash.doc)).not.toContain('ab'.repeat(32));
    const svc = services({ payer: file });
    expect(await lab.main(['payer', 'explain', '--as', 'customer-payer'], svc)).toBe(2);
    expect(await lab.main(['payer', 'explain', '--as', 'customer-payer', '--operation', 'X', '--payment-hash', 'ab'.repeat(32)], svc)).toBe(2);
    expect(await lab.main(['payer', 'explain', '--as', 'customer-payer', '--payment-hash', 'zz'], svc)).toBe(2);
    expect(await lab.main(['receiver', 'explain', '--as', 'merchant', '--order', 'bad id'], services({ receiver: dir.path('empty-r.db') }))).toBe(2);
  });

  it('--refresh: a node error exits 4 with a warning and the explanation from the records; a disagreeing node is a refreshed fact', async () => {
    const file = dir.path('refresh-payer.db');
    const store = payerStore(file);
    const { paymentHash } = preimageFor('refresh');
    store.recordIntent({ operationId: 'OP-R', kind: 'payout', paymentRequest: requestFor('refresh'), invoice: decoded(paymentHash, 1000n),
      feeLimitMsat: 100n, maxParts: 1 });
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    store.applyUpdate(payment('refresh', 'IN_FLIGHT'), 'SendPaymentV2', 1);
    store.close();

    const failing = new ScriptedPayerApi();
    failing.track.push(() => Promise.reject(new lab.TransportError('connection refused', 'connect')));
    failing.track.push(() => Promise.reject(new lab.TransportError('connection refused', 'connect')));
    const failed = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-R', '--refresh'], services({ payer: file }, failing));
    expect(failed.code).toBe(4);
    expect(failed.textCode).toBe(4);
    expect(failed.doc).toMatchObject({ ok: false, error: { code: 4, step: 'refresh' }, warnings: [{ code: 'refresh-failed' }] });
    expect(failed.doc.result?.timeline.map(item => item.kind)).toContain('intent');
    expect(failed.stderr).toContain('warning: refresh-failed:');
    expect(failed.text).toContain('timeline');

    const disagreeing = new ScriptedPayerApi();
    for (let call = 0; call < 2; call += 1) {
      disagreeing.track.push(async onUpdate => { onUpdate(payment('refresh', 'SUCCEEDED', [attempt('1', 'SUCCEEDED', { fee: 10n })])); });
    }
    const refreshed = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-R', '--refresh'], services({ payer: file }, disagreeing));
    expect(refreshed.code).toBe(0);
    const fact = refreshed.doc.result?.timeline.find(item => item.kind === 'refreshed');
    expect(fact?.detail).toContain('TrackPaymentV2 now: SUCCEEDED');
    expect(fact?.detail).toContain('differs from the record (in_flight)');
    assertClean(refreshed, payerSecrets('refresh'));
    // Read-only: the record is unchanged.
    const after = payerStore(file);
    expect(after.payment(paymentHash)?.state).toBe('in_flight');
    after.close();
  });

  it('--refresh on the receiver: LookupInvoice agrees, and its memo is escaped', async () => {
    const file = dir.path('refresh-receiver.db');
    const store = receiverStore(file);
    const { preimage, paymentHash } = preimageFor('r-refresh');
    store.recordInvoiceIntent({ orderId: 'ORD-R', amountMsat: 1000n, kind: 'standard', preimage, paymentHash });
    store.markCreated(paymentHash, requestFor('r-refresh'), 1n);
    store.close();
    const api: FakeInvoiceApi = { ...noInvoiceCalls, lookupInvoice: () => Promise.resolve(invoice(paymentHash, 'OPEN', 0n, 0n, 'memo \u001b]0;title\u0007')) };
    const result = await run(['receiver', 'explain', '--as', 'merchant', '--order', 'ORD-R', '--refresh'], services({ receiver: file }, undefined, api));
    expect(result.code).toBe(0);
    const fact = result.doc.result?.timeline.find(item => item.kind === 'refreshed');
    expect(fact?.detail).toContain('LookupInvoice now: OPEN');
    expect(fact?.detail).toContain('agrees with the record (open)');
    expect(result.text).toContain('memo');
    assertClean(result, [preimage, paymentHash, requestFor('r-refresh')]);
  });
});

describe('explain: rules and the replay corpus', () => {
  it('every rule name appears in the README as it is cited, and every predicate is one of the oracle\'s', () => {
    for (const rule of Object.values(explain.RULES)) {
      const form = rule.form === 'paragraph' ? `**${rule.name}.**` : rule.form === 'section' ? `\n## ${rule.name}\n` : `${rule.name}:`;
      expect(README, rule.name).toContain(form);
      for (const predicate of rule.predicates) expect(Object.keys(harness.PREDICATES), predicate).toContain(predicate);
    }
  });

  it('after every replay of the corpus, every subject in the resulting stores is explained without error', async () => {
    const runner = await loadHarnessRunner();
    const harnessLab = await runner.loadHarnessLab();
    const names = new Set(Object.values(explain.RULES).map(rule => rule.name));
    const cited = new Map<string, Set<string>>();
    let subjects = 0;
    for (const file of harness.replayFiles(CORPUS)) {
      const replay = harness.readReplay(file);
      const scratch = dir.path(`replay-${replay.predicate}`);
      mkdirSync(scratch, { recursive: true });
      const caseRun = new runner.Run(harnessLab, replay.config, scratch);
      const predicates = new Set<string>();
      try {
        for (const event of replay.events) await caseRun.step(event);
        await caseRun.quiesce();
        const files = { payer: join(caseRun.dir, 'payer.db'), receiver: join(caseRun.dir, 'receiver.db') };
        const payer = payerStore(files.payer);
        const receiver = receiverStore(files.receiver);
        const operations = payer.db.prepare('SELECT operation_id FROM operations').all().map(row => String(row.operation_id));
        const orders = receiver.db.prepare('SELECT order_id FROM orders').all().map(row => String(row.order_id));
        const secrets = [
          ...payer.db.prepare('SELECT preimage, payment_request, payment_hash FROM payments').all().flatMap(row => [row.preimage, row.payment_request, row.payment_hash]),
          ...receiver.db.prepare('SELECT preimage, payment_request, payment_hash FROM invoices').all().flatMap(row => [row.preimage, row.payment_request, row.payment_hash]),
        ].filter((value): value is string => typeof value === 'string' && value !== '');
        payer.close();
        receiver.close();
        const argvs = [...operations.map(id => ['payer', 'explain', '--as', 'customer-payer', '--operation', id]),
          ...orders.map(id => ['receiver', 'explain', '--as', 'merchant', '--order', id])];
        for (const argv of argvs) {
          const result = await run(argv, services(files));
          expect(result.code, `${replay.predicate}: ${argv.join(' ')}`).toBe(0);
          expect(result.textCode).toBe(0);
          expect(result.doc.ok).toBe(true);
          for (const item of result.doc.result?.timeline ?? []) if (item.rule !== undefined) expect(names.has(item.rule), item.rule).toBe(true);
          for (const decision of result.doc.result?.reconciliation ?? []) {
            for (const predicate of decision.predicates) {
              expect(Object.keys(runner.PREDICATES)).toContain(predicate);
              predicates.add(predicate);
            }
          }
          assertClean(result, secrets);
        }
        subjects += operations.length + orders.length;
      } finally {
        for (const store of opened.splice(0)) {
          try { store.close(); } catch { /* already closed */ }
        }
        await caseRun.dispose();
      }
      cited.set(replay.predicate, predicates);
    }
    expect(cited.size).toBe(Object.keys(harness.PREDICATES).length);
    expect(subjects).toBeGreaterThanOrEqual(Object.keys(harness.PREDICATES).length);
    // The rules the explanations cite match the oracle: after each replay whose records show its rule at work, the explanation of
    // some subject cites that replay's predicate. (The others leave records where the rule had nothing to decide: a budget refusal
    // before any operation, the cursor, the reconcile counts, no-internal-error.)
    for (const predicate of ['one-pending-payment-per-operation', 'reservation-held-iff-live', 'ledger-once-per-succeeded-payment',
      'stale-submission-changes-nothing', 'notfound-revert-keeps-live-updates', 'terminal-states-final', 'canceled-final-for-open-accepted',
      'settled-outranks-canceled', 'settlement-posted-once']) {
      expect([...cited.get(predicate) ?? []], predicate).toContain(predicate);
    }
  }, 120_000);
});

describe('explain: redaction, subject IDs and bounds', () => {
  /** render.ts, loaded the way the helpers load the lab's modules. */
  interface Render { renderText(explanation: unknown): string }
  const loadRender = async (): Promise<Render> =>
    await import(/* @vite-ignore */ `../examples/payment-lab/src/explain/${'render.ts'}`) as Render;
  type Truncated = NonNullable<ExplainDocument['result']> & { truncated?: Record<string, number> };

  function openPayment(label: string, operationId: string, file: string, budgetId?: string): { store: PayerStore; paymentHash: string } {
    const store = payerStore(file);
    if (budgetId !== undefined) store.setBudget(budgetId, 10n ** 15n);
    const { paymentHash } = preimageFor(label);
    expect(store.recordIntent({ operationId, kind: 'payout', paymentRequest: requestFor(label), invoice: decoded(paymentHash, 1000n),
      feeLimitMsat: 100n, maxParts: 1, ...(budgetId === undefined ? {} : { budgetId }) }).outcome).toBe('recorded');
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    return { store, paymentHash };
  }

  it('scrubs a hash-named fallback, a secret inside a longer hex run, a payment request inside a word and a value split by a format character', async () => {
    const file = dir.path('scrub-round2-payer.db');
    const { store, paymentHash } = openPayment('scrub-r2', 'OP-SCRUB2', file);
    const named = 'cd'.repeat(32);
    const inner = 'ef'.repeat(32);
    const split = '12'.repeat(32);
    const upper = 'LNBC2500U1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5XYSXXATSYP3K7ENXV4JS';
    store.markUncertain(paymentHash, `file =sha256-${named}.json; plain sha256-${named}; 00${inner}; pay_${requestFor('scrub-r2')}; 9${upper}; `
      + `zw ${split.slice(0, 32)}\u200b${split.slice(32)}; lone \u200b mark`);
    store.close();
    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-SCRUB2'], services({ payer: file }));
    expect(result.code).toBe(0);
    const json = JSON.stringify(result.doc);
    expect(json).toContain(`=sha256-${explain.fingerprint(named)}.json`);
    expect(json).toContain('plain sha256-[redacted];');
    expect(json).toContain('; [redacted hex 66 chars];');
    expect(json).toContain('pay_[payment request];');
    expect(json).toContain('; 9[payment request];');
    expect(json).toContain('zw [redacted];');
    const both = `${json}\n${result.text}`;
    for (const secret of [named, inner, split.slice(0, 32), upper.slice(0, 24)]) expect(both.toLowerCase()).not.toContain(secret.toLowerCase());
    expect(both).not.toMatch(/ln(?:bc|tb|bcrt|sb)[0-9a-z]{20,}/i);
    // A format character outside a secret stays, and text output escapes it.
    expect(result.text).toContain('lone \\u200b mark');
    expect(result.text).not.toContain('\u200b');
    assertClean(result, payerSecrets('scrub-r2'));
  });

  it('a subject ID that is 64 hex is shown as a fingerprint, found all the same, and fingerprinted in the unknown-subject error', async () => {
    const file = dir.path('hexid-payer.db');
    const operationId = '9f'.repeat(32);
    openPayment('hexid', operationId, file).store.close();
    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', operationId], services({ payer: file }));
    expect(result.code).toBe(0);
    const fp = explain.fingerprint(operationId);
    expect(result.doc.result?.subject.operationId).toBe(fp);
    expect((result.doc.result?.outcome.operation as { operationId: string }).operationId).toBe(fp);
    expect(result.text.split('\n')[0]).toContain(`operation ${fp}`);
    expect(result.doc.result?.timeline.find(item => item.kind === 'operation')?.detail).toContain(`operation ${fp}`);
    expect(`${JSON.stringify(result.doc)}${result.text}`).not.toContain(operationId);
    const missing = 'ab'.repeat(32);
    const unknown = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', missing], services({ payer: file }));
    expect(unknown.code).toBe(3);
    expect(unknown.doc.error?.message).toContain(`operation ${explain.fingerprint(missing)}`);
    expect(`${JSON.stringify(unknown.doc)}${unknown.stderr}`).not.toContain(missing);
  });

  it('renders 60,000 timeline items without exhausting the stack', async () => {
    const { renderText } = await loadRender();
    const timeline = Array.from({ length: 60_000 }, (_item, index) => ({ at: '2026-10-10T00:00:00.000Z', kind: 'event',
      detail: `item ${index} ${'word '.repeat(60)}`,
      rule: 'A timeout is not a failure' }));
    const text = renderText({ subject: { component: 'payer', operationId: 'OP-BIG', payments: [] }, timeline, outcome: { summary: 'open' },
      reservation: null, journal: [], outbox: [], reconciliation: [] });
    expect(text.split('\n').length).toBeGreaterThan(120_000);
  });

  it('50,000 journal entries explain in under 3 s and under 100 MB, with the timeline, journal and reservations cut and the cut noted', async () => {
    const file = dir.path('volume-journal-payer.db');
    const { store, paymentHash } = openPayment('vol-j', 'OP-VOLJ', file, 'VB');
    const now = new Date().toISOString();
    store.db.exec('BEGIN');
    const reservation = store.db.prepare(`INSERT INTO reservations (budget_id, operation_id, payment_hash, principal_msat, fee_allowance_msat, state,
      created_at, updated_at) VALUES ('VB', 'OP-VOLJ', ?, 1000, 10, 'released', ?, ?)`);
    const entry = store.db.prepare(`INSERT INTO journal_entries (event, reference, operation_id, payment_hash, origin, posted_at)
      VALUES (?, ?, 'OP-VOLJ', ?, 'live', ?)`);
    const line = store.db.prepare(`INSERT INTO journal_lines (entry_id, line_no, account, direction, amount_msat, leg, balance_after)
      VALUES (?, ?, ?, ?, 1010, NULL, '0')`);
    const rowid = (value: unknown): bigint => BigInt((value as { lastInsertRowid: number | bigint }).lastInsertRowid);
    for (let index = 0; index < 25_000; index += 1) {
      const id = rowid(reservation.run(paymentHash, now, now));
      for (const event of ['budget-held', 'budget-released']) {
        // A reference no reservation matches: every lookup misses, the worst case for a scan.
        const entryId = rowid(entry.run(event, `reservation:${id}x`, paymentHash, now));
        line.run(entryId, 1, 'budget:VB:held', 'debit');
        line.run(entryId, 2, 'budget:VB:available', 'credit');
      }
    }
    store.db.exec('COMMIT');
    store.close();
    for (const json of [true, false]) {
      stdout.length = 0;
      const started = performance.now();
      const code = await lab.main(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-VOLJ', ...(json ? ['--json'] : [])],
        services({ payer: file }));
      const elapsed = performance.now() - started;
      expect(code).toBe(0);
      expect(elapsed, `${json ? 'json' : 'text'} took ${Math.round(elapsed)} ms`).toBeLessThan(3000);
      const output = stdout.join('');
      expect(Buffer.byteLength(output)).toBeLessThan(100 * 1024 * 1024);
      if (json) {
        const result = (JSON.parse(output) as ExplainDocument).result as Truncated;
        expect(result.timeline).toHaveLength(2000);
        expect(result.timeline.at(-1)?.kind).toBe('outcome');
        expect(result.truncated?.timeline).toBeGreaterThan(95_000);
        expect(result.journal).toHaveLength(200);
        // 50,000 entries and the budget-held entry of the intent's own reservation.
        expect(result.truncated?.journal).toBe(50_001 - 200);
        expect((result.reservation as { reservations: unknown[] }).reservations).toHaveLength(200);
        expect(result.truncated?.reservations).toBe(25_001 - 200);
      } else {
        expect(output).toMatch(/^ {2}… \d+ items omitted …$/m);
        expect(output).toMatch(/^ {2}… 49801 entries omitted …$/m);
      }
    }
  }, 60_000);

  it('caps HTLC attempts per submission at 200 with a count, and any one string at 1,024 characters', async () => {
    const file = dir.path('volume-htlc-payer.db');
    const { store, paymentHash } = openPayment('vol-h', 'OP-VOLH', file);
    store.db.exec('BEGIN');
    const insert = store.db.prepare(`INSERT INTO htlc_attempts (payment_hash, attempt_id, status, principal_msat, fee_msat, hops, route, failure_code,
      failure_source_index, attempt_time_ns, resolve_time_ns, submission) VALUES (?, ?, 'FAILED', 1000, 10, 3, '1>2>3', 'TEMPORARY_CHANNEL_FAILURE', 1, ?, ?, 1)`);
    for (let index = 0; index < 5000; index += 1) insert.run(paymentHash, String(index + 1), BigInt(index + 1), BigInt(index + 2));
    store.db.exec('COMMIT');
    store.markUncertain(paymentHash, `long ${'reason '.repeat(3000)}end`);
    store.close();
    const result = await run(['payer', 'explain', '--as', 'customer-payer', '--operation', 'OP-VOLH'], services({ payer: file }));
    expect(result.code).toBe(0);
    const doc = result.doc.result as Truncated;
    const attemptItems = doc.timeline.filter(item => item.kind === 'htlc-attempt');
    expect(attemptItems).toHaveLength(201);
    expect(attemptItems.some(item => item.detail.includes('4800 more HTLC attempt(s) of submission 1 not shown'))).toBe(true);
    expect(attemptItems.some(item => item.detail.includes('HTLC attempt 5000 '))).toBe(true);
    expect(doc.truncated?.htlcAttempts).toBe(4800);
    const uncertain = doc.timeline.find(item => item.kind === 'uncertain');
    expect(uncertain?.detail).toMatch(/…\(\d+ more\)$/);
    expect(uncertain?.detail.length).toBeLessThanOrEqual(1024 + '…(99999 more)'.length);
    expect(result.text).not.toContain('reason '.repeat(200));
  });
});
