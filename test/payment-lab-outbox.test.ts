import { spawn, spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  labModuleUrl, loadLab, preimageFor, tempDirectory,
  type DecodedPayReq, type EffectTarget, type FakeInvoiceApi, type FakePayerApi, type Invoice, type Lab, type LedgerVerification,
  type OutboxRow, type Payment, type PayerStore, type ReceiverStore,
} from './helpers/payment-lab-modules.js';

/**
 * The payment lab's transactional outbox (examples/payment-lab/src/outbox, design brief 1.3.0
 * item 2): a settlement or a completed operation enqueues its effect in the transaction of the
 * state change; a worker performs it (a receipt or confirmation file with an HMAC) and
 * acknowledges it, retrying with backoff; leases keep two workers off one row; and every crash
 * point, killed with SIGKILL and restarted, ends with exactly one acknowledged row, exactly one
 * file with a valid HMAC, no temporary file, and balanced books. Real stores on temporary SQLite
 * files and real files; no node, no Docker, no credential.
 */

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

function receiverStore(file: string): ReceiverStore {
  const store = new lab.ReceiverStore(dir.path(file));
  opened.push(store);
  return store;
}

const DESTINATION = `02${'11'.repeat(32)}`;
const VALUE = 1000n;
const FEE = 10n;
const quiet = (): void => undefined;
const KEY = Buffer.from('7a'.repeat(32), 'hex');

function target(name: string): EffectTarget {
  return { dir: dir.path(name), key: KEY };
}

function decoded(paymentHash: string): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat: VALUE, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-outbox' };
}

function lndPayment(label: string, status: 'FAILED' | 'SUCCEEDED'): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: VALUE, feeMsat: status === 'SUCCEEDED' ? FEE : 0n, preimage: status === 'SUCCEEDED' ? preimage : undefined,
    paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '', creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
}

function submitted(store: PayerStore, label: string, operationId: string, kind = 'order-payment'): string {
  const { paymentHash } = preimageFor(label);
  expect(store.recordIntent({ operationId, kind, paymentRequest: `lnbcrt1${label}`, invoice: decoded(paymentHash), feeLimitMsat: 100n,
    maxParts: 1 }).outcome).toBe('recorded');
  expect(store.claimForSubmission(paymentHash)).toBe(true);
  return paymentHash;
}

function invoice(paymentHash: string, state: string, amtPaidMsat = 0n, settleIndex = 0n): Invoice {
  return { paymentHash, state, memo: '', valueMsat: VALUE, amtPaidMsat, addIndex: 1n, settleIndex, paymentRequest: '', htlcs: [] };
}

function openInvoice(store: ReceiverStore, orderId: string, label: string): string {
  const { preimage, paymentHash } = preimageFor(label);
  expect(store.recordInvoiceIntent({ orderId, amountMsat: VALUE, kind: 'standard', preimage, paymentHash }).outcome).toBe('recorded');
  expect(store.markCreated(paymentHash, `lnbcrt1${label}`, 1n)).toBe('open');
  return paymentHash;
}

/** A receiver store with one settled order (and so one pending fulfill-order row). */
function settledOrder(file: string, orderId: string, settleIndex = 1n): { store: ReceiverStore; hash: string } {
  const store = receiverStore(file);
  const hash = openInvoice(store, orderId, `${file}:${orderId}`);
  expect(store.applyInvoice(invoice(hash, 'SETTLED', VALUE, settleIndex), 'subscription')).toBe('fulfilled');
  return { store, hash };
}

function expectBalanced(result: LedgerVerification): void {
  expect(result.unbalancedEntries).toEqual([]);
  expect(result.firstDifference).toBeUndefined();
  expect(result.balanced).toBe(true);
}

/** The HMAC computed here from the definition (sorted [name, value] pairs as JSON), not with the lab's own function. */
function independentHmac(fields: Record<string, unknown>): string {
  const canonical = JSON.stringify(Object.keys(fields).sort().map(name => [name, fields[name]]));
  return createHmac('sha256', KEY).update(canonical).digest('hex');
}

function readFile(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
}

/**
 * The end state every crash point must reach after a restart: one row, acknowledged; one effect file,
 * whose HMAC is valid (checked independently) and whose fields are the row's; no temporary file left.
 */
function expectExactlyOnce(rows: OutboxRow[], effects: EffectTarget): void {
  expect(rows).toHaveLength(1);
  const [row] = rows;
  expect(row?.state).toBe('done');
  expect(row?.acknowledgedAt).toEqual(expect.any(String));
  expect(row?.leaseOwner).toBeUndefined();
  const files = readdirSync(effects.dir);
  expect(files.filter(name => name.endsWith('.tmp'))).toEqual([]);
  expect(files.filter(name => name.endsWith('.json'))).toEqual([`${lab.outbox.fileBase(row?.subject ?? '')}.json`]);
  const { hmacSha256, ...fields } = readFile(lab.outbox.effectPath(effects, row?.subject ?? ''));
  expect(hmacSha256).toBe(independentHmac(fields));
  expect(fields).toEqual({ kind: row?.kind, idempotencyKey: row?.idempotencyKey, ...row?.payload });
}

describe('payment lab outbox: the effect is enqueued in the transaction of the state change', () => {
  it('receiver: a settlement that fulfills the order enqueues one fulfill-order row with the ledger entry; repeats, second payments and underpaid settlements enqueue nothing', () => {
    const store = receiverStore('enqueue-receiver.db');
    const hash = openInvoice(store, 'ORD-E', 'enqueue-e');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 7n), 'subscription')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 7n), 'lookup')).toBe('duplicate');
    const entryId = store.journal('ORD-E')[0]?.entryId;
    expect(store.outbox('ORD-E')).toEqual([expect.objectContaining({ kind: 'fulfill-order', idempotencyKey: `ORD-E:${hash}`, subject: 'ORD-E',
      state: 'pending', attempts: 0, acknowledgedAt: undefined,
      payload: { orderId: 'ORD-E', paymentHash: hash, amountMsat: '1000', settleIndex: '7', ledgerEntryId: entryId } })]);
    // A second payment of a fulfilled order and an underpaid settlement move money but fulfil nothing.
    const { preimage, paymentHash: late } = preimageFor('enqueue-late');
    store.recordInvoiceIntent({ orderId: 'ORD-E2', amountMsat: VALUE, kind: 'standard', preimage, paymentHash: late });
    store.markNotCreated(late);
    const live = openInvoice(store, 'ORD-E2', 'enqueue-live');
    expect(store.applyInvoice(invoice(live, 'SETTLED', VALUE, 8n), 'subscription')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(late, 'SETTLED', VALUE, 9n), 'subscription')).toBe('second-payment');
    const short = openInvoice(store, 'ORD-EU', 'enqueue-short');
    expect(store.applyInvoice(invoice(short, 'SETTLED', 900n, 10n), 'subscription')).toBe('underpaid');
    expect(store.outbox().map(row => row.idempotencyKey)).toEqual([`ORD-E:${hash}`, `ORD-E2:${live}`]);
  });

  it('payer: an order payment, a refund and a payout each enqueue one confirm-operation row on completion; a double payment and a failure enqueue nothing', () => {
    const store = payerStore('enqueue-payer.db');
    const paid = submitted(store, 'enq-order', 'OP-O', 'order-payment');
    submitted(store, 'enq-refund', 'OP-R', 'refund');
    submitted(store, 'enq-payout', 'OP-P', 'payout');
    submitted(store, 'enq-failed', 'OP-F', 'payout');
    store.applyUpdate(lndPayment('enq-order', 'SUCCEEDED'), 'SendPaymentV2', 1);
    store.applyUpdate(lndPayment('enq-order', 'SUCCEEDED'), 'TrackPaymentV2');
    store.applyUpdate(lndPayment('enq-refund', 'SUCCEEDED'), 'SendPaymentV2', 1);
    store.applyUpdate(lndPayment('enq-payout', 'SUCCEEDED'), 'SendPaymentV2', 1);
    store.applyUpdate(lndPayment('enq-failed', 'FAILED'), 'SendPaymentV2', 1);
    const entryId = store.journal('OP-O').find(entry => entry.event === 'payment-succeeded')?.entryId;
    expect(store.outbox('OP-O')).toEqual([expect.objectContaining({ kind: 'confirm-operation', idempotencyKey: `OP-O:${paid}`, subject: 'OP-O',
      state: 'pending', payload: { operationId: 'OP-O', operationKind: 'order-payment', paymentHash: paid, valueMsat: '1000', feeMsat: '10',
        ledgerEntryId: entryId } })]);
    expect(store.outbox().map(row => [row.subject, row.payload.operationKind])).toEqual([['OP-O', 'order-payment'], ['OP-R', 'refund'], ['OP-P', 'payout']]);
    // A double payment: the operation was already completed, so the second success completes nothing and enqueues nothing.
    submitted(store, 'dp-a', 'OP-D');
    store.applyUpdate(lndPayment('dp-a', 'FAILED'), 'SendPaymentV2', 1);
    submitted(store, 'dp-b', 'OP-D');
    store.applyUpdate(lndPayment('dp-a', 'SUCCEEDED'), 'TrackPaymentV2');
    store.applyUpdate(lndPayment('dp-b', 'SUCCEEDED'), 'SendPaymentV2', 1);
    expect(store.outbox('OP-D').map(row => row.idempotencyKey)).toEqual([`OP-D:${preimageFor('dp-a').paymentHash}`]);
  });

  /** Crash point 1, between the state transaction and the outbox write: there is none; a failure of the insert takes the state change with it. */
  const CRASH = `CREATE TEMP TRIGGER crash_on_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT, 'simulated crash'); END`;

  it('crash point 1 (receiver): a failing outbox insert rolls back the settlement, the fulfillment, the journal entry and the delivery', async () => {
    const store = receiverStore('atomic-receiver.db');
    const hash = openInvoice(store, 'ORD-A', 'atomic-r');
    store.db.exec(CRASH);
    expect(() => store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'subscription')).toThrow(/simulated crash/);
    expect(store.invoice(hash)?.state).toBe('open');
    expect(store.order('ORD-A')?.state).toBe('awaiting-payment');
    expect(store.fulfillmentCount('ORD-A')).toBe(0);
    expect(store.journal('ORD-A')).toEqual([]);
    expect(store.outbox()).toEqual([]);
    store.db.exec('DROP TRIGGER crash_on_outbox');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'subscription')).toBe('fulfilled');
    expect(store.outbox()).toHaveLength(1);
    expectBalanced(await lab.verifyLedger(store));
  });

  it('crash point 1 (payer): a failing outbox insert rolls back the success, the completion, the journal and the budget', async () => {
    const store = payerStore('atomic-payer.db');
    const hash = submitted(store, 'atomic-p', 'OP-A', 'refund');
    store.db.exec(CRASH);
    expect(() => store.applyUpdate(lndPayment('atomic-p', 'SUCCEEDED'), 'SendPaymentV2', 1)).toThrow(/simulated crash/);
    expect(store.payment(hash)?.state).toBe('submitting');
    expect(store.operation('OP-A')?.state).toBe('open');
    expect(store.journal('OP-A')).toEqual([]);
    store.db.exec('DROP TRIGGER crash_on_outbox');
    expect(store.applyUpdate(lndPayment('atomic-p', 'SUCCEEDED'), 'SendPaymentV2', 1).state).toBe('succeeded');
    expect(store.outbox()).toHaveLength(1);
    expectBalanced(await lab.verifyLedger(store));
  });

  const STATE_CHILD = `
import { writeFileSync } from 'node:fs';
const [url, file, step, json] = process.argv.slice(-4);
const input = JSON.parse(json, (_key, value) => value !== null && typeof value === 'object' && '$big' in value ? BigInt(value.$big) : value);
const module = await import(url);
const store = new (module.PayerStore ?? module.ReceiverStore)(file);
const result = step === 'update' ? store.applyUpdate(input, 'TrackPaymentV2').state : store.applyInvoice(input, 'subscription');
writeFileSync(file + '.done', String(result));
process.kill(process.pid, 'SIGKILL');
`;

  function killedAfterStateChange(module: string, file: string, step: 'update' | 'settle', input: unknown): string {
    const json = JSON.stringify(input, (_key, value: unknown) => typeof value === 'bigint' ? { $big: value.toString() } : value);
    const child = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', STATE_CHILD,
      labModuleUrl(module), dir.path(file), step, json], { encoding: 'utf8', timeout: 60_000 });
    expect(child.status === 0 && child.signal === null, child.stderr).toBe(false);
    return readFileSync(`${dir.path(file)}.done`, 'utf8');
  }

  it('crash point 1, killed: a worker killed right after the settlement or the success committed leaves the row with the entry', async () => {
    const setup = receiverStore('kill-state-receiver.db');
    const hash = openInvoice(setup, 'ORD-KS', 'kill-state');
    setup.close();
    expect(killedAfterStateChange('receiver/store.ts', 'kill-state-receiver.db', 'settle', invoice(hash, 'SETTLED', VALUE, 1n))).toBe('fulfilled');
    const store = receiverStore('kill-state-receiver.db');
    expect(store.outbox().map(row => [row.state, row.payload.ledgerEntryId])).toEqual([['pending', store.journal('ORD-KS')[0]?.entryId]]);
    expectBalanced(await lab.verifyLedger(store));

    const payerSetup = payerStore('kill-state-payer.db');
    submitted(payerSetup, 'kill-state-p', 'OP-KS', 'payout');
    payerSetup.close();
    expect(killedAfterStateChange('payer/store.ts', 'kill-state-payer.db', 'update', lndPayment('kill-state-p', 'SUCCEEDED'))).toBe('succeeded');
    const payer = payerStore('kill-state-payer.db');
    expect(payer.outbox().map(row => row.state)).toEqual(['pending']);
    expectBalanced(await lab.verifyLedger(payer));
  });
});

describe('payment lab outbox: the worker', () => {
  it('performs a pending row: the receipt carries order, hash, amount, settle index and ledger entry with a valid HMAC; the row is acknowledged', async () => {
    const { store, hash } = settledOrder('worker-basic.db', 'ORD-W', 5n);
    const effects = target('worker-basic-receipts');
    const events: Record<string, unknown>[] = [];
    expect(lab.outbox.runPass(store.db, effects, { emit: event => events.push(event) })).toEqual({ performed: 1, alreadyPresent: 0, failed: 0,
      leaseLost: 0, remaining: 0 });
    expectExactlyOnce(store.outbox(), effects);
    const receipt = readFile(join(effects.dir, 'ORD-W.json'));
    expect(receipt).toMatchObject({ kind: 'fulfill-order', idempotencyKey: `ORD-W:${hash}`, orderId: 'ORD-W', paymentHash: hash, amountMsat: '1000',
      settleIndex: '5', ledgerEntryId: store.journal('ORD-W')[0]?.entryId });
    expect(lab.outbox.readEffect(join(effects.dir, 'ORD-W.json'), KEY)).toMatchObject({ state: 'valid' });
    expect(lab.outbox.readEffect(join(effects.dir, 'ORD-W.json'), Buffer.alloc(32))).toMatchObject({ state: 'invalid', reason: 'HMAC does not match' });
    expect(events).toEqual([expect.objectContaining({ event: 'outbox-done', effect: 'written', attempts: 1 })]);
    // Nothing is due any more.
    expect(lab.outbox.runPass(store.db, effects, { emit: quiet })).toMatchObject({ performed: 0, remaining: 0 });
    expectBalanced(await lab.verifyLedger(store));
  });

  it('the effect is idempotent: a receipt already present with a valid HMAC over the same fields is not written again', () => {
    const { store } = settledOrder('worker-idempotent.db', 'ORD-I');
    const effects = target('worker-idempotent-receipts');
    lab.outbox.runPass(store.db, effects, { emit: quiet });
    const path = join(effects.dir, 'ORD-I.json');
    const before = readFileSync(path, 'utf8');
    // The ack is undone, as if the worker had died after the effect: the row is performed again and finds the receipt.
    store.db.exec(`UPDATE outbox SET state = 'pending', acknowledged_at = NULL`);
    const events: Record<string, unknown>[] = [];
    expect(lab.outbox.runPass(store.db, effects, { emit: event => events.push(event) })).toMatchObject({ performed: 0, alreadyPresent: 1 });
    expect(events[0]).toMatchObject({ event: 'outbox-done', effect: 'already-present', attempts: 2 });
    expect(readFileSync(path, 'utf8')).toBe(before);
    expectExactlyOnce(store.outbox(), effects);
  });

  it('a damaged receipt is replaced; a valid receipt for another key is a conflict, never overwritten, retried with backoff', () => {
    const { store } = settledOrder('worker-conflict.db', 'ORD-C');
    const effects = target('worker-conflict-receipts');
    mkdirSync(effects.dir, { recursive: true });
    const path = join(effects.dir, 'ORD-C.json');
    writeFileSync(path, '{"kind":"fulfill-order","idempotencyKey":"ORD-C:');
    expect(lab.outbox.runPass(store.db, effects, { emit: quiet })).toMatchObject({ performed: 1 });
    expectExactlyOnce(store.outbox(), effects);

    const other = { kind: 'fulfill-order', idempotencyKey: 'ORD-C:other', orderId: 'ORD-C' };
    writeFileSync(path, JSON.stringify({ ...other, hmacSha256: independentHmac(other) }));
    store.db.exec(`UPDATE outbox SET state = 'pending', acknowledged_at = NULL, attempts = 0`);
    const now = Date.now() + 1000;
    const events: Record<string, unknown>[] = [];
    expect(lab.outbox.runPass(store.db, effects, { emit: event => events.push(event), clock: () => now })).toMatchObject({ failed: 1, remaining: 1 });
    expect(events[0]).toMatchObject({ event: 'outbox-failed', conflict: true, rescheduled: true });
    expect(readFile(path)).toMatchObject(other);
    expect(store.outbox()[0]).toMatchObject({ state: 'pending', attempts: 1, nextAttemptAt: new Date(now + 1000).toISOString(),
      lastError: expect.stringMatching(/holds a valid effect for ORD-C:other/) as string });
  });

  it('retries back off exponentially from 1 s, capped at 5 minutes, with the same idempotency key', () => {
    expect([1, 2, 3, 4, 8, 9, 10, 30, 1000].map(lab.outbox.backoffMs)).toEqual([1000, 2000, 4000, 8000, 128_000, 256_000, 300_000, 300_000, 300_000]);
    const { store, hash } = settledOrder('worker-backoff.db', 'ORD-B');
    // The effect cannot be performed: the receipts directory is a file.
    writeFileSync(dir.path('worker-backoff-receipts'), 'not a directory');
    const blocked = target('worker-backoff-receipts');
    let now = Date.now() + 1000;
    const clock = (): number => now;
    const expected = [1000, 2000, 4000, 8000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000, 300_000];
    for (const [index, wait] of expected.entries()) {
      expect(lab.outbox.runPass(store.db, blocked, { emit: quiet, clock })).toMatchObject({ failed: 1 });
      expect(store.outbox()[0]).toMatchObject({ state: 'pending', attempts: index + 1, idempotencyKey: `ORD-B:${hash}`,
        nextAttemptAt: new Date(now + wait).toISOString() });
      // Not due before its time.
      now += wait - 1;
      expect(lab.outbox.runPass(store.db, blocked, { emit: quiet, clock })).toMatchObject({ failed: 0, performed: 0, remaining: 1 });
      now += 1;
    }
    const effects = target('worker-backoff-fixed');
    expect(lab.outbox.runPass(store.db, effects, { emit: quiet, clock })).toMatchObject({ performed: 1 });
    expectExactlyOnce(store.outbox(), effects);
  });

  it('leases: a second worker on the same file cannot claim a leased row until the lease expires, and the first then loses its ack', () => {
    const { store: setup } = settledOrder('worker-lease.db', 'ORD-L1', 1n);
    const second = openInvoice(setup, 'ORD-L2', 'lease-2');
    setup.applyInvoice(invoice(second, 'SETTLED', VALUE, 2n), 'subscription');
    setup.close();
    const a = receiverStore('worker-lease.db');
    const b = receiverStore('worker-lease.db');
    const now = Date.now() + 1000;
    const rowA = lab.outbox.claim(a.db, 'worker-a', now, 60_000);
    expect(rowA?.subject).toBe('ORD-L1');
    expect(lab.outbox.claim(b.db, 'worker-b', now, 60_000)?.subject).toBe('ORD-L2');
    expect(lab.outbox.claim(b.db, 'worker-b', now + 59_999, 60_000)).toBeUndefined();
    // Not the holder: no ack, no retry.
    expect(lab.outbox.acknowledge(b.db, rowA?.outboxId ?? 0, 'worker-b', now)).toBe(false);
    expect(lab.outbox.retryLater(b.db, rowA?.outboxId ?? 0, 'worker-b', 'x', now)).toBe(false);
    // The lease runs out (worker A stalled or died): B claims it, and A's late ack is refused.
    expect(lab.outbox.claim(b.db, 'worker-b', now + 60_000, 60_000)).toMatchObject({ subject: 'ORD-L1', attempts: 2, leaseOwner: 'worker-b' });
    expect(lab.outbox.acknowledge(a.db, rowA?.outboxId ?? 0, 'worker-a', now + 60_001)).toBe(false);
    expect(lab.outbox.acknowledge(b.db, rowA?.outboxId ?? 0, 'worker-b', now + 60_001)).toBe(true);
    // ORD-L2's lease, taken at the same time, has run out too.
    expect(lab.outbox.outboxStatus(a.db, now + 60_002, 300)).toMatchObject({ pending: 0, leased: 1, done: 1, expiredLeases: 1 });
  });

  const WORKER_CHILD = `
const [storeUrl, workerUrl, file, effectsDir, keyHex] = process.argv.slice(-5);
const { ReceiverStore } = await import(storeUrl);
const { runPass } = await import(workerUrl);
const store = new ReceiverStore(file);
const result = runPass(store.db, { dir: effectsDir, key: Buffer.from(keyHex, 'hex') },
  { emit: event => process.stdout.write(JSON.stringify(event) + '\\n') });
process.stdout.write(JSON.stringify({ event: 'result', ...result }) + '\\n');
store.close();
`;

  function worker(file: string, effects: EffectTarget): Promise<Record<string, unknown>[]> {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', WORKER_CHILD,
        labModuleUrl('receiver/store.ts'), labModuleUrl('outbox/worker.ts'), dir.path(file), effects.dir, effects.key.toString('hex')]);
      let out = '';
      let err = '';
      child.stdout.on('data', (chunk: Buffer) => { out += chunk.toString(); });
      child.stderr.on('data', (chunk: Buffer) => { err += chunk.toString(); });
      child.on('error', reject);
      child.on('close', code => code === 0 ? resolve(out.split('\n').filter(line => line !== '').map(line => JSON.parse(line) as Record<string, unknown>))
        : reject(new Error(`worker exited ${code}: ${err}`)));
    });
  }

  it('two worker processes on one file perform every row exactly once between them', async () => {
    const file = 'worker-race.db';
    const setup = receiverStore(file);
    const count = 40;
    for (let index = 1; index <= count; index += 1) {
      const hash = openInvoice(setup, `ORD-R${index}`, `race-${index}`);
      setup.applyInvoice(invoice(hash, 'SETTLED', VALUE, BigInt(index)), 'subscription');
    }
    setup.close();
    const effects = target('worker-race-receipts');
    const [first, second] = await Promise.all([worker(file, effects), worker(file, effects)]);
    const done = [...first ?? [], ...second ?? []].filter(event => event.event === 'outbox-done');
    expect(done.filter(event => event.effect === 'written')).toHaveLength(count);
    expect(new Set(done.map(event => event.idempotencyKey)).size).toBe(count);
    expect(done).toHaveLength(count);
    const store = receiverStore(file);
    expect(store.outbox().filter(row => row.state === 'done' && row.attempts === 1)).toHaveLength(count);
    expect(readdirSync(effects.dir).filter(name => name.endsWith('.json'))).toHaveLength(count);
    expect(readdirSync(effects.dir).filter(name => name.endsWith('.tmp'))).toEqual([]);
    expectBalanced(await lab.verifyLedger(store));
  }, 120_000);
});

describe('payment lab outbox: every crash point, killed and restarted, performs the effect exactly once', () => {
  /** A worker that SIGKILLs itself at `point` (after writing a marker, so the test knows it got there). */
  const CRASH_CHILD = `
import { writeFileSync } from 'node:fs';
const [storeUrl, workerUrl, file, effectsDir, keyHex, point, leaseMs] = process.argv.slice(-7);
const module = await import(storeUrl);
const { runPass } = await import(workerUrl);
const store = new (module.PayerStore ?? module.ReceiverStore)(file);
const die = () => { writeFileSync(file + '.' + point, 'reached'); process.kill(process.pid, 'SIGKILL'); };
runPass(store.db, { dir: effectsDir, key: Buffer.from(keyHex, 'hex') }, { emit: () => undefined, leaseMs: Number(leaseMs), hooks: { [point]: die } });
writeFileSync(file + '.survived', 'yes');
`;

  type Point = 'afterClaim' | 'duringWrite' | 'afterEffect' | 'afterAck';

  function killedAt(module: string, file: string, effects: EffectTarget, point: Point, leaseMs = 1): void {
    const child = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', CRASH_CHILD,
      labModuleUrl(module), labModuleUrl('outbox/worker.ts'), dir.path(file), effects.dir, effects.key.toString('hex'), point, String(leaseMs)],
    { encoding: 'utf8', timeout: 60_000 });
    expect(child.status === 0 && child.signal === null, child.stderr).toBe(false);
    expect(existsSync(`${dir.path(file)}.${point}`), child.stderr).toBe(true);
    expect(existsSync(`${dir.path(file)}.survived`)).toBe(false);
  }

  /** The state the kill left, as seen by the restarted worker before it runs. */
  function leftBehind(rows: OutboxRow[], effects: EffectTarget): { state: string | undefined; receipt: boolean; tmp: number } {
    const files = existsSync(effects.dir) ? readdirSync(effects.dir) : [];
    return { state: rows[0]?.state, receipt: files.some(name => name.endsWith('.json')), tmp: files.filter(name => name.endsWith('.tmp')).length };
  }

  const CASES: { point: Point; left: { state: string; receipt: boolean; tmp: number }; restart: Record<string, number> }[] = [
    // 2: after the claim, before the effect: leased, nothing written; the lease runs out and the restart performs it.
    { point: 'afterClaim', left: { state: 'leased', receipt: false, tmp: 0 }, restart: { performed: 1, alreadyPresent: 0 } },
    // 5: killed mid-effect: a partial temporary file, no receipt; the restart removes it and performs the effect.
    { point: 'duringWrite', left: { state: 'leased', receipt: false, tmp: 1 }, restart: { performed: 1, alreadyPresent: 0 } },
    // 3: after the effect, before the ack: the receipt is there; the restart finds it by its HMAC and only acknowledges.
    { point: 'afterEffect', left: { state: 'leased', receipt: true, tmp: 0 }, restart: { performed: 0, alreadyPresent: 1 } },
    // 4: after the ack (which clears the lease in the same statement): done; the restart has nothing to do.
    { point: 'afterAck', left: { state: 'done', receipt: true, tmp: 0 }, restart: { performed: 0, alreadyPresent: 0 } },
  ];

  for (const { point, left, restart } of CASES) {
    it(`receiver, killed ${point}: one acknowledged row, one receipt with a valid HMAC, books balanced`, async () => {
      const file = `crash-${point}.db`;
      const { store: setup } = settledOrder(file, `ORD-${point}`);
      setup.close();
      const effects = target(`crash-${point}-receipts`);
      killedAt('receiver/store.ts', file, effects, point);
      const store = receiverStore(file);
      expect(leftBehind(store.outbox(), effects)).toEqual(left);
      expect(lab.outbox.runPass(store.db, effects, { emit: quiet })).toMatchObject({ ...restart, failed: 0, leaseLost: 0, remaining: 0 });
      expectExactlyOnce(store.outbox(), effects);
      expectBalanced(await lab.verifyLedger(store));
      // A second restart changes nothing.
      expect(lab.outbox.runPass(store.db, effects, { emit: quiet })).toMatchObject({ performed: 0, alreadyPresent: 0, remaining: 0 });
    });

    it(`payer, killed ${point}: one acknowledged row, one confirmation with a valid HMAC, books balanced`, async () => {
      const file = `crash-payer-${point}.db`;
      const setup = payerStore(file);
      setup.setBudget('B', 10_000n);
      const { paymentHash } = preimageFor(`crash-payer-${point}`);
      setup.recordIntent({ operationId: `OP-${point}`, kind: 'refund', paymentRequest: 'lnbcrt1x', invoice: decoded(paymentHash), feeLimitMsat: 100n,
        maxParts: 1, budgetId: 'B' });
      setup.claimForSubmission(paymentHash);
      setup.applyUpdate(lndPayment(`crash-payer-${point}`, 'SUCCEEDED'), 'SendPaymentV2', 1);
      setup.close();
      const effects = target(`crash-payer-${point}-confirmations`);
      killedAt('payer/store.ts', file, effects, point);
      const store = payerStore(file);
      expect(leftBehind(store.outbox(), effects)).toEqual(left);
      expect(lab.outbox.runPass(store.db, effects, { emit: quiet })).toMatchObject({ ...restart, failed: 0, leaseLost: 0, remaining: 0 });
      expectExactlyOnce(store.outbox(), effects);
      expect(readFile(join(effects.dir, `OP-${point}.json`))).toMatchObject({ kind: 'confirm-operation', operationId: `OP-${point}`,
        operationKind: 'refund', paymentHash, valueMsat: '1000', feeMsat: '10' });
      expectBalanced(await lab.verifyLedger(store));
    });
  }

  it('a restart before the dead worker\'s lease runs out leaves the row alone; once it has run out, the row is performed once', () => {
    const file = 'crash-lease.db';
    const { store: setup } = settledOrder(file, 'ORD-CL');
    setup.close();
    const effects = target('crash-lease-receipts');
    killedAt('receiver/store.ts', file, effects, 'afterClaim', 60_000);
    const store = receiverStore(file);
    expect(lab.outbox.runPass(store.db, effects, { emit: quiet })).toMatchObject({ performed: 0, remaining: 1 });
    expect(lab.outbox.outboxStatus(store.db, Date.now(), 300)).toMatchObject({ leased: 1, expiredLeases: 0 });
    expect(existsSync(effects.dir)).toBe(false);
    const later = Date.now() + 60_001;
    expect(lab.outbox.outboxStatus(store.db, later, 300)).toMatchObject({ leased: 1, expiredLeases: 1 });
    expect(lab.outbox.runPass(store.db, effects, { emit: quiet, clock: () => later })).toMatchObject({ performed: 1, remaining: 0 });
    expectExactlyOnce(store.outbox(), effects);
  });
});

describe('payment lab outbox: upgrading a database without an outbox', () => {
  it('receiver (migration 4): every recorded fulfillment gets one pending row with its ledger entry', async () => {
    const file = 'migrate-receiver.db';
    const { store, hash } = settledOrder(file, 'ORD-M', 3n);
    const entryId = store.journal('ORD-M')[0]?.entryId;
    store.db.exec('DROP TABLE outbox; PRAGMA user_version = 3');
    store.close();
    const upgraded = receiverStore(file);
    expect(upgraded.db.prepare('PRAGMA user_version').all()[0]?.user_version).toBe(4n);
    expect(upgraded.outbox()).toEqual([expect.objectContaining({ idempotencyKey: `ORD-M:${hash}`, state: 'pending',
      payload: { orderId: 'ORD-M', paymentHash: hash, amountMsat: '1000', settleIndex: '3', ledgerEntryId: entryId } })]);
    const effects = target('migrate-receiver-receipts');
    lab.outbox.runPass(upgraded.db, effects, { emit: quiet });
    expectExactlyOnce(upgraded.outbox(), effects);
    expectBalanced(await lab.verifyLedger(upgraded));
  });

  it('payer (migration 7): every completed operation gets one row for the payment that completed it, not for a double payment', () => {
    const file = 'migrate-payer.db';
    const store = payerStore(file);
    submitted(store, 'mig-a', 'OP-M');
    store.applyUpdate(lndPayment('mig-a', 'FAILED'), 'SendPaymentV2', 1);
    submitted(store, 'mig-b', 'OP-M');
    store.applyUpdate(lndPayment('mig-a', 'SUCCEEDED'), 'TrackPaymentV2');
    store.applyUpdate(lndPayment('mig-b', 'SUCCEEDED'), 'SendPaymentV2', 1);
    submitted(store, 'mig-open', 'OP-OPEN');
    store.db.exec('DROP TABLE outbox; PRAGMA user_version = 6');
    store.close();
    const upgraded = payerStore(file);
    expect(upgraded.db.prepare('PRAGMA user_version').all()[0]?.user_version).toBe(7n);
    expect(upgraded.outbox().map(row => [row.idempotencyKey, row.state])).toEqual([[`OP-M:${preimageFor('mig-a').paymentHash}`, 'pending']]);
  });
});

describe('payment lab outbox: bounds and names', () => {
  it('an effect file over the bound is invalid without being parsed; a key file must be 64 hex digits', () => {
    const big = dir.path('big-receipt.json');
    writeFileSync(big, `{"pad":"${'x'.repeat(lab.outbox.MAX_RECEIPT_BYTES)}"}`);
    expect(lab.outbox.readEffect(big, KEY)).toEqual({ state: 'invalid', reason: expect.stringMatching(/more than 65536/) as string });
    expect(lab.outbox.readEffect(dir.path('missing.json'), KEY)).toEqual({ state: 'absent' });
    writeFileSync(dir.path('array.json'), '[]');
    expect(lab.outbox.readEffect(dir.path('array.json'), KEY)).toMatchObject({ state: 'invalid', reason: 'not an object' });
    const badKey = dir.path('bad-key-lab');
    mkdirSync(badKey);
    writeFileSync(join(badKey, 'outbox.key'), 'not hex\n');
    expect(() => lab.outbox.labKey(badKey)).toThrow(/64-digit hex key/);
  });

  it('the per-lab key is created once, owner-only, and read back by every later use', () => {
    const labDir = dir.path('key-lab');
    mkdirSync(labDir);
    const key = lab.outbox.labKey(labDir);
    expect(key).toHaveLength(32);
    expect(lab.outbox.labKey(labDir).equals(key)).toBe(true);
    expect(readFileSync(join(labDir, 'outbox.key'), 'utf8').trim()).toBe(key.toString('hex'));
    expect(readdirSync(labDir)).toEqual(['outbox.key']);
  });

  it('file names: every character other than letters, digits, _ and - is percent-encoded; device names are escaped', () => {
    expect(lab.outbox.fileBase('ORD-1_a')).toBe('ORD-1_a');
    expect(lab.outbox.fileBase('a:b.c')).toBe('a%3Ab%2Ec');
    expect(lab.outbox.fileBase('..')).toBe('%2E%2E');
    expect(lab.outbox.fileBase('a%3A')).toBe('a%253A');
    expect(lab.outbox.fileBase('CON')).toBe('%43ON');
    expect(lab.outbox.fileBase('nul')).toBe('%6Eul');
    expect(lab.outbox.fileBase('ä')).toBe('%C3%A4');
    expect(lab.outbox.fileBase('é'.repeat(128))).toMatch(/^sha256-[0-9a-f]{64}$/);
  });
});

describe('payment lab outbox: the command line', () => {
  let stdout: string[];
  beforeEach(() => {
    stdout = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => { vi.restoreAllMocks(); });

  const lines = (): Record<string, unknown>[] => stdout.flatMap(chunk => chunk.split('\n')).filter(line => line !== '')
    .map(line => JSON.parse(line) as Record<string, unknown>);
  const noInvoiceCalls: FakeInvoiceApi = { lookupInvoice: () => Promise.reject(new Error('not used')), settleInvoice: async () => undefined,
    cancelInvoice: async () => undefined, subscribeInvoices: async () => undefined };
  const noPayerCalls = {} as FakePayerApi;

  function receiverServices(file: string, effects?: EffectTarget) {
    return {
      payer: () => { throw new Error('not used'); },
      receiver: () => ({ api: noInvoiceCalls, store: receiverStore(file), emit: quiet }),
      ...(effects === undefined ? {} : { outbox: () => effects }),
    };
  }

  it('receiver outbox-status and outbox-run: 75 while a row is pending past its deadline, 0 once performed; no target is a configuration error', async () => {
    const file = 'cli-receiver.db';
    const { store } = settledOrder(file, 'ORD-CLI');
    store.db.exec(`UPDATE outbox SET created_at = '2026-01-01T00:00:00.000Z'`);
    store.close();
    expect(await lab.main(['receiver', 'outbox-status', '--as', 'merchant', '--json'], receiverServices(file))).toBe(75);
    expect(lines()[0]).toMatchObject({ pending: 1, leased: 0, done: 0, overdueCount: 1, deadlineS: 300,
      overdue: [expect.objectContaining({ idempotencyKey: expect.stringMatching(/^ORD-CLI:/) as string })] });
    expect((lines()[0]?.oldestPendingAgeS as number) > 300).toBe(true);
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once'], receiverServices(file))).toBe(4);
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once', '--interval-s', 'x'], receiverServices(file))).toBe(2);
    const effects = target('cli-receiver-receipts');
    stdout = [];
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once'], receiverServices(file, effects))).toBe(0);
    expect(lines().map(item => item.event)).toEqual(['outbox-done', 'outbox-pass']);
    stdout = [];
    expect(await lab.main(['receiver', 'outbox-status', '--as', 'merchant'], receiverServices(file))).toBe(0);
    expect(lines()[0]).toMatchObject({ event: 'outbox-status', pending: 0, done: 1, oldestPendingAgeS: null, overdueCount: 0 });
    stdout = [];
    expect(await lab.main(['receiver', 'show', '--as', 'merchant', '--order', 'ORD-CLI'], receiverServices(file))).toBe(0);
    expect((lines()[0]?.outbox as { state: string }[]).map(row => row.state)).toEqual(['done']);
    expectExactlyOnce(receiverStore(file).outbox(), effects);
  });

  it('outbox-run --once exits 75 when a row is left in backoff', async () => {
    const file = 'cli-backoff.db';
    settledOrder(file, 'ORD-CB').store.close();
    writeFileSync(dir.path('cli-backoff-blocked'), 'file');
    expect(await lab.main(['receiver', 'outbox-run', '--as', 'merchant', '--once'], receiverServices(file, target('cli-backoff-blocked')))).toBe(75);
    expect(lines().map(item => item.event)).toEqual(['outbox-failed', 'outbox-pass']);
  });

  it('payer reconcile performs pending rows after its pass; payer outbox-status reports them', async () => {
    const file = 'cli-payer.db';
    const setup = payerStore(file);
    submitted(setup, 'cli-payer', 'OP-CLI', 'payout');
    setup.applyUpdate(lndPayment('cli-payer', 'SUCCEEDED'), 'SendPaymentV2', 1);
    setup.close();
    const effects = target('cli-payer-confirmations');
    const services = { payer: () => ({ api: noPayerCalls, store: payerStore(file), emit: quiet }), receiver: () => { throw new Error('not used'); },
      outbox: () => effects };
    expect(await lab.main(['payer', 'outbox-status', '--as', 'customer-payer', '--json'], services)).toBe(0);
    expect(lines()[0]).toMatchObject({ pending: 1, overdueCount: 0 });
    stdout = [];
    expect(await lab.main(['payer', 'reconcile', '--as', 'customer-payer'], services)).toBe(0);
    expect(lines().map(item => item.event)).toEqual(['reconcile-started', 'outbox-done', 'outbox-pass']);
    expectExactlyOnce(payerStore(file).outbox(), effects);
  });

  it('receiver listen runs the worker after its reconciliation pass', async () => {
    const file = 'listen.db';
    const { store } = settledOrder(file, 'ORD-LISTEN');
    const effects = target('listen-receipts');
    const stop = new AbortController();
    const api: FakeInvoiceApi = { ...noInvoiceCalls, subscribeInvoices: (_from, _onInvoice, signal) => new Promise(resolve => {
      signal?.addEventListener('abort', () => resolve(), { once: true });
    }) };
    const listening = lab.listen({ api, store, emit: quiet }, { reconcileIntervalMs: 3_600_000, signal: stop.signal,
      afterReconcile: () => { lab.outbox.runPass(store.db, effects, { emit: quiet }); stop.abort(); } });
    await listening;
    expectExactlyOnce(store.outbox(), effects);
  });
});
