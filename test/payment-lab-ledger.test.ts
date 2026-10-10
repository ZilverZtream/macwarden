import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  labModuleUrl, loadLab, preimageFor, tempDirectory,
  type DecodedPayReq, type FakeInvoiceApi, type FakePayerApi, type Invoice, type Lab, type LedgerVerification, type LndLedgerSource,
  type Payment, type PayerStore, type ReceiverStore,
} from './helpers/payment-lab-modules.js';

/**
 * The payment lab's double-entry ledger (examples/payment-lab/src/ledger, design brief 1.3.0
 * item 3): the balance theorem after every scenario the README describes, the migration of a
 * 1.2 database, `ledger-verify` and its exit codes, a corrupted row found and named, LND
 * disagreeing, and every posting committing in the transaction of its state change (a crash
 * inside it leaves neither; a kill after it leaves both). Real stores on temporary SQLite
 * files, scripted stand-ins for LND; no node, no Docker, no credential.
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
const quiet = (): void => undefined;
const VALUE = 1000n;
const FEE = 10n;
const ALLOWANCE = 100n;

function decoded(paymentHash: string, amountMsat: bigint): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-ledger' };
}

function lndPayment(label: string, status: 'IN_FLIGHT' | 'FAILED' | 'SUCCEEDED', feeMsat = FEE): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: VALUE, feeMsat: status === 'SUCCEEDED' ? feeMsat : 0n,
    preimage: status === 'SUCCEEDED' ? preimage : undefined, paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '',
    creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
}

function intentInput(label: string, operationId: string, kind: string, budgetId?: string) {
  const { paymentHash } = preimageFor(label);
  return { operationId, kind, paymentRequest: `lnbcrt1${label}`, invoice: decoded(paymentHash, VALUE), feeLimitMsat: ALLOWANCE, maxParts: 1,
    ...(budgetId === undefined ? {} : { budgetId }) };
}

/** Records a payment intent (and a reservation with a budget) and claims it for submission 1. */
function submitted(store: PayerStore, label: string, operationId: string, kind = 'order-payment', budgetId?: string): string {
  const intent = store.recordIntent(intentInput(label, operationId, kind, budgetId));
  expect(intent.outcome).toBe('recorded');
  const hash = preimageFor(label).paymentHash;
  expect(store.claimForSubmission(hash)).toBe(true);
  return hash;
}

function invoice(paymentHash: string, state: string, amtPaidMsat = 0n, settleIndex = 0n): Invoice {
  return { paymentHash, state, memo: '', valueMsat: VALUE, amtPaidMsat, addIndex: 1n, settleIndex, paymentRequest: '', htlcs: [] };
}

/** Records an order's invoice and LND's answer that created it. */
function openInvoice(store: ReceiverStore, orderId: string, label: string, amountMsat = VALUE): string {
  const { preimage, paymentHash } = preimageFor(label);
  expect(store.recordInvoiceIntent({ orderId, amountMsat, kind: 'standard', preimage, paymentHash }).outcome).toBe('recorded');
  expect(store.markCreated(paymentHash, `lnbcrt1${label}`, 1n)).toBe('open');
  return paymentHash;
}

/** Net debit per account, as verify computed it. */
function balances(result: LedgerVerification): Record<string, bigint> {
  return Object.fromEntries(result.accounts.filter(item => item.computed !== 0n).map(item => [item.account, item.computed]));
}

/** The theorem: every entry balances, the accounts sum to zero, and stored balances and records agree with the entries. */
function expectBalanced(result: LedgerVerification): void {
  expect(result.unbalancedEntries).toEqual([]);
  expect((result as LedgerVerification & { invalidEntries?: unknown[] }).invalidEntries ?? []).toEqual([]);
  expect(result.firstDifference).toBeUndefined();
  expect(result.balanced).toBe(true);
  expect(result.accounts.reduce((sum, item) => sum + item.computed, 0n)).toBe(0n);
  for (const item of result.accounts) {
    expect(item.difference, item.account).toBe(0n);
    expect(item.recordsDifference ?? 0n, item.account).toBe(0n);
  }
}

describe('payment lab ledger: the balance theorem per scenario', () => {
  it('invoice settled: lnd-wallet-incoming against customer-receivable, once however often it is delivered', async () => {
    const store = receiverStore('settled.db');
    const hash = openInvoice(store, 'ORD-S', 'settled');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'subscription')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'lookup')).toBe('duplicate');
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(result.entries).toBe(1);
    expect(balances(result)).toEqual({ 'lnd-wallet-incoming': VALUE, 'customer-receivable': -VALUE });
    expect(store.ledger('ORD-S')).toEqual([{ paymentHash: hash, amountMsat: VALUE, postedAt: expect.any(String) as string }]);
    expect(store.journal('ORD-S').map(entry => entry.event)).toEqual(['invoice-settled']);
    expect(result.lnd).toBe('not-requested');
  });

  it('payment succeeded with fees: principal and fee posted separately; the budget commits principal plus the actual fee', async () => {
    const store = payerStore('succeeded.db');
    store.setBudget('B', 10_000n);
    const hash = submitted(store, 'succeeded', 'OP-S', 'order-payment', 'B');
    expect(store.applyUpdate(lndPayment('succeeded', 'SUCCEEDED'), 'SendPaymentV2', 1).state).toBe('succeeded');
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(balances(result)).toEqual({ 'customer-receivable': VALUE, 'lnd-wallet-outgoing': -(VALUE + FEE), 'routing-fees': FEE,
      'budget:B': VALUE + FEE, 'budget-commitments': -(VALUE + FEE) });
    expect(store.ledger('OP-S').map(item => [item.account, item.amountMsat])).toEqual([['principal', VALUE], ['routing-fee', FEE]]);
    expect(store.journal('OP-S').map(entry => entry.event)).toEqual(['budget-held', 'payment-succeeded', 'budget-consumed']);
    const succeeded = store.journal('OP-S')[1];
    expect(succeeded?.paymentHash).toBe(hash);
    expect(succeeded?.lines.map(line => `${line.direction}:${line.account}:${line.amountMsat}`)).toEqual([
      `debit:customer-receivable:${VALUE}`, `credit:lnd-wallet-outgoing:${VALUE}`, `debit:routing-fees:${FEE}`, `credit:lnd-wallet-outgoing:${FEE}`]);
    expect(store.budgetStatus('B')).toMatchObject({ heldMsat: 0n, consumedMsat: VALUE + FEE });
    // A repeated SUCCEEDED posts nothing more.
    store.applyUpdate(lndPayment('succeeded', 'SUCCEEDED'), 'TrackPaymentV2');
    expect((await lab.verifyLedger(store)).entries).toBe(3);
  });

  it('refund and payout: the operation kind chooses the counter-account', async () => {
    const store = payerStore('refund-payout.db');
    submitted(store, 'refund', 'OP-R', 'refund');
    submitted(store, 'payout', 'OP-P', 'payout');
    store.applyUpdate(lndPayment('refund', 'SUCCEEDED'), 'SendPaymentV2', 1);
    store.applyUpdate(lndPayment('payout', 'SUCCEEDED', 0n), 'SendPaymentV2', 1);
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(balances(result)).toEqual({ 'refunds-payable': VALUE, 'payouts-payable': VALUE, 'lnd-wallet-outgoing': -(2n * VALUE + FEE),
      'routing-fees': FEE });
    // A zero fee still has its routing-fee leg, as in 1.2.
    expect(store.ledger('OP-P').map(item => [item.account, item.amountMsat])).toEqual([['principal', VALUE], ['routing-fee', 0n]]);
  });

  it('budget hold, release and consume: a failed payment releases, a retry holds again, success consumes', async () => {
    const store = payerStore('budget.db');
    store.setBudget('B', 1100n);
    const hash = submitted(store, 'budget', 'OP-B', 'payout', 'B');
    expectBalanced(await lab.verifyLedger(store));
    expect(balances(await lab.verifyLedger(store))).toEqual({ 'budget:B': 1100n, 'budget-commitments': -1100n });
    store.applyUpdate(lndPayment('budget', 'FAILED'), 'SendPaymentV2', 1);
    let result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(balances(result)).toEqual({});
    expect(store.prepareRetry('OP-B').outcome).toBe('recorded');
    expect(store.claimForSubmission(hash)).toBe(true);
    store.applyUpdate(lndPayment('budget', 'SUCCEEDED'), 'SendPaymentV2', 2);
    result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(result.accounts.find(item => item.account === 'budget:B')).toMatchObject({ computed: VALUE + FEE, records: VALUE + FEE });
    expect(store.journal('OP-B').map(entry => entry.event)).toEqual(['budget-held', 'budget-released', 'budget-held', 'payment-succeeded',
      'budget-consumed']);
  });

  it('a withdrawn replacement releases its hold; a success after a recorded failure consumes the released reservation', async () => {
    const store = payerStore('withdrawn.db');
    store.setBudget('B', 10_000n);
    submitted(store, 'late-a', 'OP-W', 'payout', 'B');
    store.applyUpdate(lndPayment('late-a', 'FAILED'), 'SendPaymentV2', 1);
    expect(store.recordIntent(intentInput('late-b', 'OP-W', 'payout', 'B')).outcome).toBe('recorded');
    // LND reports the first payment succeeded after all; the replacement was never sent and is withdrawn.
    store.applyUpdate(lndPayment('late-a', 'SUCCEEDED'), 'TrackPaymentV2');
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(balances(result)).toMatchObject({ 'budget:B': VALUE + FEE, 'payouts-payable': VALUE });
    expect(store.journal('OP-W').map(entry => entry.event)).toEqual(['budget-held', 'budget-released', 'budget-held', 'budget-released',
      'payment-succeeded', 'budget-consumed']);
  });

  it('double payment (payer): the second success moves its principal into suspense', async () => {
    const store = payerStore('double-payer.db');
    store.setBudget('B', 10_000n);
    submitted(store, 'dp-a', 'OP-D', 'order-payment', 'B');
    store.applyUpdate(lndPayment('dp-a', 'FAILED'), 'SendPaymentV2', 1);
    submitted(store, 'dp-b', 'OP-D', 'order-payment', 'B');
    store.applyUpdate(lndPayment('dp-a', 'SUCCEEDED'), 'TrackPaymentV2');
    store.applyUpdate(lndPayment('dp-b', 'SUCCEEDED'), 'SendPaymentV2', 1);
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(balances(result)).toEqual({ 'customer-receivable': VALUE, 'suspense-double-payment': VALUE, 'lnd-wallet-outgoing': -2n * (VALUE + FEE),
      'routing-fees': 2n * FEE, 'budget:B': 2n * (VALUE + FEE), 'budget-commitments': -2n * (VALUE + FEE) });
    expect(store.journal('OP-D').filter(entry => entry.event === 'double-payment').map(entry => entry.paymentHash))
      .toEqual([preimageFor('dp-b').paymentHash]);
    expect(store.ledger('OP-D')).toHaveLength(4);
  });

  it('double payment (receiver) and an underpaid settlement: the money is posted, into suspense', async () => {
    const store = receiverStore('double-receiver.db');
    const { preimage, paymentHash: late } = preimageFor('dr-late');
    expect(store.recordInvoiceIntent({ orderId: 'ORD-D', amountMsat: VALUE, kind: 'standard', preimage, paymentHash: late }).outcome).toBe('recorded');
    expect(store.markNotCreated(late)).toBe(true);
    const live = openInvoice(store, 'ORD-D', 'dr-live');
    expect(store.applyInvoice(invoice(live, 'SETTLED', VALUE, 1n), 'subscription')).toBe('fulfilled');
    expect(store.applyInvoice(invoice(late, 'SETTLED', VALUE, 2n), 'subscription')).toBe('second-payment');
    const short = openInvoice(store, 'ORD-U', 'underpaid');
    expect(store.applyInvoice(invoice(short, 'SETTLED', 900n, 3n), 'subscription')).toBe('underpaid');
    expect(store.applyInvoice(invoice(short, 'SETTLED', 900n, 3n), 'lookup')).toBe('underpaid');
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(balances(result)).toEqual({ 'lnd-wallet-incoming': 2n * VALUE + 900n, 'customer-receivable': -VALUE,
      'suspense-double-payment': -(VALUE + 900n) });
    expect(store.ledger('ORD-D')).toHaveLength(2);
    expect(store.ledger('ORD-U')).toHaveLength(0);
    expect(store.journal('ORD-D').map(entry => entry.event)).toEqual(['invoice-settled', 'invoice-settled', 'double-payment']);
  });
});

describe('payment lab ledger: migration of a 1.2 database', () => {
  const PAYER_LEGACY = `CREATE TABLE ledger_entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL REFERENCES operations (operation_id),
    payment_hash TEXT NOT NULL REFERENCES payments (payment_hash),
    account TEXT NOT NULL CHECK (account IN ('principal', 'routing-fee')),
    amount_msat INTEGER NOT NULL CHECK (amount_msat >= 0),
    posted_at TEXT NOT NULL,
    UNIQUE (operation_id, payment_hash, account))`;
  const RECEIVER_LEGACY = `CREATE TABLE ledger_entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL REFERENCES orders (order_id),
    payment_hash TEXT NOT NULL REFERENCES invoices (payment_hash),
    account TEXT NOT NULL CHECK (account IN ('sales')),
    amount_msat INTEGER NOT NULL CHECK (amount_msat > 0),
    posted_at TEXT NOT NULL,
    UNIQUE (order_id, payment_hash, account))`;
  const DROP_JOURNAL = 'DROP TABLE journal_lines; DROP TABLE journal_entries; DROP TABLE balances;';
  const POSTED = '2026-01-02T03:04:05.000Z';

  it('payer (migration 6): principal and routing-fee rows become balanced entries; reservations get their budget entries', async () => {
    const file = 'migrate-payer.db';
    const store = payerStore(file);
    store.setBudget('B', 10_000n);
    const paid = submitted(store, 'm-paid', 'OP-M1', 'order-payment', 'B');
    store.applyUpdate(lndPayment('m-paid', 'SUCCEEDED'), 'SendPaymentV2', 1);
    const refund = submitted(store, 'm-refund', 'OP-M2', 'refund');
    store.applyUpdate(lndPayment('m-refund', 'SUCCEEDED'), 'SendPaymentV2', 1);
    submitted(store, 'm-open', 'OP-M3', 'payout', 'B');
    // Back to the 1.2 schema: no journal, single-leg rows, user_version 5.
    store.db.exec(`${DROP_JOURNAL} ${PAYER_LEGACY}; PRAGMA user_version = 5`);
    const insert = store.db.prepare('INSERT INTO ledger_entries (operation_id, payment_hash, account, amount_msat, posted_at) VALUES (?, ?, ?, ?, ?)');
    insert.run('OP-M1', paid, 'principal', VALUE, POSTED);
    insert.run('OP-M1', paid, 'routing-fee', FEE, POSTED);
    insert.run('OP-M2', refund, 'principal', VALUE, POSTED);
    insert.run('OP-M2', refund, 'routing-fee', FEE, POSTED);
    store.close();
    const upgraded = payerStore(file);
    expect(upgraded.db.prepare(`SELECT name FROM sqlite_master WHERE name = 'ledger_entries'`).all()).toHaveLength(0);
    expect(upgraded.db.prepare('PRAGMA user_version').all()[0]?.user_version).toBe(7n); // 6 is the ledger migration; 7, the outbox, runs after it
    const result = await lab.verifyLedger(upgraded);
    expectBalanced(result);
    expect(balances(result)).toEqual({ 'customer-receivable': VALUE, 'refunds-payable': VALUE, 'lnd-wallet-outgoing': -2n * (VALUE + FEE),
      'routing-fees': 2n * FEE, 'budget:B': VALUE + FEE + VALUE + ALLOWANCE, 'budget-commitments': -(VALUE + FEE + VALUE + ALLOWANCE) });
    // The 1.2 accessor's shape and values are unchanged.
    expect(upgraded.ledger('OP-M1')).toEqual([{ account: 'principal', amountMsat: VALUE, postedAt: POSTED },
      { account: 'routing-fee', amountMsat: FEE, postedAt: POSTED }]);
    expect(upgraded.journal('OP-M1').map(entry => [entry.event, entry.origin])).toEqual([['payment-succeeded', 'migrated'],
      ['budget-consumed', 'migrated']]);
    expect(upgraded.journal('OP-M3').map(entry => [entry.event, entry.origin])).toEqual([['budget-held', 'migrated']]);
    // Postings after the migration continue the same balances.
    upgraded.applyUpdate(lndPayment('m-open', 'SUCCEEDED'), 'SendPaymentV2', 1);
    expectBalanced(await lab.verifyLedger(upgraded));
  });

  it('receiver (migration 3): sales rows become balanced entries; a second payment and an underpaid settlement go to suspense', async () => {
    const file = 'migrate-receiver.db';
    const store = receiverStore(file);
    const { preimage, paymentHash: late } = preimageFor('mr-late');
    store.recordInvoiceIntent({ orderId: 'ORD-M', amountMsat: VALUE, kind: 'standard', preimage, paymentHash: late });
    store.markNotCreated(late);
    const live = openInvoice(store, 'ORD-M', 'mr-live');
    store.applyInvoice(invoice(live, 'SETTLED', VALUE, 1n), 'subscription');
    store.applyInvoice(invoice(late, 'SETTLED', VALUE, 2n), 'subscription');
    const short = openInvoice(store, 'ORD-MU', 'mr-short');
    store.applyInvoice(invoice(short, 'SETTLED', 900n, 3n), 'subscription');
    store.db.exec(`${DROP_JOURNAL} ${RECEIVER_LEGACY}; PRAGMA user_version = 2`);
    const insert = store.db.prepare(`INSERT INTO ledger_entries (order_id, payment_hash, account, amount_msat, posted_at) VALUES (?, ?, 'sales', ?, ?)`);
    insert.run('ORD-M', live, VALUE, POSTED);
    insert.run('ORD-M', late, VALUE, POSTED);
    store.close();
    const upgraded = receiverStore(file);
    const result = await lab.verifyLedger(upgraded);
    expectBalanced(result);
    expect(balances(result)).toEqual({ 'lnd-wallet-incoming': 2n * VALUE + 900n, 'customer-receivable': -VALUE,
      'suspense-double-payment': -(VALUE + 900n) });
    expect(upgraded.ledger('ORD-M')).toEqual([{ paymentHash: live, amountMsat: VALUE, postedAt: POSTED },
      { paymentHash: late, amountMsat: VALUE, postedAt: POSTED }]);
    expect(upgraded.journal('ORD-M').map(entry => entry.event)).toEqual(['invoice-settled', 'invoice-settled', 'double-payment']);
    expect(upgraded.journal('ORD-MU').map(entry => [entry.event, entry.origin])).toEqual([['underpaid-settlement', 'migrated']]);
  });
});

describe('payment lab ledger: corrupted rows are found and named', () => {
  function paidStore(file: string): { store: PayerStore; entryId: number } {
    const store = payerStore(file);
    submitted(store, `${file}-c`, 'OP-C');
    store.applyUpdate(lndPayment(`${file}-c`, 'SUCCEEDED'), 'SendPaymentV2', 1);
    const entryId = store.journal('OP-C')[0]?.entryId ?? 0;
    return { store, entryId };
  }

  it('an amount changed through the raw database: the entry is unbalanced, and it is the first difference', async () => {
    const { store, entryId } = paidStore('corrupt-amount.db');
    store.db.exec(`UPDATE journal_lines SET amount_msat = amount_msat + 1 WHERE entry_id = ${entryId} AND line_no = 3`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.unbalancedEntries).toEqual([expect.objectContaining({ entryId, event: 'payment-succeeded', debitsMsat: VALUE + FEE + 1n,
      creditsMsat: VALUE + FEE })]);
    expect(result.firstDifference).toMatchObject({ entryId, event: 'payment-succeeded', account: 'routing-fees' });
    expect(result.accounts.find(item => item.account === 'routing-fees')).toMatchObject({ computed: FEE + 1n, stored: FEE, difference: 1n,
      firstEntry: { entryId } });
  });

  it('a stored balance changed: the account differs and the entry that last moved it is named', async () => {
    const { store, entryId } = paidStore('corrupt-balance.db');
    store.db.exec(`UPDATE balances SET balance_msat = '5' WHERE account = 'routing-fees'`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.unbalancedEntries).toEqual([]);
    const report = result.accounts.find(item => item.account === 'routing-fees');
    expect(report).toMatchObject({ computed: FEE, stored: 5n, difference: FEE - 5n });
    expect(report?.firstEntry?.reason).toMatch(new RegExp(`stored balance 5 msat differs.*entry ${entryId} \\(payment-succeeded`));
  });

  it('a line\'s running balance changed: the line is named', async () => {
    const { store, entryId } = paidStore('corrupt-running.db');
    store.db.exec(`UPDATE journal_lines SET balance_after = '999' WHERE entry_id = ${entryId} AND line_no = 1`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.firstDifference).toMatchObject({ entryId, account: 'customer-receivable' });
    expect(result.firstDifference?.reason).toMatch(/recorded 999 msat/);
  });

  it('a deleted entry: its stored balances no longer match, and the record names the payment', async () => {
    const { store, entryId } = paidStore('corrupt-deleted.db');
    store.db.exec(`DELETE FROM journal_lines WHERE entry_id = ${entryId}; DELETE FROM journal_entries WHERE entry_id = ${entryId}`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.accounts.find(item => item.account === 'routing-fees')).toMatchObject({ computed: 0n, stored: FEE, records: FEE });
    expect(result.firstDifference?.paymentHash).toBe(preimageFor('corrupt-deleted.db-c').paymentHash);
  });
});

describe('payment lab ledger: comparison with LND', () => {
  function payments(...items: Payment[]): LndLedgerSource {
    return { listPaymentsPage: async offset => offset === 0n ? { payments: items, lastIndexOffset: BigInt(items.length) }
      : { payments: [], lastIndexOffset: offset } };
  }

  it('payer: agrees with ListPayments over the store\'s payment hashes; other payments on the node are outside the window', async () => {
    const store = payerStore('lnd-agree.db');
    submitted(store, 'lnd-a', 'OP-L');
    store.applyUpdate(lndPayment('lnd-a', 'SUCCEEDED'), 'SendPaymentV2', 1);
    const result = await lab.verifyLedger(store, payments(lndPayment('lnd-a', 'SUCCEEDED'), lndPayment('someone-else', 'SUCCEEDED'),
      lndPayment('lnd-other-failed', 'FAILED')));
    expectBalanced(result);
    expect(result.lnd).toBe('compared');
    expect(result.accounts.find(item => item.account === 'lnd-wallet-outgoing')).toMatchObject({ lnd: -(VALUE + FEE), lndDifference: 0n });
    expect(result.accounts.find(item => item.account === 'routing-fees')).toMatchObject({ lnd: FEE, lndDifference: 0n });
  });

  it('payer: LND reporting a different fee is a difference, named by the payment\'s entry', async () => {
    const store = payerStore('lnd-disagree.db');
    const hash = submitted(store, 'lnd-d', 'OP-LD');
    store.applyUpdate(lndPayment('lnd-d', 'SUCCEEDED'), 'SendPaymentV2', 1);
    const result = await lab.verifyLedger(store, payments(lndPayment('lnd-d', 'SUCCEEDED', FEE + 7n)));
    expect(result.balanced).toBe(false);
    expect(result.lnd).toBe('compared');
    expect(result.accounts.find(item => item.account === 'routing-fees')).toMatchObject({ computed: FEE, lnd: FEE + 7n, lndDifference: -7n });
    expect(result.firstDifference).toMatchObject({ event: 'payment-succeeded', paymentHash: hash });
  });

  it('payer: a success LND reports that the record has not learned yet is pending, not a difference', async () => {
    const store = payerStore('lnd-pending.db');
    submitted(store, 'lnd-p', 'OP-LP');
    const result = await lab.verifyLedger(store, payments(lndPayment('lnd-p', 'SUCCEEDED')));
    expect(result.balanced).toBe(true);
    expect(result.lnd).toBe('pending');
  });

  it('receiver: compares lnd-wallet-incoming with settled invoices\' amt_paid_msat', async () => {
    const store = receiverStore('lnd-receiver.db');
    const hash = openInvoice(store, 'ORD-L', 'lnd-r');
    store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'subscription');
    const source = (amount: bigint): LndLedgerSource => ({ listInvoicesPage: async () => ({ invoices: [invoice(hash, 'SETTLED', amount, 1n),
      invoice(preimageFor('not-ours').paymentHash, 'SETTLED', 5n, 2n)], lastIndexOffset: 2n }) });
    expectBalanced(await lab.verifyLedger(store, source(VALUE)));
    const differs = await lab.verifyLedger(store, source(VALUE + 1n));
    expect(differs.balanced).toBe(false);
    expect(differs.accounts.find(item => item.account === 'lnd-wallet-incoming')).toMatchObject({ lnd: VALUE + 1n, lndDifference: -1n });
    expect(differs.firstDifference).toMatchObject({ event: 'invoice-settled', paymentHash: hash });
  });

  it('paging is bounded: a list longer than the bound is incomplete; a failing or missing call is unavailable', async () => {
    const store = payerStore('lnd-bounds.db');
    const page = Array.from({ length: 500 }, () => lndPayment('filler', 'FAILED'));
    let calls = 0;
    const endless: LndLedgerSource = { listPaymentsPage: async offset => { calls += 1; return { payments: page, lastIndexOffset: offset + 500n }; } };
    expect((await lab.verifyLedger(store, endless)).lnd).toBe('incomplete');
    expect(calls).toBe(201); // 200 full pages, then one probe for a 100,001st item
    const failing: LndLedgerSource = { listPaymentsPage: async () => { throw new lab.TransportError('connection refused', 'connect'); } };
    expect(await lab.verifyLedger(store, failing)).toMatchObject({ lnd: 'unavailable', lndDetail: expect.stringMatching(/connection refused/) as string });
    expect((await lab.verifyLedger(store, {})).lnd).toBe('unavailable');
  });
});

describe('payment lab ledger: ledger-verify on the command line', () => {
  let stdout: string[];
  beforeEach(() => {
    stdout = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(chunk => { stdout.push(String(chunk)); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => { vi.restoreAllMocks(); });

  const noPayerCalls = {} as FakePayerApi;
  const lines = (): Record<string, unknown>[] => stdout.flatMap(chunk => chunk.split('\n')).filter(line => line !== '')
    .map(line => JSON.parse(line) as Record<string, unknown>);

  function payerServices(file: string, source?: LndLedgerSource) {
    return {
      payer: () => ({ api: noPayerCalls, store: payerStore(file), emit: quiet }),
      receiver: () => { throw new Error('not used'); },
      ...(source === undefined ? {} : { ledgerSource: () => source }),
    };
  }

  function paid(file: string, label: string): void {
    const store = payerStore(file);
    submitted(store, label, `OP-${label}`);
    store.applyUpdate(lndPayment(label, 'SUCCEEDED'), 'SendPaymentV2', 1);
    store.close();
  }

  const agreeing = (label: string): LndLedgerSource => ({ listPaymentsPage: async () => ({ payments: [lndPayment(label, 'SUCCEEDED')], lastIndexOffset: 1n }) });

  it('payer: exit 0 and one JSON object with --json when the books balance and agree with LND', async () => {
    paid('cli-ok.db', 'cli-ok');
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer', '--json'], payerServices('cli-ok.db', agreeing('cli-ok')))).toBe(0);
    const [report, ...rest] = lines();
    expect(rest).toEqual([]);
    expect(report).toMatchObject({ balanced: true, lnd: 'compared' });
    expect(report?.accounts).toContainEqual(expect.objectContaining({ account: 'routing-fees', computed: '10', stored: '10', lnd: '10', difference: '0' }));
    expect(report).not.toHaveProperty('firstDifference');
  });

  it('payer: without --json, one ledger-account event per account and a ledger-verify summary', async () => {
    paid('cli-events.db', 'cli-events');
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer'], payerServices('cli-events.db', agreeing('cli-events')))).toBe(0);
    const events = lines().map(item => item.event);
    expect(events.filter(event => event === 'ledger-account')).toHaveLength(3);
    expect(events.at(-1)).toBe('ledger-verify');
  });

  it('payer: exit 75 when LND can not be compared (the pay-only API cannot list payments)', async () => {
    paid('cli-75.db', 'cli-75');
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer', '--json'], payerServices('cli-75.db'))).toBe(75);
    expect(lines()[0]).toMatchObject({ balanced: true, lnd: 'unavailable' });
  });

  it('payer: exit 1 for a corrupted entry, with the entry named in firstDifference', async () => {
    paid('cli-corrupt.db', 'cli-corrupt');
    const store = payerStore('cli-corrupt.db');
    const entryId = store.journal('OP-cli-corrupt')[0]?.entryId ?? 0;
    store.db.exec(`UPDATE journal_lines SET amount_msat = 1 WHERE entry_id = ${entryId} AND line_no = 2`);
    store.close();
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer', '--json'],
      payerServices('cli-corrupt.db', agreeing('cli-corrupt')))).toBe(1);
    expect(lines()[0]).toMatchObject({ balanced: false, firstDifference: { entryId, event: 'payment-succeeded' } });
  });

  it('payer: exit 1 when LND disagrees', async () => {
    paid('cli-lnd.db', 'cli-lnd');
    const source: LndLedgerSource = { listPaymentsPage: async () => ({ payments: [lndPayment('cli-lnd', 'SUCCEEDED', 99n)], lastIndexOffset: 1n }) };
    expect(await lab.main(['payer', 'ledger-verify', '--as', 'customer-payer', '--json'], payerServices('cli-lnd.db', source))).toBe(1);
    expect(lines()[0]).toMatchObject({ balanced: false, lnd: 'compared' });
  });

  it('receiver: uses the profile\'s invoice API (ListInvoices) and exits 0, 1 or 75', async () => {
    const file = 'cli-receiver.db';
    const setup = receiverStore(file);
    const hash = openInvoice(setup, 'ORD-CLI', 'cli-receiver');
    setup.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'subscription');
    setup.close();
    const run = (api: FakeInvoiceApi) => ({
      payer: () => { throw new Error('not used'); },
      receiver: () => ({ api, store: receiverStore(file), emit: quiet }),
    });
    const base: FakeInvoiceApi = { lookupInvoice: () => Promise.reject(new Error('not used')), settleInvoice: async () => undefined,
      cancelInvoice: async () => undefined, subscribeInvoices: async () => undefined };
    const listing = (amount: bigint): FakeInvoiceApi => ({ ...base,
      listInvoicesPage: async () => ({ invoices: [invoice(hash, 'SETTLED', amount, 1n)], lastIndexOffset: 1n }) });
    expect(await lab.main(['receiver', 'ledger-verify', '--as', 'merchant', '--json'], run(listing(VALUE)))).toBe(0);
    expect(await lab.main(['receiver', 'ledger-verify', '--as', 'merchant', '--json'], run(listing(VALUE - 1n)))).toBe(1);
    expect(await lab.main(['receiver', 'ledger-verify', '--as', 'merchant', '--json'], run(base))).toBe(75);
    expect(lines().map(item => [item.balanced, item.lnd])).toEqual([[true, 'compared'], [false, 'compared'], [true, 'unavailable']]);
  });

  it('show includes the journal', async () => {
    paid('cli-show.db', 'cli-show');
    expect(await lab.main(['payer', 'show', '--as', 'customer-payer', '--operation', 'OP-cli-show'], payerServices('cli-show.db'))).toBe(0);
    const record = lines().find(item => item.event === 'payment-record');
    expect((record?.journal as { event: string }[]).map(entry => entry.event)).toEqual(['payment-succeeded']);
  });
});

describe('payment lab ledger: a posting commits with its state change', () => {
  const CRASH = `CREATE TEMP TRIGGER crash_before_posting BEFORE INSERT ON journal_lines BEGIN SELECT RAISE(ABORT, 'simulated crash'); END`;
  const RECOVER = 'DROP TRIGGER crash_before_posting';

  it('a failure inside the transaction leaves neither the state change nor the entry, for every event type', async () => {
    const payer = payerStore('atomic-payer.db');
    payer.setBudget('B', 10_000n);
    // budget-held: the intent and its reservation are not recorded either.
    payer.db.exec(CRASH);
    expect(() => payer.recordIntent(intentInput('atomic', 'OP-A', 'order-payment', 'B'))).toThrow(/simulated crash/);
    expect(payer.operation('OP-A')).toBeUndefined();
    expect(payer.budgetStatus('B')).toMatchObject({ heldMsat: 0n });
    payer.db.exec(RECOVER);
    const hash = submitted(payer, 'atomic', 'OP-A', 'order-payment', 'B');
    // budget-released: the payment stays submitting, the reservation held.
    payer.db.exec(CRASH);
    expect(() => payer.applyUpdate(lndPayment('atomic', 'FAILED'), 'SendPaymentV2', 1)).toThrow(/simulated crash/);
    expect(payer.payment(hash)?.state).toBe('submitting');
    expect(payer.budgetStatus('B')).toMatchObject({ heldMsat: VALUE + ALLOWANCE });
    // payment-succeeded and budget-consumed: not succeeded, not completed, nothing consumed.
    expect(() => payer.applyUpdate(lndPayment('atomic', 'SUCCEEDED'), 'SendPaymentV2', 1)).toThrow(/simulated crash/);
    expect(payer.payment(hash)?.state).toBe('submitting');
    expect(payer.operation('OP-A')?.state).toBe('open');
    expect(payer.budgetStatus('B')).toMatchObject({ heldMsat: VALUE + ALLOWANCE, consumedMsat: 0n });
    payer.db.exec(RECOVER);
    expectBalanced(await lab.verifyLedger(payer));
    payer.applyUpdate(lndPayment('atomic', 'SUCCEEDED'), 'SendPaymentV2', 1);
    expectBalanced(await lab.verifyLedger(payer));

    const receiver = receiverStore('atomic-receiver.db');
    const settled = openInvoice(receiver, 'ORD-A', 'atomic-r');
    receiver.db.exec(CRASH);
    // invoice-settled: no settlement, no fulfillment, no delivery logged.
    expect(() => receiver.applyInvoice(invoice(settled, 'SETTLED', VALUE, 1n), 'subscription')).toThrow(/simulated crash/);
    expect(receiver.invoice(settled)?.state).toBe('open');
    expect(receiver.fulfillmentCount('ORD-A')).toBe(0);
    // underpaid-settlement likewise.
    const short = openInvoice(receiver, 'ORD-AU', 'atomic-u');
    expect(() => receiver.applyInvoice(invoice(short, 'SETTLED', 900n, 2n), 'subscription')).toThrow(/simulated crash/);
    expect(receiver.invoice(short)?.state).toBe('open');
    receiver.db.exec(RECOVER);
    expect(receiver.applyInvoice(invoice(settled, 'SETTLED', VALUE, 1n), 'subscription')).toBe('fulfilled');
    expectBalanced(await lab.verifyLedger(receiver));
  });

  /**
   * A worker killed (SIGKILL, no close, WAL left behind) right after the transaction returned:
   * after a restart the state change and its entry are both there and the books balance.
   */
  const CHILD = `
import { writeFileSync } from 'node:fs';
const [url, file, step, json] = process.argv.slice(-4);
const input = JSON.parse(json, (_key, value) => value !== null && typeof value === 'object' && '$big' in value ? BigInt(value.$big) : value);
const module = await import(url);
const store = new (module.PayerStore ?? module.ReceiverStore)(file);
const result = step === 'intent' ? store.recordIntent(input).outcome
  : step === 'update' ? store.applyUpdate(input, 'TrackPaymentV2').state : store.applyInvoice(input, 'subscription');
writeFileSync(file + '.done', String(result));
process.kill(process.pid, 'SIGKILL');
`;

  function killedAfter(module: string, file: string, step: 'intent' | 'update' | 'settle', input: unknown): string {
    const json = JSON.stringify(input, (_key, value: unknown) => typeof value === 'bigint' ? { $big: value.toString() } : value);
    const child = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', CHILD,
      labModuleUrl(module), dir.path(file), step, json], { encoding: 'utf8', timeout: 60_000 });
    expect(child.status === 0 && child.signal === null, child.stderr).toBe(false);
    expect(existsSync(`${dir.path(file)}.done`), child.stderr).toBe(true);
    return readFileSync(`${dir.path(file)}.done`, 'utf8');
  }

  it('payer: budget-held, budget-released, payment-succeeded with budget-consumed, and double-payment survive a kill', async () => {
    const setup = payerStore('kill-payer.db');
    setup.setBudget('B', 10_000n);
    setup.close();
    expect(killedAfter('payer/store.ts', 'kill-payer.db', 'intent', intentInput('kill-a', 'OP-K', 'order-payment', 'B'))).toBe('recorded');
    let store = payerStore('kill-payer.db');
    expectBalanced(await lab.verifyLedger(store));
    expect(store.journal('OP-K').map(entry => entry.event)).toEqual(['budget-held']);
    expect(store.claimForSubmission(preimageFor('kill-a').paymentHash)).toBe(true);
    store.close();
    expect(killedAfter('payer/store.ts', 'kill-payer.db', 'update', lndPayment('kill-a', 'FAILED'))).toBe('failed');
    store = payerStore('kill-payer.db');
    expectBalanced(await lab.verifyLedger(store));
    submitted(store, 'kill-b', 'OP-K', 'order-payment', 'B');
    store.close();
    expect(killedAfter('payer/store.ts', 'kill-payer.db', 'update', lndPayment('kill-a', 'SUCCEEDED'))).toBe('succeeded');
    store = payerStore('kill-payer.db');
    expectBalanced(await lab.verifyLedger(store));
    store.close();
    expect(killedAfter('payer/store.ts', 'kill-payer.db', 'update', lndPayment('kill-b', 'SUCCEEDED'))).toBe('succeeded');
    store = payerStore('kill-payer.db');
    const result = await lab.verifyLedger(store, { listPaymentsPage: async () => ({
      payments: [lndPayment('kill-a', 'SUCCEEDED'), lndPayment('kill-b', 'SUCCEEDED')], lastIndexOffset: 2n }) });
    expectBalanced(result);
    expect(result.lnd).toBe('compared');
    expect(store.journal('OP-K').map(entry => entry.event)).toEqual(['budget-held', 'budget-released', 'budget-held', 'payment-succeeded',
      'budget-consumed', 'payment-succeeded', 'double-payment', 'budget-consumed']);
  });

  it('receiver: invoice-settled, double-payment and underpaid-settlement survive a kill', async () => {
    const setup = receiverStore('kill-receiver.db');
    const { preimage, paymentHash: late } = preimageFor('kill-late');
    setup.recordInvoiceIntent({ orderId: 'ORD-K', amountMsat: VALUE, kind: 'standard', preimage, paymentHash: late });
    setup.markNotCreated(late);
    const live = openInvoice(setup, 'ORD-K', 'kill-live');
    const short = openInvoice(setup, 'ORD-KU', 'kill-short');
    setup.close();
    expect(killedAfter('receiver/store.ts', 'kill-receiver.db', 'settle', invoice(live, 'SETTLED', VALUE, 1n))).toBe('fulfilled');
    expect(killedAfter('receiver/store.ts', 'kill-receiver.db', 'settle', invoice(late, 'SETTLED', VALUE, 2n))).toBe('second-payment');
    expect(killedAfter('receiver/store.ts', 'kill-receiver.db', 'settle', invoice(short, 'SETTLED', 900n, 3n))).toBe('underpaid');
    const store = receiverStore('kill-receiver.db');
    const result = await lab.verifyLedger(store, { listInvoicesPage: async () => ({ invoices: [invoice(live, 'SETTLED', VALUE, 1n),
      invoice(late, 'SETTLED', VALUE, 2n), invoice(short, 'SETTLED', 900n, 3n)], lastIndexOffset: 3n }) });
    expectBalanced(result);
    expect(result.lnd).toBe('compared');
    expect([...store.journal('ORD-K'), ...store.journal('ORD-KU')].map(entry => entry.event))
      .toEqual(['invoice-settled', 'invoice-settled', 'double-payment', 'underpaid-settlement']);
  });
});

/** The fields of the verification the helper's structural type does not declare yet. */
type Verified = LedgerVerification & { invalidEntries?: { entryId: number; event: string; reference: string; reason: string }[] };
const MAX = 2n ** 63n - 1n;
const UNCHECKED = 'PRAGMA ignore_check_constraints = ON';

describe('payment lab ledger: record-level differences unbalance the result', () => {
  it('two payment-succeeded entries posted under each other\'s payment: the totals agree, the records do not', async () => {
    const store = payerStore('swap-hash.db');
    const a = submitted(store, 'swap-a', 'OP-SA', 'payout');
    const b = submitted(store, 'swap-b', 'OP-SB', 'payout');
    store.applyUpdate(lndPayment('swap-a', 'SUCCEEDED', 10n), 'SendPaymentV2', 1);
    store.applyUpdate(lndPayment('swap-b', 'SUCCEEDED', 20n), 'SendPaymentV2', 1);
    // Payment, reference and operation swapped between the two entries: each entry is well formed and every account total unchanged.
    store.db.exec(`UPDATE journal_entries SET payment_hash = 'x', reference = 'x', operation_id = 'x' WHERE payment_hash = '${a}';
      UPDATE journal_entries SET payment_hash = '${a}', reference = '${a}', operation_id = 'OP-SA' WHERE payment_hash = '${b}';
      UPDATE journal_entries SET payment_hash = '${b}', reference = '${b}', operation_id = 'OP-SB' WHERE payment_hash = 'x';`);
    const result = await lab.verifyLedger(store) as Verified;
    expect(result.accounts.every(item => item.difference === 0n && (item.recordsDifference ?? 0n) === 0n)).toBe(true);
    expect(result.invalidEntries ?? []).toEqual([]);
    expect(result.balanced).toBe(false);
    expect(result.firstDifference).toMatchObject({ event: 'payment-succeeded' });
    expect(result.accounts.find(item => item.account === 'routing-fees')?.firstEntry?.reason).toMatch(/fee (10|20) msat in the record; its entries post (20|10) msat to routing-fees/);
  });

  it('a budget entry naming a reservation that does not exist: unbalanced, named by the entry', async () => {
    const store = payerStore('missing-reservation.db');
    store.setBudget('B', 10_000n);
    submitted(store, 'mr-a', 'OP-MR', 'payout', 'B');
    const held = store.journal('OP-MR')[0]?.entryId ?? 0;
    store.db.exec(`UPDATE journal_entries SET reference = 'reservation:999' WHERE entry_id = ${held}`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.firstDifference).toMatchObject({ entryId: held });
    expect(result.accounts.find(item => item.account === 'budget:B')?.firstEntry).toMatchObject({ entryId: held });
  });

  it('a succeeded payment with no payment-succeeded entry, at zero value and fee: unbalanced, the payment named', async () => {
    const store = payerStore('missing-entry.db');
    const hash = submitted(store, 'me-a', 'OP-ME', 'payout');
    store.applyUpdate({ ...lndPayment('me-a', 'SUCCEEDED', 0n), valueMsat: 0n }, 'SendPaymentV2', 1);
    store.db.exec('DELETE FROM journal_lines; DELETE FROM journal_entries; DELETE FROM balances;');
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.firstDifference).toMatchObject({ account: 'lnd-wallet-outgoing', paymentHash: hash });
    expect(result.firstDifference?.reason).toMatch(/no payment-succeeded entry/);
  });

  it('an LND difference on a budgeted payment names the entry that touches the account, not the budget-held one', async () => {
    const store = payerStore('first-of-account.db');
    store.setBudget('B', 10_000n);
    submitted(store, 'fa-a', 'OP-FA', 'payout', 'B');
    store.applyUpdate(lndPayment('fa-a', 'SUCCEEDED'), 'SendPaymentV2', 1);
    const succeeded = store.journal('OP-FA').find(entry => entry.event === 'payment-succeeded')?.entryId;
    expect(succeeded).toBe(2);
    const result = await lab.verifyLedger(store, { listPaymentsPage: async () => ({ payments: [lndPayment('fa-a', 'SUCCEEDED', FEE + 1n)],
      lastIndexOffset: 1n }) });
    expect(result.balanced).toBe(false);
    expect(result.firstDifference).toMatchObject({ entryId: succeeded, event: 'payment-succeeded' });
    expect(result.accounts.find(item => item.account === 'routing-fees')?.firstEntry).toMatchObject({ entryId: succeeded });
  });
});

describe('payment lab ledger: a corrupt stored balance is named, and the column refuses one', () => {
  it('an unreadable balance on an account at zero ("0-", "00") is corrupt, not 0', async () => {
    for (const [file, raw] of [['corrupt-zero-minus.db', '0-'], ['corrupt-zero-double.db', '00']] as const) {
      const store = payerStore(file);
      store.setBudget('B', 10_000n);
      submitted(store, file, 'OP-CZ', 'payout', 'B');
      store.applyUpdate(lndPayment(file, 'FAILED'), 'SendPaymentV2', 1);
      expectBalanced(await lab.verifyLedger(store));
      store.db.exec(`${UNCHECKED}; UPDATE balances SET balance_msat = '${raw}' WHERE account = 'budget:B'`);
      const result = await lab.verifyLedger(store);
      expect(result.balanced, raw).toBe(false);
      expect(result.accounts.find(item => item.account === 'budget:B')?.firstEntry?.reason, raw).toMatch(/corrupt/);
    }
  });

  it('the balance columns hold canonical decimals only', () => {
    const store = payerStore('canonical.db');
    store.setBudget('B', 10_000n);
    submitted(store, 'canon', 'OP-CN', 'payout', 'B');
    for (const bad of ['0-', '00', '-0', '01', '', '1-0', '+1', '1'.repeat(40)]) {
      expect(() => store.db.exec(`UPDATE balances SET balance_msat = '${bad}' WHERE account = 'budget:B'`), bad).toThrow(/CHECK constraint failed/);
      expect(() => store.db.exec(`UPDATE journal_lines SET balance_after = '${bad}' WHERE line_no = 1`), bad).toThrow(/CHECK constraint failed/);
    }
    for (const good of ['0', '-5', '12', `-${'9'.repeat(39)}`]) {
      expect(() => store.db.exec(`UPDATE balances SET balance_msat = '${good}' WHERE account = 'budget:B'`), good).not.toThrow();
    }
  });
});

describe('payment lab ledger: an entry\'s shape is checked against its posting rule and the records', () => {
  /** A budgeted payout (entries 1 held, 2 payment-succeeded, 3 consumed) and a second payout (entry 4). */
  async function shaped(file: string): Promise<PayerStore> {
    const store = payerStore(file);
    store.setBudget('B', 10_000n);
    submitted(store, `${file}-a`, 'OP-A', 'payout', 'B');
    store.applyUpdate(lndPayment(`${file}-a`, 'SUCCEEDED'), 'SendPaymentV2', 1);
    submitted(store, `${file}-b`, 'OP-B', 'payout');
    store.applyUpdate(lndPayment(`${file}-b`, 'SUCCEEDED'), 'SendPaymentV2', 1);
    expect(store.journal('OP-A').map(entry => entry.entryId)).toEqual([1, 2, 3]);
    expect(store.journal('OP-B').map(entry => entry.entryId)).toEqual([4]);
    expectBalanced(await lab.verifyLedger(store));
    return store;
  }

  const cases: [string, string, number][] = [
    ['a line\'s leg cleared', 'UPDATE journal_lines SET leg = NULL WHERE entry_id = 2 AND line_no = 1', 2],
    ['a principal leg named routing-fee', `UPDATE journal_lines SET leg = 'routing-fee' WHERE entry_id = 2 AND line_no = 1`, 2],
    ['line numbers not 1..n', 'UPDATE journal_lines SET line_no = 9 WHERE entry_id = 2 AND line_no = 1', 2],
    ['the two wallet lines\' numbers swapped', `UPDATE journal_lines SET line_no = 99 WHERE entry_id = 2 AND line_no = 2;
      UPDATE journal_lines SET line_no = 2 WHERE entry_id = 2 AND line_no = 4; UPDATE journal_lines SET line_no = 4 WHERE entry_id = 2 AND line_no = 99`, 2],
    ['the event of the other book', `UPDATE journal_entries SET event = 'invoice-settled' WHERE entry_id = 2`, 2],
    ['a reference that is not the payment hash', `UPDATE journal_entries SET reference = 'other' WHERE entry_id = 2`, 2],
    ['the operation of another payment', `UPDATE journal_entries SET operation_id = 'OP-B' WHERE entry_id = 2`, 2],
    ['an origin outside the enum', `${UNCHECKED}; UPDATE journal_entries SET origin = 'imported' WHERE entry_id = 2`, 2],
    ['a migrated entry after a live one', `UPDATE journal_entries SET origin = 'migrated' WHERE entry_id = 2`, 2],
    ['an unreadable posted_at', `UPDATE journal_entries SET posted_at = 'junk' WHERE entry_id = 2`, 2],
    ['a posted_at earlier than the previous live entry\'s', `UPDATE journal_entries SET posted_at = '2000-01-01T00:00:00.000Z' WHERE entry_id = 4`, 4],
    ['a budget entry without the reservation\'s payment hash', 'UPDATE journal_entries SET payment_hash = NULL WHERE entry_id = 1', 1],
    ['a budget entry with its directions reversed', `UPDATE journal_lines SET direction = CASE direction WHEN 'debit' THEN 'credit'
      ELSE 'debit' END WHERE entry_id = 1`, 1],
  ];
  cases.forEach(([name, sql, target], index) => {
    it(`${name}: unbalanced, the entry named`, async () => {
      const store = await shaped(`shape-${index}.db`);
      store.db.exec(sql);
      const result = await lab.verifyLedger(store) as Verified;
      expect(result.balanced).toBe(false);
      expect(result.firstDifference?.entryId).toBe(target);
      expect((result.invalidEntries ?? []).map(entry => entry.entryId)).toContain(target);
    });
  });

  it('a balances row whose last_entry_id or updated_at is not its last entry\'s: unbalanced, the account named', async () => {
    for (const [file, sql, reason] of [
      ['shape-last-id.db', `UPDATE balances SET last_entry_id = 999 WHERE account = 'routing-fees'`, /names entry 999/],
      ['shape-updated.db', `UPDATE balances SET updated_at = 'junk' WHERE account = 'routing-fees'`, /updated at "junk"/],
    ] as const) {
      const store = await shaped(file);
      store.db.exec(sql);
      const result = await lab.verifyLedger(store);
      expect(result.balanced, file).toBe(false);
      expect(result.accounts.find(item => item.account === 'routing-fees')?.firstEntry, file).toMatchObject({ entryId: 4,
        reason: expect.stringMatching(reason) as string });
    }
  });

  it('receiver: a settlement posted to another order is named', async () => {
    const store = receiverStore('shape-receiver.db');
    const hash = openInvoice(store, 'ORD-SH', 'shape-r');
    openInvoice(store, 'ORD-SH2', 'shape-r2');
    store.applyInvoice(invoice(hash, 'SETTLED', VALUE, 1n), 'subscription');
    expectBalanced(await lab.verifyLedger(store));
    store.db.exec(`UPDATE journal_entries SET operation_id = 'ORD-SH2' WHERE payment_hash = '${hash}'`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.firstDifference).toMatchObject({ entryId: 1, event: 'invoice-settled' });
  });
});

describe('payment lab ledger: the LND page bound', () => {
  /** A ListPayments of `total` failed payments (outside the window), paged by offset. */
  function listing(total: number, counter: { calls: number }): LndLedgerSource {
    const filler = lndPayment('bound', 'FAILED');
    return { listPaymentsPage: async (offset, max) => {
      counter.calls += 1;
      const count = Math.max(0, Math.min(max, total - Number(offset)));
      return { payments: Array.from({ length: count }, () => filler), lastIndexOffset: offset + BigInt(count) };
    } };
  }

  it('exactly 100,000 items is compared; 100,001 is incomplete', async () => {
    const store = payerStore('bound.db');
    for (const [total, expected] of [[99_999, 'compared'], [100_000, 'compared'], [100_001, 'incomplete']] as const) {
      const counter = { calls: 0 };
      expect((await lab.verifyLedger(store, listing(total, counter))).lnd, String(total)).toBe(expected);
      expect(counter.calls, String(total)).toBeLessThanOrEqual(201);
    }
  });
});

describe('payment lab ledger: principal plus fee above 2^63 - 1', () => {
  function bigPayment(store: PayerStore, label: string): string {
    store.setBudget('B', MAX);
    const { paymentHash } = preimageFor(label);
    expect(store.recordIntent({ operationId: `OP-${label}`, kind: 'payout', paymentRequest: `lnbcrt1${label}`, invoice: decoded(paymentHash, MAX - 10n),
      feeLimitMsat: 10n, maxParts: 1, budgetId: 'B' }).outcome).toBe('recorded');
    expect(store.claimForSubmission(paymentHash)).toBe(true);
    store.applyUpdate(lndPayment(label, 'FAILED'), 'SendPaymentV2', 1);
    // LND reports success after the recorded failure, with a fee above the allowance: the released reservation is consumed at MAX - 10 + 11.
    expect(store.applyUpdate({ ...lndPayment(label, 'SUCCEEDED', 11n), valueMsat: MAX - 10n }, 'TrackPaymentV2').state).toBe('succeeded');
    return paymentHash;
  }

  it('a success after a recorded failure is recorded; budget-consumed posts principal and fee as two balanced pairs', async () => {
    const store = payerStore('overflow.db');
    const hash = bigPayment(store, 'overflow');
    expect(store.payment(hash)?.state).toBe('succeeded');
    const result = await lab.verifyLedger(store);
    expectBalanced(result);
    expect(result.accounts.find(item => item.account === 'budget:B')).toMatchObject({ computed: MAX + 1n, records: MAX + 1n });
    const consumed = store.journal('OP-overflow').find(entry => entry.event === 'budget-consumed');
    expect(consumed?.lines.map(line => `${line.direction}:${line.account}:${line.amountMsat}`)).toEqual([
      `debit:budget:B:${MAX - 10n}`, `credit:budget-commitments:${MAX - 10n}`, 'debit:budget:B:11', 'credit:budget-commitments:11']);
  });

  it('a 1.2 database holding such a consumed reservation opens, and its migration preserves the total', async () => {
    const file = 'overflow-migrate.db';
    const store = payerStore(file);
    const hash = bigPayment(store, 'overflow-m');
    store.db.exec(`DROP TABLE journal_lines; DROP TABLE journal_entries; DROP TABLE balances; CREATE TABLE ledger_entries (
      entry_id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, payment_hash TEXT NOT NULL,
      account TEXT NOT NULL CHECK (account IN ('principal', 'routing-fee')), amount_msat INTEGER NOT NULL CHECK (amount_msat >= 0),
      posted_at TEXT NOT NULL, UNIQUE (operation_id, payment_hash, account)); PRAGMA user_version = 5`);
    const insert = store.db.prepare('INSERT INTO ledger_entries (operation_id, payment_hash, account, amount_msat, posted_at) VALUES (?, ?, ?, ?, ?)');
    insert.run('OP-overflow-m', hash, 'principal', MAX - 10n, '2026-01-02T03:04:05.000Z');
    insert.run('OP-overflow-m', hash, 'routing-fee', 11n, '2026-01-02T03:04:05.000Z');
    store.close();
    const upgraded = payerStore(file);
    const result = await lab.verifyLedger(upgraded);
    expectBalanced(result);
    expect(balances(result)).toMatchObject({ 'budget:B': MAX + 1n, 'budget-commitments': -(MAX + 1n), 'lnd-wallet-outgoing': -(MAX + 1n) });
  });
});
