import { DatabaseSync } from 'node:sqlite';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  labModuleUrl, loadLab, preimageFor, tempDirectory,
  type DecodedPayReq, type Invoice, type Lab, type LedgerVerification, type Payment, type PayerStore, type RawDb, type ReceiverStore,
} from './helpers/payment-lab-modules.js';

/**
 * The payment lab's ledger (examples/payment-lab/src/ledger) against the pre-1.4 audit's
 * findings: a 1.2.1 underpaid-then-full settlement migrates into a book that verifies, with the
 * receipt's amount the entry's; entries at the edges of the int64 range are read and named; a
 * released reservation's history is required, not only its net; the clock clamp is bounded and a
 * live entry far ahead is named; origins are checked against the migration's watermark; verify
 * on the store's own connection reads LND outside its transaction. Real stores on temporary
 * SQLite files; no node, no credential.
 */

let lab: Lab;
let migrate: {
  upgradePayerLedger(db: RawDb): void;
  upgradeReceiverLedger(db: RawDb): void;
};
const dir = tempDirectory();

beforeAll(async () => {
  lab = await loadLab();
  migrate = await import(/* @vite-ignore */ labModuleUrl('ledger/migrate.ts')) as typeof migrate;
});
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
const ALLOWANCE = 100n;
const POSTED = '2026-01-02T03:04:05.000Z';
const MIN_INT64 = -(2n ** 63n);

function decoded(paymentHash: string): DecodedPayReq {
  return { destination: DESTINATION, paymentHash, amountMsat: VALUE, timestamp: BigInt(Math.floor(Date.now() / 1000)), expirySeconds: 3600n,
    description: 'payment-lab-ledger-audit' };
}

function lndPayment(label: string, status: 'FAILED' | 'SUCCEEDED'): Payment {
  const { preimage, paymentHash } = preimageFor(label);
  return { paymentHash, status, valueMsat: VALUE, feeMsat: status === 'SUCCEEDED' ? FEE : 0n, preimage: status === 'SUCCEEDED' ? preimage : undefined,
    paymentRequest: '', failureReason: status === 'FAILED' ? 'FAILURE_REASON_NO_ROUTE' : '', creationTimeNs: 1n, paymentIndex: '1', htlcs: [] };
}

function submitted(store: PayerStore, label: string, operationId: string, budgetId?: string): string {
  const { paymentHash } = preimageFor(label);
  const intent = store.recordIntent({ operationId, kind: 'payout', paymentRequest: `lnbcrt1${label}`, invoice: decoded(paymentHash),
    feeLimitMsat: ALLOWANCE, maxParts: 1, ...(budgetId === undefined ? {} : { budgetId }) });
  expect(intent.outcome).toBe('recorded');
  expect(store.claimForSubmission(paymentHash)).toBe(true);
  return paymentHash;
}

function paid(store: PayerStore, label: string): string {
  const hash = submitted(store, label, `OP-${label}`);
  store.applyUpdate(lndPayment(label, 'SUCCEEDED'), 'SendPaymentV2', 1);
  return hash;
}

function settled(paymentHash: string, amtPaidMsat: bigint): Invoice {
  return { paymentHash, state: 'SETTLED', memo: '', valueMsat: VALUE, amtPaidMsat, addIndex: 1n, settleIndex: 1n, paymentRequest: '', htlcs: [] };
}

function expectBalanced(result: LedgerVerification): void {
  expect(result.unbalancedEntries).toEqual([]);
  expect(result.invalidEntries).toEqual([]);
  expect(result.firstDifference).toBeUndefined();
  expect(result.balanced).toBe(true);
}

/** Every reason the result gives: listed entries and the accounts' first entries. */
function reasons(result: LedgerVerification): string {
  return [...result.unbalancedEntries, ...result.invalidEntries, ...result.accounts.flatMap(item => item.firstEntry ?? [])]
    .map(item => item.reason).join('\n');
}

/** Runs a migration step as openDatabase does: inside one BEGIN IMMEDIATE. */
function inTransaction(db: RawDb, step: (db: RawDb) => void): void {
  db.exec('BEGIN IMMEDIATE');
  try {
    step(db);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

const count = (db: RawDb, sql: string): number => Number(db.prepare(sql).all()[0]?.n);

const DROP_JOURNAL = 'DROP TABLE journal_lines; DROP TABLE journal_entries; DROP TABLE balances; DROP TABLE IF EXISTS journal_migration; DROP TABLE outbox;';

describe('payment lab ledger audit: a 1.2.1 underpaid-then-full settlement migrates into a book that verifies', () => {
  const RECEIVER_LEGACY = `CREATE TABLE ledger_entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL REFERENCES orders (order_id),
    payment_hash TEXT NOT NULL REFERENCES invoices (payment_hash), account TEXT NOT NULL CHECK (account IN ('sales')),
    amount_msat INTEGER NOT NULL CHECK (amount_msat > 0), posted_at TEXT NOT NULL, UNIQUE (order_id, payment_hash, account))`;

  /** 1.2.1: SETTLED for 900 then for 1000; the record kept 900, the order was fulfilled, and the sales row says 1000. */
  function legacyReceiver(file: string): string {
    const store = receiverStore(file);
    const { preimage, paymentHash } = preimageFor(`${file}-u`);
    store.recordInvoiceIntent({ orderId: 'ORD-U', amountMsat: VALUE, kind: 'standard', preimage, paymentHash });
    store.markCreated(paymentHash, 'lnbcrt1u', 1n);
    store.applyInvoice(settled(paymentHash, 900n), 'subscription');
    store.db.exec(`${DROP_JOURNAL} ${RECEIVER_LEGACY}; PRAGMA user_version = 2`);
    store.db.prepare(`INSERT INTO fulfillments (payment_hash, order_id, fulfilled_at) VALUES (?, 'ORD-U', ?)`).run(paymentHash, POSTED);
    store.db.prepare(`INSERT INTO ledger_entries (order_id, payment_hash, account, amount_msat, posted_at) VALUES ('ORD-U', ?, 'sales', ?, ?)`)
      .run(paymentHash, VALUE, POSTED);
    store.db.prepare(`UPDATE orders SET state = 'fulfilled', fulfilled_at = ? WHERE order_id = 'ORD-U'`).run(POSTED);
    store.close();
    return paymentHash;
  }

  it('the record takes the fulfilling amount, the conflict is logged naming both, and the receipt carries the entry\'s amount', async () => {
    const hash = legacyReceiver('underpaid-then-full.db');
    const upgraded = receiverStore('underpaid-then-full.db');
    expectBalanced(await lab.verifyLedger(upgraded));
    expect(upgraded.invoice(hash)?.amtPaidMsat).toBe(VALUE);
    const conflicts = upgraded.db.prepare(`SELECT source FROM deliveries WHERE payment_hash = ? AND outcome = 'settlement-amount-conflict'`).all(hash);
    expect(conflicts).toHaveLength(1);
    expect(String(conflicts[0]?.source)).toMatch(/amt_paid_msat 900 msat.*settlement 1000 msat/);
    const [entry] = upgraded.journal('ORD-U');
    expect(entry).toMatchObject({ event: 'invoice-settled', origin: 'migrated' });
    expect(upgraded.outbox('ORD-U').map(row => row.payload)).toEqual([expect.objectContaining({ amountMsat: '1000', ledgerEntryId: entry?.entryId })]);
  });

  it('a book a 1.3.0 conversion left (record at 900, receipt row at 900, no watermark) is completed by upgradeReceiverLedger, idempotently', async () => {
    const hash = legacyReceiver('underpaid-then-full-130.db');
    const store = receiverStore('underpaid-then-full-130.db');
    // What 1.3.0's migrations 3 and 4 left: the record and the pending receipt row at 900, no conflict logged, no watermark.
    store.db.exec(`UPDATE invoices SET amt_paid_msat = 900; UPDATE outbox SET payload = json_set(payload, '$.amountMsat', '900');
      DELETE FROM deliveries WHERE outcome = 'settlement-amount-conflict';`);
    const before = await lab.verifyLedger(store);
    expect(before.balanced).toBe(false);
    expect(reasons(before)).toMatch(/settles 1000 msat; the invoice record's amt_paid_msat 900/);
    store.db.exec('DROP TABLE journal_migration');
    inTransaction(store.db, migrate.upgradeReceiverLedger);
    expectBalanced(await lab.verifyLedger(store));
    expect(store.invoice(hash)?.amtPaidMsat).toBe(VALUE);
    expect(store.outbox('ORD-U').map(row => row.payload.amountMsat)).toEqual(['1000']);
    const deliveries = count(store.db, 'SELECT COUNT(*) AS n FROM deliveries');
    inTransaction(store.db, migrate.upgradeReceiverLedger);
    expect(count(store.db, 'SELECT COUNT(*) AS n FROM deliveries')).toBe(deliveries);
    expectBalanced(await lab.verifyLedger(store));
  });
});

describe('payment lab ledger audit: entry IDs at the edges of the int64 range', () => {
  const insertEntry = (db: RawDb, id: bigint, reference: string): void => {
    db.prepare(`INSERT INTO journal_entries (entry_id, event, reference, operation_id, payment_hash, origin, posted_at)
      VALUES (?, 'payment-succeeded', ?, 'OP-X', ?, 'live', ?)`).run(id, reference, reference, POSTED);
  };

  it('entries with no lines at -2^63 and at 2^60 are read and listed by ID; one above 2^53 is malformed', async () => {
    const store = payerStore('edge-ids.db');
    paid(store, 'edge-1');
    insertEntry(store.db, MIN_INT64, 'a'.repeat(64));
    insertEntry(store.db, 2n ** 60n, 'b'.repeat(64));
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.unbalancedEntries.map(item => item.entryId)).toEqual([Number(MIN_INT64), 2 ** 60]);
    expect(result.unbalancedEntries[1]?.reason).toMatch(/entry ID 1152921504606846976 is outside ±\(2\^53 - 1\)/);
  });

  it('an entry at -2^63 occupying a payment\'s key is found before the payment\'s success is recorded', async () => {
    const store = payerStore('edge-hidden.db');
    const hash = submitted(store, 'edge-h', 'OP-H');
    insertEntry(store.db, MIN_INT64, hash);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.entries).toBe(1);
    expect(result.unbalancedEntries.map(item => item.entryId)).toEqual([Number(MIN_INT64)]);
  });

  it('post refuses an entry ID a number can not hold exactly, and the state change rolls back with it', () => {
    const store = payerStore('edge-post.db');
    const hash = submitted(store, 'edge-p', 'OP-P');
    insertEntry(store.db, 2n ** 60n, 'c'.repeat(64));
    expect(() => store.applyUpdate(lndPayment('edge-p', 'SUCCEEDED'), 'SendPaymentV2', 1)).toThrow(/outside ±\(2\^53 - 1\)/);
    expect(store.payment(hash)?.state).not.toBe('succeeded');
    expect(store.outbox('OP-P')).toEqual([]);
  });
});

describe('payment lab ledger audit: a released reservation\'s history is required', () => {
  const PAYER_LEGACY = `CREATE TABLE ledger_entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL REFERENCES operations (operation_id),
    payment_hash TEXT NOT NULL REFERENCES payments (payment_hash), account TEXT NOT NULL CHECK (account IN ('principal', 'routing-fee')),
    amount_msat INTEGER NOT NULL CHECK (amount_msat >= 0), posted_at TEXT NOT NULL, UNIQUE (operation_id, payment_hash, account))`;
  const DELETE_BUDGET_HISTORY = `DELETE FROM journal_lines WHERE entry_id IN (SELECT entry_id FROM journal_entries WHERE reference LIKE 'reservation:%');
    DELETE FROM journal_entries WHERE reference LIKE 'reservation:%';
    DELETE FROM balances WHERE account IN ('budget:B', 'budget-commitments');`;

  function failedBudgeted(file: string): PayerStore {
    const store = payerStore(file);
    store.setBudget('B', 10_000n);
    submitted(store, `${file}-f`, 'OP-R', 'B');
    store.applyUpdate(lndPayment(`${file}-f`, 'FAILED'), 'SendPaymentV2', 1);
    return store;
  }

  it('deleting the hold and the release of a released reservation unbalances the result, naming the reservation', async () => {
    const store = failedBudgeted('released-deleted.db');
    expectBalanced(await lab.verifyLedger(store));
    store.db.exec(DELETE_BUDGET_HISTORY);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(reasons(result)).toMatch(/reservation 1 is released; it has no budget-held or budget-released entry/);
  });

  it('migration 6 posts the pair for a 1.2 released reservation; upgradePayerLedger posts it for a book 1.3.0 converted without it', async () => {
    const file = 'released-migrated.db';
    const store = failedBudgeted(file);
    store.db.exec(`${DROP_JOURNAL} ${PAYER_LEGACY}; PRAGMA user_version = 5`);
    store.close();
    const upgraded = payerStore(file);
    expectBalanced(await lab.verifyLedger(upgraded));
    expect(upgraded.journal('OP-R').map(entry => [entry.event, entry.origin])).toEqual([['budget-held', 'migrated'], ['budget-released', 'migrated']]);
    // What 1.3.0 converted it into: nothing for the reservation, and no watermark.
    upgraded.db.exec(`${DELETE_BUDGET_HISTORY} DROP TABLE journal_migration;`);
    expect((await lab.verifyLedger(upgraded)).balanced).toBe(false);
    inTransaction(upgraded.db, migrate.upgradePayerLedger);
    expectBalanced(await lab.verifyLedger(upgraded));
    expect(upgraded.journal('OP-R').map(entry => [entry.event, entry.origin])).toEqual([['budget-held', 'live'], ['budget-released', 'live']]);
    inTransaction(upgraded.db, migrate.upgradePayerLedger);
    expect(count(upgraded.db, 'SELECT COUNT(*) AS n FROM journal_entries')).toBe(2);
  });
});

describe('payment lab ledger audit: the clock clamp is bounded', () => {
  const FUTURE = '2099-01-01T00:00:00.000Z';

  it('a last live entry far ahead of the clock is named, and the next entry is posted at the clock, not pinned to it', async () => {
    const store = payerStore('clock-ahead.db');
    paid(store, 'ahead-1');
    store.db.exec(`UPDATE journal_entries SET posted_at = '${FUTURE}'; UPDATE balances SET updated_at = '${FUTURE}'`);
    const alone = await lab.verifyLedger(store);
    expect(alone.balanced).toBe(false);
    expect(alone.invalidEntries.map(item => [item.entryId, item.reason])).toEqual([[1, expect.stringMatching(/more than 24 hours after this run's clock/)]]);
    paid(store, 'ahead-2');
    const times = store.db.prepare('SELECT posted_at FROM journal_entries ORDER BY entry_id').all().map(row => String(row.posted_at));
    expect(times[0]).toBe(FUTURE);
    expect(times[1]).not.toBe(FUTURE);
    expect(Math.abs(Date.parse(times[1] ?? '') - Date.now())).toBeLessThan(3_600_000);
    const result = await lab.verifyLedger(store);
    expect(result.invalidEntries.map(item => item.entryId)).toEqual([1]);
  });
});

describe('payment lab ledger audit: origins are checked against the migration\'s watermark', () => {
  it('relabelling every live entry migrated is named (no migration posted them)', async () => {
    const store = payerStore('relabel-migrated.db');
    paid(store, 'relabel-1');
    paid(store, 'relabel-2');
    store.db.exec(`UPDATE journal_entries SET origin = 'migrated'`);
    const result = await lab.verifyLedger(store);
    expect(result.balanced).toBe(false);
    expect(result.invalidEntries.map(item => item.entryId)).toEqual([1, 2]);
    expect(result.invalidEntries[0]?.reason).toMatch(/it is migrated, but the ledger migration posted entries up to 0 only/);
  });

  it('a migrated entry relabelled live is named', async () => {
    const store = payerStore('relabel-live.db');
    paid(store, 'relabel-l');
    // A migration that posted entry 1 (as the 1.3 conversion records it).
    store.db.exec(`UPDATE journal_entries SET origin = 'migrated'; UPDATE journal_migration SET migrated_through = 1`);
    expectBalanced(await lab.verifyLedger(store));
    store.db.exec(`UPDATE journal_entries SET origin = 'live'`);
    const result = await lab.verifyLedger(store);
    expect(result.invalidEntries.map(item => [item.entryId, item.reason])).toEqual([[1, expect.stringMatching(/it is live, but at or below entry 1/)]]);
  });

  it('a fresh store records a watermark of 0', () => {
    const store = payerStore('watermark-fresh.db');
    expect(store.db.prepare('SELECT migrated_through FROM journal_migration').all()).toEqual([{ migrated_through: 0n }]);
  });
});

describe('payment lab ledger audit: LND differences are kept per payment', () => {
  it('two fee differences that cancel in the account totals are listed and explained', async () => {
    const store = payerStore('lnd-offsetting.db');
    const fees = new Map<string, bigint>();
    for (const [label, fee] of [['off-1', 10n], ['off-2', 20n]] as const) {
      const hash = submitted(store, label, `OP-${label}`);
      store.applyUpdate({ ...lndPayment(label, 'SUCCEEDED'), feeMsat: fee }, 'SendPaymentV2', 1);
      fees.set(hash, fee === 10n ? 20n : 10n);
    }
    const result = await lab.verifyLedger(store, {
      listPaymentsPage: () => Promise.resolve({ payments: [...fees].map(([hash, fee], index) =>
        ({ ...lndPayment(index === 0 ? 'off-1' : 'off-2', 'SUCCEEDED'), paymentHash: hash, feeMsat: fee })), lastIndexOffset: 2n }),
    });
    expect(result.lnd).toBe('compared');
    expect(result.balanced).toBe(false);
    for (const report of result.accounts) expect(report.lndDifference ?? 0n, report.account).toBe(0n);
    const listed = result as LedgerVerification & { lndDifferences: { account: string; paymentHash?: string; reason: string }[]; lndDifferenceCount: number };
    expect(listed.lndDifferenceCount).toBe(4);
    expect(listed.lndDifferences.map(item => [item.account, item.paymentHash])).toEqual([...fees.keys()].flatMap(hash =>
      [['lnd-wallet-outgoing', hash], ['routing-fees', hash]]));
    expect(result.firstDifference?.reason).toMatch(/^LND reports .* msat for .* on payment hash [0-9a-f]{64}; the entries post/);
  });
});

describe('payment lab ledger audit: verify on the store\'s own connection reads LND outside its transaction', () => {
  /** An in-memory copy of a store's database: verify then reads on the store's own connection. */
  function inMemoryCopy(file: string): DatabaseSync {
    const db = new DatabaseSync(':memory:', { readBigInts: true });
    db.exec(`ATTACH DATABASE '${dir.path(file).replaceAll("'", "''")}' AS src`);
    const objects = db.prepare(`SELECT type, name, sql FROM src.sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
      ORDER BY type = 'index'`).all();
    for (const object of objects) db.exec(String(object.sql));
    for (const object of objects) if (object.type === 'table') db.exec(`INSERT INTO main."${String(object.name)}" SELECT * FROM src."${String(object.name)}"`);
    db.exec('DETACH DATABASE src');
    return db;
  }

  it('the read transaction is not open while ListPayments is awaited', async () => {
    const store = payerStore('shared-connection.db');
    const hash = paid(store, 'shared-1');
    store.close();
    const db = inMemoryCopy('shared-connection.db');
    try {
      const during: boolean[] = [];
      const result = await lab.verifyLedger({ db, book: 'payer' } as unknown as PayerStore, {
        listPaymentsPage: async () => {
          during.push(db.isTransaction);
          await new Promise(resolve => { setImmediate(resolve); });
          during.push(db.isTransaction);
          return { payments: [{ ...lndPayment('shared-1', 'SUCCEEDED'), paymentHash: hash }], lastIndexOffset: 1n };
        },
      });
      expect(during).toEqual([false, false]);
      expect(result.lnd).toBe('compared');
      expectBalanced(result);
      expect(db.isTransaction).toBe(false);
    } finally {
      db.close();
    }
  });
});
